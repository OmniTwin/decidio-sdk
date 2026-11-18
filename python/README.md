# decidio (Python)

The one-line approval gate for AI-agent actions — the agent **suspends** for human approval and **resumes**, sealing a portable Authority Receipt the customer owns. Decidio gates (proceed | route | block) + records; **the agent executes its own action** on resume. Decidio never executes and holds no downstream credentials. Python-first, with a TS twin (`@decidio/sdk`) that emits an identical request + receipt (conformance-asserted).

**Coding agents and assistants:** a one-page skill file for adding the gate to an agent — Python and TypeScript on the same page — is published at https://decidioai.com/skills/decidio-guard.md (the site summary for machines is https://decidioai.com/llms.txt).

The wrapper IS the SDK: `guard.protect(fn, describe)` ships in this package, and `python -m decidio` is the two-minute
tour, the sign-in and the token admin around it. Install, wrap one function, run — the tour is optional.

```python
from decidio import guard

# one line — same surface in every runtime
create_opp = guard.protect(
    create_opp_raw,
    lambda o: {"action": "createOpportunity", "amount": o["Amount"], "scope": "Opportunity"},
)

# The call returns what your function returned AND what Decidio recorded about it (since 0.2.0).
done = create_opp({"Amount": 86_000})
print(done.value)                              # your function's own return value, untouched
print(done.confirmation["evidence_tier"])      # e.g. "application_confirmed"
# Only want the value? `guard.protect_best_effort(...)` returns it bare — but then "the report
# was not recorded" becomes invisible again, which is the gap this shape exists to close.
```

- **proceed** → runs immediately (auto-approved under a named, versioned policy rule), sealed.
- **route** → **suspends** (`DecidioSuspended`): parks the call args in an agent-side store, the process may exit; resumes when a human approves and re-runs *your* function.
- **block** → raises `DecidioBlocked`; your function never runs.

## Setup

> Update check: network commands ask PyPI once a day whether a newer version exists; if so, an interactive run asks
> `Upgrade now? [y/n]` first (`y` upgrades through the pip of the interpreter you are running and re-runs your command once; `n` exits), a headless run prints the
> notice and continues (`DECIDIO_REQUIRE_LATEST=1` makes it exit). `DECIDIO_NO_UPDATE_CHECK=1` skips it. Nothing is sent
> to Decidio; `verify` never checks.
>
> The token recovery journal (`.decidio-token-journal`, owner-only, gitignored; append-only by the CLI's behaviour, not
> OS-enforced or tamper-evident; ids and timestamps, never a token
> value) has one JSON row per event: `minted` (issued, written BEFORE the credential file), `retired how=persisted` (the
> credential file holds it - live, and that file is its handle; not revoked), `retired how=revoked`, `probe`. `doctor`
> names outstanding rows; `quickstart cleanup` sweeps them.
>
> No invite yet? The local demo — the whole tour on your machine against a stand-in of the API — ships in the TypeScript CLI
> first: `npx @decidio/sdk quickstart --demo`. It comes to `python -m decidio` when asked for.
>
> Sign in once with `python -m decidio login` (the CLI emails you a link; you paste it). The sign-in is stored
> owner-only in your profile, bound to this terminal window, for 30 days or until `logout` / `quickstart cleanup`
> forgets it here (the session token itself stays valid until it expires (up to 30 days) — there is no server-side revocation yet).
> The tour's human step offers three doors: answer in the terminal, open the decision in the web app (a one-time
> link, signed in for you), or scan the QR with your phone — the terminal follows whichever decides first.
>
> If you exported `DECIDIO_SESSION_TOKEN` to sign in from a headless shell, unset it before launching agent
> code from that shell: child processes inherit exported variables, and that credential is your workspace
> login, not the agent's (`unset DECIDIO_SESSION_TOKEN` in bash/zsh, `Remove-Item Env:DECIDIO_SESSION_TOKEN` in
> PowerShell). In the tour's human step, `y` approves and `n` rejects — the rejection half is
> worth watching once: the request is refused and your function does not run.
```bash
pip install 'decidio[signing]'
export DECIDIO_API_URL=https://mcp-staging.decidioai.com   # the invite-only lab (the default is Decidio, https://mcp.decidioai.com)
python -m decidio init my-agent   # sign in, register the agent, mint its API token, write .env
```
> Just ran `python -m decidio quickstart` in this directory and kept its agent? Its `.env` already
> works — skip `init` and protect your function.
Every later command that talks to Decidio reads `.env` from the same directory (`verify` is offline and
never does). First run tip: pass
`mode="blocking"` to `guard.protect(...)` to watch the whole loop live (trigger → route to a
human → approve with `python -m decidio approvals approve <id>` → your function executes).
A brand-new agent matches no auto-approve rule, so **every** request routes to a human —
routing-by-default is the product working, not a misconfiguration. (A **block** is different: a
named block rule, or the universal backstop when no active policy governs agents at all — fail
closed, no human involved.)
Other commands: `doctor` (config + connectivity + token scope), `receipt <id>` (download the
sealed Authority Receipt). One runtime dependency — `cryptography`, which signs the request-bound
identity proof and the execution report, so it is a base dependency rather than an extra (without
it a signed agent could not reach a confirming tier at all). Engine adapters are extras.

## Durable resume (real approvals take minutes to days)
Without `mode="blocking"`, a routed action suspends: it parks its call args locally and raises
`DecidioSuspended`; the process may exit. **The parked payload is plaintext on the agent's disk:**
the full call arguments and their signature sit in `.decidio-pending/` until the decision resolves —
owner-only permissions where the OS supports it, gitignored by `init`, but not encrypted. Treat that
directory as you treat the `.env` beside it; a custom `PendingStore` can encrypt at rest. **Self-serve transport — start here:**
`guard.worker()` — a durable poll worker that re-executes parked actions on approval, exactly
once. No inbound URL, no shared secrets; this is the transport for the hosted sandbox.

**Operator deployments** can use the signed webhook instead — Decidio POSTs a signed wake-up to your
resume URL; the handler verifies the HMAC fail-closed, asks Decidio for the decision, and runs the
parked action only if Decidio says THIS request was approved (the verdict inside the webhook is never
the authority — see "Every door confirms the approval" below):
```python
# FastAPI
@app.post("/decidio/resume")
async def decidio_resume(req: Request):
    return guard.resume.handle(await req.body(), req.headers.get("x-decidio-signature"))
```
Honest requirement: webhook signing uses a shared secret configured on BOTH sides — your
`DECIDIO_WEBHOOK_SECRET` must equal the Decidio server's, and self-hosted production also
allow-lists resume hosts. Against the hosted sandbox, use the worker. Since 0.7.0 there is **no
API-token fallback**: without `webhook_secret` (or `allow_unsigned`, for a trusted network only)
`handle()` raises `PermissionError` naming the fix. The worker needs no inbound secret. The secret is a
dedicated one — **never the Decidio server's `API_AUTH_TOKEN`** (its admin bearer, which must not be
copied onto an agent host); since this release the server sends no webhook at all without
`DECIDIO_WEBHOOK_SECRET`.

**Closing the last window yourself.** Pass `with_context=True` and your action receives an
`ExecutionContext` as its first argument — `{decision_id, attempt_id, idempotency_key}`:

```python
pay_invoice = guard.protect(
    lambda ctx, inv: stripe.PaymentIntent.create(
        amount=inv["amount"], currency="usd",
        idempotency_key=ctx.idempotency_key,      # stable across every attempt at this decision
    ),
    lambda inv: {"action": "payInvoice", "amount": inv["amount"]},
    with_context=True,
)
```

Opt-in rather than inferred from the signature, because guessing wrong would hand a payment call
a context object where it expected an invoice. `describe` still receives your arguments only — it
describes the *request*, while the context describes the *execution*.

Either way the re-execution guarantee is: **once invocation may have begun, the SDK never
automatically invokes it again unless the downstream system provides an idempotency guarantee or
an operator explicitly reconciles it.** That holds across processes and restarts — a durable
`invoking` marker is written to the pending store before your function is called. It is not
exactly-once against an external API, which no client can offer; an action that ran and then
raised becomes `indeterminate` and waits for `reconcile()` rather than being retried into a
double-write.

`reconcile()` records an outcome; it does not undo an authority decision. A DENIED decision is
refused on both outcomes — nothing ran, so there is no outcome to record. And a decision that is
still `invoking` may be running the action right now, so releasing it takes an explicit assertion
from the person who can actually check:

It refuses by returning, not by raising — check `report_recorded` and read `diagnostic`:

```python
guard.resume.reconcile(id, outcome="not_committed", reason="...")                       # refused while invoking
guard.resume.reconcile(id, outcome="not_committed", reason="...", worker_stopped=True)  # accepted
```

The assertion is stamped into the ledger (`reconciled.workerStopped`), so the record shows that a
person claimed to have checked — not merely that the decision was released.

**If you wrote a custom store, see the upgrade section above** — there are three changes, not two,
and the third (`mark_discarded`) is a hard construction failure rather than a signature widening.
Note also that Python raises `TypeError` on the old `delete` arity and the SDK treats a failed
`delete` as best-effort cleanup, so a store left on the 0.2.x signature stops removing payloads
*silently*.

`indeterminate` needs no such flag: the handler has already returned or raised, so nothing is in
flight — only the downstream result is unknown.

## The durable store is a revision chain (since 0.3.2)

`FilePendingStore` keeps each decision's execution record as an **append-only revision chain** —
`<id>.rev.1`, `<id>.rev.2`, … — and the head is the highest number. Every state change reads the
head, validates against exactly that record, writes the successor to a temp file, and publishes it
with `os.link` to the next revision number. `os.link` fails if that name already exists, so **exactly
one writer wins each revision**, with no lock, no timeout and no daemon — on any volume that
supports hard links (NTFS, ext4, APFS, XFS; not FAT/exFAT, and not every network or FUSE mount —
on those every write fails closed rather than silently degrading). A loser re-reads the new head
and validates again — against what actually happened, not a snapshot. **No revision file is ever
deleted:** a name that could be reused is a race that could be lost, so the chain is genuinely
append-only and a decision's whole history stays readable in place.

This replaced the 0.2/0.3 one-marker-per-state layout after an external retest showed why it had to:
that layout made a transition in three separate steps (read the markers, write the new one, sweep
the weaker ones), so a process holding `claimed_preinvoke` could validate its snapshot, lose to a
second process that durably wrote *and returned* a denial, then write `invoking` anyway — and its
sweep deleted the tombstone. The SDK reported a denial as final and ran the denied action. Every
*sequential* schedule was safe; the window was inside one transition. The chain has no such window:
nothing ever deletes the head, and the rule that refuses a denied decision now runs against the
denial that just landed.

**Upgrading.** A directory in the older layout is migrated once, at the first construction of a
0.3.2 store: each decision's markers become the head of a fresh chain and the markers are removed.
Corrupt markers are left exactly as found and the decision reads as unreadable until a person
inspects it. **Stop every older worker that shares the directory BEFORE the first 0.3.2 process
constructs its store, then upgrade them together.** The one-time migration reads the markers it
finds and removes exactly those; an older SDK still writing leaves a marker beside a chain, and
that decision is then *unreadable* by design — neither reading can be trusted over the other, so
the store refuses to pick one.

**Custom stores.** The `PendingStore` contract has said since 0.2.0 that every method must be atomic
against concurrent callers. The shipped file store did not honor that until now; a custom store must.
The deterministic two-process schedules that proved the defect live in the Decidio source
repository's conformance suite (not part of this package): a denial landing while an invoker is
paused between validating and publishing; two conflicting settlements from one head; and a denier
paused while the approver publishes four revisions past it. A store that cannot pass those schedules
is not atomic, whatever its methods say.

**Sizing envelope.** Nothing deletes a revision, so each decision leaves a handful of small files (one
per transition, typically four to six) and a head lookup lists the directory. That is comfortable for
tens of thousands of decisions on a local disk; beyond that, or for any deployment that shares a store
across hosts, use a transactional custom `PendingStore`. The tested envelope is a **single host on a local
filesystem with hard links** — network, FUSE and multi-host volumes are outside it, and their link
semantics have not been exercised. Never compact the directory while a worker runs; if compaction is
ever wanted it is an offline job with every writer stopped.

## Reading a receipt

The cryptography is only half the evidence. These are the fields that an outside reader has
actually misread on a first run, and what each one means.

**`ratified: yes` next to `nominated deciders: 0` is not a contradiction.** `nominatedDeciders` is the list of people
nominated **in advance** to decide. When an agent's request is *routed* rather than pre-assigned,
that list is empty — nobody was nominated, because the request had not happened yet. The person who
actually decided is the **ratifier** (`ratifiedBy`). So a receipt for a human-approved action reads
`nominated deciders: 0, ratified: yes`, and the human is recorded, in the field named for the role they
played. The verifier prints this explanation whenever the pair appears.

**`evaluatedLimits` is what the request was MEASURED AGAINST, not a rule that fired.** (Receipts sealed before 0.5.0 spell these two `deciders` and `appliedLimits` - schemaVersion 1; the verifier reads both.) It holds up to
three entries, and only those that have a value: `requested_amount` (the amount actually asked for),
`auto_approve_threshold` and `hard_cap` (the ceilings on the agent's own token). So a decision routed
to a human because *no rule matched* can still list an `auto_approve_threshold` — that is the bar the
request was compared to and did not clear, not a limit that was applied to it. Read
`requested_amount` as the ask, the other two as ceilings.

**`firedRules` is what the policy engine actually matched — for any verdict.** It is not an
auto-approve indicator: a request **blocked by the universal backstop** (no active policy governs
agents at all) carries that backstop rule here, so
non-empty does not mean "approved" and empty does not mean "blocked". The field that states the
disposition is `authority.result`; `firedRules` tells you which named, versioned rules produced it.

**`payloadSchemaUri` is a `urn:`, not a URL.** It is content-addressed —
`urn:decidio:sealed-payload:1:sha256:<hash>` — so it *identifies* the exact schema the record was
sealed under and pins it against substitution. It does not locate a document, and nothing will
resolve it. (Shipping the schema alongside the verifier so you can check the hash yourself is on
the roadmap; today the URN is an identifier only, and this note exists so it does not look broken.)

**`prevHash` proves a pointer, not an ancestry.** A non-null `prevHash` shows this record was
sealed after a specific predecessor, but a single-file verification cannot check that predecessor
exists or is what it claims. Verify a chain (`python -m decidio.verify --issuer <did> a.json b.json c.json`) when the sequence
matters.

**Pinning is trust-on-first-use.** The first sign-in (or `init`) against a Decidio remembers the DID
it publishes at `<api>/api/did` — so that first contact trusts the connection, not the key. What
remembering buys is everything afterwards: every later verification is checked against a key this
computer already holds rather than one it was handed with the receipt, and a host that starts
publishing a different key is flagged, never silently adopted. Receipts from Decidio's hosted service
also verify against the issuer built into the verifier. The verifier refuses an unpinned run unless you
ask for one (`--allow-unpinned`), and marks that verdict.

## Upgrading from 0.2.x to 0.3.0

0.3.0 is a breaking release. Every item below changes behaviour a 0.2.x caller may depend on, so
none of it is left to be discovered at runtime.

**If you wrote a custom `PendingStore`, it will fail to construct.** `mark_discarded(decision_id,
verdict, reason=None)` is now REQUIRED — it writes the tombstone that makes a denied decision
permanently unclaimable, and a store that cannot record a denial cannot uphold the guarantee, so
this is refused at construction rather than deep inside a resolve. `delete` also takes an optional
owning attempt (`delete(decision_id, attempt_id=None)`) so a superseded attempt cannot clean up the live one's
payload, and `settle` takes `worker_stopped`. The shipped stores show the shape; the ownership
corpus that pins these rules (claim fencing, terminal denial, advance-only transitions, settle
preconditions) lives in the Decidio source repository and is not part of this package — the rules
themselves are the ones stated above.

**`recover()` now raises instead of returning `[]`** when the ledger cannot be read
(`DecidioRecoveryUnavailable`). `[]` and "I cannot tell you what you owe" are the same value
to a caller and mean opposite things, so a script reading `if (!(await recover()).length)` treated
a permissions change as proof that nothing was outstanding. Wrap the call if you poll it.

**`reconcile()` refuses two things it used to allow.** A DENIED decision cannot be reconciled on
either outcome, and releasing a decision that is still `invoking` takes an explicit
`worker_stopped=True` — that is the one state where the handler may be running right now, and
releasing it hands one approved action to two live workers. It refuses by RETURNING, not raising:
check `report_recorded` and read `diagnostic`.

**The adapters return a different shape.** `decidio.adapters.temporal.gate` and the LangGraph adapter returns
`ProtectedExecution` — `{ value, decisionId, confirmation }` — instead of the bare value.
`decidio.adapters.inngest.gate` returns `ProtectedExecution` too — for a Python caller this is a SILENT break: `result = await ...gate(...)` keeps working and starts holding a dataclass.
`gate_interruptions` is now `authorize_interruptions` and returns a THREE-tuple ending in
`confirmation_supported=False`; the old name is a deprecated alias, but the arity change means
unpacking into two names raises — a loud failure, chosen over silently dropping the flag. Read
`.value` where you previously read the result.

**The transport rule refuses URLs it used to accept.** A gate URL must now be absolute and either
https or an exact loopback host, whatever credentials the config holds. A relative or scheme-less
`apiUrl` throws at startup — it used to pass on the reasoning that the shipped transport rejects
it, which says nothing about a custom transport.

**Decision ids are shape-checked.** Letters, digits, dot, dash and underscore, starting with a
letter or digit, at most 128 characters, never trimmed. The server enforces the same grammar (it
had none before 0.3.0, which is why the SDK was the stricter of the two). Ids Decidio issues are
well inside it.

**`/agent/confirm` can answer 409.** `TERMINALLY_DENIED` means a human refused the decision and
your action appears to have run anyway; `NOT_AUTHORIZED` means there is no approved, sealed
decision for evidence to attach to. Neither is a report failure and neither is retryable — the SDK
raises `DecidioHttpError` with advice that says so, rather than the "only its report failed" note
that fits every other confirm error.

## Engine adapters (durable suspend on the engine you already run)
Thin translators onto each engine's native durable wait — `pip install decidio[langgraph|temporal|openai]`:
```python
# LangGraph — true drop-in (interrupt() is contextvar-based)
create_opp = guard.protect(create_opp_raw, describe, adapter="langgraph")

# Inngest / Temporal / OpenAI Agents — pass the engine handle:
await decidio.adapters.inngest.gate(step, guard, ctx, run=lambda: create_opp_raw(o))
await decidio.adapters.temporal.gate(wf, guard, ctx, run=..., )
# Authorization-only: the OpenAI runtime executes the tool itself, so this door never sees the
# return value and has nothing to attest. It says so rather than handing back an empty confirmation.
resolved, pending, confirmation_supported = decidio.adapters.openai.authorize_interruptions(guard, run_state, describe)
```

### Every door confirms the approval is for THIS request (0.7.0)
Before 0.7.0 a resume ran on the word of whatever woke it — a webhook, a Temporal signal, an Inngest
event, a LangGraph resume value saying "approved". Now every door (inline, the durable webhook and
worker, LangGraph, Temporal, Inngest, OpenAI Agents) asks Decidio before your function runs:
`GET /agent/status` must say `approved` (or `auto_approved`) **and** return the request commitment
this SDK sent with `/agent/authorize`, recomputed over the request about to run. A wake-up is only a
wake-up.

- **The commitment** is an HMAC-SHA256 under your agent's key material over the canonical request:
  `{action, amount, scope, args, kwargs}` on the core wrapper (`kwargs` only when there are any, so it
  matches the TypeScript twin byte for byte), the described context on an engine adapter (plus the tool
  call itself on the OpenAI door). With the Ed25519 key `init` writes (`DECIDIO_AGENT_KEY` +
  `DECIDIO_AGENT_DID`) only your agent holds the key, and Decidio stores and returns an opaque value it
  can neither read nor forge for another request. **Prefer that key.** Without it the commitment is keyed
  by `DECIDIO_API_TOKEN` — a bearer Decidio receives on every call — so it is opaque to everyone except
  the Decidio server itself.
- **Rotating key material strands pending approvals.** Re-minting the agent token, changing
  `DECIDIO_AGENT_KEY`, or running the guard and the resume controller with different key material makes
  every routed approval still pending fail its check as `request_changed` (the recompute no longer
  matches). Drain pending approvals before rotating, or ask again for each afterwards.
- **Refusals** (both subclass `DecidioBlocked`; nothing ran): `DecidioRequestChanged` — "the request
  changed after approval", naming the decision — and `DecidioApprovalUnverified` (`code ==
  "commitment_missing"` when Decidio returns no commitment for a request this SDK bound, or
  `"unverifiable"`). The durable path reports `not_approved` (Decidio still says pending: the action
  stays parked) or `request_unverified`. **`resolve()` now asks Decidio before it runs, so it RAISES when
  Decidio is unreachable** (nothing ran; the entry stays parked) — catch it and retry, or leave the entry
  for the worker.
- **LangGraph** needs key material (`init`, or `DECIDIO_API_TOKEN`) and a checkpointer run with a
  `thread_id` (a routed gate without the run's thread, task and per-execution scratchpad refuses, naming
  its decision). LangGraph re-runs an interrupted node on resume; the re-run authorizes with an
  idempotency key derived from its own thread + task + commitment, so Decidio answers with the SAME
  decision instead of minting a second one. Edit the graph state and the edited request becomes a NEW
  pending decision — an approval is never applied across requests. `decidio_resume_command` now
  requires the webhook's `decisionId`.
- **Temporal**: whenever you pass `authorize_fn`, also pass `verify_fn=lambda decision_id:
  workflow.execute_activity(verify_activity, ...)`, where the activity returns
  `decidio.adapters.temporal._verify_activity(guard, decision_id, ctx)` for the same `ctx`. A signal
  only wakes the workflow; still pending → it waits for the next one. Since 0.12.0 also pass
  `claim_fn=lambda decision_id, claim_key: workflow.execute_activity(claim_activity, ...)`, where the
  activity returns `_claim_activity(guard, decision_id, claim_key)`; `_authorize_activity` keys the
  request on the activity's workflow, run and activity ids.
- **Inngest**: the check runs as a memoized step after the event; a premature or forged event waits
  again. `resume_event(raw_body, signature, webhook_secret)` now verifies Decidio's HMAC like the
  TypeScript bridge (it used to accept a parsed dict unverified); `allow_unsigned=True` is for a
  trusted network only.
- **OpenAI Agents**: `apply_resume(state, item, verdict)` is removed. Use
  `apply_verified_resume(guard, state, item, decision_id, describe)`, which approves the interruption
  only when Decidio records that decision as approved for THIS tool call: the approval is bound to the
  call's name, call id and exact argument string as well as `describe(item)`, so an item edited after
  approval, or a second identical call, never rides it. Park each pending `(item.call_id, decision_id)`
  with the serialized state and, after `RunState.from_string`, find each item again by `item.call_id`.
  An interruption with no call id is refused (`ValueError`) before anything is sent.
- **Known limit — one gated action per LangGraph node** (true before 0.7.0 too). LangGraph re-runs the
  whole node on resume, so an earlier gate in the same node runs again: if its request auto-approved and
  its action already ran, the replay answers `proceed` to your verified agent and the action runs twice.
  Put each gated action in its own node, or make the actions idempotent.
- **An approval is collected once (0.12.0).** Before acting on a person's approval, the blocking wait,
  the durable resume, Temporal and `apply_verified_resume` claim it (`POST /agent/claim/<id>`) with a key
  random to that run, and run only if Decidio says this run collected it - otherwise `DecidioBlocked`:
  "This approval was already used by another run. Ask again for a new approval." Auto-approvals are
  never claimed; reading the status never claims. Every authorize with a request commitment also sends
  a request key (a fresh id per call, your own `request_key=`, or the engine's id for the call), and a
  retried authorize carries the same key.
- **Known limit — LangGraph and Inngest do not claim yet.** Two concurrent resumes of the same LangGraph
  thread (the checkpoint is your storage) can both pass the check and both run the action; resume each
  one from one place (one worker per thread id, or a lock). Inngest relies on its own step semantics.
- **Upgrade the gate first.** A keyed SDK refuses a routed approval from a Decidio gate that does not
  return commitments (`commitment_missing`) — it fails closed, never silently passes.

## Own the record — verify it yourself
Every outcome is a sealed W3C-VC (Ed25519 did:key), tamper-evident and **offline-verifiable with no Decidio dependency**:
```bash
pip install decidio[verify]
python -m decidio verify receipt.json                      # the SDK door: no DID to paste
python -m decidio.verify --issuer <did:key:...> receipt.json   # the standalone door, pinned explicitly
```
Every run pins to a **trust anchor** and prints it first. In order: an explicit `--issuer <did:key>`;
else (the SDK door, `python -m decidio verify`) the issuer DID this computer remembered for your
Decidio when you signed in or ran `init` — fetched from the host's public `<api>/api/did` and kept in
your profile beside the stored sign-in; else the built-in issuers of Decidio's own services
(`decidio.verify.KNOWN_ISSUERS`: each one published at its host's `/api/did`, e.g. https://mcp.decidioai.com/api/did and,
for the lab, https://mcp-staging.decidioai.com/api/did). A receipt's own `issuer` field is never the anchor — it is only
what the file claims, and any key can sign a file that names itself — so a receipt from any other issuer
is refused (exit 2) until you pin one. If a later sign-in sees the host publish a DIFFERENT DID - or a server's
verify response names one - the CLI says so loudly and keeps the remembered one. `receipt` pins to the DID
remembered for the host, else the DID the server names as its own (`expectedIssuer`), checks the file offline
against it, and fails (exit 1) when that check or the server's own check says the record does not verify. The SDK
door takes its host from your shell's `DECIDIO_API_URL`, never `.env`. An
unpinned run proves internal consistency only — any keyholder could have issued such a file — so it
stays a named choice (`--allow-unpinned`), and its verdict says so.

**What VALID means — and what it does not.** A pinned `VALID` proves the receipt's bytes were
sealed by that issuer and are unaltered since. It does **not** prove the approved action ran.
Execution is confirmed *after* the seal, and a sealed record is immutable, so the receipt's own
`authority.result` and `confirmation.status` are a snapshot taken at seal time — a receipt for an
approved-but-never-executed action verifies `VALID`, correctly. The verifier prints those fields
under `as sealed`, plus a note saying exactly this. The check is **cryptographic, not semantic**:
it does not evaluate business rules, timestamp plausibility, revocation, or whether a later record
superseded this one. For current execution status, ask the issuer.

## Errors
Every Decidio error subclasses `DecidioError`, so one `except DecidioError:` catches all of them.

- `DecidioBlocked` / `DecidioRejected` — policy blocked it / a human rejected it; your function never ran.
- `DecidioRequestChanged` (0.7.0, a `DecidioBlocked`) — Decidio approved the decision for a *different* request than the one about to run ("the request changed after approval"); nothing executed. Ask again for the request you mean to run.
- `DecidioApprovalUnverified` (0.7.0, a `DecidioBlocked`) — the approval could not be tied to this request: `code == "commitment_missing"` (Decidio returned no request commitment although this SDK sent one — typically a gate older than 0.7.0) or `"unverifiable"`. Nothing executed.
- `DecidioSuspended` — durable mode: parked for async approval. Not a failure.
- `DecidioTimeout` — blocking mode only: nobody decided in time; nothing executed. Since 0.6.4 the SDK's last act before raising is to tell Decidio it gave up, so the request is closed as **withdrawn** (it leaves the queue; a later approval does nothing) — `err.withdrawn` is `True` when that landed and `False` when the call failed and the request may still be open. Withdrawing needs the bound agent token and the signing key `init` writes (an unbound or unsigned caller cannot withdraw anything — it just gets `withdrawn=False`). If a human decided in the last poll window, the SDK honours that decision instead: the action runs as approved, or `DecidioRejected` is raised. The durable path never withdraws: its parked action is what a later approval resumes. Since 0.12.0 a request that may be shared is never withdrawn: after an `idempotentReplay` or `openTwin` answer, or a 409 `SHARED_REQUEST`, `err.shared` is `True` and a person still decides it.
- `DecidioRateLimitError` — the workspace's governed-action limit; carries `limit` / `remaining` / `reset_at`.
- `DecidioUnsafeArguments` — your call arguments cannot survive JSON with their meaning intact, so
  nothing was routed and nothing ran. The message names the field and the fix. Most often: a `NaN`
  or `Decimal`, a `datetime`, a set, or **an integer larger than 2^53** — a JSON reader on the other
  side parses that into a float and rounds it, so the human would approve a different number from
  the one your function received. Pass those as strings.
- `DecidioHttpError` — the gate refused the call. Carries `status`, `endpoint`, the parsed `body`,
  and **`retryable`** — the field to branch on. A 401/403 is terminal (the agent token expired, or
  someone re-ran `init` for that agent and revoked it): retrying cannot help, so the message names
  the fix. Anything else is transient: the SDK already retried the authorize with the same request key
  (0.12.0) - a request still waiting is answered with the one already waiting - and retrying is safe: it
  can never double-execute.

```python
try:
    pay_invoice(inv)
except DecidioHttpError as e:
    if not e.retryable:
        alert_oncall(str(e))   # a fresh token is needed; no amount of retrying helps
        raise
    backoff_and_retry()
```

## What 0.4 does not yet claim

The retest that graded 0.3.3 *A- for the core and the shipped stores* and the first-run reviews of
0.3.3 and 0.3.5 agree on what is left, and none of it is a defect a patch release closes. Stated here so
the next reader grades a promise, not a moving target:

- **Engine adapters are Beta and outside the stability promise.** They pass the same conformance
  battery as the core against structural mocks; no live LangGraph/Temporal/Inngest/OpenAI restart suite
  exists yet. Use the core path for production until it does.
- **The issuer DID is trust on first use.** Sign-in and `init` remember the DID your Decidio publishes at
  `<api>/api/did`; the tour and `receipt` pin to the DID the server names as its own, never to the one
  the receipt claims. Pinned verification is only as strong as that first contact: cross-check the DID
  through a channel you trust independently (published in the open by the Decidio host you use at
  `<api>/api/did` - for Decidio https://mcp.decidioai.com/api/did; Decidio's own services' DIDs are also
  built into the verifier).
- **Verification is cryptographic, not schema validation.** `VALID` means the issuer's key signed these
  canonical claims; the sealed-payload schema the receipt names by hash is not shipped, so a
  structurally odd but correctly signed document is not refused on shape. Shipping the schema is on
  the roadmap.
- **The conformance suites are not in the package.** The deterministic two-process schedules that
  prove the durable store, and the corpus every door is held to, live in the Decidio source repository.
  A customer cannot rerun them from this tarball; a public conformance kit is on the roadmap.
- **No provenance attestation, no repository link.** The source repository is private; npm refuses
  provenance for private repositories, and a link that 404s is worse than none. Registry signatures and
  lockfile integrity are what you can check today.

## Compatibility and support

- **Stable in 0.4:** `guard.protect` and its options; the durable resume controller
  (`ResumeController`: `park`, `resolve`, `reconcile`, `reconfirm`, `recover`, the worker and `handle`); the `PendingStore` contract and both shipped stores, including the on-disk
  revision-chain layout; the outcome dict keys (`report_recorded`, `execution_confirmed`, `evidence_tier`,
  `execution_report_verified`, `execution_report_reason`, `confirmation_retryable`, `report_journalled`,
  `diagnostic`), the resume `status` strings and the recover() `state` strings (additive growth only);
  the error classes; the CLI's commands, flags and exit codes; the receipt verifier's verdict and
  reasons. Changes to any of these announce themselves in the changelog first.
- **Beta:** the engine adapters (above).
- **Deprecated, kept until 1.0:** `protect_best_effort` (the value-only shape) and the old adapter
  name `gate_interruptions`. They will be removed in 1.0.0, not before.
- **Versioning:** 0.x minor releases may still carry deliberate breaking cleanups, announced in the
  changelog with the upgrade step. 1.0.0 follows user-acceptance testing of this release and freezes the
  surface above.

## Invariants
Decidio never executes downstream / holds no downstream credentials (the only downstream touch is the opt-in, read-only read-back tier) · holds none of the parked payload · fail-closed signatures · no automatic re-invocation once invocation may have begun · deny-by-default policy · request-bound identity proof. The agent executes; Decidio gates, records, and signals.
