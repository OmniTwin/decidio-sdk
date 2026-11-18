# @decidio/sdk

One line to put a human-or-policy approval gate in front of any AI-agent action — and get a signed, verifiable Authority Receipt for every decision, with execution evidence accruing on the record.

`@decidio/sdk` is the client for Decidio — the system of record for enterprise authority, from OmniTwin Technologies.
The wrapper IS the SDK: `guard.protect(fn, describe)` ships in this package, and the `npx @decidio/sdk` command line
is the two-minute tour, the sign-in and the token admin around it. Install, wrap one function, run — the tour is optional.

## The two-minute tour

```bash
npx decidio                          # the short form: asks one question, then does the thing you picked
npx @decidio/sdk quickstart          # against your workspace (you need an invite - request one below)
npx @decidio/sdk quickstart --demo   # no invite yet? the same tour on this machine, against a local stand-in of the API
# Not sure? The bare command asks: with no sign-in on this computer it asks whether you have an
# invite (n → the local demo; y → sign in, then the tour or your own agent). Every answer prints
# the command it stands for, so you never need the questions twice.
```

One command, guided: it registers a fresh agent (key generated locally), gates a demo action
with the same one line you'll use on your real function, routes it to a human — **you** — lets
you approve right there (or from your Decidio app), executes on approval, then downloads the
sealed Authority Receipt and verifies it offline in front of you, pinned to your workspace's
issuer. It mints a **7-day** tour token (`init` mints 90-day tokens — different jobs, different
lifetimes) and ends by offering to clean itself up (`quickstart cleanup` works later too).
Sign in once — `npx @decidio/sdk login`, or when the tour asks: the CLI emails you an 8-character code, you type it, and
the sign-in is kept in your profile (owner-only) for 30 days, or until this terminal closes, `logout`, or
`quickstart cleanup`. At the human step the tour offers three doors: answer here, open the decision in
the web app (a one-time link, signed in for you), or scan the QR with your phone — whichever answers
first wins, and the terminal follows. No config: with no `DECIDIO_API_URL` set it targets the hosted synthetic
sandbox. Headless, the tour **stops at the routed decision** — approving is a human act, so it
prints the approve command and exits rather than approve its own request (CI can pass
`--auto-approve-demo`, which labels that authority as automated).

## Quickstart — seven steps to your first sealed receipt

Under 30 minutes for all seven steps (the tour itself is two minutes), no help needed. You'll need Node 20.6+ and a terminal.

**You'll need a Decidio workspace.** → Request one at [decidioai.com](https://decidioai.com/#early-access)

The hosted sandbox is synthetic data, safe to experiment in. Every invited tester gets their OWN
workspace: workspace-wide views like `tokens list` or `approvals` show every agent and decision in
your workspace — yours alone unless you invite others into it. Production workspaces are per-tenant too.

Lab workspaces have a **governed-action allowance** (currently 30 actions/hour); hitting it raises
a typed `DecidioRateLimitError` naming the limit and reset time — nothing is routed or executed —
and `tokens list` shows your remaining allowance any time. The counter is in memory, per API instance: a
deploy resets it, so `30/30` right after a governed action means the API restarted, not that the action was free.

**PowerShell users** — the equivalents for every Bash idiom used below:

```powershell
mkdir decidio-quickstart; cd decidio-quickstart          # instead of mkdir ... && cd ...
$env:DECIDIO_API_URL = "https://mcp-staging.decidioai.com" # the lab; instead of export NAME=value
$env:DECIDIO_AGENT_ID = "my-agent"; npx @decidio/sdk init
                                                          # instead of VAR=value npx ... (inline env)
```

**1. Install**

```bash
mkdir decidio-quickstart && cd decidio-quickstart
npm install @decidio/sdk
```

**2. Register your agent**

```bash
npx @decidio/sdk init --unique my-agent   # --unique appends a random suffix: collision-proof
```

> Just ran `npx @decidio/sdk quickstart` in this directory and kept its agent? Its `.env` already
> works — skip this step and continue at step 3.

Every network command talks to Decidio (`https://mcp.decidioai.com`) by default (`verify` is offline) and announces its
target host on stderr each run — set `DECIDIO_API_URL` (env or `.env`) to point at another Decidio instead: the invite-only
lab is `https://mcp-staging.decidioai.com`.

`init` signs you into your workspace (the 8-character code the CLI emails you — type it where you asked —
or, for an account made before sign-up became passwordless, its email + password), generates the agent's Ed25519 keypair **locally** (only the public `did:key`
is sent), registers the agent, mints its **floor-limited API token** (limited to the agent runtime — request authorization, poll status, report signed confirmation; it cannot administer the workspace or approve anything — and your workspace session never touches the agent's disk), and writes `.env`.
Every later command that talks to Decidio reads `.env` from this directory automatically (`verify` is
offline and never does). Re-running init for an
agent that already has a token REPLACES it — the server keeps one active token per agent, so
the previous one is revoked and init says so.

What `.env` contains after a successful init: `DECIDIO_API_URL`, `DECIDIO_AGENT_ID`,
`DECIDIO_AGENT_DID` + `DECIDIO_AGENT_KEY` (the local keypair — the key is what earns
`application_confirmed` evidence later), `DECIDIO_API_TOKEN` (the floor-limited agent token —
90 days by default, `--expires-days N` to change),
`DECIDIO_WORKSPACE_ID`, and `DECIDIO_WEBHOOK_SECRET` (operator deployments only). Pick any
agent name — if it's already taken in your workspace, `init` stops cleanly and suggests a
fresh one (or pass `--unique` to auto-append a random suffix — collision-proof for shared
workspaces and CI). Interactive terminals sign in once (`npx @decidio/sdk login` — stored owner-only in your
profile, bound to this terminal window, 30 days). Headless terminal (no prompts possible)? Export `DECIDIO_SESSION_TOKEN` first:
request a sign-in link from the web app's sign-in screen, then exchange its `?login=` value at `POST /demo/login-consume` with the body `{"token":"<login value>","client":"cli"}` — the
response's `token` is your session token (marked as the command line's, so it can't show AI assistants more or confirm a name as
anything but a person) (the CLI prints these exact instructions when it
can't prompt). That session token is your workspace login, not the agent's credential: unset it
before launching agent code from the same shell, because child processes inherit exported
variables (`unset DECIDIO_SESSION_TOKEN` in bash/zsh, `Remove-Item Env:DECIDIO_SESSION_TOKEN` in
PowerShell). In the tour's human step, `y` approves and `n` rejects — the rejection half is worth
watching once: the request is refused and your function does not run.

**3. Protect one function** — save this as `quickstart.mjs`:

```js
import { guard } from "@decidio/sdk";

// Your real action — a Salesforce write, a payment, a DB change. Here: a stand-in.
const payInvoiceRaw = async (invoice) => ({ paid: true, id: invoice.id });

// One line: wrap it. `describe` tells Decidio what is being asked.
const payInvoice = guard.protect(
  payInvoiceRaw,
  (invoice) => ({ action: "payInvoice", amount: invoice.amount, scope: "Invoice" }),
  { mode: "blocking" },   // blocking = watch the whole loop live in one terminal sitting.
);                        // Production agents use durable mode instead — see below.

const { value, confirmation } = await payInvoice({ id: "INV-2026-001", amount: 86_000 });
console.log("executed after approval:", value);
console.log("Decidio recorded it as:", confirmation.evidenceTier);   // e.g. application_confirmed
```

**4. Trigger it:**

```bash
node --env-file=.env quickstart.mjs
```

A brand-new agent matches **no** auto-approve rule, so Decidio **routes every request to a
human by default** — that is the point: nothing executes without either a named policy rule or
a person. (Routing-by-default is distinct from a policy **block**, which refuses the action
outright — no human can approve a blocked request. Policy `proceed` rules — named auto-approve
for requests carrying the agent's signed identity proof — are configured per workspace by its
owner.) The script prints the decision id and waits.

**5. Approve it** — in a second terminal (same directory; replace `<decisionId>` with the id
step 4 printed — angle brackets are placeholders, never typed literally). Approvals are a
*human* act, so this terminal needs your sign-in too: it will prompt, or export
`DECIDIO_SESSION_TOKEN` here as well for headless shells (the `.env` deliberately holds only
the agent's floor-limited token — it cannot approve anything):

```bash
npx @decidio/sdk approvals --mine        # see it pending (--mine narrows to THIS agent; the
                                         # workspace is yours alone unless you invite others,
                                         # so the bare command lists every pending decision in it)
npx @decidio/sdk approvals approve <decisionId>
```

The moment you approve, the first terminal wakes: **your own function executes** — Decidio never
holds your credentials or runs your code — and the SDK reports the captured result back, which
becomes the record's execution evidence.

**6. Download the receipt (online), then verify it (offline):**

```bash
npx @decidio/sdk receipt <decisionId>
npx @decidio/sdk verify decidio-receipt-<decisionId>.json
```

No DID to paste: `verify` pins to a **trust anchor** and prints it first. In order: an explicit
`--issuer <did:key>` if you give one; else the issuer DID this computer remembered for your Decidio
when you signed in (`login`, or the sign-in `init`/the tour asks for) — fetched from the host's
public `<api>/api/did` and kept in your profile beside the stored sign-in; else the built-in
issuers of Decidio's own services (`KNOWN_ISSUERS` in `@decidio/verify`: each one published at its host's
`/api/did`, e.g. https://mcp.decidioai.com/api/did and, for the lab, https://mcp-staging.decidioai.com/api/did). A receipt's own `issuer` field is never the
anchor — it is only what the file claims, and any key can sign a file that names itself. If a later
sign-in sees the host publish a DIFFERENT DID - or a server's verify response names one - the CLI
says so loudly and keeps the remembered one: a new key is confirmed with the host's operator, not
adopted silently. The `receipt` command pins to the DID remembered for the host, else the DID the
server names as its own (`expectedIssuer`); checks the file offline against it; fails (exit 1) when
that check or the server's own check says the record does not verify; and prints the flagless verify
command only when `verify` - which takes its host from your shell's `DECIDIO_API_URL`, never `.env` -
would land on the same DID. An UNPINNED check proves internal consistency only, so it stays a named choice
(`--allow-unpinned`), and its verdict says so. The download is an authenticated fetch from your
workspace; the *verification* is fully offline — the verifier ships inside this package (no second download, no registry probe, same
implementation as the standalone `@decidio/verify`). The receipt is a W3C Verifiable
Credential: signature and content binding verify with no Decidio account and no network — the
evidence is yours, not ours. On another machine, pin the same DID explicitly:
`npx @decidio/verify --issuer <did:key:...> receipt.json` (receipts from the hosted service need no
flag there either — the anchor is built in).

**What VALID means — and what it does not.** A pinned `VALID` proves the receipt's **claims** were
sealed by your workspace's issuer and that none of them has changed since. Not its *bytes*: the
signature covers the record's canonical form (JCS), so reformatting the file — reindenting it,
minifying it, reordering keys — still verifies, and should, because none of that alters a claim.
If you need byte-for-byte custody, hash the file and keep that hash yourself; this proves the
content, which is what an auditor is asking about. It does **not** prove the approved
action ran. Execution is confirmed *after* the seal, and a sealed record is immutable, so the
receipt's own `authority.result` and `confirmation.status` are a snapshot taken at seal time — a
receipt for an approved-but-never-executed action verifies `VALID`, correctly. The verifier now
prints those fields under `as sealed`, plus a note saying exactly this, so the distinction is on
screen rather than left to inference. The check is **cryptographic, not semantic**: it does not
evaluate business rules, timestamp plausibility, revocation, or whether a later record superseded
this one. For current execution status, ask the issuer (`npx @decidio/sdk receipt <decisionId>`
reports the live evidence tier).

One receipt proves itself. Pass several files and their **ordering** is verified too — in
**seal order** (each receipt's `prevHash` links to its predecessor's `contentHash`), which is
the order decisions were *sealed*, not the order of their displayed decision numbers (two
decisions created together can seal in either order). The first
file is the anchor and each subsequent receipt must follow it, so verifying any consecutive
*segment* works — you are told whether the segment starts at your workspace's genesis or
mid-history, and a set spanning two different issuers is refused outright.

What the credential contains, honestly: the sealed **authority decision** — who decided, what
was authorized, when, under which policy. It seals at decision time and is immutable — which is
why the credential's own `confirmation.status` field reads `"pending"` forever. Execution
evidence that arrives *after* the seal (your function's captured result) lives on the
**record**, not inside the credential bytes: the `receipt` command prints the record's current
tier next to the file, and with the signing key `init` wrote you'll see `application_confirmed`
— the wrapper's report carried a signed identity proof bound to your agent, this decision, and
a freshness window.

Since 0.1.11 the report also carries an **execution report**: a separate, domain-separated,
versioned envelope signed over a SHA-256 digest of the canonicalized response, bound to the
decision, your agent and your workspace, with a single-use nonce and a short expiry. The server
recomputes that digest from the response on the same request and refuses the attestation if they
disagree — so "this agent reported this exact result for this decision" is checked, not asserted.
It is deliberately separate from the evidence TIER: the tier says how strongly the outcome was
observed, the report says what was reported and by whom, and no signature can turn a weak
observation into a strong one. An unverifiable report is refused as an attestation (and the
refusal is itself audited) while the confirmation is still recorded — an optional proof never
destroys the record of an execution that really happened; the confirm response tells you which
happened. (No signing key configured? No execution report is sent, the server caps the evidence
at the weaker `agent_asserted`, and the SDK warns at confirm time.) Immutable seal + accruing evidence is the design, not an omission — corrections and
later facts supersede, they never rewrite.

One sharing note: a receipt is **not a secret, but it is not metadata-free** — it names the
action, amount limits, policy, agent and issuer identifiers, and the decision reason. Share it
with auditors and counterparties deliberately, the way you would any business record.

**7. Prove a replay is rejected:**

```bash
npx @decidio/sdk approvals approve <the same decisionId>
```

Decisions are single-use: the CLI reports "already resolved — nothing changed" and exits
non-zero. The server answers replays idempotently — a second approve can never re-execute the
action. (The durable resume path has the same property: parked actions are claimed exactly
once, and its webhook handler fails closed without a verified signature — unless you
explicitly set `allowUnsigned: true`, which removes webhook authenticity and makes the
controller say so loudly at startup; never use it on an internet-reachable endpoint.)

That's the whole contract: gate → human decision → your execution → owned, verifiable evidence.

## What happens on a call

1. The wrapper asks Decidio's gate to authorize `{action, amount, scope}` for your `agentId`.
2. Decidio's policy engine — your workspace's active policy, whose versioned rules decide every request (Cedar is compiled from them for validation and export) — returns **proceed | route | block**:
   - **proceed** — your function runs immediately (auto-approved under a named, versioned rule).
   - **route** — the action suspends (durable) or waits (blocking) for a human decision in Decidio's queue, then runs your function (or throws `DecidioRejectedError`).
   - **block** — the wrapper throws `DecidioBlockedError`; your function never runs.
3. After your function runs, the wrapper reports the **real response it captured** back to Decidio (which minimizes + tokenizes before storing — the immutable record never stores raw payloads). The tier that report earns depends on what it can prove: `application_confirmed` when the agent has key material and signs the execution report, `agent_asserted` when it does not, and `execution_unconfirmed` when the reported value carries no usable evidence. The SDK tells you which it got; it never claims the top tier by default.

Your agent executes its own action. **Decidio holds no write credentials for your system** — it authorizes the decision, records it, and (optionally) independently verifies it.

## Production mode: durable async resume

Real approvals take minutes to days, and nobody keeps a terminal open for them. Omit
`mode: "blocking"` (durable is the default) and a routed action **suspends** instead of
waiting: it parks its call arguments agent-side (`.decidio-pending/` by default — Decidio
stores none of your downstream payload) and throws `DecidioSuspendedError`. The process may
exit. **The parked payload is plaintext on the agent's disk:** the full call arguments and their
signature sit in `.decidio-pending/` until the decision resolves — owner-only permissions where the
OS supports it, gitignored by `init`, but not encrypted. Treat that directory as you treat the `.env`
beside it; a custom `PendingStore` can encrypt at rest. Two ways the parked action resumes when a
human decides:

**The worker (self-serve — start here).** No inbound URL, no shared secrets, and it resumes work
the current process never started. Here is a complete `agent.mjs` you can run:

Two files, on purpose — **the worker and the thing that creates work are different programs**.
A single file that both starts the worker and calls the action submits a NEW request every time
you restart it, which is the opposite of what a recovery test should show.

`agent.mjs` — the long-lived worker. Restart it as often as you like; it creates nothing:

```js
import { guard } from "@decidio/sdk";

const payInvoiceRaw = async (invoice) => ({ paid: true, id: invoice.id, success: true });

// Declaring the action name registers the handler at LOAD time, not on first call — that is
// what lets a restarted process resume actions approved while it was down.
guard.protect(
  payInvoiceRaw,
  (invoice) => ({ action: "payInvoice", amount: invoice.amount, scope: "Invoice" }),
  { action: "payInvoice" },
);

guard.worker();   // polls Decidio and resumes approved actions; creates no work of its own
console.log("worker running — approve a decision and watch it resume here");
```

`submit.mjs` — run this ONCE when you want a new request:

```js
import { guard } from "@decidio/sdk";

const payInvoice = guard.protect(
  async (invoice) => ({ paid: true, id: invoice.id, success: true }),
  (invoice) => ({ action: "payInvoice", amount: invoice.amount, scope: "Invoice" }),
  { action: "payInvoice" },
);

try { await payInvoice({ id: "INV-1", amount: 86_000 }); }
catch (e) { console.log(e.name); }   // DecidioSuspendedError — expected, not a failure
```

Run `node --env-file=.env agent.mjs`, then `node --env-file=.env submit.mjs` once, approve from
another terminal, and the running worker executes it.

To see recovery, the approval has to be waiting while nothing is running — so submit a **second**
request with the worker stopped:

1. Stop the worker (Ctrl-C).
2. `node --env-file=.env submit.mjs` again — it parks; nothing is running to pick it up.
3. Approve it from the other terminal. It stays parked, approved and unexecuted.
4. Start the worker again: it executes that request exactly once, and restarting created no
   duplicate.

Step 2 is the one that is easy to skip: by the time you restart, the first request has already
executed, so without a second submission there is nothing left to approve.

**If you can't declare the name at wrap time** (a dynamic
`describe`), register the raw function explicitly at startup instead —
`guard.register("payInvoice", payInvoiceRaw)` — before calling `guard.worker()`. Without one of
those two, a cold worker has an empty registry and reports `no_handler` (the parked action is
kept, not lost, and the message names the exact fix).

**The signed webhook (operator deployments).** Decidio POSTs a signed wake-up to your agent's
`resumeUrl`; the handler verifies the HMAC signature fail-closed, asks Decidio for the decision, and
re-runs your function only if Decidio says THIS request was approved (the verdict inside the webhook
is never the authority — see "Every door confirms the approval" below):

```js
// Express:   app.post("/decidio/resume", guard.resumeHandler())
// Next.js:   export const POST = (req) => guard.resumeFetchHandler()(req)
```

Honest requirement: webhook signing uses a **shared secret configured on both sides** — your
`DECIDIO_WEBHOOK_SECRET` must equal the Decidio server's, and self-hosted production deployments
also allow-list resume hosts (default-deny). That's operator territory: if you run your own
Decidio (or we run a pilot with you), the webhook is set up then. Against the hosted sandbox,
use the worker — a webhook secret your server never learned would (correctly) fail closed. Since
0.7.0 there is **no API-token fallback**: without `webhookSecret` (or `allowUnsigned`, for a trusted
network only) the handler answers 401 and names the fix. The worker needs no inbound secret. The
secret is a dedicated one — **never the Decidio server's `API_AUTH_TOKEN`** (its admin bearer, which
must not be copied onto an agent host); since this release the server sends no webhook at all without
`DECIDIO_WEBHOOK_SECRET`.

**Earning the strongest evidence tier.** Decidio records `application_confirmed` — its
strongest wrapper tier — only when your function's captured response shows a committed record:
a record id (`id` / `recordId` / `Id`) and no explicit denial of success. Precisely, as
implemented: an id with no `success`/`ok` field is taken as a commit; `success: false` (or
`ok: false`) records `execution_unconfirmed` even with an id; and a response carrying no id at
all records `execution_unconfirmed`, because Decidio then has no evidence the downstream write
committed. Note what this does and does not mean: Decidio is trusting your wrapper's report of
an identifier — it does not independently read that record back (that is the stronger
`independently_reconciled` tier). If your API returns an id before the write is durable (a
202-Accepted or queued shape), map an explicit success flag with `evidence` so the tier reflects
the commit rather than the acknowledgement. Keep your API's natural shape and map it instead:

```js
guard.protect(chargeCard, describe, {
  action: "chargeCard",
  evidence: (r) => ({ recordId: r.transactionId, success: r.status === "committed" }),
});
```

The SDK tells you which of the two is missing rather than leaving you to guess, and it reports
`reportRecorded` (Decidio accepted the report) separately from `executionConfirmed` (the
recorded tier attests a commit) — two different questions that used to share one name.

**The supported argument data model is plain JSON**: `null`, booleans, strings, finite
numbers, arrays, and plain objects. Anything that cannot survive JSON with its meaning intact
— `NaN`/`Infinity`, `undefined`, `BigInt`, `Map`/`Set`/`Date`, class instances, functions,
circular structures, symbol keys, getters, non-enumerable or sparse values — is **refused
before the decision is routed or the payload signed** (typed error naming the offending path),
because a value that silently drifts in serialization would mean a human approves one thing and
your function executes another.

Your arguments are canonicalized ONCE, and that canonical snapshot is what `describe` sees, what
the signature covers, what is parked, and what your function ultimately receives — so the
approved value and the executed value are the same. Consequence worth stating plainly: JSON
canonicalization preserves **value** semantics, not JavaScript object identity. Two properties
pointing at the same object arrive as two equal objects, and mutating an argument inside your
function does not affect the caller's copy.

**What the SDK can and cannot promise about duplicates.** The guarantee, stated exactly:

> Once invocation may have begun, the SDK never automatically invokes it again unless the
> downstream system provides an idempotency guarantee or an operator explicitly reconciles it.

It holds across processes and restarts, not just within one worker. Before your function is
called the SDK writes a durable `invoking` marker to the pending store; from that moment no
poll, no duplicate webhook, no fresh process and no worker cycle will call it again. Deletion of
the parked row is cleanup, not the guarantee — a store whose `delete()` silently fails cannot
cause a second execution.

**Closing the last window yourself.** Pass `withContext: true` and your action receives an
`ExecutionContext` as its first argument:

```js
const payInvoice = guard.protect(
  async (ctx, invoice) => stripe.paymentIntents.create(
    { amount: invoice.amount, currency: "usd" },
    { idempotencyKey: ctx.idempotencyKey },   // ← stable across every attempt at this decision
  ),
  (invoice) => ({ action: "payInvoice", amount: invoice.amount }),
  { withContext: true },
);
```

`ctx` is `{ decisionId, attemptId, idempotencyKey }`. It is opt-in rather than inferred from your
function's arity, because guessing wrong would hand a payment call a context object where it
expected an invoice. `describe` still receives your arguments only — it describes the *request*,
while the context describes the *execution*.

It still cannot make an external side effect exactly-once — no client can. If your action
succeeds and the process dies before the result is recorded, whether the downstream write
committed is not knowable from this machine. The difference is what the SDK does about it: that
decision becomes **`indeterminate`** and stops, rather than being retried into a duplicate
payment. You settle it with `reconcile()` once you have looked downstream. Pass the decision id
as your vendor's idempotency key and that window closes on their side too.

Recovery is explicit rather than magical:

```js
for (const item of await guard.resume.recover()) {
  console.log(item.state, item.decisionId, item.guidance);
}
// "executed_unreported" → guard.resume.reconfirm(id) re-sends the saved report (never re-runs)
// "indeterminate"       → no outcome was recorded; check downstream, then reconcile. Never blind-retry
// "parked"              → still waiting on a human; nothing has executed
```

Two things `reconcile()` will refuse, because both would undo an authority decision rather than
record one. **It refuses by returning, not by throwing** — check `reportRecorded`, and read
`diagnostic` to see why:

```js
// A denial is final. There is no outcome to record — nothing ran — so neither outcome is accepted.
const r = await guard.resume.reconcile(deniedId, { outcome: "not_committed" });
r.reportRecorded;   // false — r.diagnostic says the decision was DENIED

// A decision that is still `invoking` may be running the action at this moment. Releasing it would
// let a second worker run the same approved action, so it takes an explicit assertion — from you,
// after you have checked. Nothing here can see another machine's process table, so this is your
// judgement, and it is stamped into the ledger as such.
await guard.resume.reconcile(id, { outcome: "not_committed", reason: "…" });   // refused while invoking
await guard.resume.reconcile(id, { outcome: "not_committed", reason: "…", workerStopped: true });  // released
```

`indeterminate` needs no such flag: the handler has already returned or thrown, so nothing is in
flight — only the downstream result is unknown.

The report a worker sends is written to the pending store's execution ledger *before* the first
send attempt, so a lost confirmation is recoverable; and because that record holds no handler
binding, replaying it can only re-send evidence — never re-run your function. The ledger lives in
the store you configured, so two workers sharing one Redis or Postgres store can reconfirm each
other's work. (Through 0.1.x this was a separate local-filesystem journal, which meant two
workers kept two disjoint journals and neither could. `reportDir` is accepted and ignored now.)

**Parked arguments must be JSON-serializable — and that is checked BEFORE routing.** Values that
do not survive JSON with their meaning intact — `Date`, `Map`, `undefined`, `NaN`, class instances,
functions — are refused with `DecidioUnsafeArgumentsError` before any decision exists and before any
network call (since 0.1.12): nothing is parked, nothing is routed. The parked payload is also
signed, so a file edited on disk fails the integrity check on resume (a refusal, never a wrong
execution). Pass plain data; rehydrate inside your function.

**Payload integrity.** When a routed action is parked, the SDK signs its arguments (bound to the
decision id) with your agent key; on resume it **refuses to execute** if the parked payload was
modified, its signature stripped, or the file swapped into another decision's slot. That defends
against tampering by anything lacking your agent's key — note a *fully compromised agent host*
can bypass the guard entirely (it holds both the key and the function), so the durable guarantee
that closes that gap is server-sealed argument binding, auditable in the receipt itself, which is
on the roadmap. **Upgrading from ≤0.1.5:** entries parked by an older version carry no signature
and are refused once your agent has a key — drain pending approvals before upgrading, or delete
the parked files and re-run those actions.

### Already on a durable engine? Use its native wait

If your agent runs on Inngest/Temporal/LangGraph, the engine *is* the durable store.
`@decidio/sdk/inngest` maps the gate onto `step.waitForEvent`; `@decidio/sdk/langgraph` is a
drop-in via `interrupt()`; `@decidio/sdk/temporal` uses `condition` + signal;
`@decidio/sdk/openai` gates RunState approvals. All optional peer dependencies — the core SDK
imports none of them — install the engine you use alongside the SDK (`npm i inngest`,
`@langchain/langgraph`, `@temporalio/workflow`, or `@openai/agents`); nothing is downloaded
for engines you don't. Each adapter's shipped `.d.ts` header documents its wiring; `npx
@decidio/sdk quickstart` is the fastest runnable end-to-end.

### Every door confirms the approval is for THIS request (0.7.0)

Before 0.7.0 a resume ran on the word of whatever woke it — a webhook, a Temporal signal, an Inngest
event, a LangGraph resume value saying "approved". Now every door (inline, the durable webhook and
worker, LangGraph, Temporal, Inngest, OpenAI Agents) asks Decidio before your function runs:
`GET /agent/status` must say `approved` (or `auto_approved`) **and** return the request commitment
this SDK sent with `/agent/authorize`, recomputed over the request about to run. A wake-up is only a
wake-up.

- **The commitment** is an HMAC-SHA256 under your agent's key material over the canonical request:
  `{action, amount, scope, args}` on the core wrapper, the described context on an engine adapter
  (plus the tool call itself on the OpenAI door). With the Ed25519 key `init` writes
  (`DECIDIO_AGENT_KEY` + `DECIDIO_AGENT_DID`) only your agent holds the key, and Decidio stores and
  returns an opaque value it can neither read nor forge for another request. **Prefer that key.** Without
  it the commitment is keyed by `DECIDIO_API_TOKEN` — a bearer Decidio receives on every call — so it is
  opaque to everyone except the Decidio server itself.
- **Rotating key material strands pending approvals.** Re-minting the agent token, changing
  `DECIDIO_AGENT_KEY`, or running the guard and the resume controller with different key material makes
  every routed approval still pending fail its check as `request_changed` (the recompute no longer
  matches). Drain pending approvals before rotating, or ask again for each afterwards.
- **Refusals** (both extend `DecidioBlockedError`; nothing ran): `DecidioRequestChangedError` —
  "the request changed after approval", naming the decision — and `DecidioApprovalUnverifiedError`
  (`code: "commitment_missing"` when Decidio returns no commitment for a request this SDK bound, or
  `"unverifiable"`). The durable path reports `not_approved` (Decidio still says pending: the action
  stays parked) or `request_unverified`. **`resolve()` now asks Decidio before it runs, so it THROWS when
  Decidio is unreachable** (nothing ran; the entry stays parked) — catch it and retry, or leave the entry
  for the worker.
- **LangGraph** needs key material (`init`, or `DECIDIO_API_TOKEN`) and a checkpointer run with a
  `thread_id` (a routed gate without the run's thread, task and per-execution scratchpad refuses, naming
  its decision). LangGraph re-runs an interrupted node on resume; the re-run authorizes with an
  idempotency key derived from its own thread + task + commitment, so Decidio answers with the SAME
  decision instead of minting a second one. Edit the graph state and the edited request becomes a
  NEW pending decision — an approval is never applied across requests. `decidioResumeCommand` now
  requires the webhook's `decisionId`.
- **Temporal**: whenever you pass `authorize`, also pass `verify: (id) => executeActivity(verifyActivity, id)`,
  where the activity returns `verifyApprovalActivity(config, id, ctx)` (from `@decidio/sdk/temporal`)
  for the same `ctx`. A signal only wakes the workflow; still pending → it waits for the next one.
  Since 0.12.0 also pass `claim: (id, key) => executeActivity(claimActivity, id, key)`, where the
  activity returns `claimApprovalActivity(config, id, key)`, and return `authorizeActivity(config, ctx)`
  from the authorize activity: it keys the request on the activity's workflow, run and activity ids.
- **Inngest**: the check runs as a memoized step after the event; a premature or forged event waits again.
- **OpenAI Agents**: `applyResume(state, item, verdict)` is removed. Use
  `await applyVerifiedResume(config, state, item, decisionId, describe)`, which approves the
  interruption only when Decidio records that decision as approved for THIS tool call: the approval is
  bound to the call's name, call id and exact argument string as well as `describe(item)`, so an item
  edited after approval, or a second identical call, never rides it. Park each pending
  `{ callId, decisionId }` (both on `authorizeInterruptions(...).pending`) with the serialized state and,
  after `RunState.fromString`, find each item again by `item.rawItem.callId`. An interruption with no
  call id is refused before anything is sent.
- **Known limit — one gated action per LangGraph node** (true before 0.7.0 too). LangGraph re-runs the
  whole node on resume, so an earlier gate in the same node runs again: if its request auto-approved and
  its action already ran, the replay answers `proceed` to your verified agent and the action runs twice.
  Put each gated action in its own node, or make the actions idempotent.
- **An approval is collected once (0.12.0).** Before acting on a person's approval, the blocking wait,
  the durable resume, Temporal and `applyVerifiedResume` claim it (`POST /agent/claim/<id>`) with a key
  random to that run, and run only if Decidio says this run collected it - otherwise
  `DecidioBlockedError`: "This approval was already used by another run. Ask again for a new
  approval." Auto-approvals are never claimed; reading the status never claims. Every authorize with a
  request commitment also sends a request key (a fresh id per call, your own `requestKey`, or the
  engine's id for the call), and a retried authorize carries the same key.
- **Known limit — LangGraph and Inngest do not claim yet.** Two concurrent resumes of the same LangGraph
  thread (the checkpoint is your storage) can both pass the check and both run the action; resume each
  one from one place (one worker per thread id, or a lock). Inngest relies on its own step semantics.
- **Upgrade the gate first.** A keyed SDK refuses a routed approval from a Decidio gate that does not
  return commitments (`commitment_missing`) — it fails closed, never silently passes.




## The durable store is a revision chain (since 0.3.2)

`FilePendingStore` keeps each decision's execution record as an **append-only revision chain** —
`<id>.rev.1`, `<id>.rev.2`, … — and the head is the highest number. Every state change reads the
head, validates against exactly that record, writes the successor to a temp file, and publishes it
with `link()` to the next revision number. `link()` fails if that name already exists, so **exactly
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
agents at all) carries that backstop rule here, so non-empty does not mean "approved" and empty does
not mean "blocked". The field that states the
disposition is `authority.result`; `firedRules` tells you which named, versioned rules produced it.

**`payloadSchemaUri` is a `urn:`, not a URL.** It is content-addressed —
`urn:decidio:sealed-payload:1:sha256:<hash>` — so it *identifies* the exact schema the record was
sealed under and pins it against substitution. It does not locate a document, and nothing will
resolve it. (Shipping the schema alongside the verifier so you can check the hash yourself is on
the roadmap; today the URN is an identifier only, and this note exists so it does not look broken.)

**`prevHash` proves a pointer, not an ancestry.** A non-null `prevHash` shows this record was
sealed after a specific predecessor, but a single-file verification cannot check that predecessor
exists or is what it claims. Verify a chain (`verify --issuer <did> a.json b.json c.json`) when the sequence
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

**If you wrote a custom `PendingStore`, it will fail to construct.** `markDiscarded(decisionId,
verdict, reason?)` is now REQUIRED — it writes the tombstone that makes a denied decision
permanently unclaimable, and a store that cannot record a denial cannot uphold the guarantee, so
this is refused at construction rather than deep inside a resolve. `delete` also takes an optional
owning attempt (`delete(id, attemptId?)`) so a superseded attempt cannot clean up the live one's
payload, and `settle` takes `workerStopped`. The shipped stores show the shape; the ownership
corpus that pins these rules (claim fencing, terminal denial, advance-only transitions, settle
preconditions) lives in the Decidio source repository and is not part of this package — the rules
themselves are the ones stated above.

**`recover()` now throws instead of returning `[]`** when the ledger cannot be read
(`DecidioRecoveryUnavailableError`). `[]` and "I cannot tell you what you owe" are the same value
to a caller and mean opposite things, so a script reading `if (!(await recover()).length)` treated
a permissions change as proof that nothing was outstanding. Wrap the call if you poll it.

**`reconcile()` refuses two things it used to allow.** A DENIED decision cannot be reconciled on
either outcome, and releasing a decision that is still `invoking` takes an explicit
`workerStopped: true` — that is the one state where the handler may be running right now, and
releasing it hands one approved action to two live workers. It refuses by RETURNING, not throwing:
check `reportRecorded` and read `diagnostic`.

**The adapters return a different shape.** `decidioGate` (LangGraph, Temporal) returns
`ProtectedExecution` — `{ value, decisionId, confirmation }` — instead of the bare value.
`decidioGateStep` (Inngest) renames `result` to `value` and carries `confirmation`.
`gateInterruptions` is now `authorizeInterruptions` and returns `confirmationSupported: false`
(the old name remains as a deprecated alias). Read `.value` where you previously read the result.

**The transport rule refuses URLs it used to accept.** A gate URL must now be absolute and either
https or an exact loopback host, whatever credentials the config holds. A relative or scheme-less
`apiUrl` throws at startup — it used to pass on the reasoning that the shipped transport rejects
it, which says nothing about a custom `fetchImpl`.

**Decision ids are shape-checked.** Letters, digits, dot, dash and underscore, starting with a
letter or digit, at most 128 characters, never trimmed. The server enforces the same grammar (it
had none before 0.3.0, which is why the SDK was the stricter of the two). Ids Decidio issues are
well inside it.

**`/agent/confirm` can answer 409.** `TERMINALLY_DENIED` means a human refused the decision and
your action appears to have run anyway; `NOT_AUTHORIZED` means there is no approved, sealed
decision for evidence to attach to. Neither is a report failure and neither is retryable — the SDK
raises `DecidioHttpError` with advice that says so, rather than the "only its report failed" note
that fits every other confirm error.

## Engine adapters (BETA) — and Python too

- **Engine adapters are BETA.** They share the core's gate semantics — the verdict allow-list,
  the canonical argument model, the transport rule and evidence handling are ONE implementation,
  and a conformance matrix runs the same malformed-verdict, unsafe-argument, plaintext-transport and
  malformed-description (blank action, negative amount) battery against every door. What is *not* yet
  verified is the engine integration itself: those
  paths are exercised against structural mocks, not live LangGraph/Temporal/Inngest/OpenAI
  runtimes. Use the core path for production until that changes. Each adapter is bound through its
  own `@decidio/sdk/<engine>` subpath (they need the engine handle at call time); no engine at all?
  The worker/webhook resume is the universal path and is not beta.
- **One result shape on every door (0.3.0, breaking).** `decidioGate` (LangGraph, Temporal) and
  `decidioGateStep` (Inngest) now return `{ value, decisionId, confirmation }` — the same
  `ProtectedExecution` the core path returns. They used to hand back the bare value and discard what
  Decidio recorded, so "it ran and was recorded" and "it ran and Decidio does not know" were the
  same return value to a caller. Inngest keeps its `status`, because its durable path can end in
  `rejected` or `blocked` without ever calling your action; its value field is `value`, not
  `result`.
  The OpenAI door is the exception and now says so: it was renamed `gateInterruptions` →
  `authorizeInterruptions` and returns `confirmationSupported: false`. The OpenAI runtime executes
  the tool itself, so this SDK never sees the return value and has nothing to attest — and an
  ABSENT confirmation must not look like a failed one. The old name remains as a deprecated alias.
- **Python twin:** `pip install decidio` exposes the identical `guard.protect` (plus the `@guard.approve` decorator, adapters, and the offline verifier); a conformance suite asserts both languages emit an identical request + receipt.

## CLI

`npx @decidio/sdk <cmd>`:

- `quickstart` — the guided two-minute tour (gate → approve → execute → proof)
  - `--auto-approve-demo` approves the tour's own synthetic decision so it can run headless; it
    then revokes the tour token and deletes its local credentials automatically (the inert
    registration row and the permanent sealed record stay). Pass `--keep-agent` to keep them.
  - An interactive run keeps the agent by default and offers cleanup at the end;
    `quickstart cleanup` works later too.
- `init [agentId] [--unique] [--force] [--expires-days N]` — sign in, register, mint the agent token, write `.env` (+ `.gitignore` entries). Refuses to overwrite a *different* agent's key in this directory; `--force` backs the old `.env` up first.
- `doctor` — config, connectivity, and what your current token can do
- `approvals [--mine] [--json]` / `approvals approve|reject <id> [reason]` — the human side, from your terminal (the list is workspace-wide; `--mine` narrows it to this directory's agent). Run by a coding agent behind the hook, `approve|reject` is refused: a person decides, not the agent
- `receipt <id> [--json]` — download a sealed decision's Authority Receipt to a `.json` file (`--json`: stdout is the JSON result only; the identities your access covers print only on a terminal, or in the JSON)
- `verify [--issuer <did>] <file>...` — verify receipts offline (the canonical verifier; the standalone `@decidio/verify` package is the same implementation, for auditors who want zero Decidio dependency — the sdk depends on the verifier released alongside it, at the same version). Unknown flags are refused, never ignored. It pins to the trust anchor it prints first: `--issuer`, else the DID remembered for your Decidio at sign-in, else the built-in hosted-service issuer — never the receipt's own `issuer` field. Fully offline AND fully decoupled: it touches no network and reads no `.env` (only the issuer DIDs remembered in your profile) — a receipt verifies identically from any directory.
- `tokens list [--mine]` / `tokens revoke <jti>` — see and kill agent tokens (values are never re-shown; the jti is the revocation handle). Each row carries its status — `active`, `expired`, or `REVOKED <date>` — so the list confirms the revocations it performs; re-revoking is an honest no-op (exit 1). The list is workspace-wide (a shared workspace shows every member's agents); `--mine` narrows to this directory's agent
- `quickstart cleanup` — revoke the tour's token and delete its local credentials. What stays, honestly: sealed records (permanent by design) and the agent's registration row (inert without key or token; server-side deregistration is on the roadmap) Also ends the stored sign-in.
- **Update check.** Network commands ask the public npm registry once a day whether a newer version exists; if so, an interactive run asks `Upgrade now? [y/n]` first (`y` upgrades the way you installed - `npm i @decidio/sdk@latest` in the project for a local install, `-g` for a global one, and under `npx` it prints the `@latest` form - then re-runs your command once; `n` exits), a headless run prints the notice and continues (`DECIDIO_REQUIRE_LATEST=1` makes it exit). `DECIDIO_NO_UPDATE_CHECK=1` skips it. Nothing is sent to Decidio; `verify` never checks.
- **The token recovery journal** (`.decidio-token-journal`, owner-only, gitignored; ids and timestamps, never a token value; append-only by the CLI's behaviour — not OS-enforced or tamper-evident). One JSON row per event: `minted` (a token was issued, written BEFORE its credential file), `retired how=persisted` (the credential file now holds it - the token is live and that file is its handle; not revoked), `retired how=revoked` (revoked server-side), `probe` (a durability check). `doctor` names rows still outstanding; `quickstart cleanup` sweeps them.
- `quickstart --demo` — the same tour with no account: an in-process stand-in of the API on 127.0.0.1 (shipped in this package) answers every door, a key generated for the run signs a real receipt (its content says `local-demo`; pinning it to the hosted issuer fails), and the web/phone door is a hosted demo decision page reached through a one-word relay (no account, no record, ten minutes). Your folder gains exactly one file, the receipt. Offline, the tour is terminal-only and says so.
- `quickstart --phone web` — the QR at the human step opens the phone web rendering even when the Decidio app is installed (by default it opens the app when there is one).
- `login [email]` / `logout` — sign in ONCE (the CLI emails you an 8-character code; you type it) and forget that sign-in on this computer (the session token itself stays valid until it expires (up to 30 days) — there is no server-side revocation yet). The session is stored in your user profile, owner-only, bound to the terminal window that created it, for 30 days; `DECIDIO_SESSION_TOKEN` in the environment outranks it (headless shells).
- `dev [--target URL] [--port N]` — local relay for the resume webhook (operator setups)
- `github init | request | verify | lockdown` — Decidio's GitHub deploy approvals. `init` writes the two workflow files in a checkout; `request` and `verify` run inside a GitHub Actions job (its own OIDC token, no repository secret). `lockdown [--dry-run | --yes --plan <id>] [--codeowners "@org/team"] [--without-review-rule]`, run by the workspace owner in the bound repository's checkout, reads the three lock-down settings, prints a plan with its id and changes nothing until you say yes; then it sets them in GitHub, adds CODEOWNERS lines to the checkout for you to commit, and reports to Decidio what GitHub shows afterwards. Every GitHub call goes through GitHub's own CLI (`gh`), so Decidio never sees your GitHub sign-in; it never touches a secret's value, never commits and never pushes. The "reviewed changes" rule it adds has no bypass, admins included; `--without-review-rule` leaves it out (a team of one, who can't approve their own pull request). An admin who must merge alone switches the rule off in GitHub, merges and switches it back on - the deploy that ships the change says it merged without an approving review. Until it has been tried on a real repository, applying needs `DECIDIO_GITHUB_LOCKDOWN_APPLY=1`; `--dry-run` works without it.
- `hook install [--project] [--approver <email>]` / `hook rules` / `hook wait <id>` / `hook justify <id> "<why>"` — the Claude Code hook (0.8.0; widened in 0.9.0). `install` writes PreToolUse/PostToolUse hooks into `.claude/settings.local.json` (`--project`: `settings.json`): the shell calls, plus Write/Edit/MultiEdit on Claude Code's own settings and the Decidio plugin (the `decidio-guard` category: a change that takes Decidio's check away needs a person). The pretool hook fails closed (`onFailure: block`, a hold capped under its 150 s timeout). `hook rules` lists what is gated, including the files a command runs that are followed one level, and the recipes behind `make`, `just` and `npm`/`pnpm`/`yarn`/`bun` scripts, up to three files deep; in a followed file, a plain delete of build output inside the project (`dist`, `build`, `node_modules` and the like) doesn't ask when nothing before it changes folder or runs other code, while typing it does. For a gated call the hook sends Decidio the command (secrets redacted), its directory, category, subject and any matched script line; the permission mode; the repository, branch and commit; and the user's last prompt in the session (with the one before it when the last is under 40 characters; at most 1,000 characters each, secrets redacted) - shown to people allowed to read the request, never on Slack or Teams. `DECIDIO_HOOK_SHARE_PROMPT=0` leaves the prompt out. A policy's auto-approval prints nothing, so Claude Code's own permission check still decides; a person's approval of the exact call allows it once.
- `hook lock [--strict] [--print]` / `hook unlock` — run as `cd / && sudo npx @decidio/sdk hook lock`: lock Decidio on a computer (macOS, Linux; an administrator, as root). It installs this release root-owned and writes Claude Code's managed settings (the plugin's copy switched off, bypass mode disabled, Claude Code 2.1.295+), so Claude's file tools can't switch the hook off, replace it, or point it at another server, and a shell write to Claude Code's settings is asked about first. Connect the computer first, then run it once without sudo: it prints the exact sudo line with your workspace's key (check it on the Agents page); under sudo with no key, nothing is locked. Node and Claude Code must be installed system-wide too (the lock refuses a user-owned Node); restart Claude Code afterwards. Known gap: a shell command that rewrites a shell profile isn't asked about, and neither is a script the agent writes and runs; on Linux that can switch the hook off from its next session, and anywhere a profile can point `claude` at another, unlocked copy - `--strict`, recommended for security-conscious teams, closes it. `--strict` adds Claude Code's sandbox: anything the agent runs can't write outside the project (shell profiles and Claude Code's settings included), can't read credential folders (`~/.aws`, `~/.ssh`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker/config.json`, `~/.npmrc`, `~/.netrc`, `~/.pgpass`, Decidio's own folder), and reaches only listed hosts (package registries, github.com and gitlab.com to start, no production host among them; add yours to `sandbox.network.allowedDomains`) - it covers shell commands only. `--print` writes nothing and prints the document for device management or claude.ai's server-managed settings (which, like a device-management profile, outrank the lock's file). A cloud session (only server-managed settings reach it), or a user who can become root, isn't contained; native Windows can't be locked (`--print` there gives the document for device management). `hook unlock` removes the lock (the installed release stays).

The CLI's stream contract: **stdout carries results only** (safe to pipe — `--json` output is
pure JSON); errors, usage shown on *error* paths, and the per-run target-host announcement go
to **stderr**. Asked-for help (an explicit `--help`, or invoking the bare CLI) is itself a
result and prints on stdout. Exit codes: 0 success · 1 failure or honest no-op · 2 usage error · 3 `quickstart` stopped at the human moment (headless: the decision routed, but nothing executed and no receipt was written, so the run is deliberately not reported as a completed tour).

Commands that administer your workspace (`init`, `approvals`, `receipt`, `tokens`) use a **session**
sign-in: `login` stores it in your user profile (owner-only, bound to this terminal window, 30 days;
`logout` or `quickstart cleanup` forgets it here — the token itself stays valid until it expires), or `DECIDIO_SESSION_TOKEN` supplies it for headless shells. What lands on disk in `.env`: the agent's floor-limited
API token, its locally-generated private signing key, and a webhook secret (used only in
operator deployments) — `init` adds `.env` to `.gitignore` for you; move secrets to a secret
manager for production.

## MCP tool calls

Decidio's Claude Code hook reads an MCP tool call only when the tool's name says it may drop, delete, run a command or write a file
(the hook's matcher is generated from its own word lists). It then asks a person first when the call's name or its command, code or
SQL argument is destructive. Every other MCP call runs without Decidio reading it - that is most of them.

**The notice.** The first time in a session that Claude makes an MCP call Decidio doesn't read, you see one line beside the call,
naming the server as your settings do: "Claude just used github via MCP. This call isn't protected by Decidio". It shows once per
server per session (a server Decidio reads some tools of still shows it on its first other call), only in the main conversation, and
never for Decidio's own connector. It never errors or blocks the call (a run past Claude Code's 15-second hook timeout - npx's first
download, say - shows Claude Code's own timeout line). Nothing is sent anywhere: the hook writes an empty marker file in its own state
folder and nothing else.

**To have a server's calls approved first**, pick one:
- **Claude Code's own prompt:** add the server to your settings' `permissions.ask` (for example `"ask": ["mcp__github"]`, every tool of
  the server `github`). Claude Code then asks you before each call. This is Claude Code's prompt, not a Decidio approval: nothing is
  recorded or sealed.
- **An administrator's allow-list:** managed settings' `allowedMcpServers` / `deniedMcpServers` decide which MCP servers Claude Code may
  use at all.
- **A server you run:** wrap its handlers in `guard.protect()` (above), so each call is approved and sealed in Decidio.

**Limits:** a server used only inside a subagent never shows the notice; a call that fails shows nothing; a session longer than a day
may show it again (the markers are swept after 24 hours); the notice reaches you with the next SDK and plugin release. It costs one small node start after each MCP call (about 40 ms),
never npx.

## Errors

- `DecidioBlockedError` — policy blocked the action: a named block rule, or the universal backstop that fires when NO active policy governs agents at all (fail closed, no human involved). Distinct from routing-by-default — with an active policy and no matching auto-approve rule, a request is not blocked, it is ROUTED to a person.
- `DecidioRejectedError` — a human rejected the routed action.
- `DecidioRequestChangedError` (0.7.0, a `DecidioBlockedError`) — Decidio approved the decision for a *different* request than the one about to run ("the request changed after approval"); nothing executed. Ask again for the request you mean to run.
- `DecidioApprovalUnverifiedError` (0.7.0, a `DecidioBlockedError`) — the approval could not be tied to this request: `code: "commitment_missing"` (Decidio returned no request commitment although this SDK sent one — typically a gate older than 0.7.0) or `"unverifiable"`. Nothing executed.
- `DecidioSuspendedError` — (durable mode) the action was routed and is parked for async approval; the process may exit and resume later. Not a failure.
- `DecidioTimeoutError` — (blocking mode only) no human decided within `pollTimeoutMs` (default 10 min); nothing executed locally. Since 0.6.4 the SDK's last act before throwing is to tell Decidio it gave up, so the request is closed as **withdrawn** (it leaves the queue; a later approval does nothing) — `error.withdrawn` is `true` when that landed and `false` when the call failed and the request may still be open. Withdrawing needs the bound agent token and the signing key `init` writes (an unbound or unsigned caller cannot withdraw anything — it just gets `withdrawn:false`). If a human decided in the last poll window, the SDK honours that decision instead: the action runs as approved, or `DecidioRejectedError` is thrown. The durable path never withdraws: its parked action is what a later approval resumes. Since 0.12.0 a request that may be shared is never withdrawn: after an `idempotentReplay` or `openTwin` answer, or a 409 `SHARED_REQUEST`, `error.shared` is `true` and a person still decides it.
- `DecidioRateLimitError` — the workspace's governed-action limit was hit; carries the server's `limit` / `remaining` / `resetAt`.
- `DecidioHttpError` — the gate refused the call. Carries `status`, `endpoint`, the parsed `body`,
  and **`retryable`** — the field to branch on. A 401/403 is terminal (the agent token expired, or
  someone re-ran `init` for that agent and revoked it): retrying cannot help, so the message names
  the fix. Anything else is transient: the SDK already retried the authorize with the same request key
  (0.12.0) - a request still waiting is answered with the one already waiting - and retrying is safe: it
  can never double-execute.
- `DecidioNetworkError` — the gate was unreachable (after the SDK's own retries, for the authorize). Nothing executed locally.
- `DecidioUnsafeArgumentsError` — your call arguments cannot survive JSON with their meaning intact, so nothing was routed and nothing ran. The message names the field and the fix. Most often: `NaN`/`Infinity`, `-0`, a `Date`, `Map` or class instance, a `BigInt`, or a sparse array — anything whose serialized form would differ from the value the approval and signature cover. Pass the already-serialized form.

```js
try { await payInvoice(inv); }
catch (e) {
  if (e instanceof DecidioHttpError && !e.retryable) { await alertOncall(e.message); throw e; }
  if (e instanceof DecidioHttpError) { await backoff(); return retry(); }
  throw e;
}
```

Every error raised after a decision exists carries the `decisionId`, so a suspended or
timed-out action is always findable in
your queue.

## What the SDK does not yet claim

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
  `<api>/api/did` — for Decidio https://mcp.decidioai.com/api/did; Decidio's own services' DIDs are also
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

- **Stable surface:** `guard.protect` / `withApproval` and their options; the durable resume
  controller (`createDecidioResume`: `park`, `resolve`, `reconcile`, `reconfirm`, `recover`, the worker
  and both webhook handlers); the `PendingStore` contract and both shipped stores, including the on-disk
  revision-chain layout; `EvidenceOutcome` (a root export) and `ResumeStatus` / `RecoveryState` (on the
  `@decidio/sdk/resume` subpath), additive growth only; the error classes; the CLI's commands, flags and exit codes; the receipt verifier's verdict and
  reasons. Changes to any of these announce themselves in the changelog first.
- **Beta:** the engine adapters (above).
- **Deprecated, kept until 1.0:** `protectBestEffort` (the value-only shape) and the old adapter
  name `gateInterruptions`. They will be removed in 1.0.0, not before.
- **Versioning:** 0.x minor releases may still carry deliberate breaking cleanups, announced in the
  changelog with the upgrade step. 1.0.0 follows user-acceptance testing of this release and freezes the
  surface above.

## Notes

- **Coding agents and assistants:** a one-page skill file for adding the gate to an agent — TypeScript and Python on the same page, what the gate does and does not do, the wrapper, first run vs production, the typed errors, how to verify a receipt — is published at https://decidioai.com/skills/decidio-guard.md (the site summary for machines is https://decidioai.com/llms.txt).
- **Framework-agnostic:** it wraps at the tool-call boundary, so it works with any agent runtime (LangGraph, OpenAI Agents SDK, CrewAI, a raw tool loop) and any action (Salesforce, M365, SAP, a DB write).
- **Confirmation integrity:** the wrapper runs in your process, so it captures the genuine API response — a materially stronger signal than an agent self-report, but it trusts the host. For high-assurance, Decidio can *independently* read the source back (`independently_reconciled`) where it holds a read connection.
- **Zero-code alternative:** an agent that speaks MCP (e.g. Claude on the web) can reach the same gate via Decidio's `request_approval` MCP tool with no code at all.
- **API surface:** the agent-gate REST contract this SDK speaks is described in [`openapi.yaml`](./openapi.yaml), shipped in the package.

## Using this for real?

The hosted sandbox is synthetic data in a workspace of your own. Production workspaces are per-tenant too, with your own
issuer key and receipts that verify offline against it.

[decidioai.com](https://decidioai.com) · [Developer docs](https://decidioai.com/developers/) · [Request access](https://decidioai.com/#early-access)

Built by OmniTwin Technologies.
