# Changelog — decidio (Python)

Release notes for the Python client SDK. `@decidio/sdk` (npm) ships the same changes under the same
version (the two are conformance-locked twins). Each entry names what changed, what a reader must do on
upgrade, and what proved it.

## Unreleased

## 0.20.1 - published with attestations (2026-11-18)

- **The first Python release from the public repository** (`OmniTwin/decidio-sdk`, PyPI trusted publishing, PEP 740
  attestations). 0.20.0 never reached PyPI: the upload action's older twine refused its metadata (founder F-1118-S1 (a)).
  Unchanged from 0.19.0 otherwise; it moves in lockstep with `@decidio/sdk`.

## 0.20.0 - published with attestations (2026-11-17)

- **Published from a public repository** (Lane S; founder F-1117-6 (a), F-1117-S3 (a)).
  - `decidio` is built and published by [`OmniTwin/decidio-sdk`](https://github.com/OmniTwin/decidio-sdk) through PyPI trusted
    publishing, with PEP 740 attestations naming the workflow run that built it.
  - The Python package is otherwise unchanged. It moves to 0.20.0 in lockstep with `@decidio/sdk`, whose 0.20.0 changes are the
    TypeScript hook's.
## 0.19.0 - production by default, and its receipts trusted (2026-11-10)

- **Release order (as 0.18.0, founder F-1110-2):** `enable_guard` (`apps/api/src/mcp/guard.ts` `GUARD_SDK_VERSION`) and the
  `decidio-approvals` plugin (0.14.0) pin 0.19.0. The hooks fail closed, so tag `sdk-v0.19.0` right after the merge: until npm
  serves 0.19.0, a hook set from `enable_guard` blocks Bash. The release checks both built-in DIDs live (staging and production).
- **Decidio by default** (launch plan L9, founder F-1106-C2 (a)): with no `DECIDIO_API_URL`, every network command talks to
  `https://mcp.decidioai.com`, which is production after the cutover window (it was the lab, `decidio-api.onrender.com`).
  The invite-only lab is `https://mcp-staging.decidioai.com`. A sign-in's "invite-only lab ... request access" hint shows only
  against the lab; elsewhere it says the address needs an account and where to sign up. `quickstart --demo`'s relay stays on the lab.
  - **The hosted tour stays on the lab** (founder F-1106-C4 (a)): `quickstart` with no `DECIDIO_API_URL` - its first-run
    questions, the tour and `quickstart cleanup` - runs on the lab, so its synthetic agent and permanent sealed record never
    land in a production workspace; no lab invite: `npx @decidio/sdk quickstart --demo`. With `DECIDIO_API_URL` set, the tour is that
    workspace's, and its target line says it adds one agent and one permanent sealed record. (`--demo` and the first-run
    menu are the TypeScript CLI's.)
  - **`api.decidioai.com` is production too** (after the window): its links go to `app.decidioai.com`, and the Claude Code cloud
    grant check finds production's key there (it is production's `alsoAt` in the built-in issuers, beside `mcp.decidioai.com`).
  - **Release condition:** publish only AFTER the cutover window (docs/Deployment_Runbook.md B), and with production's
    built-in issuer (cycle c-verifier-prod): before the window this default is staging under production's name, and a `.env`
    written then would move to production at the window.
  - **Upgrade:** a `.env` written by `init` keeps its own `DECIDIO_API_URL`, so existing agents are unaffected. Testers on the
    lab set `DECIDIO_API_URL=https://mcp-staging.decidioai.com` for new commands.
  - **Proved by:** cli-smoke and cli_smoke.py (the lab's origins, exact, and look-alikes refused, twins).

- **The links the command line prints follow the API's own web app** (launch plan L1c). Staging's API maps to
  `staging.decidioai.com`, production's (`mcp.decidioai.com`) to `app.decidioai.com`, and any other origin to itself.
  `DECIDIO_APP_URL` wins only as a plain `http(s)` address, and the host line names it.
  - **Release condition:** publish only after `staging.decidioai.com` serves staging's web app (docs/Deployment_Runbook.md
    A1). Tell testers to run `github init` again to refresh their AGENTS.md section.

- **The verifiers trust production's receipts** (launch plan L9, founder F-1106-C1 (a), cycle c-verifier-prod): the built-in
  issuers (`@decidio/verify`'s `KNOWN_ISSUERS`, `decidio.verify.KNOWN_ISSUERS`) are Decidio's two deployments - the staging
  lab (`decidio-api.onrender.com`, also at `mcp-staging.decidioai.com`) and production
  (`did:key:z6MkpBwpAT98VAqg2UpiSGJZieg7DGQpoNkdioDUEo4kQXnJ`, `decidio-prod-api.onrender.com`, also at `mcp.decidioai.com`;
  its key is Ed25519 in AWS KMS). `verify` with no `--issuer` now verifies a production receipt and names its anchor
  `built in: Decidio production, decidio-prod-api.onrender.com`. The staging entry reads "Decidio staging lab" (was "Decidio
  hosted service"). The Claude Code cloud grant and pause check finds each deployment's key at its other address too.
  - **Release condition:** production must answer `/api/did` at every release from now on (the release checks each built-in
    DID live).
  - **Proved by:** the verify smokes (production's DID pinned, every entry its own deployment), cli-smoke (each address to
    its own deployment's key), and the release's live check run by hand (both hosts, 2026-11-10).

- **`approvals` lists every pending agent request** (launch plan L7, cycle g-probes): it reads the Queue's own paged feed
  (`GET /api/queue/all?view=agent_requests`, 100 a page, newest first) until the server's total is read, instead of the cards
  view's first 50. `approvals --mine --json` could print `[]` and exit 0 while an older request of this agent waited; it now
  lists it. When the total fills the server's 1,000-row window, `--json` exits 1 (never `[]` with 0) and both forms say older
  requests may exist. Proved by `cli-smoke.ts` / `cli_smoke.py` (a stub with this agent's request on page 2).

## 0.18.0 - the command line's sign-ins

- **Every sign-in `python -m decidio` completes says it is the command line's** (cycle ai-cli-fence; founder F-1109-25 (a)), as in
  `@decidio/sdk` 0.18.0. The password and link sign-ins send `client: "cli"`, and so does the hint for `POST /demo/login-consume`.
  Decidio marks the session, so it can't show AI assistants more or confirm a name as anything but a person. An older API ignores
  the field.
- `@decidio/sdk` 0.18.0 also renames the connector tools its Claude Code hook names and makes `connect` aware of the two plugins.
  The Python package has neither, so nothing else changes here.
- **Proved by:** `cli_smoke.py` (the sign-in body's `client`, the taught hint).

## 0.17.0 - lockstep

- **Version only** (cycle claude-delivery): `@decidio/sdk` 0.17.0 hands Claude the person's context at session start and writes
  pointer skills from `context pull`. The Python package has no Claude Code hook. (This entry was missing when 0.17.0 shipped.)

## 0.16.0 - lockstep

- **Version only** (connect-once slice 6d): `@decidio/sdk` 0.16.0 adds `decidio help` and `decidio status` to the Claude Code hook. The
  Python package carries no Claude Code hook, so nothing else changes here.

## 0.15.0 - lockstep

- **Version only** (connect-once slice 6c): `@decidio/sdk` 0.15.0 fetches the workspace's own guard rules for Claude Code; the Python
  package has no hooks.

## 0.14.0 - lockstep

- **Version only** (connect-once slice 6b): `@decidio/sdk` 0.14.0 pauses Decidio's Claude Code guard by kind (`decidio pause git`);
  the Python package has no hooks.

## 0.13.5 - lockstep

- **Version only** (connect-once slice 5g): `@decidio/sdk` 0.13.5 changes the Claude Code prompt hook's answer to a typed pause
  or resume; the Python package has no hooks.

## 0.13.4 - lockstep

- **Version only** (connect-once slice 5f): `@decidio/sdk` 0.13.4 changes the Claude Code hook (a grant with leading whitespace, the
  refusal's words, "decidio check"'s numbered steps); the Python package has no hooks, so nothing else changes here.

## 0.13.3 — lockstep

- No Python change. `@decidio/sdk` 0.13.3 adds where (repository, branch, commit) to a cloud session's request and a shorter
  "decidio check" (connect-once slice 5e); the Python package ships the same version.

## 0.13.2 — lockstep

- No Python change. `@decidio/sdk` 0.13.2 changes the Claude Code hook's words for a connector tool blocked in claude.ai
  (connect-once slice 5d); the Python package ships the same version.

## 0.13.1 — lockstep

- No change in the Python package: the version moves with `@decidio/sdk` 0.13.1, whose changes are the Claude Code hook's (the Node
  CLI only - a cloud session asks through the Decidio connector; "decidio check").

## 0.13.0 — the tour cleans up its agent; a plan's refusal and a removed agent in their own words

- **The tour's cleanup removes its own agent** (launch plan L4, Remove agent). `python -m decidio quickstart cleanup` asks the
  server to remove the tour's `quickstart-` agent: its new requests stop and its name stays taken; the records it made stay. A
  removal the server refuses is a non-zero exit naming the Agents page; an older server with no remove door leaves the agent
  registered, says so, and exits 0.
- **A 402 in its own words**: a refusal for the workspace's plan quotes the server's sentence and says it isn't a sign-in
  problem. **A removed agent, said as such**: a 409 `AGENT_REMOVED` says the agent was removed and to register a new one.
- **This hour's allowance by kind.** `tokens list` says the server's two hourly limits on agent requests - those that need a
  person and those the rules decide (launch plan L4, agent limits by kind); against an older server, the one allowance as before.
- The Claude Code hook (`npx @decidio/sdk hook`, connect-once slice 5) and `disconnect --new-key` are TypeScript only.
  Upgrade: nothing to do.

## 0.12.0 — request keys by default; an approval is collected once

The Python twin of `@decidio/sdk` 0.12.0, in step:

- **A request key by default** (founder 11f). Every authorize that carries a request commitment now carries an
  `idempotencyKey` too: a keyed digest of a fresh id for the call and the commitment. The SDK retries the authorize twice
  (after 0.3 s and 1 s) with the same request when the network fails (an `OSError`), on a 5xx, or on a 429 that is not
  the workspace's hourly limit - so a retry never runs an action twice, and a retry of a request still waiting is answered
  with the one already waiting. A 4xx is never retried. A retry
  signs a fresh identity proof; nothing else changes. No key material: no commitment and no key, as before.
  - `guard.protect(..., request_key=lambda *args: ...)` uses your own key (an order id) instead, keyed before it is sent.
    The same key for a changed request is refused (409 IDEMPOTENCY_CONFLICT).
  - The result names the key it sent: `ProtectedExecution.request_key`. `ExecutionContext.idempotency_key` stays the
    decision id.
  - The engines key on their own ids: OpenAI on the tool call id; Temporal on the activity's workflow, run and activity
    ids (`_authorize_activity` reads them inside an activity, or takes `ids=`); Inngest on `run_id` (new argument).
- **An approval is collected once** (founder call 24 "(a)"). Before the SDK runs an action on a person's approval it
  claims it (`POST /agent/claim/<decision_id>`, `claim_approval`) with a key random to that run, and runs only if
  Decidio says this run collected it - otherwise `DecidioBlocked`, in plain words. This covers the blocking wait, the
  durable resume, Temporal (`claim_fn`, an activity returning `_claim_activity(guard, decision_id, claim_key)`) and the
  OpenAI verified resume (`claim_key=` to keep your own). A durable action keeps its claim key with it
  (`PendingAction.claim_key`). Auto-approvals are never claimed; reading the status never claims.
- **A shared request is left open:** no timeout withdraw after an `idempotentReplay`/`openTwin` answer; a 409
  `SHARED_REQUEST` sets `DecidioTimeout.shared`.
- `decidio.adapters.bind("openai", ...)` now names `authorize_interruptions` / `apply_verified_resume` - it pointed at an
  `openai.gate(...)` that does not exist.

On upgrade: the gate must have `POST /agent/claim`; Temporal hosts pass `claim_fn` beside `verify_fn`. Entries parked by
an older SDK (or put into a store directly) carry no claim key: they claim with a fresh random key on every resolve, so
an answer lost on the way back costs a new approval - never a second run. Proved by: smoke.py (287 -> 323),
adapters_smoke.py (116 -> 127), cli_smoke.py (199 -> 201), runner.py, the acceptance gate.

## 0.11.0 - the links follow the API's own web app

- **The links the command line prints follow the API's own web app** (launch plan L1c). Staging's API maps to
  `staging.decidioai.com`, production's (`mcp.decidioai.com`) to `app.decidioai.com`, and any other origin to itself.
  `DECIDIO_APP_URL` wins only as a plain `http(s)` address, and the host line names it. (This entry sat under "Unreleased"
  until 0.18.0.)

## 0.7.0 — approvals bind to the exact request they approved; receipts pin to a real trust anchor

- **The receipt trust anchor is built in — nobody pastes an issuer DID, and nothing pins to a receipt's own
  claimed issuer** (founder-approved 3A, 2026-09-24). `receipt` and the tour used to pin their offline check to the
  `issuer` field of the server's verify response — which echoes the credential's OWN claim — and never read `valid`:
  a receipt signed by any key that names itself verified "pinned" against itself, and a record the server's own check
  had failed was shown as VALID. Now:
  - `receipt` and the tour pin to `expectedIssuer` — the server's configured key, which the API now returns beside
    `issuer` — else to the DID remembered for that host; they fail (exit 1) when the server says `valid: false`.
  - Sign-in (`login`, the tour's or `init`'s sign-in) and `init` fetch the host's public `/api/did` and remember it in
    the profile beside the stored sign-in (`issuers.json`, owner-only; kept past logout). A later `/api/did` answering
    a DIFFERENT DID is warned about loudly and NOT adopted.
  - `verify` with no `--issuer` pins to that remembered DID for the configured host, else to the built-in
    `KNOWN_ISSUERS` (in `decidio.verify`: the hosted service's issuer only — never the verification kit's
    published sample key), else refuses (exit 2) with the remedy. An explicit `--issuer` always wins, and every run
    prints its trust anchor first. An unreadable `issuers.json` refuses rather than falling back.
  - `python -m decidio.verify` with no `--issuer` pins to the built-in list (`decidio.verify.KNOWN_ISSUERS`, the
    twin of the TS constant); a receipt from any other issuer is refused (exit 2) with the remedy.
    `decidio.verify.run` prints `trust anchor: …` as its first line.
  On upgrade: nothing to do; scripts that pass `--issuer` behave as before (plus the anchor line on stdout). Deploy the
  API first: against a server without `expectedIssuer`, `receipt` and the tour fall back to the remembered DID and
  otherwise fail closed. Proved by: `cli_smoke.py` (a forged receipt naming itself fails the tour and is never offered
  as the anchor; `valid:false` fails `receipt` and the tour; init/sign-in remember `/api/did`; flagless verify pins to
  it; `--issuer` wins; a changed DID is not adopted; nothing remembered → exit 2 naming the built-in anchor; an
  unreadable store refuses), `verify_smoke.py` (the built-in list's content and refusals), the three-door
  conformance run (every door names the same built-in anchor), and a claims tombstone for the retired
  "refuses to run without --issuer" sentence.

- **SECURITY — a project's `.env` leaked into the CLI's shell environment (pre-existing, found by the 3A review).**
  `python -m decidio` imports the `decidio` package first, and that import runs `Guard.from_env()` for the `guard`
  singleton, which fills `os.environ` from `./.env`. The CLI's `_SHELL_ENV` snapshot - which the update gate reads its
  switches from and runs `pip` with - was taken after that, so a hostile repository's `.env` could set
  `PIP_INDEX_URL` / `DECIDIO_UPDATE_REGISTRY` (point the update check and the "Upgrade now?" `pip install` at its own
  index) or `DECIDIO_NO_UPDATE_CHECK` (switch the check off), undoing the 2026-09-04 fix; and the offline `verify` read
  the project's `DECIDIO_API_URL`, which the TypeScript CLI never does. `Guard.from_env()` now records the keys it
  injects (`decidio.guard._DOTENV_INJECTED`) and the CLI removes exactly those before it snapshots the shell's
  environment; network commands then load `.env` under the CLI's own rules, as before. Library behaviour is unchanged
  (`from decidio import guard` still auto-loads `.env`). Proved by `cli_smoke.py`: "update gate: a project .env cannot
  switch the update check off" (with a subprocess probe that `_SHELL_ENV` carries none of the `.env`'s PIP_INDEX_URL,
  DECIDIO_UPDATE_REGISTRY, DECIDIO_NO_UPDATE_CHECK) and "verify reads no .env in either SDK" - both red against the old
  code.
- **3A follow-up (independent invariant-guard review, 2026-09-24).**
  - **The remembered DID wins over a server that names another.** `receipt` and the tour compared nothing: a server whose
    `expectedIssuer` differed from the DID remembered for its host was followed, so "not adopted" held at sign-in and
    failed one command later. Now the same loud HAS CHANGED warning prints and the pin stays the remembered DID (the
    receipt then fails its offline check: `receipt` exits 1, the tour fails). An unreadable `issuers.json` now yields no
    anchor at all rather than the server's.
  - **`receipt` checks the file offline against the anchor it prints.** It honoured the server's `valid` but never
    checked the credential against the anchor it recommended - a server naming the built-in DID over another key's
    credential got "No --issuer needed" and exit 0 while that flagless verify then refused. Any failure now behaves like
    `valid:false`: exit 1, the file kept for inspection only.
  - **One host rule.** `verify` resolves its remembered DID for `DECIDIO_API_URL` from the shell (it reads no `.env`),
    and `receipt` prints the flagless command only when that verify lands on the same anchor - a host set only in `.env`
    gets the explicit `--issuer` form and says why.
  - **`issuers.json` is keyed by URL origin** (scheme + lowercased host + non-default port, no path, no trailing slash):
    `HTTP://Host:80/` and `http://host` are one entry, so a variant spelling cannot pass as a first sighting and skip
    the change warning.
  - **Output contract.** `receipt --json`'s `issuer` is the trust anchor the file was checked against (null against an
    older server with nothing remembered), and `valid` is false when the server's check or the offline check failed.
    `verify`'s stdout starts with a `trust anchor: <did>  (<source>)` line before the verdicts.
  Proved by: `cli_smoke.py` +9 (a server naming a different key than the remembered DID: warned, not followed, receipt
  exit 1, tour fails; a server naming the built-in DID over another key's credential: exit 1, never "No --issuer
  needed"; the flipped forged vector now exits 1; a variant spelling of the host is the same entry; eight origin-key
  cases shared with TypeScript; `.env` never chooses verify's anchor; the flagless command follows verify's host; an issuer
  store with `"v": true` is refused; the update gate's switches come from the shell) - all red against the previous
  commit's code; the release workflow now fails if `KNOWN_ISSUERS` differs from the live
  `https://decidio-api.onrender.com/api/did`.
- **3A follow-up, round 2 (guard re-review, 2026-09-24) — same hostile-`.env` threat model.**
  - **SECURITY — the session and the trust store live where the SHELL says.** `_session_dir()` (and the terminal-id
    read) took `XDG_CONFIG_HOME`/`LOCALAPPDATA`/`HOME` from `os.environ` *after* `.env` was loaded, so a project `.env`
    with `XDG_CONFIG_HOME=.cfg` put the session token and `issuers.json` inside the repo — and let the repo plant a DID
    that then showed as "remembered on this computer". Both now read the shell snapshot (`_SHELL_ENV`).
  - **SECURITY — a project `.env` promotes only `DECIDIO_*`.** It configures Decidio; it does not reconfigure the OS,
    toolchain or network stack. A cloned repo's `.env` can no longer inject `HTTP(S)_PROXY`/`NO_PROXY` (which would route
    this CLI's authenticated `urllib` calls, bearer token and all, through the repo's server), `SSL_CERT_FILE`/
    `REQUESTS_CA_BUNDLE`/`PYTHONHTTPSVERIFY`, `PYTHONPATH`/`PYTHONSTARTUP`/`GIT_*` code loaders, or the session-dir
    variables into the environment a network command runs with. A switch genuinely wanted is set in the shell, which
    still wins (`_SHELL_ENV` is snapshotted first).
  - **The cached update-check value is validated like the network answer** (a full `x.y.z`), and `_semver_newer`
    requires exactly three all-digit components: a planted `update-check.json` with trailing bytes can no longer be
    printed as an available-version notice or used to force an upgrade.
  - **`receipt --json` reports `valid: null` when no offline check ran** (no anchor — e.g. an unreadable store): the
    server's own verdict alone is not enough to call a receipt verified.
  - **Parity refactors (behaviour unchanged on the tested vectors).** `_issuer_store_key` is now the same explicit,
    fail-closed parser as the TS twin (validate ASCII-label host or bracketed real IPv6, else key as the trimmed
    lowercased self); Python already refused a non-integer `v` and already keyed exotic hosts literally, so these two
    align the implementations while the TS CLI is the one whose observable behaviour changed.
  Proved by: `cli_smoke.py` +5 (session/trust-store location; `.env` promotes only `DECIDIO_*`; the poisoned cache; the
  `1.0` version literal; `receipt --json` valid:null) plus 7 new origin-key cases — 4 of the new checks red against the
  previous commit's code; the origin-key and `1.0` cases were already green in Python (fixed in TS). The release
  workflow's live-DID gate now uses `curl --retry-all-errors` and emits an explicit `::error::` on an unreachable host
  or a malformed body.

### An approval is bound to the exact request it approved (#4B, BREAKING)

**Breaking.** Read "On upgrade" before bumping. The version is not bumped here; this ships as the next minor,
together with `@decidio/sdk`.

- **Every door confirms with Decidio that THIS request was approved before it runs it** - inline (the blocking
  wait), the durable webhook and worker, LangGraph, Temporal, Inngest and OpenAI Agents, through one check
  (`decidio.check_approval`; the adapters share `adapters/_common.py`). `GET /agent/status` must answer
  `approved`/`auto_approved` AND return the request commitment this SDK sent, recomputed over the request about to
  run. A resume webhook, Temporal signal, Inngest event or LangGraph resume value is now only a WAKE-UP. A mismatch
  raises `DecidioRequestChanged` ("the request changed after approval", naming the decision); a gate that returns
  no commitment for a bound request raises `DecidioApprovalUnverified` (`code == "commitment_missing"`, or
  `"unverifiable"`). Both subclass `DecidioBlocked`. The durable resolve reports `not_approved` (still pending -
  stays parked) or `request_unverified` (refused, kept parked, named once). Because it now asks Decidio first,
  **`resolve()` RAISES when Decidio is unreachable** (nothing ran; the entry stays parked) - callers must catch it.
- **The commitment is keyed, never a digest** (invariant I5): HMAC-SHA256 under a subkey of the agent's Ed25519
  key (when `agent_key`+`agent_did` are set) or its API token, over `committed_request_json(...)`. Byte-identical
  to the TypeScript twin (shared vectors, `packages/conformance/vectors/canonical.json` `commitments`). The core
  wrapper commits `kwargs` only when there are any, so a call without keyword arguments binds the same bytes as
  the TS twin. **Prefer the Ed25519 key for binding**: under the API-token fallback the key is a bearer Decidio
  receives on every call, so the commitment is opaque to everyone except the Decidio server itself. **Rotation
  strands pending approvals**: re-minting the token, changing `DECIDIO_AGENT_KEY`, or a guard and resume controller
  with different key material turns every routed approval still pending into `request_changed` - drain first.
- **LangGraph: the $100 -> $1,000,000 resume bug is closed** (see the TS entry; same design): the re-run node
  authorizes with an idempotency key from its own thread + checkpoint namespace + call index + commitment, gets
  the SAME decision back, requires the resume value to name it, and runs the check; an edited state becomes a
  NEW pending decision. `decidio_resume_command(body)` requires `decisionId` (`ValueError` otherwise). Needs key
  material and a checkpointed run with a `thread_id` and the node execution's scratchpad (without one the routed
  gate refuses, naming its decision, instead of counting gates on a key of `None`).
- **Temporal**: `gate(..., verify_fn=...)` runs the check after the signal and before `run`; REQUIRED whenever
  `authorize_fn` is given (`ValueError` before anything is routed). Activity body:
  `decidio.adapters.temporal._verify_activity(guard, decision_id, ctx)`.
- **Inngest**: the check runs as a memoized step after each wait; a premature or forged event waits again.
  **`resume_event(raw_body, signature, webhook_secret=None, *, allow_unsigned=False)` now verifies Decidio's HMAC**
  like the TS bridge (it took a parsed dict and verified nothing, so any body became a resume event); a dict is
  refused with `TypeError`, a missing secret or bad signature with `PermissionError`.
- **OpenAI Agents: `apply_resume(state, item, verdict)` is REMOVED** (a verdict string cannot be checked; see the TS
  entry). Use `apply_verified_resume(guard, state, item, decision_id, describe)`: the approval is bound to THIS tool
  call - its name, call id and exact argument string from `raw_item`, beside `describe(item)`
  (`tool_call_request`) - so an item edited after approval and a second identical call whose own decision is still
  pending are both refused (`DecidioRequestChanged`). An interruption with no call id raises `ValueError` before
  anything is sent. Park `(item.call_id, decision_id)` with the state and find items again by `item.call_id`.
- **The resume webhook no longer falls back to the API token** (`ResumeController.handle`): no `webhook_secret`
  and no `allow_unsigned` -> `PermissionError` naming the fix - a dedicated secret, **never the Decidio server's
  `API_AUTH_TOKEN`**. The local integrity signature on parked payloads keeps its token fallback, so entries parked
  before the upgrade still verify.
- **Known limit (predates this release): one gated action per LangGraph node.** The node re-runs on resume, so an
  earlier gate in it runs again; one whose request auto-approved (action already run) replays as `proceed` to a
  verified agent and its action runs a second time when a later gate in the node resumes. Put each gated action
  in its own node, or make the actions idempotent.
- **Known limit (predates this release): LangGraph and OpenAI Agents have no single-execution claim.** Two
  concurrent resumes of the same thread or RunState can both pass the check and both run the action; resume each
  from one place. The core durable path claims each execution in its store.

**On upgrade:** the same eight steps as `@decidio/sdk` (gate first; webhook secret or worker; LangGraph checkpointer +
`decidio_resume_command(webhook_body)`; Temporal `verify_fn`; `apply_verified_resume` with parked call ids; test
doubles return `requestCommitment`; catch `resolve()` errors; drain before rotating keys), plus: an Inngest bridge
must pass the raw body and the `x-decidio-signature` header to `resume_event`.

Proved by: `smoke.py`, `adapters_smoke.py` (the REAL langgraph incl. a missing scratchpad, Temporal with a scripted
`wait_condition` delivering a forged signal first, Inngest, the bridge HMAC, OpenAI incl. an edited target and a
second identical call), `cli_smoke.py`, both conformance runners and `conformance/run.mjs`.

## 0.6.4 — the request closes when the agent gives up

- **The README links the agent skill file** published on the site (https://decidioai.com/skills/decidio-guard.md, one page for both languages) and the site's llms.txt. The file is served by the site, not shipped in the package; an in-package copy is a one-line publish-boundary decision for this release if wanted.
- **A blocking wait that hits `poll_timeout` now WITHDRAWS its request** (`POST /agent/withdraw/<id>`
  `{"reason": "timeout"}`) before raising `DecidioTimeout`. Before, the decision stayed open in Decidio
  forever after this process had stopped waiting, so the queue carried a request nobody could act on and a
  later tap sealed "approved" for an action that never ran. Now it leaves the queue as *withdrawn* and a
  later approval is a no-op. `DecidioTimeout.withdrawn` says whether the call landed; a failed withdraw
  changes nothing else (nothing executes either way). Withdrawing needs the bound agent token and the
  signing key `init` writes — the gate refuses anyone else with 404, so an unbound or unsigned caller simply
  sees `withdrawn=False`. If a human decided in the last poll window, the gate answers 409 with that decision
  and the SDK honours it: the action runs as approved (and confirms), or `DecidioRejected` is raised — never
  a timeout that hides a decision. The durable path is untouched; the CLI tour says which of these happened.
  Nothing to do on upgrade. Proved by: `smoke.py` (the timeout vector asserts exactly one withdraw after the
  last poll, and a failing withdraw still raises the same error with `withdrawn=False`; a 409 carrying
  `approved` runs and confirms, `rejected` rejects; a wait that ends in a decision never withdraws) — the
  TypeScript twin carries the same vectors, and the server side is proved in
  `apps/api/src/invariants/integration.smoke.ts` #W2 (lab posture, real bound tokens) and #W (IdP posture).

## 0.6.0 — `quickstart --demo` (TypeScript CLI first): the whole tour on your machine, no account

An uninvited developer could not run the tour at all: a workspace needs an invite (no open signup, by ruling). A
hosted sandbox was designed, red-teamed by the privacy council (BLOCK as written; eight design-level highs) and then
costed against the alternatives: the cheapest, least-maintenance path for a stranger's first two minutes is a LOCAL
demo with a hosted page for the phone moment. Founder ruling 2026-09-05.

- **`npx @decidio/sdk quickstart --demo`** runs the SAME tour code against an in-process stand-in of the Decidio API
  on 127.0.0.1 (`demo-gate.ts`, shipped in this package): register, mint, gate, route, approve or reject, execute
  once, and a REAL Ed25519 receipt signed by a key generated for the run — verifiable offline with the shipped
  verifier, and provably NOT the hosted issuer's (pinning it to the hosted DID fails). Nothing hosted, no account, no
  workspace: the tour runs in a temporary folder and leaves exactly one file behind, the receipt (never over an
  existing one). Its content says `recordSeries: local-demo`.
- **The web and phone doors still work.** The stand-in asks a hosted RELAY (`POST /demo/relay`) for a code, a link to
  the demo decision page (`app.decidioai.com/demo/<code>`) and a QR; the page shows the product's decision surface for
  the tour's fixed scenario and writes one word — approve or reject — which the stand-in reads while the tour waits.
  The relay holds no account, no record and no personal data; a code lives ten minutes, takes one verdict, and every
  failure answers with one shape. Offline (relay unreachable) the tour is terminal-only and says so.
- **Honesty is asserted, not hoped:** the frames say LOCAL DEMO; ④ says the issuer is a key this demo generated and
  where real tours pin theirs; the smoke plants the forbidden phrases ("PINNED to your workspace issuer", "hosted
  synthetic sandbox", "your trust anchor") and asserts the directory diff is the receipt alone; a decision made on the
  page reaches the terminal with no keystroke. The sign-in dead end now offers `--demo`.
- TypeScript CLI first — `npx @decidio/sdk quickstart` is where an uninvited developer arrives; the Python twin gains
  `--demo` when asked for (the version bump is in lockstep).

## 0.5.0 — `verify` pins by default

**Breaking, on purpose (founder ruling 2026-09-04, after the prodsec review of 0.4.3).** Every CLI verify door - `npx
@decidio/sdk verify`, the standalone `decidio-verify`, `python -m decidio verify` and `python -m decidio.verify` -
now REFUSES to run without `--issuer <did:key>` (exit 2, with the remedy printed). An unpinned VALID only proves the
file agrees with itself: the reviewer forged a self-signed "wire all funds" receipt and the exit code said yes. Scripts
trust exit status, not warnings, so the safe check is now the default and the structural check is a named choice:
`--allow-unpinned` runs it, and its verdict carries the UNPINNED warning as before. `--allow-unpinned` together with
`--issuer` is refused as ambiguous, like a disagreeing repeated pin.

- **What to change:** add `--issuer <your workspace DID>` to any scripted verify (the `receipt` command prints the
  DID; the app's record-verify panel shows it), or `--allow-unpinned` where you genuinely want structure only.
- **Unchanged:** the LIBRARY (`verifyReceipt(vc)` / `verify_receipt(vc)`) still verifies unpinned when no issuer is
  passed - a caller reads `issuer` in the result and decides; the CLIs are what scripts trust blindly.
- Vectors in all three suites: the refusal (exit 2, names `--issuer` and `--allow-unpinned`), the named unpinned run
  reaching a verdict, both flags refused together. The usage pages, both READMEs and the `receipt` command's hint
  say the new rule; the live selftest names its one unpinned run.
- **The sealed payload names two fields for what they are (schemaVersion 2).** `deciders` → `nominatedDeciders` (the
  people nominated IN ADVANCE; the ratifier is who decided, so `nominated deciders: 0, ratified: yes` reads as it
  should) and, inside `authority`, `appliedLimits` → `evaluatedLimits` (what the request was measured against - the
  requested amount, the auto-approve threshold, the hard cap - not limits that "applied"). New records carry the v2
  `payloadSchemaUri`; the canonicalization (`jcs-v1`) is unchanged, so verification is untouched. Both verifiers print
  `nominated deciders: N` and read the v1 names too (every record sealed before 0.5.0 is lab test data). Founder
  ruling 2026-09-04: rename now, while no customer record carries the old names.
- **From the 0.4.4 first-run audit (B+), the small items** (founder: go): quickstart checks connectivity BEFORE its
  first disk write (a dead host leaves the directory untouched and says "Nothing was written"); `tokens list --mine`
  after cleanup reads this directory's agents from the token recovery journal; `receipt` prints resolved identities
  only on a terminal (a pipe or a log gets a one-line note; `--json` hands them over explicitly); the ④ frame says the
  issuer DID was first seen over this connection and where to cross-check it (`<api>/api/did`, public, no sign-in);
  the help page and README say what cleanup leaves behind; the README no longer calls the lab ONE SHARED workspace
  (every invited tester has their own), explains the in-memory quota counter, lists `receipt --json` and `dev --port`,
  and calls the journal append-only by behaviour, not by enforcement. Vectors: the dead-host tour, `--mine` from the
  journal, the receipt in a pipe vs on a terminal.
- Two Lows from the prodsec retest of 0.4.4: `quickstart cleanup` with nothing to clean still ENDS the stored sign-in
  (the early "Nothing to clean up here" return skipped it, contradicting the documented promise; vector in both
  suites), and the resume module's comments say `lost_race` / `already_resolved` where the runtime does (they still
  said `unknown`); `onResolved` is documented as firing for every outcome except `unknown`.

## 0.4.4 — the small findings of the 0.4.3 prodsec run: frames at 80 columns, a local install upgrades in place, a key-less .env survives the tour

An external prodsec reviewer ran 0.4.3 from a stranger's install (2026-09-04; grade B, "trust in the core mechanics
went up"). Its design questions (a mandatory `--issuer`, out-of-band issuer distribution, npm provenance) are founder
calls in the backlog; these are its small findings, each with a vector that was red first.

- **Frames never wider than the terminal.** The 0.4.2 frames had a width FLOOR of 84 columns, and the terminal driver
  that gates the tours ran only at 300 columns - so on the most common width, 80, every border wrapped. The floor now
  yields to the terminal, and both suites run the approval tour at 80 columns: no frame line wider than the window,
  every frame line closes with its border.
- **The update gate knows a project-local install.** `npm install @decidio/sdk` then `npx @decidio/sdk …` (this
  README's own path) runs the CLI from the project's node_modules; the gate offered `npm i -g` (global state nobody
  asked for) and then re-ran the same old local file. Three shapes now, each upgraded the way it was installed:
  project-local → `npm i @decidio/sdk@latest` in that project; global → `-g`; under npx → the `@latest` form,
  printed. The re-run the gate spawns carries `DECIDIO_UPDATE_REEXEC=1` and never checks again, so a version that did
  not move cannot loop the prompt. (Python: `pip install -U` already upgrades the interpreter that is running; it
  gains the re-run marker.)
- **A key-less agent `.env` is left alone.** The tour used its own `.env.quickstart` only when `.env` held a signing
  key; the SDK's `agentKey` is optional, so an agent configured without one had its agent fields overwritten and then
  stripped by cleanup. ANY agent identity in `.env` (`DECIDIO_AGENT_ID`, `_DID`, `_KEY` or `DECIDIO_API_TOKEN`) now
  sends the tour to its own file. Vector: such a file is byte-identical after the tour and its cleanup.
- **The ④ frame names what was sealed** without `--explain`: `decision  payInvoice $86,000 · APPROVED · routed to
  a human by policy (no auto-approve rule for this agent)` (REJECTED on the denial's record).
- A `.gitignore` the tour CREATES also ignores `node_modules/`; an existing file gets only the secret entries.
- `openapi.yaml` now states the release version (it read 0.1.11 beside a 0.4.3 package), and a seven-manifest
  lockstep check (`packages/conformance/manifests.mjs`: both package.json, both package-lock.json, pyproject,
  `__init__`, openapi) runs in CI and on the publish path - 0.4.3 shipped with both locks a version behind.
- Documented: the token recovery journal's vocabulary (`minted`, `retired how=persisted`, `retired how=revoked`,
  `probe`) - `persisted` means the credential file holds the token and is its handle, not that it was revoked.
- **`logout` says what it does** (prodsec second pass on 0.4.3 - "A / A-", two Lows): it forgets the stored sign-in on
  this computer; the session token itself stays valid until it expires - there is no server-side revocation yet, and no
  wording implies one any more (`logout`, cleanup, the sign-in prompt, the usage page, both READMEs). Vectors: the
  statement is asserted, and `logout` makes no API call.
- The shipped `.d.ts` state-machine comment names the terminal `discarded` state beside the chain that omitted it.
- Confirmed as intended, no change: the online `receipt` command prints the tokenized identities your access
  covers ("Resolved for you"); the file keeps its tokens.

## 0.4.3 — the stale-install gate, frames you can read at a glance, and a phone door that lands

The founder's UAT round 2, second half (2026-09-04). Nobody is on 0.4.2 yet, so it was never tagged; this carries both.

- **A stale install must not keep running its defects** (founder ruling). Network commands (`quickstart`, `init`,
  `login`, `doctor`, `approvals`, `receipt`, `tokens`) ask the public registry once a day whether a newer version
  exists — npm for the TypeScript CLI, PyPI for Python, never our servers, cached in the user's profile, silent when
  offline. If one does, an interactive run asks `<latest> is available (you have <yours>). Upgrade now? [y/n]`: `y`
  runs the package manager's own upgrade (`npm i -g @decidio/sdk@latest` / `pip install -U decidio`, with its
  integrity checks) and re-runs your command on the new version; `n` exits 1 naming the command to run when ready.
  Under `npx` there is nothing installed to upgrade, so it prints the `@latest` form and exits. A headless run prints
  the notice and continues; `DECIDIO_REQUIRE_LATEST=1` makes it exit instead (pinned CI is a choice, not a
  surprise). `DECIDIO_NO_UPDATE_CHECK=1` skips the check. `verify`, `--help` and `--version` stay fully offline.
  Seven vectors in both suites: not newer prints nothing; headless + newer notices and runs; the strict flag exits 1;
  interactive `n` exits 1 running nothing; interactive `y` runs the upgrade (a labelled dry-run in the suite); an
  unreachable registry is silent; `verify` never checks.
- **Frames carry a tone.** ③ (the choice) in orange, ④ and the summary in green for an approval and red for a
  rejection — the frame and its title only, 256-colour orange with a yellow fallback, nothing under `NO_COLOR`
  or a pipe. Founder: "it's hard for the eye to pick out which box means what."
- **The phone door lands.** iOS opens the installed app for `app.decidioai.com/q/*` (the association file now
  claims it); the app consumes the code, signs in, and opens the decision. A phone without the app lands in its
  browser on the phone build (`/phone/q/<code>`), the same single-decision screen the app shows. The desktop landing
  is a hand-off page: the one decision on stage with its actions in view, the queue a click away (`?stage=1`).
- **`quickstart --phone web`** is the founder's test fork: the QR points at the phone web rendering, a path the app
  never claims, so it opens in the browser even with the app installed. The default QR opens the app when it is
  there. (`--demo` will pick the sandbox the same way, once it exists.)
- Founder decisions recorded (backlog): the sandbox for uninvited developers is TOUR-ONLY in v1 (no own agents —
  surface risk and a second policy to maintain), its boxes are torn down at cleanup or by a one-hour sweeper, and
  its phone surface is the web page, never the native app.

## 0.4.2 — the zero-miss release: three gates, and every finding of the two 0.4.1 reviews

Built to the plan in `docs/Decidio_SDK_Zero_Miss_Plan.md` after an outside engineer's first-run review of 0.4.1 (B+)
and the prodsec retest of 0.4.1 (A-, safety A). Every item of both reports has a disposition below; the gates that
would have caught them now run on every pull request, on Linux AND Windows.

**The founder's UAT, round 2 (2026-09-04), folded in before the tag.** Steps 0–6 green on the previous build; the
web-app door landed on home (fixed twice the same night: the desktop's deep link is `/queue?focus=<id>`, and a browser
with no session bounced to `/login` before the link was consumed), and approving from the queue proved the terminal
follows an outside decision. Then six findings on the tour itself, all taken but one (which became a founder call):
- **One line per event.** The tour's paragraphs are gone from the default output: every step is a frame with two to
  four terse rows, the outcome is one line, the reminder is two, and "Where next" is one. `--explain` prints the
  narration that used to be the default. Target met: the approval tour is about 40 lines without the QR.
- **Every step framed** (①②③④ and the summary), with an escape-aware word wrap so a styled row never overflows a
  narrow window; continuation lines hang under the label column.
- **A short hand-off link.** `POST /demo/session-link` now returns `https://app.decidioai.com/q/<13-char code>`
  instead of a 110-character URL: it fits the frame, stays clickable AND copyable, and the credential row remembers
  which decision the code was minted for (`handoff_decision_id`, cleared in the same single-use burn), so the web
  app's new `/q/<code>` route signs in and lands on that decision. A hand-off never flips `emailVerified`.
- **A small QR, still printed by default** (the founder's call: "it looks impressive in a demo"). The QR carries the
  short link upper-cased, so the encoder uses its alphanumeric mode, at the lowest error-correction level with a
  one-module quiet zone: 25 modules instead of 41, about 14 rows instead of 23.
- **The lab is invite-only, and the CLI says so.** An uninvited address running `login` used to be told "we emailed
  you a link" and wait for nothing (the server's anti-enumeration answer). The CLI now says a link arrives only for
  an invited address and where to request access.
- **"The wrapper IS the SDK."** The first sentence of the help (and the READMEs) settles the SDK-versus-wrapper
  question: `guard.protect(fn, describe)` ships in this package; the CLI is the tour, the sign-in and the token admin.
- Founder calls recorded, not built: a sandbox tenant with device-bound identities and a single-decision preview page
  for developers who are not invited (the SDK's distribution unlock); scan → native app → the decision (iOS claims
  `/d/*` for the installed app; the QR opens Safari today); `record kind: agent-receipt` wording.

**Round 2, second look (2026-09-04, same night).** The founder re-ran on the deployed build: web-app approval and the
deep link now work; the QR was MISSING; the text above and below the frames was still dense. Fixes: (1) `qrcode@1.5`'s
half-block renderer throws "Invalid array length" on an ODD margin, so the 1-module quiet zone silently produced no QR
(the server logged it, the CLI showed nothing) - margin 2 with level L renders 25 modules in 13 rows, and the CLI now
says when no QR came back instead of dropping the row; (2) the sign-in block is six lines instead of eleven (one intro,
prompts that carry their own hints, one signed-in line); (3) the tour no longer prints the stderr "decidio →" host line
when its own Target line already said it; (4) ④ is three short rows (VALID + file / record kind + evidence / issuer)
instead of one wrapping line; (5) the reminder is two lines, the take-away has a breath around it.

**The founder's UAT pass (2026-09-03), folded in before the tag.** The script's steps 1–5 went green in a real
PowerShell; step 6 stopped on the sign-in: every command that needed the workspace asked for a fresh emailed link,
and "nobody would log in this many times". Ruled: sign in ONCE, no better and no worse than the web app; and a
human step you can believe from outside the terminal.
- **Sign in once.** `login [email]`: the CLI requests the emailed link itself, you paste it; the 30-day session is
  kept in your user profile (`%LOCALAPPDATA%\decidio` / `~/.config/decidio`, owner-only, written through the same
  atomic secret writer as `.env`), bound to the terminal window that created it (a second window gets its own) and to
  the token's expiry. `logout` ends it; so does `quickstart cleanup` (the tour's sign-in ends with the tour, the way
  the web app drops its session on sign-out). An exported `DECIDIO_SESSION_TOKEN` still outranks it for headless
  shells. No server-side session revocation exists yet (the web app has none either); the stored token is discarded.
- **Three doors at the human step.** The ③ frame offers: answer **here** (y/n), open the decision in the **web app**
  (a link that lands on it signed in), or scan a **QR** with **your phone** (the same link). The link comes from a
  new authenticated endpoint, `POST /demo/session-link {decisionId}`: it mints the SAME single-use sign-in token the
  emailed link carries, for the caller's own credential, five minutes instead of fifteen because it is shown on a
  screen and lands in terminal scrollback, and it replaces any pending emailed link (one slot per credential). It
  grants a sign-in and only a sign-in: the token is prefixed `h.` and the password-reset door refuses it, so a
  session can move itself to a browser but never mint itself a durable password (invariant-guard block, fixed, with a
  negative-smoke lock). The terminal races the prompt against the gated call: a decision
  made in the app or on the phone closes the prompt, the CLI posts no approve/reject of its own, says "approved (or
  rejected) in the web app (or on your phone) — this terminal saw it and followed", and the function runs
  once, after the approval, exactly as before. If the hand-off endpoint fails, the terminal door still works alone.
- **Layout.** Each step is a headed section; the doors and the closing summary are frames sized to their content and
  the terminal; the summary is a table (gated / decided / executed / receipt); the help page is in sections. Colour,
  bold and clickable (OSC-8) links only on a TTY and never under `NO_COLOR`; every phrase the gates assert is unchanged.
- **Two platform defects found by the doors vector, both fixed:** on Windows a console read abandoned when the app
  decided first kept libuv's reader thread blocked and Node's teardown waited forever (the process printed its last
  line and never exited) — the CLI now drains stdout/stderr and exits explicitly on that path only; and Python's
  `isatty()` is true for `NUL`, so the console-key reader spun on a headless run — a real console is now detected
  through `GetConsoleMode` (and that same check now decides whether the CLI may prompt at all, so `NUL` is headless on every OS), pipes and `NUL` read on a thread, POSIX uses `select`.
- Vectors, both languages: `login` under a real terminal (email → link → stored session); the next command in the
  same terminal asks nothing; another terminal is refused; `logout` removes the file; a headless tour on the stored
  session; cleanup signs out; and the browser-decided tour (the fake gate approves after two polls; the CLI must post
  no approval, run the function once, exit 0).

**Gates (structural):**
- **The stranger run.** Both CLI suites drive the interactive tour under a REAL terminal on every platform through one
  shared driver (`packages/conformance/tty_driver.py`: POSIX pty, Windows ConPTY). `y`, `n` and three blank answers
  are exercised end to end; a missing terminal driver is red on CI, never a skip. A `windows-latest` gates job runs
  both CLI suites under ConPTY.
- **Claims as vectors.** `packages/conformance/vectors/claims.json`: retired phrases are tombstones that fail the build
  if they reappear in shipped text; the help must carry what is true (`y approves`, `n rejects`, exit 3 at the human
  moment, `--help` anywhere, `receipt <id> [--json]`); the no-answer stop's exit code is asserted from what the help
  promises. The tombstone gate found a Python twin of a 0.4.1 text fix that had been missed.
- **Twin parity.** `packages/conformance/parity.mjs`: the vector labels of the TS and Python suites must match; a
  one-sided vector is red unless `parity-allowlist.json` names it with a reason. The pre-0.4.2 asymmetry is
  recorded as a baseline to burn down before 1.0.
- **No swallowed ledger read.** `packages/conformance/sdk-lint.mjs` refuses `.catch(() => undefined)`,
  `except Exception: x = None` and empty catches around ledger and journal reads; it was red on seven such sites in
  0.4.1 and is green now, with two justified allowances that carry their reason.

**Fixed, both languages unless noted:**
- The help said "YOUR Enter is the approval" (false since 0.4.1); it now says y approves, n rejects, Enter is not an
  answer. `--help`/`-h` after any command prints the one help page (exit 0); the bare word `help` past the usage
  positions stays a positional. `receipt <id> [--json]` is documented.
- The rejection half of the tour downloads and verifies the DENIAL's receipt, pinned, and names its record kind; all
  three verifier doors print `kind:` (read from the receipt's own canonical record). The approval half names its kind
  too. The tour's receipt goes through the same no-overwrite writer as the `receipt` command.
- Receipt filenames escape rather than strip: `a.b` and `ab` can no longer share a file (`~` + hex code point).
- The unset-session reminder prints on every end of the tour (approved, rejected, stopped) with both the bash and the
  PowerShell command; the README carries both.
- An answer typed after the tour's blocking call expired (5 minutes) is not posted; the tour says the request must be
  decided in the queue.
- `resolve()` on a decision whose entry was consumed between reading and claiming it now reads the ledger through one
  shared mapping: `already_resolved` when it ran, never "durable state undefined" or a false live-attempt claim; the
  resolved hook fires for every non-`unknown` outcome including the ledger-fallback ones.
- **A corrupt terminal ledger head is loud** (prodsec V041-01): `resolve()` propagates the state-corrupt error instead
  of returning `unknown`; the poll worker says it once per decision and keeps serving the other actions; the webhook
  doors answer 500 naming the error.
- A landed `init` token whose `persisted` journal note failed to write is held, not an orphan (the credential file is
  the proof); the failed note is reported, never silent. `quickstart cleanup` names a held token instead of saying
  the journal owes nothing (prodsec V041-02).
- The tour prints the call it actually makes (TS: the blocking primitive, with the note that real agents use
  `guard.protect`; Python already ran `guard.protect(..., mode="blocking")` and now prints that too).
- Node relay: `--target` is never echoed raw, even on the shape-check refusal; the relay binds `127.0.0.1`.

**Guard round (one, by ruling): no block, six warnings, all taken.** The verifiers no longer print a record kind on an
INVALID receipt (an attacker-supplied field on a rejected document); Python's `receipt --json` keeps stdout JSON-only
and both suites now assert that on a stdout-only capture; an unreadable store directory is corruption, not "no
revisions", and an unlistable store makes the worker say so once instead of idling silently; the lint reaches
directory listings and multi-form excepts and refuses a `lint-allow` without a reason; the three-door gate carries a
correctly signed DENIAL fixture and all three doors print `kind: denial` (69/69); the claims scan walks the adapters too.

**Not reproduced:** the reviewer saw the no-answer stop exit 1 in PowerShell; under ConPTY on Windows and under a pty
on Linux both CLIs exit 3, and the gates now assert that code from the help's own table on both platforms.

**Unchanged by ruling:** adapters stay Beta (no real-engine suites yet); provenance and repository metadata stay
post-1.0.

## 0.4.1 — "no" means no

Two first-run defects found by an outside engineer within sixteen minutes of installing 0.4.0. Both were
in the CLI's own tour and cleanup, not in the SDK's gate, ledger or verifier; both are fixed in both
languages, and the two blind spots that let them ship are now test axes.

- **The tour's approval prompt is a question.** "Press Enter to approve" accepted ANY completed line —
  the literal `no` included — as approval, because the answer was never read. Now `y` approves, `n`
  REJECTS (the tour rehearses the rejection half: the request is refused, your function does not run, and
  the tour says so), and anything else asks again; three non-answers stop the tour with the decision still
  pending (exit 3) rather than guess. The rule is one pure function, `approval_answer`, driven by a shared
  corpus (`packages/conformance/vectors/consent-answers.json`) in both languages, and the interactive
  branch itself is exercised under a real terminal on the Linux gate. The automated `--auto-approve-demo`
  path is unchanged and still labeled as automated authority.
- **A lost `.env` no longer loses the token.** 0.3.5's recovery journal retired a token id the moment its
  credential file was written, so moving or deleting `.env` afterwards left `quickstart cleanup` saying the
  journal owed nothing over a live seven-day token. Only a revocation retires a journal entry now. Cleanup
  revokes tour tokens from the journal even when the credential file is gone, and still revokes a token
  whose credential file never landed (the double fault the journal was built for). It never revokes an
  `init` token that DID land: one a credential file here holds is named and left alone; one that was written
  to a file no longer found here is named with the `tokens revoke` command (it may simply live elsewhere);
  `doctor` shows a held token as live-and-held. **Upgrading from 0.3.5/0.4.0:** rows those versions retired as `persisted` count as
  outstanding again. A tour you already cleaned up will show in `doctor` until you run
  `python -m decidio quickstart cleanup` once, which reports the token as already revoked and retires the row.
- **Truth and disclosure.** The failure text after a refused registration no longer claims nothing was
  written (the `.gitignore` entries were); the preflight discloses the five-minute wait for your answer and
  that receipts are shareable but carry business metadata; cleanup names the retained journal; the
  worker's "prints once" is "once per worker process"; the tour tells you to unset `DECIDIO_SESSION_TOKEN`
  before launching agent code from the same shell.
- **the `dev` relay exists only in the Node CLI;** its wire-rule fix is in `@decidio/sdk` 0.4.1.
- **A race loser says so** (prodsec retest of 0.4.0, V040-01). A resume signal that finds the pre-invocation
  claim held by another live attempt, or loses the invocation-boundary race to one, answers the new additive
  status `lost_race` (it did nothing; the winner reports). It used to read `unknown` — the word for "not
  ours" — and `no_handler` although the handler was registered. A boundary loss to a DENIAL is final and
  answers `already_resolved` with the denial named; a store fault at the boundary answers `lost_race` with
  "nothing ran … a later signal may retry". A signal that arrives after the entry was consumed now consults
  the ledger: already ran or denied → `already_resolved`; in flight → `indeterminate`; a claim held by another
  attempt → `lost_race`; only a decision with no record at all is `unknown`. Exhaustive switches over the
  status union gain one case.
- The prodsec retest's adapter-declaration and provenance items (V040-02/03/04) concern the npm package's
  types and manifest; nothing changes here. Adapters stay Beta.
- Deliberately not changed, recorded in the backlog for a product decision: per-subcommand `--help`, the
  tour showing the exact call it makes (`withApproval` in blocking mode rather than the `guard.protect`
  line it prints as the takeaway), dot-stripping in receipt filenames, and a shared no-overwrite receipt
  writer for the tour.

## 0.4.0 — the scope statement

- **README: "What 0.4 does not yet claim" and "Compatibility and support."** The stability promise is
  stated: what is stable, what is Beta (the engine adapters), what is deprecated and kept until 1.0
  (`protect_best_effort`, `gate_interruptions`), and the five things reviewers keep finding that only
  product decisions close (trust-on-first-use issuer DID, the unshipped schema, the unshipped
  conformance suites, provenance and the repository link). 1.0.0 follows user-acceptance testing.
- **The tour fails closed on an unpinned check.** If the API omits the issuer DID, the tour now fails
  and cleans up instead of reporting success on an unpinned verification.
- **The tour's preflight names everything it writes**, including `.decidio-token-journal` and
  `.decidio-pending/`.
- **`--` ends option parsing on all three verifier doors**, so a receipt saved under a dash-leading
  name can be verified.
- **The token recovery journal treats corruption as uncertainty, never absence** (prodsec retest of
  0.3.5). Every row is parsed and schema-checked before any mint; a row that cannot be trusted refuses
  `init` and `quickstart`, turns `doctor` red and makes `quickstart cleanup` exit non-zero - the bytes are
  left as found. Appends are framed (a delimiter first if the previous row lost its newline, a schema
  version, a write loop before the fsync), so a torn row stays discoverable.
- **A resume signal that finds the decision `invoking` answers `indeterminate`**, not `already_resolved`
  with "already ran": the action may still be running, may have crashed before any effect, or may have
  finished without reporting. `already_resolved` is reserved for the final states.
- **Temporal (Beta): async `authorize_fn`/`confirm_fn` callbacks are awaited**, and the default confirm
  activity returns what Decidio recorded instead of `{}`. An async confirm used to be never awaited - the
  action ran and the confirmation body never executed.
- **Transport: every refusal redacts URL userinfo**, including the opaque `scheme:user:secret@` spelling,
  and Unicode space and format characters (NBSP, ideographic space, zero-width space, …) are refused in
  both runtimes from one explicit list. Four cases joined the shared transport corpus.
- **This file ships** in the sdist, as a deliberate publish-boundary line.

## 0.3.5 — the retest residuals

- **Transport:** any control character or whitespace anywhere in the URL is refused before anything is
  sent; refusals echo a redacted spelling (URL userinfo is a credential).
- **Credential lifecycle:** the quickstart inspects a previous `.env.quickstart` before minting; secret
  files are written temp + fsync + replace; **the token recovery journal** (`.decidio-token-journal`,
  owner-only, append-only) records every minted token id before the credential file exists and retires
  it on a durable write or any proven revoke. Credential creation fails closed if the journal cannot be
  written. `quickstart cleanup` sweeps it; `doctor` lists outstanding entries.
- **Verifiers (all three doors):** the `verificationMethod` must be the issuer's exact `did:key` method
  identifier, and `created` must be a real calendar date-time; the patterns use `\Z` and `re.ASCII` so
  this door agrees with the TypeScript doors byte for byte.
- **Outcomes:** a resume signal that lost the race to a final answer is `already_resolved`; a parked row
  whose payload is gone is `orphaned_state`.
- Upgrade: no action. Custom stores are unaffected.

## 0.3.4 — first-run consistency

- Tour and README pointers, routing-by-default vs the universal-backstop block named as two states,
  cleanup discloses the durable store, help never loads `.env` (and only when usage will actually
  print), adapter headers current.
- Upgrade: no action.

## 0.3.2 / 0.3.3 — the transition itself is atomic (COORDINATED UPGRADE)

- **The shipped file store is an append-only revision chain** (`<key>.rev.<N>`), published with a hard
  link that refuses an existing name: exactly one writer wins each transition. This closed the
  pre-0.3.2 race in which a denial could be written and returned and the denied action still run.
- **Upgrade — read this if a directory is shared by more than one worker:** the first 0.3.2+ store
  migrates the older marker layout one way. **Stop every older worker that shares the directory before
  the first 0.3.2+ process starts**, then upgrade them together. Nothing deletes a revision; each
  decision keeps a handful of small files (see the README's sizing envelope).
- 0.3.3: one snapshot of `describe()`'s answer (a non-dict Mapping is refused); the shared id grammar
  at every exported resume door; a compensating revoke when a minted token's credential file fails to
  write; `reconfirm()` on a reported decision tells the truth about confirmation.

## 0.3.1

- The verifier says what it proves; proof options are part of the claim on every door; duplicate
  `--issuer` flags are refused everywhere; orphaned token ids survive every replacement.

## 0.3.0

- `report_recorded` and `execution_confirmed` are distinct, honest booleans. A denial is final on every
  path. The decision-id grammar is defined server-side and mirrored here.
- Upgrade for custom stores: `mark_discarded` is required (a hard construction failure without it).

## 0.2.x

- The execution state machine, `reconcile()`, `ExecutionContext` with a stable idempotency key, and
  the composite return with `protect_best_effort` keeping the old shape.
