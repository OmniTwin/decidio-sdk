# Changelog — @decidio/sdk

Release notes for the client SDK. The Python package `decidio` ships under the same version; the core -
the gate, signing, receipts and the verifier - is conformance-locked between the two, while the command line's
first-run surfaces (the fork, `--demo`, the code sign-in) are TypeScript-first and named as such in the parity
allowlist. Each entry names what changed, what a reader must do on upgrade, and what proved it.

## Unreleased

## 0.20.0 - published with provenance, and the hook guards Monitor and MCP calls (2026-11-17)

- **Published from a public repository, with provenance** (Lane S; founder F-1117-6 (a), F-1117-S3 (a)).
  - From this release, `@decidio/sdk`, `@decidio/verify` and `decidio` are built and published by
    [`OmniTwin/decidio-sdk`](https://github.com/OmniTwin/decidio-sdk) through npm trusted publishing. Each version carries a
    provenance statement naming the commit and workflow run that built it, and `npm audit signatures` checks it.
  - The Python package carries PyPI attestations.
  - **Upgrade:** none. The package's code and contents are unchanged by this.
- **Release order (as 0.19.0, founder F-1117-S5 (b)):** `enable_guard` (`apps/api/src/mcp/guard.ts` `GUARD_SDK_VERSION`) and the
  `decidio-approvals` plugin (0.15.0) pin 0.20.0.
  - The hooks fail closed, so tag `sdk-v0.20.0` right after the merge and approve the public repository's run: until npm serves
    0.20.0, a hook set from `enable_guard` blocks Bash.
  - The production API is released only after npm serves it.
  - `enable_guard`'s hook set is now the plugin's exact set (25 handlers): the shell trio with Monitor, the MCP groups, and the MCP
    notice.
  - The lockdown apply fence stays on until the founder's T3.
- **The hook reads inside task runners** (Lane L, cycle l-matching-runners; GH-10; founder F-1116-LL18 (b); a speed bump, never a
  guarantee). `make`, `just` and `npm`/`pnpm`/`yarn`/`bun` scripts (pre/post scripts, the install lifecycle, the common workspace
  selectors, arguments after the script name) are read up to three files deep, and each line is checked by the same rules as a typed
  command: a force push in a `predeploy` script, or `make deploy`, now asks. **Changed:** a delete of plain build output inside the
  project (`dist`, `build`, `node_modules` and the like) in a script the hook follows no longer asks - `npm run build` with
  `rm -rf dist && tsc` asked before and is quiet now; typing `rm -rf dist` still asks. It is quiet only in a script that doesn't
  change folder or run other code first: a recipe that does `cd web && rm -rf dist`, or a typed `cd web && npm run build`, asks (use
  `npm run build -w web`).
- **`github lockdown`: lock a deploy down for you** (Lane L, cycle l-lockdown-fix; founder F-1115-22 (a), F-1117-LL6 (a)). Run by the
  workspace owner in the bound repository's checkout, it signs in through GitHub's own CLI (`gh auth login --web`; Decidio never
  sees the token), reads Decidio's lock-down check, and plans the three settings - the Actions policy on the deploy workflow,
  production's branches with the admins-only rollback rule, and a "reviewed changes" ruleset that nobody bypasses (or none, with
  `--without-review-rule`) with CODEOWNERS lines written to the checkout. It applies only on a yes (`--yes --plan <id>` from a dry
  run), then reports to Decidio what GitHub shows. **Release condition:** applying needs `DECIDIO_GITHUB_LOCKDOWN_APPLY=1` until it has
  been run on a real repository (the founder's T3); the fence comes off in one line after it. **Release order:** deploy the API first
  (`GET /api/github/status` gains the app's id).

- **The coding-agent hook trusts only Decidio's signed answers** (Lane L, cycle l-signed-gate; founder F-1115-18 (c), F-1115-19;
  GH-1, GH-12, GH-14). A policy's yes, a person's approval and a pause let a command through only when Decidio signed that answer
  for this request, this Claude Code session and this run (a fresh challenge each run), checked against the issuer built into this
  SDK for the host it asks - never one the `.env`, settings or the server names. A host with no built-in issuer (a stand-in on
  this computer, a look-alike, localhost) is refused before anything is asked. A person's approval is claimed - spent - before the
  `allow`, so the same approval can't run twice. **Upgrade:** none for hosted Decidio, once its API has deployed this cycle (release
  order: deploy the API, then tag the SDK; an SDK released first refuses every gated command until the API has it). A self-hosted
  Decidio is refused by the hook until the lock pins its issuer (`l-lock`).

## 0.19.0 - Decidio's production by default, and its receipts trusted (2026-11-10)

- **Release order (as 0.18.0, founder F-1110-2):** `enable_guard` (`apps/api/src/mcp/guard.ts` `GUARD_SDK_VERSION`) and the
  `decidio-approvals` plugin (0.14.0) pin 0.19.0. The hooks fail closed, so tag `sdk-v0.19.0` right after the merge: until npm
  serves 0.19.0, a hook set from `enable_guard` blocks Bash. The release checks both built-in DIDs live (staging and production).
- **Decidio by default** (launch plan L9, founder F-1106-C2 (a)): with no `DECIDIO_API_URL`, every network command talks to
  `https://mcp.decidioai.com`, which is production after the cutover window (it was the lab, `decidio-api.onrender.com`).
  The invite-only lab is `https://mcp-staging.decidioai.com`. A sign-in's "invite-only lab ... request access" hint shows only
  against the lab; elsewhere it says the address needs an account and where to sign up. `quickstart --demo`'s relay stays on the lab.
  - **The hosted tour stays on the lab** (founder F-1106-C4 (a)): `quickstart` with no `DECIDIO_API_URL` - its first-run
    questions, the tour and `quickstart cleanup` - runs on the lab, so its synthetic agent and permanent sealed record never
    land in a production workspace; no lab invite: `quickstart --demo`. With `DECIDIO_API_URL` set, the tour is that
    workspace's, and its target line says it adds one agent and one permanent sealed record. The bare command's menu names
    the tour as the lab's.
  - **`api.decidioai.com` is production too** (after the window): its links go to `app.decidioai.com`, and the Claude Code cloud
    grant check finds production's key there (it is production's `alsoAt` in the built-in issuers, beside `mcp.decidioai.com`).
  - **Release condition:** publish only AFTER the cutover window (docs/Deployment_Runbook.md B), and with production's
    built-in issuer (cycle c-verifier-prod): before the window this default is staging under production's name, and a `.env`
    written then would move to production at the window.
  - **Upgrade:** a `.env` written by `init` keeps its own `DECIDIO_API_URL`, so existing agents are unaffected. Testers on the
    lab set `DECIDIO_API_URL=https://mcp-staging.decidioai.com` for new commands.
  - **Proved by:** cli-smoke and cli_smoke.py (the lab's origins, exact, and look-alikes refused, twins).

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

## 0.18.0 - the command line's sign-ins, the connector's new tool names, and the two plugins

- **Every sign-in the command line completes says it is the command line's** (cycle ai-cli-fence; founder F-1109-25 (a)). The
  password, link and code sign-ins send `client: "cli"`, and so does the `curl` line printed for `POST /demo/login-consume`.
  - **What it changes:** Decidio marks the session, and any browser or phone opened from it with a hand-off. That session can't
    show AI assistants more, and it can't confirm a name as anything but a person. Both are done on the web or on the phone.
  - An API that predates the fence ignores the field.
- **The CLI names the connector's current tools** (cycles connector-discovery, lookup-restructure and amounts-and-lookup).
  - `hook session`'s context lines name `get_company_context`.
  - `context pull`'s pack skills, and `--chatgpt`'s blocks, say to call `get_company_context` with the pack's slug as `pack`.
  - `context always` and the help text follow, and `github init`'s AGENTS.md section names `check_plan_against_company_rules`.
  - The names 0.17.0 wrote (`get_my_context`, `get_context_pack`, `check_plan`) are retired: Decidio no longer serves them.
- **`connect` knows the two plugins** (cycle plugins; founder F-1109-13 (a′)). The marketplace `decidio` now holds `decidio` (the
  connector and its skill, no hooks) and `decidio-approvals` (the approval hooks, which install `decidio` with them).
  - As before, it finds `decidio-approvals` by name and writes no second set of hooks.
  - When `decidio` isn't on, it prints the one command that adds it from `OmniTwin/decidio-plugins`. It never installs it.
  - It reads `claude --version`, and below Claude Code 2.1.295 it warns that a hook that can't answer lets the command run.
- **The plugin `decidio-approvals` 0.13.0** pins `@decidio/sdk@0.18.0`. Its hooks run in exec form,
  `node ${CLAUDE_PLUGIN_ROOT}/hooks/decidio-hook.mjs <event>`, with the same matchers, filters, timeouts and `onFailure: "block"`.
  The release copies the marketplace to the public `OmniTwin/decidio-plugins` (publish.yml's `plugins` job).
- **Upgrade:**
  - Run `npx @decidio/sdk@0.18.0 connect` again. It moves the hooks' pin, so the session start stops naming `get_my_context`.
  - Run `npx @decidio/sdk@0.18.0 context pull` again: the pack skills an earlier pull wrote name `get_context_pack`.
  - Run `npx @decidio/sdk@0.18.0 github init` again in a repository it set up: the AGENTS.md section it wrote names `check_plan`.
    It rewrites only its own marked section.
  - From the API deploy that carries this release, `enable_guard` hands out `@decidio/sdk@0.18.0`, and the hooks fail closed:
    until npm serves 0.18.0, a hook set from `enable_guard` blocks every Bash call. Either publish 0.18.0 before that deploy (the
    API side of everything above is already live), or tag right after the merge and accept a window of one publish run (about
    ten minutes for 0.17.0).
  - The `plugins` job copies the marketplace to `OmniTwin/decidio-plugins` once npm serves 0.18.0 (with `PLUGINS_REPO_TOKEN`).
- **Proved by:**
  - cli-smoke: `client: "cli"` on the code sign-in and in the taught `curl`; the pack skill and `--chatgpt` block naming
    `get_company_context`; connect's plugin offer, its dependency and its version warning; the plugin's exec-form hooks equal to
    `hook install`'s; the launcher, with a decoy `npx` in the project;
  - the Python twin's `cli_smoke.py`;
  - the manifests check (7 files, the plugin's 3 pins, the marketplace's two plugins), parity, and `connect.smoke` (`enable_guard`'s
    pin equals the SDK's version).

## 0.17.0 - Claude starts the session knowing your context

- **`hook session` hands Claude your context** (cycle claude-delivery): at each session start (startup, resume, clear,
  compact) it reads `GET /api/my-context` with your own stored sign-in, in the same 1.5 seconds as your team's rules. Claude
  gets the guard sentence, then Decidio's opening, your organisation and units, your packs as pointers and the always-on
  decisions, exactly as Decidio sent them. It never uses the computer's agent token or `DECIDIO_SESSION_TOKEN`.
  - Past 9,000 characters (Claude Code's cap is 10,000) it sends the context without the always-on decisions and a line to
    call `get_my_context`; past that again, the line alone. Nothing is cut.
  - Not signed in, refused, unreachable or slow: the guard sentence alone, as in 0.16.
- **The SessionStart matcher is `startup|resume|clear|compact`** in `hook install`, `hook managed-settings`, the plugin's
  hooks.json and `enable_guard`'s set. Installing over a 0.16 settings file replaces Decidio's old handler; it doesn't add a
  second.
- **`context pull` writes pointers:** each pack is a skill whose body says to call `get_context_pack` with its slug, with no
  rows and no record ids (`--chatgpt` the same). An always-pack is no file. Pull removes the always-pack rules files an
  earlier pull wrote (only its own, never one git tracks; your own `decidio-*` files stay), even when no packs are served.
- **`context always`** says who may switch a pack on: the organisation's at most two (the workspace owner's) and your own
  at most two. A unit's pack can't be one.
- **Upgrade:** cut the tag `sdk-v0.17.0` right after the API with cycle claude-delivery deploys, BEFORE anyone updates the
  plugin to 0.11.0 or runs `enable_guard`: the hooks fail closed, and a pin npm can't resolve yet blocks every Bash call. An
  older API answers `/api/my-context` with 404, and the hook sends the guard sentence alone.
- **Proved by:** cli-smoke (the stub `/api/my-context`; signed in and every way of not being; 401/500/not-the-context/slow;
  each cap tier with the largest context the server can send; the tier-2 body without a version; the pointer pull; the rules
  sweep with and without packs; the 0.16 settings upgrade; `DECIDIO_SESSION_TOKEN` alone fetching nothing), the manifests
  and parity checks.

## 0.16.0 - commands people can find

- **`decidio help`** (connect-once slice 6d; also a bare `decidio`, `decidio ?`, `--help`, `-h`, `commands`) answers with every command,
  each kind you can pause in plain words, and your team's own rules by name. It is local: no network.
- **`decidio status`** asks Decidio what's paused in this session, each kind with its time left. It also names who approves and how
  many team rules ask, plus the SDK version (the workspace's name stays on the session line). Unreachable: it says nothing changed. Not connected, or a cloud session
  with only the connector: it says what this computer knows.
- **A few other words get an answer instead of a guess.** `decidio stop`, `decidio off`, `decidio on`, `decidio state`, a kind
  (`decidio git`), or a command with a `?` or dashes (`decidio pause?`, `decidio --start`) answer with what to type, and nothing
  changes. Any other word, such as `decidio doctor`, `decidio pending` or "decidio is great", reaches Claude untouched.
- The session line names `decidio help`. `hook rules` shows each category's pause word (`pause: deletes`; Decidio's own check:
  `never paused`).
- **Upgrade:** `@decidio/sdk@0.16.0` in the hooks. `decidio status` needs the Decidio API with slice 6d; an older API answers it
  with "Decidio couldn't say what's paused ... nothing changed".
- **Proved by:** cli-smoke:
  - help and its spellings, with no request to Decidio and team rule words never in it;
  - status nothing paused, paused by kind, unreachable, kept on and back, not connected, and cloud;
  - the closed word list and a pass-through set;
  - the session lines and the `hook rules` pause words;
  - no hint word is an `npx decidio` subcommand.

## 0.15.0 - your team's own rules from the web

- **The workspace's own rules reach every connected computer** (connect-once slice 6c): the owner adds them on Decidio's Coding Agents
  page; at each session start (`hook session`, with a credential) the hook fetches them - at most 1.5 seconds - and keeps a copy beside
  `DECIDIO_HOOK_EXTRA_RULES`. Matching stays on the computer. Unreachable: the last copy; no copy: the built-in list. A copy that doesn't
  parse is dropped (the built-in list stands) and a pattern that doesn't compile is skipped. `decidio pause <rule name>` knows them.
- The session line says when your team's own rules ask too - and when Decidio refused to give them (no copy here yet).
- **A team pattern has 100 ms per check:** one that runs out counts as a match, so the command asks instead of waiting minutes (a
  pattern like `(.|\s)*prod` backtracks without end on a long command). A team's words print without control characters.
- **The hook's lines no longer send members to the workspace owner** (connect-once 6a part 2: a member connects and answers for their
  own computer): the link's person allows it, "Yes, it's mine" is its person's, and "Should another person approve this?" is answered on
  the Coding Agents page (`/connect/agents/coding`) by the owner's rule or the computer's own person.
- **Upgrade:** `@decidio/sdk@0.15.0` in the hooks; needs the Decidio API with slice 6c (an older API answers 404 - the last copy stands).
- **Proved by:** cli-smoke (the fetch writes the copy, a matching command asks, a malformed copy or pattern is dropped, an unreachable
  fetch keeps the last copy, a slow pattern asks within its budget, a refused fetch is said).

## 0.14.0 - pause by kind

- **`decidio pause git`** (connect-once slice 6b; founder: "decidio pause --xyz, where decidio pause by itself means --all"): pause
  one kind of command for this session - `deletes`, `git`, `sql`, `infra`, `docker`, `publish`, `curl`, `system`, or a team's own rule
  by its name; several at once (`decidio pause git deletes`, `--git`). Plain `decidio pause` is everything, as before. Each kind's
  pause lasts 12 hours on its own clock; `decidio start` ends them all and says what it ended. A word that isn't a kind pauses nothing.
- A command runs paused only when EVERY kind it touches is paused: `rm -rf dist && npm publish` under `decidio pause deletes` still
  asks (the line two shells deep and the files it runs are all read).
- Through the connector (a cloud session), a pause by kind is a new signed form that an SDK before 0.14 refuses - it stays on rather
  than read it as a pause of everything. A pause of everything is unchanged, word for word.
- **Upgrade:** `@decidio/sdk@0.14.0` in the hooks. Needs the Decidio API with slice 6b (an older API refuses a pause by kind: the guard
  stays on).
- **Proved by:** cli-smoke (the kinds parsed, refused words, the multi-kind line, the two local pause files, the v2 form and its
  tamper checks), connect.smoke (the routes' kinds, clocks and coverage; the v2 bytes held equal).

## 0.13.5 - "decidio pause" and "decidio start" read as done

- **The person's own typed "decidio pause" / "decidio start" now reaches Claude with the one line to say** (connect-once slice 5g),
  instead of a `decision: "block"`. The Claude Code web app drew every block as "A hook blocked your prompt", so a resume that had
  worked read as a failure.
- A prompt marked as not the person's (an assistant-scheduled one) is still blocked. Where Claude Code doesn't send `source` (today's
  build leaves it out), a resume works - it only turns the guard on - and a pause says it isn't available here. "Start" also ends a
  pause the connector stored on this machine. The pause itself still happens in the hook (or
  through the connector's guard_pause in a cloud session), and an agent's own pause or resume is still refused at PreToolUse.
- **Upgrade:** nothing to do - `@decidio/sdk@0.13.5` in the hooks.
- **Proved by:** cli-smoke (pause, resume, already-on, the organisation's lock and a cloud resume relay their line; a scheduled prompt
  is still blocked).

## 0.13.4 - a grant that can't be misread; the code sent once

- **The grant's use can't be misread** (connect-once slice 5f): a cloud refusal said to run the command again "with
  DECIDIO_GRANT=<the grant> and one space in front of it", which reads as a space *before* the grant - and the hook took a grant only
  as the command's first characters, so it refused ("isn't a Decidio approval"). The refusal now says ``DECIDIO_GRANT=<the grant>
  <the same command>`` - "DECIDIO_GRANT first, with nothing in front of it" - and the hook also takes leading spaces or a tab before
  it. The grant still covers only the exact command after it, in that session.
- **The request code on a line of its own**, copied exactly; while guard_request answers PENDING, Claude polls with the decisionId
  it gave, not the code (the server holds the decoded request in memory for the code's lifetime).
- **"decidio check" is numbered, with the literal commands** (make the folder, `rm -rf .decidio-check`, then
  ``DECIDIO_GRANT=<grant> rm -rf .decidio-check``); the API's enable_guard hands Claude the same steps.
- **Upgrade:** nothing to do - `@decidio/sdk@0.13.4` in the hooks; a 0.13.3 hook keeps working with the API (its codes decode the
  same; its refusal keeps the old wording).
- **Proved by:** cli-smoke (leading spaces and a tab before the grant run their command once, never another; the refusal's code line
  and words), connect.smoke (the steps and the grant wording held equal with the API), twin parity (hook-only, allowlisted).

## 0.13.3 - where on every card; the enablement record

- **A cloud session's request names where** (connect-once slice 5e): the request code carries the repository (origin's owner/name -
  a local git proxy's path too), the branch and the commit beside the command, outside the part the grant is bound to (HEAD may move
  between the ask and the retry). The approver's card shows "owner/repo · branch · commit". A server before 0.13.3's refuses a code
  with it, so 0.13.3 is published before the server that names it.
- **"decidio check" ends with one line** (guard_request's `say`), and the session-start note tells Claude to mention Decidio only when
  it stops a command or the person asks. Upgrade: say "enable decidio" again, or edit the pins. Proved by cli-smoke and connect.smoke.

## 0.13.2 — the words for a blocked connector tool

- **A Claude Code cloud session names the claude.ai setting to change** (connect-once slice 5d). When the hook refuses a destructive
  command with a request code and the Decidio connector isn't available, the words now say: add the connector in claude.ai
  (Settings → Connectors), and if its "Ask a person to approve a command Decidio's hook refused" tool is blocked there, set it to
  Always allow or Needs approval. There is no box to tick any more - every Decidio connection can ask from sign-in, and connections
  made before keep working without reconnecting (a server change). "decidio check" says the same when `guard_request` is blocked.
  Upgrade: say "enable decidio" again, or edit the pins. Proved by cli-smoke (the cloud-session words) and connect.smoke (the check's
  words equal the server's).

## 0.13.1 — a cloud session asks through the connector; "decidio check"

- **A Claude Code cloud session asks through the Decidio connector, whether or not it can reach Decidio** (connect-once slice 5c).
  With Decidio's committed line (keyed with the workspace's guard key) and no credential, the hook refuses a destructive shell command
  with a request code for the connector's `guard_request` - it no longer starts connecting the cloud machine (no link and code), and
  never lets a command through after one notice there. A change that switches Decidio's check off, or a file tool's edit of the
  settings, is refused plainly (a grant never carries it). Without the connector, the words say to add it and tick the box that lets
  it create approval requests - not to change the session's network. A cloud session already connected, terminals, and lines with no
  workspace key are unchanged. Upgrade: say "enable decidio" again (it replaces the 0.13.0 lines), or edit the pins.
- **"decidio check"** - the prompt hook hands Claude a check that shows the guard working: a `.decidio-check` folder whose
  `rm -rf` Decidio stops, approved through the connector (or, on a computer that isn't connected, its link), and two facts said in
  plain words: Decidio stopped it, and the approval came back. Not blocked; needs no credential.
- Proved by: cli-smoke (a cloud session that CAN reach Decidio, the team answering "don't hold": refused with a request code every
  try, no `/connect/` call, no pending link - red against 0.13.0, which connected, told and let through; the off switch refused
  plainly; a terminal unchanged; "decidio check" as context, unblocked).

## 0.13.0 — Claude Code on the web through the Decidio connector

- **The tour's cleanup removes its own agent** (launch plan L4, Remove agent; both languages). `quickstart cleanup` now asks the
  server to remove the tour's `quickstart-` agent: its new requests stop and its name stays taken; the records it made stay. A
  removal the server refuses is a non-zero exit naming the Agents page; a Decidio with no remove door (an older server) leaves the
  agent registered, says so, and exits 0. Only the tour's own agent, never a developer's.
- **`npx @decidio/sdk disconnect --new-key`** forgets this machine's key as well as its token, so connecting again makes a new
  key and a new agent - what Decidio asks for when this machine's agent was removed (removal is final, and so is the key it held).
- **A 402 in its own words.** A refusal for the workspace's plan says so, quotes the server's sentence (which names what clears it
  and who can) and says it isn't a sign-in problem - from `init`, the tour's registration and `DecidioHttpError` (not retryable).
  It used to print the raw body, and the tour said "check the target and your sign-in".
- **This hour's allowance by kind.** `tokens list` says the server's two hourly limits on agent requests - those that need a person
  and those the rules decide (launch plan L4, agent limits by kind) - in both languages; against an older server it prints the one
  allowance, as before. Upgrade: nothing to do.
- **A removed agent, said as such.** `init` of a removed agent's name stops with the server's words and a new name (nothing
  written - never the reuse path), and `DecidioHttpError` on a 409 `AGENT_REMOVED` says the agent was removed and to register a new
  one. Upgrade: nothing to do.
- **The hook asks through the connector when it can't reach Decidio** (connect-once slice 5). In a session with no credential
  whose start gets no answer (a Claude Code cloud session's default network; any failure but "connect is off" in a cloud session),
  a committed line carrying the workspace's guard key (`--unconnected=tell --policy=<key>`) refuses a destructive command with a
  request code - base64url canonical JSON of the committed request (plus `f`, the full binding keyed by the session id), the
  session's key (sha256 of a domain tag and the session id - the id never leaves), the workspace key, a nonce and a 15-minute
  expiry - and tells Claude to hand it to the Decidio connector's `guard_request`.
- **`DECIDIO_GRANT=<grant> <command>`**: a grant Decidio signed with its issuer key for that exact committed request, session and
  workspace key, at most 10 minutes ahead, is checked with no network against `@decidio/verify`'s `KNOWN_ISSUERS` (never a key
  from the environment) and allows that one run (a local spent list, a day). A grant that doesn't verify is refused, and the
  command without it asks again.
- **`DECIDIO_PAUSE=<token> true`**: a pause Decidio signed for this session (the connector's `guard_pause`) is checked and kept
  for the session; destructive commands then run with a line to the person, never a change that switches Decidio's check off.
- **"decidio restart" and "decidio resume"** mean "decidio start". With no credential, "start" removes the session's pause on the
  machine and "pause" reaches Claude with the connector's `guard_pause`; the session line says approvals go through the connector.
- **A terminal whose Decidio answers 429 or 5xx** keeps slice 4's words (it holds either way); only no answer at all is "no route".

On upgrade: nothing to change. The connector path needs a committed line with the workspace's key - `enable_guard` (the connector)
or `connect --team` writes one; the plugin's and managed settings' lines carry no key, so they keep today's words. The plugin pins
0.13.0 (plugin 0.7.0). Proved by: cli-smoke.ts (427 → 440).

## 0.12.0 — request keys by default; an approval is collected once; the owner's guard controls

- **A request key by default** (founder 11f). Every authorize that carries a request commitment now carries an
  `idempotencyKey` too: a keyed digest of a fresh id for the call and the commitment. The SDK retries the authorize twice
  (after 0.3 s and 1 s) with the same request when the network fails, on a 5xx, or on a 429 that is not the workspace's
  hourly limit - so a retry never runs an action twice, and a retry of a request still waiting is answered with the one
  already waiting. A 4xx is never retried. A retry signs a fresh
  identity proof (its nonce is single-use); nothing else changes. No key material: no commitment and no key, as before.
  - `withApproval(..., { requestKey: (...args) => string })` / `protect(..., { requestKey })` uses your own key (an order
    id) instead, keyed before it is sent. The same key for a changed request is refused (409 IDEMPOTENCY_CONFLICT).
  - The result names the key it sent: `ProtectedExecution.requestKey`. `ExecutionContext.idempotencyKey` stays the
    decision id - keep using it downstream.
  - The engines key on their own ids: OpenAI on the tool call id; Temporal on the activity's workflow, run and activity
    ids (`authorizeActivity`, new); Inngest on `runId` (new argument of `decidioGateStep`).
- **An approval is collected once** (founder call 24 "(a)"). Before the SDK runs an action on a person's approval it
  claims it (`POST /agent/claim/<decisionId>`, `claimApproval`) with a key random to that run, and runs only if Decidio
  says this run collected it. Otherwise it raises `DecidioBlockedError` in plain words, e.g. "This approval was already
  used by another run. Ask again for a new approval." This covers the blocking wait, the durable resume, Temporal and the
  OpenAI verified resume. A durable action keeps its claim key with it (`PendingAction.claimKey`), so a restarted worker
  claims with the same key and is answered as the same run; a claim refused as used or expired is recorded like a block
  (`status: "blocked"` with the reason). Auto-approvals are never claimed, and reading the status never claims.
- **A shared request is left open.** The blocking timeout no longer withdraws a request the authorize answered as
  `idempotentReplay` or `openTwin`, and a 409 `SHARED_REQUEST` from the withdraw is reported, not thrown:
  `DecidioTimeoutError.shared` is true and `withdrawn` false.
- The messages that said "a retry creates a NEW request" now say the SDK already retried with the same request.

On upgrade: the gate must have `POST /agent/claim` (the server's claim-once release). Against an older gate the claim
answers 404 and nothing runs on a person's approval - durable entries stay parked until the gate is upgraded. Temporal:
pass `claim: (decisionId, claimKey) => executeActivity(claimActivity, decisionId, claimKey)` (the activity returns
`claimApprovalActivity(config, decisionId, claimKey)`) beside `verify` - an injected `authorize` without it is refused
before anything is routed - and return `authorizeActivity(config, ctx)` from the authorize activity. Entries parked by an
older SDK (or put into a store directly) still resume, but carry no claim key: they claim with a fresh random key on
every resolve, so an answer lost on the way back costs a new approval - never a second run. Proved by: smoke.ts
(256 -> 292), adapters-smoke.ts (74 -> 83), cli-smoke.ts (416 -> 418), the conformance runners (a refusal-advice vector)
and the three-door gate (the authorize bodies stay byte-identical with a pinned invocation id).

### The owner's guard controls (connect-once slice 4)

Cycle connect-once's slice 4 (founder 2026-10-30: "the owner would have controls to make the guard mandatory, disable pause").
Upgrade: nothing to do for a person; a team that wants its repositories held runs `connect --team` again and commits the file.

- **A team's committed hook line carries its guard policy key.** `connect --team` writes `--policy=<key>` into the tell line
  (Team and Enterprise). A computer that isn't connected sends the key when it starts its link, and the start answers one
  yes/no: whether the workspace owner holds computers that aren't connected. Held, a destructive command is refused until the
  computer connects, instead of being told once and let through. If Decidio can't answer (unreachable, a server error, rate
  limited), a keyed line holds; Decidio's connect switched off (404) falls back to the line's own `--unconnected`. An older
  server that refuses the key is asked again without it. Editing the key out of the line is switching the check off, so it
  is refused like any other such edit. A keyed line tells once ONLY when Decidio answered for its key that the team doesn't hold
  (or connect is switched off): a project `.env` naming an agent or another server, or a link another check is starting, holds.
- **`connect --team` says when the line carries no team key** - a connection made before 0.12.0, or credentials from the shell
  or `.env` - so the owner's hold won't reach the repository, and how to fix it (`connect --team --force`).
- **Claude Code cloud sessions**: when the hook can't reach Decidio, it says the environment's network access must allow
  Decidio's host, under Network access → Allowed domains (the default level doesn't list it), with the docs link.
- **`hook managed-settings`** prints the Decidio hooks as JSON for Claude Code's managed settings (an organisation-wide
  install), from the same set `hook install` writes - a test holds it equal to the plugin's `hooks.json`. Where the file goes,
  and what it does and doesn't guarantee, go to stderr.
- **The session line follows the owner's keep-on switch** from the next pause answer (the computer remembers it).
- Proved by: cli-smoke 418 -> 427 (the keyed line held, told, unanswerable, a `.env` or a lock in the way, connect off, the key edited
  out, the cloud network words, the keyless `--team` line, managed-settings equal to hooks.json, the remembered answer); connect.smoke and the integration suite on the server side. 


## 0.11.0 — connect once, on in every project; no surprises; the connector connects a computer

0.10.0's tag was held for this release, so 0.11.0 is the first release meant to carry `connect` (0.10.0 was then published by
mistake on 2026-10-30, from a tag on its own merge; 0.11.0 supersedes it). It carries
cycle connect-once's slice 1, 2a and 2b (founder 2026-10-29: one tag, after they merge).

- **One connect per computer.** A connection now covers every repository on the computer, and `connect` switches the hook
  on in your own `~/.claude/settings.json`, which every project reads. A repository connected the 0.10.0 way keeps its own
  connection (read first). A cloud session and `--team` still use the repository's `.claude/settings.json`.
- **The hook connects the computer itself.** A destructive command on a computer with no credential is refused with a link
  and a short code (to Claude, and in a line to the person); once the workspace owner allows it, the next try finishes
  connecting and asks for the approval in the same run. It never writes Claude Code's settings - in auto mode the assistant
  may not, and a person put the hook there. Two hooks at once share one link. It connects only the Decidio your shell
  names (or the default), never one a repository's `.env` names, and only over HTTPS; a project whose `.env` names an agent
  with no token is refused by name rather than given the computer's connection. The run that connects tells the person which
  workspace and who allowed it, even when the command then runs at once.
- **The computer-wide hook is the pinned `npx -y @decidio/sdk@0.11.0` command**, so it works in every project; a project
  install still writes `$CLAUDE_PROJECT_DIR` unescaped, so Claude Code expands it. The settings file is written whole, and
  through a symlink.
- **No surprises** (founder 2026-10-29: "the user is fully aware and not surprised"):
  - `hook session`, a SessionStart hook: every session opens with one line - approvals are on here, what waits and for whom,
    or that this computer isn't connected yet. Local only, never blocks;
  - `connect` says what waits for approval and that everything else runs as before;
  - a held command names who approves and where they see it;
  - the plugin skill says what connecting does before doing it, and has the person run `! npx @decidio/sdk connect` when
    auto mode refuses it.
- **The plugin** (0.5.0) carries the SessionStart hook, and a marketplace file ready to publish - not published (founder:
  nothing public until the listing is ready).
- **The connector connects a computer** (slice 2a):
  - `connect --ticket <ticket>` finishes the link the Decidio connector allowed (`connect_device` returns the ticket): the
    poll carries this computer's own secret and the ticket, and only the credential is written;
  - the hook names the connector's way first when a computer isn't connected (call `connect_device` with the code, run what
    it returns), then the link and code; a link the connector allowed is kept while it waits for its ticket.
- **Pause and resume** (slice 2b): `hook prompt`, a UserPromptSubmit hook that `hook install`, `connect` and the plugin add
  behind a shell pre-filter, acts on the person's own typed "decidio pause" / "decidio start" (exact words, `source: user`
  only) and keeps the words from the model. While paused a gated command runs with a line and no decision - asked of Decidio only
  in a session paused on this computer; the settings guard (now run over the whole line, inside `sh -c` too, for the pause and
  the shared file's notice alike) and the self-decide refusal stay on; an agent running `hook prompt` itself is refused. The
  session line says how to pause, or that the organisation keeps the guard on.
- **A shared file tells, then lets through** (slice 2a): `hook pretool --unconnected=tell`, which `connect` writes into a
  shared file, refuses a computer with no credential once per session and command, then lets the same call pass with a line
  to the person - never an `allow`, so Claude Code's own permission check still decides. No flag, a value it doesn't know,
  or no session id holds, as before. `connect --team --hold-everyone` writes the holding hook instead.

On upgrade: nothing to do; 0.10.0 repository connections keep working. Proved by: cli-smoke.ts (378 -> 400; slice 1: one connect for
two repositories, the 0.10.0 file read first, the hook's own link - wait - collect-then-ask without touching settings, two
hooks sharing a link, a refused link, the approver in holds, the session line, SessionStart installed; slice 2a: the
connector's way, the ticket's usage, secret and ticket on the poll, tell once then a line, hold by default, --hold-everyone).

## 0.10.0 — connect a coding assistant in one tap (not published; folded into 0.11.0)

- **`npx @decidio/sdk connect`** (cycle connect). A coding assistant sets Decidio up for you: it runs `connect`, which prints a
  link and a short code (on a real terminal also a QR, and it opens the browser); the workspace owner opens the link signed in,
  checks the code, picks who approves and taps Allow; `connect --wait` then returns by itself (exit 0 connected, 1 still
  waiting - run it again, 3 refused or expired; within 90 s, under an assistant's 2-minute command limit). The machine gets an
  ask-only credential - never a session - kept OUTSIDE the repository (the config dir, owner-only, keyed by the repository root
  and the Decidio), and the hooks switch on in `.claude/settings.local.json` (`--team`: the shared `.claude/settings.json`).
  No `.env`, nothing to paste, the word "agent" nowhere in the setup.
- **In a cloud session the hooks go in `.claude/settings.json`.** A cloud session reads the repository's files, not your
  computer's, and only the committed shared file reaches the next cloud machine, so that is where they go. connect leaves it uncommitted and says to ask
  the person before committing it (committed, every cloud session of the repository and every teammate's clone ask too). The
  credential is that cloud machine's: a fresh one refuses destructive commands until it connects again.
- **The machine proves its key.** The start is signed with the machine's own key (the request-bound proof every signed
  request carries, over the assistant, project, machine and cloud-or-local), so nobody can file a connect in another
  machine's name; the server refuses a start without it. The connect checks the wire first (https, or a local address),
  since the poll's answer carries the credential.
- **Credentials, in order:** the shell, then the folder's `.env`, then this repository's connection - all or nothing, so a
  project with an `init` `.env` keeps exactly that identity. `disconnect` deletes this machine's token (gated commands are then
  refused until you connect again; the machine's key stays, so reconnecting reuses its agent).
- **The hook's words** for an unconnected project now name `connect` and `connect --wait` (the plugin's skill says the same);
  `hook install` with no credentials points at `connect` first.
- **The links the command line prints follow the API's own web app** (launch plan L1c). Staging's API maps to
  `staging.decidioai.com`, production's (`mcp.decidioai.com`) to `app.decidioai.com`, and any other origin to itself.
  `DECIDIO_APP_URL` wins only as a plain `http(s)` address, and the host line names it.
  - **Release condition:** publish only after `staging.decidioai.com` serves staging's web app (docs/Deployment_Runbook.md
    A1). Tell testers to run `github init` again to refresh their AGENTS.md section.

On upgrade: nothing to change - `init` projects keep their `.env`. The plugin pins 0.10.0. `connect` needs a Decidio that
serves `/connect/*` (the lab, from cycle connect's deploy). Proved by: cli-smoke.ts (356 → 378 checks: connect, its signed
start, wait, reconnect, disconnect, refused, expired, a cloud session, --team, beside the plugin, .env precedence, the hook
through a connection).

## 0.9.0 — the coding-agent hook catches what agents type, protects itself, and tells the approver what was asked

- **Wider matching, from real agent runs.** `sql-destructive` counts a statement sent through an interpreter or runner
  (`python3 db.py "drop table x"`, `python3 -c`, `node -e`, a here-doc), checked per segment so a commit message that
  says "drop table" is not gated; options are read by name before `=` (`--force-with-lease=<ref>`); git's `-C`/`-c` are
  skipped; a command handed to a shell (`bash -c`, `sh -c`, `pwsh -Command`) is matched inside, two shells deep; a file
  the command runs is followed one level inside the project (shell scripts, SQL files, `package.json` scripts, DROP or
  TRUNCATE in a program file run directly) - the request carries the matched line as `scriptLine` and the file's sha256
  in its keyed scope, never the file.
- **`decidio-guard`.** Write, Edit and MultiEdit to `.claude/settings*.json`, `~/.claude/settings*.json` or the Decidio
  plugin's files are gated when the file after the change drops or alters a Decidio hook, sets `disableAllHooks`, turns
  the plugin off, or is not valid JSON (adding a permission or another hook is not); shell writes to those files,
  `claude plugin disable|uninstall` naming Decidio and `hook install --cli` are gated whatever they write. The request
  binds tool + path + the after-file's sha256. `hook install` writes PreToolUse and PostToolUse handlers for the three
  tools, one `if` per path (Claude Code's `if` holds one rule and is tool-specific), and keys its merge on event +
  matcher + `if`: a re-run keeps each handler once and upgrades an 0.8 install in place.
- **A policy `proceed` prints nothing** (exit 0; the state is kept, so posttool still records the execution). Claude Code
  records a hook `allow` as the hook's decision in place of its own permission check; a company rule that something
  needs no person now leaves that check in place. A person's approval of the exact call still prints `allow`.
- **Card context.** The request context gains `mode`, `repo`, `branch`, `commit` and the user's prompt (`asked`, and
  `askedBefore` when the last prompt is under 40 characters; each through the redaction, at most 1,000 characters;
  `askedLength`), read from the transcript's tail only for a gated call. `DECIDIO_HOOK_SHARE_PROMPT=0` leaves the prompt
  out. The request commitment no longer covers these (they change between the ask and the retry), so a retry after the
  user typed "continue" matches its approval instead of a 409.
- **An agent running `approvals approve|reject`** (with the person's stored sign-in, which the agent's shell inherits) is
  denied by the hook itself in its usual spellings (`npx`, `decidio`, the installed or cached `cli.js`, `python -m decidio`,
  `uvx`, inside `bash -c`, an option before the subcommand); listing, `hook wait` and `receipt` are untouched. A shell
  check is not a complete close (the Backlog names the server-side one).
- The prompt reader skips transcript entries that are not the user's words (a background task's notification, bash-mode
  input and output, a local command's output, a compaction summary); a slash command the user typed counts. The settings
  guard finds an Edit's string the way Claude Code's Edit does - verbatim, else with curly and straight quotes alike - and
  an empty `old_string` on an empty or whitespace-only file as the whole new file.
- File-tool denials say "edit" and "Nothing was written."; shell denials are unchanged.

On upgrade: re-run `npx @decidio/sdk@0.9.0 hook install` (or update the plugin once it pins 0.9.0). A gate older than
this release stores the new context keys as ordinary details. Proved by: `cli-smoke.ts` (336 → 355 checks; the gated table 42 → 89
commands, verbatim from the lab's runs; the noise table 24 → 46; the guard's effect, binding, posttool spend and install;
a mock gate that 409s a reused key with another commitment, where a retry after the prompt changed is ALLOWED; mutation
runs of each change), and 15 real Claude Code sessions against a loopback gate (every gated case stopped; a policy
approval left Claude's classifier deciding).

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
    `KNOWN_ISSUERS` (exported by `@decidio/verify`: the hosted service's issuer only — never the verification kit's
    published sample key), else refuses (exit 2) with the remedy. An explicit `--issuer` always wins, and every run
    prints its trust anchor first. An unreadable `issuers.json` refuses rather than falling back.
  - `@decidio/verify` (and `npx @decidio/verify`) with no `--issuer` pins to the built-in list; a receipt from any other
    issuer is refused (exit 2) with the remedy. `runVerify` takes an optional anchor description and prints
    `trust anchor: …` as its first line.
  On upgrade: nothing to do; scripts that pass `--issuer` behave as before (plus the anchor line on stdout). Deploy the
  API first: against a server without `expectedIssuer`, `receipt` and the tour fall back to the remembered DID and
  otherwise fail closed. Proved by: `cli-smoke.ts` (a forged receipt naming itself fails the tour and is never offered
  as the anchor; `valid:false` fails `receipt` and the tour; init/sign-in remember `/api/did`; flagless verify pins to
  it; `--issuer` wins; a changed DID is not adopted; nothing remembered → exit 2 naming the built-in anchor; an
  unreadable store refuses), `decidio-verify/smoke.ts` (the built-in list's content and refusals), the three-door
  conformance run (every door names the same built-in anchor), and a claims tombstone for the retired
  "refuses to run without --issuer" sentence.

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
  Proved by: `cli-smoke.ts` +9 (a server naming a different key than the remembered DID: warned, not followed, receipt
  exit 1, tour fails; a server naming the built-in DID over another key's credential: exit 1, never "No --issuer
  needed"; the flipped forged vector now exits 1; a variant spelling of the host is the same entry; eight origin-key
  cases shared with Python; `.env` never chooses verify's anchor; the flagless command follows verify's host; an issuer
  store with `"v": true` is refused; the update gate's switches come from the shell) - 8 of them red against the
  previous commit's code; the other three are the twins of Python-only bugs the TS CLI never had. The release workflow
  now fails if `KNOWN_ISSUERS` (TS or Python) differs from the live `https://decidio-api.onrender.com/api/did`.
- **3A follow-up, round 2 (guard re-review, 2026-09-24) — same hostile-`.env` threat model.**
  - **The session and the trust store live where the SHELL says.** `sessionDir()` (and the terminal-id read) took
    `XDG_CONFIG_HOME`/`LOCALAPPDATA`/`HOME` from the environment *after* `.env` was promoted, so a project `.env` with
    `XDG_CONFIG_HOME=.cfg` put the session token and `issuers.json` inside the repo — and let the repo plant a DID that
    then showed as "remembered on this computer". Both now read the shell snapshot.
  - **A project `.env` promotes only `DECIDIO_*`.** It configures Decidio; it does not reconfigure the OS, toolchain or
    network stack. A cloned repo's `.env` can no longer inject `HTTP(S)_PROXY`/`NO_PROXY` (which would route this CLI's
    authenticated calls, bearer token and all, through the repo's server), TLS-trust or CA-bundle variables,
    `NODE_OPTIONS`/`GIT_*` code loaders, or the session-dir variables into the environment a network command runs with.
    A switch genuinely wanted is set in the shell, which still wins.
  - **The cached update-check value is validated like the network answer** (a full `x.y.z`), and `semverNewer` requires
    exactly three all-digit components: a planted `update-check.json` with trailing bytes can no longer be printed as an
    available-version notice, escape codes and all, or used to force an upgrade.
  - **`issuerStoreKey` fails closed** on host spellings it cannot canonicalise identically to the Python twin
    (percent-encoding, IDN, numeric-shorthand IPs, backslashes): it no longer uses the browser URL's canonicalisation,
    which mapped `https://%64ecidio-api.onrender.com` onto the real host — a planted store entry under an exotic spelling
    is never trusted as the real Decidio.
  - **An `issuers.json` whose version literal is `1.0`** (a float, not the integer `1`) is refused, matching Python: JS
    cannot tell `1.0` from `1` after `JSON.parse`, so the raw token is checked.
  - **`receipt --json` reports `valid: null` when no offline check ran** (no anchor — e.g. an unreadable store): the
    server's own verdict alone is not enough to call a receipt verified, because the point is the offline pin.
  Proved by: `cli-smoke.ts` +5 (session/trust-store location; `.env` promotes only `DECIDIO_*`; the poisoned cache; the
  `1.0` version literal; `receipt --json` valid:null) plus 7 new origin-key cases, all red against the previous commit's
  code. The release workflow's live-DID gate now uses `curl --retry-all-errors` and emits an explicit `::error::` when
  the host is unreachable or the body is malformed.

### An approval is bound to the exact request it approved (#4B, BREAKING)

**Breaking.** Read "On upgrade" before bumping. The version is not bumped here; this ships as the next minor.

- **Every door confirms with Decidio that THIS request was approved before it runs it** — inline (the blocking
  wait), the durable webhook and worker, LangGraph, Temporal, Inngest and OpenAI Agents, through one check
  (`checkApproval`, exported; the adapters share `adapters/_gate.ts`). `GET /agent/status` must answer
  `approved`/`auto_approved` AND return the request commitment this SDK sent with `/agent/authorize`, recomputed
  over the request about to run. A resume webhook, a Temporal signal, an Inngest event or a LangGraph resume value
  is now only a WAKE-UP; before, each of them was the authority, so anything able to send one approved the action.
  A mismatch throws `DecidioRequestChangedError` ("the request changed after approval", naming the decision); a
  gate that returns no commitment for a request this SDK bound throws `DecidioApprovalUnverifiedError`
  (`code: "commitment_missing"`; `"unverifiable"` when there is no key material to recompute it). Both extend
  `DecidioBlockedError`, so existing `catch` blocks still see a refusal. The durable resolve reports
  `not_approved` (Decidio still says pending - the entry stays parked for the next wake-up) or
  `request_unverified` (refused, kept parked, named once). Because it now asks Decidio first, **`resolve()` THROWS
  when Decidio is unreachable** (nothing ran; the entry stays parked) - callers must catch it.
- **The commitment is keyed, never a digest** (invariant I5): lowercase-hex HMAC-SHA256 over the canonical
  request (`committedRequestJson`) under a subkey of a secret only the agent holds - the Ed25519 signing key when
  `agentKey`+`agentDid` are configured, else the API token (`bindingMaterial`, `requestCommitment`). An unkeyed
  sha256 would sit in Decidio's database as a dictionary-attackable fingerprint of the request. Byte-identical to
  the Python twin: shared vectors in `packages/conformance/vectors/canonical.json` (`commitments`), consumed by
  both runners. A keyless agent sends none and is checked on Decidio's state alone. **Prefer the Ed25519 key for
  binding**: under the API-token fallback the key is a bearer Decidio receives on every call, so the commitment is
  opaque to everyone except the Decidio server itself. **Rotation strands pending approvals**: re-minting the
  token, changing `DECIDIO_AGENT_KEY`, or a guard and resume controller with different key material turns every
  routed approval still pending into `request_changed` - drain before rotating, or ask again.
- **LangGraph: the $100 -> $1,000,000 resume bug is closed.** LangGraph re-runs an interrupted node on resume, so
  the node authorized AGAIN - minting a phantom second decision nobody saw - and then ran whatever it computed the
  second time under the first approval: approve $100, edit the graph state, resume, and $1,000,000 executed (and
  was confirmed under the phantom). Now the re-run authorizes with an idempotency key derived from its own thread +
  checkpoint namespace + call index + commitment (`idempotencyKey`), Decidio answers with the SAME decision, the
  resume value must name that decision, and the check runs. An edited state is a new task and a new request: it
  becomes a NEW pending decision and the graph pauses on it; the old approval is never applied across requests.
  `decidioResumeCommand(body)` now carries - and requires - the webhook's `decisionId`. The gate needs key material
  and a checkpointed run with a `thread_id` and the node execution's scratchpad; without them it refuses (before
  sending anything, or before pausing on a decision it could never find again, naming it - it never falls back to
  a constant call index).
- **Temporal**: `DecidioGateOpts.verify` runs the check (as your activity) after the signal and before `run()`;
  it is REQUIRED whenever `authorize` is supplied (refused before anything is routed). The activity body is
  exported: `verifyApprovalActivity(config, decisionId, ctx)`. A signal only wakes the workflow; still pending
  -> it waits for the next signal.
- **Inngest**: after each wait the check runs as a memoized step (`decidio-verify-approval`); a premature or
  forged event waits again (later waits are `decidio-await-approval-1`, `-2`, ...: deterministic across replays).
- **OpenAI Agents: `applyResume(state, item, verdict)` is REMOVED**, not deprecated. Its only input was a verdict
  string, so no deprecation shim could check anything - keeping it would keep the hole. Use
  `await applyVerifiedResume(config, state, item, decisionId, describe)`: it approves the interruption only when
  Decidio records that decision as approved for THIS tool call, rejects on a rejection, and otherwise throws with
  the RunState unmodified. The approval is bound to the call itself - its name, call id and exact argument string
  from `rawItem`, beside `describe(item)` (`toolCallRequest`) - so a parked item edited after approval (a target
  `describe()` never covered) and a second identical call whose own decision is still pending are both refused
  (`request_changed`); binding `describe(item)` alone let both through (#4B review W2). `pending[]` now carries
  each `callId`; an interruption with no call id is refused before anything is sent.
- **The resume webhook no longer falls back to the API token** (`webhookHandler`, `fetchHandler`): with no
  `webhookSecret` (and no `allowUnsigned`) it answers 401 naming the fix - a dedicated secret, **never the Decidio
  server's `API_AUTH_TOKEN`** (its admin bearer). The token is a credential the agent SENDS; accepting webhooks
  signed with it let anyone holding it drive resumes. The LOCAL integrity signature on parked payloads keeps its
  token fallback, so entries parked before the upgrade still verify.
- **Known limit (predates this release): one gated action per LangGraph node.** The node re-runs on resume, so an
  earlier gate in it runs again; one whose request auto-approved (action already run) replays as `proceed` to a
  verified agent and its action runs a second time when a later gate in the node resumes. Put each gated action
  in its own node, or make the actions idempotent.
- **Known limit (predates this release): LangGraph and OpenAI Agents have no single-execution claim.** Two
  concurrent resumes of the same thread or RunState can both pass the check and both run the action; resume each
  from one place. The core durable path claims each execution in its store.
- The demo gate (`demo-gate.ts`, the `--demo` stand-in) stores and returns commitments like the real gate.

**On upgrade:** (1) deploy the Decidio gate from this release FIRST - an older gate returns no commitment and a
keyed SDK refuses its routed approvals (`commitment_missing`: fail closed, never a silent pass). (2) Webhook
deployments: set `DECIDIO_WEBHOOK_SECRET` on both sides, or switch to `worker()`. (3) LangGraph: run with a
checkpointer + `thread_id`, and build the resume with `decidioResumeCommand(webhookBody)`. (4) Temporal: add the
`verify` activity. (5) OpenAI Agents: replace `applyResume` with `applyVerifiedResume`, park each pending
`{ callId, decisionId }` and find items again by `rawItem.callId`. (6) A test double of the gate must return
`requestCommitment` from `/agent/status`. (7) Catch errors from `resolve()`. (8) Drain pending approvals before
rotating the agent token or key. Entries parked by 0.6.x carry no commitment and are checked on Decidio's state
alone.

Proved by: `smoke.ts` (the request-binding block: approved-for-another-request, gate drops the commitment,
keyless, rejected/pending wake-ups, the durable webhook and worker), `adapters-smoke.ts` (the REAL
`@langchain/langgraph`: unedited resume = one decision; edit after approval = a new pending decision and
nothing executed; rejected; keyless refused; no scratchpad refused; Inngest forged event; Temporal verify
required; OpenAI verified resume incl. an edited target and a second identical call), `inngest-smoke.ts` (a forged
event executes nothing), both conformance runners (commitment vectors incl. the OpenAI tool-call binding built by
each SDK from its own native item, every door with a gate that returns the commitment), and `conformance/run.mjs` -
which caught the two twins committing different bytes for the same call (Python sent an empty `kwargs` member)
before this shipped.

## 0.6.4 — the request closes when the agent gives up

- **The README links the agent skill file** published on the site (https://decidioai.com/skills/decidio-guard.md, one page for both languages) and the site's llms.txt. The file is served by the site, not shipped in the package; an in-package copy is a one-line publish-boundary decision for this release if wanted.
- **A blocking wait that hits `pollTimeoutMs` now WITHDRAWS its request** (`POST /agent/withdraw/<id>`
  `{reason:"timeout"}`) before throwing `DecidioTimeoutError`. Before, the decision stayed open in Decidio
  forever after this process had stopped waiting, so the queue carried a request nobody could act on and a
  later tap sealed "approved" for an action that never ran. Now it leaves the queue as *withdrawn* and a
  later approval is a no-op (`alreadyResolved`). `DecidioTimeoutError.withdrawn` says whether the call
  landed; a failed withdraw changes nothing else (nothing executes either way). Withdrawing needs the
  bound agent token and the signing key `init` writes — the gate refuses anyone else with 404, so an
  unbound or unsigned caller simply sees `withdrawn:false`. If a human decided in the last poll window,
  the gate answers 409 with that decision and the SDK honours it: the action runs as approved (and
  confirms), or `DecidioRejectedError` is thrown — never a timeout that hides a decision. The durable
  path is untouched — its parked action is exactly what a later approval resumes. The CLI tour and the
  `--demo` stand-in say which of these happened. Nothing to do on upgrade.
  Proved by: `smoke.ts` (the timeout vector now asserts exactly one withdraw after the last poll, and a
  failing withdraw still ends in the same error with `withdrawn:false`; a 409 carrying `approved` runs and
  confirms, `rejected` rejects; a wait that ends in a decision never withdraws) and, server-side,
  `integration.smoke.ts` #W2 (a lab-posture boot with real bound tokens: another agent's token, an
  anonymous caller and an unsigned receipt all get 404; the owner's later approve is `alreadyResolved`
  with no sealed record; a second withdraw → 409) and #W (IdP posture: anonymous and IdP users → 404).

## 0.6.3 — the two 0.6.2 reviews' small items

- **`DECIDIO_DEBUG_INPUT=1` no longer prints what you type** (review: Medium). The 0.6.2 trace hex-dumped every stdin
  byte - passwords, codes and links, muted prompt or not. It now prints the SHAPE only: control bytes named (`\r`, `\n`,
  ESC), every printable byte as `x`. A newline problem is visible in the shape alone.
- Four strings still described the sign-in as an emailed link to paste; they say the code now. The CHANGELOG's "twins"
  line overstated CLI parity and now says exactly what is locked and what is TypeScript-first. Two README headings
  still said "0.4". The offline local demo no longer prints "the terminal follows the web app or your phone" when it
  has just said there are no such doors. `receipt --json` help says it prints a summary; the credential is the file.

## 0.6.2 — the fork after its first real run

Founder UAT of 0.6.1 on a Windows console, same day.

- **Prompts pause.** On the founder's cmd.exe the agent-id prompt "took the folder's" name without waiting. The
  terminal driver could not reproduce it, so this is defence plus instrumentation: one readline now lives for the whole
  command (a console's `\r\n` can no longer split across two questions - the previous per-question interfaces could
  hand the second byte to the next prompt as Enter), and `DECIDIO_DEBUG_INPUT=1` prints the raw bytes stdin delivers, so
  a recurrence names its cause instead of a theory.
- **"What next?" has a way out:** `3  sign out of this computer  (npx @decidio/sdk logout)`.
- **Option 2 in a folder that already holds an agent** says so before asking for a name (with cleanup / a new folder /
  `--force` as the ways out), instead of `init` refusing afterwards with text that read like a prompt.
- **The bare command is update-gated** on a terminal, so a cached old npx copy announces the newer version instead of
  quietly showing an old first screen; `npx @decidio/sdk` is enough, `@latest` is not needed.
- **Sign in by CODE, not by paste.** When the command line asks for a sign-in, the email it triggers carries an
  8-character code and nothing to click; you type the code into the terminal that asked (dashes, case and an O for a 0
  are forgiven). Three misses and the code is dead. The web app's sign-in screen keeps its link email unchanged; two
  flows, each with exactly one action. Why this shape and not "click the link and the terminal continues": that design
  moves a session to a DIFFERENT device than the one that clicked, which is a new attack class the privacy council had
  to harden (docs/Decidio_CLI_Signin_Wait_Spec.md, retired); a code travels from the inbox to the device you are
  sitting at, and an attacker who triggers the email gains nothing. A pasted link is still accepted, quietly.
- **`npx decidio`.** A new npm package named `decidio` holds one file: it resolves the `@decidio/sdk` it pins (same
  version, released in lockstep) and runs that CLI. `npx decidio …` is `npx @decidio/sdk …` with fewer keystrokes; the
  update gate names whichever package you came through. Not something to import - the SDK stays `@decidio/sdk`.

## 0.6.1 — the first-run fork, and the local demo's loose ends

Two independent first-run reviews of 0.6.0 (grades B / A− overall) agreed on one thing: the hosted tour and the
verifier earn trust, and the new local demo had polish debts. This release pays them and adds the one question a
stranger's first minute was missing (founder ruling 2026-09-06).

- **One question, then the thing you picked.** A bare `npx @decidio/sdk quickstart` (or a bare `npx @decidio/sdk`) on
  a terminal with no sign-in asks: do you have a Decidio invite? `n` runs the local demo; `y` signs you in (the emailed
  link) and asks what next: the two-minute tour, or wiring up your own agent (`init`). Every answer prints the exact
  command it stands for, so the questions teach their own flags and you never need them twice. Nothing is stored;
  Enter is not an answer; scripts and CI never see a question (they get today's text, which now also names `--demo`).
  A signed-in `quickstart` runs straight away; the bare `npx @decidio/sdk` for a signed-in user skips the invite
  question and asks only "what next?" - the bare command always leads somewhere, usage is a `--help` away. After
  the sign-in step, the tour does not ask you to sign in again.
- **Your agent's name has a real default.** `init` with no name used `my-agent`; it now uses this folder's name (or
  the package name), slugified, and the fork explains what the name is for ("Requested by …", the key `.env` is
  written under). Any name still works.
- **A mark, not a banner:** the title lines carry the app's ✦ beside the name.
- **Headless `--demo` leaves nothing behind** (review: Medium). The stop at the human moment used to exit inside the
  tour, skipping the wrapper that removes the temporary folder - the mock key, mock token and journal stayed in the
  temp dir, and the message pointed at the hosted tour's remedies (`approvals approve`, `quickstart cleanup`), which
  cannot act on a stand-in that lives only in that process. The stop now returns through the wrapper, and says the
  demo's truth: nothing executed, nothing kept, re-run interactively or with `--auto-approve-demo`.
- **The demo receipt carries what the terminal claims** (review: Medium). Its canonical record now holds the real
  amount and currency, the reason the decision arrived with (the automated flag names itself there, exactly as it does
  in a hosted record's reason), and how it was decided (terminal, page, or the flag). The party stays tokenized, as
  the real seal keeps it.
- **`--demo --keep-agent` is refused** (both reviews: Low) - nothing of the demo's can be kept, and the flag used to
  be accepted while the opposite happened. Exit 2, with the reason.
- **A receipt the demo could not copy home is not a completed tour** (retest: Low): the temporary folder is kept and
  named, and the run exits non-zero, instead of deleting the only copy and exiting 0.
- **Words that were not true** (review: Low): the demo's Target line no longer says "nothing hosted" while the web
  door uses a hosted relay; the automated line names the demo's mock credential, not "your session credential"; a
  repeat run's ④ frame names the suffixed file that actually lands; the README no longer calls the sandbox "one shared
  lab workspace" in two places while saying the opposite in a third.

## 0.6.0 — `quickstart --demo`: the whole tour on your machine, no account

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
- **On a phone the demo IS the phone app's screen.** A phone that opens the demo link (the QR, or the link on a phone)
  lands on the phone build's own decision screen — the same Detail the installed app renders, with Approve and Reject
  where they always are — not the desktop panel squeezed into a phone viewport (founder UAT round 2). It holds no
  session and says LOCAL DEMO in one line; the decided moment says the terminal seals. Host-side only: nothing in this
  package changed for it.
- **The demo leaves your sign-in alone.** `quickstart --demo` never signs in, so its cleanup no longer ends a stored
  sign-in that happens to be on the computer (it did, in the founder's UAT; the smoke now plants one and asserts it
  survives, silently).
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
  pending (exit 3) rather than guess. The rule is one pure function, `approvalAnswer`, driven by a shared
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
  `npx @decidio/sdk quickstart cleanup` once, which reports the token as already revoked and retires the row.
- **Truth and disclosure.** The failure text after a refused registration no longer claims nothing was
  written (the `.gitignore` entries were); the preflight discloses the five-minute wait for your answer and
  that receipts are shareable but carry business metadata; cleanup names the retained journal; the
  worker's "prints once" is "once per worker process"; the tour tells you to unset `DECIDIO_SESSION_TOKEN`
  before launching agent code from the same shell.
- **`dev --target` obeys the wire rule:** the relay refuses a remote plaintext `http://` target, since the
  forwarded body is signed resume material.
- **A race loser says so** (prodsec retest of 0.4.0, V040-01). A resume signal that finds the pre-invocation
  claim held by another live attempt, or loses the invocation-boundary race to one, answers the new additive
  status `lost_race` (it did nothing; the winner reports). It used to read `unknown` — the word for "not
  ours" — and `no_handler` although the handler was registered. A boundary loss to a DENIAL is final and
  answers `already_resolved` with the denial named; a store fault at the boundary answers `lost_race` with
  "nothing ran … a later signal may retry". A signal that arrives after the entry was consumed now consults
  the ledger: already ran or denied → `already_resolved`; in flight → `indeterminate`; a claim held by another
  attempt → `lost_race`; only a decision with no record at all is `unknown`. Exhaustive switches over the
  status union gain one case.
- **Adapter declarations aligned** (V040-02): the Temporal compatibility floor checked at bind time is now the
  same `>=1.9 <2` the package declares; the peer-dependency comment says what the manifest does (optional
  peers, checked at bind time); the Inngest step outcome is a discriminated union, so `confirmation` is
  statically present when `status` is `"executed"`. Adapters stay Beta; real-engine evidence (V040-03) and
  provenance metadata (V040-04) remain open and disclosed.
- Deliberately not changed, recorded in the backlog for a product decision: per-subcommand `--help`, the
  tour showing the exact call it makes (`withApproval` in blocking mode rather than the `guard.protect`
  line it prints as the takeaway), dot-stripping in receipt filenames, and a shared no-overwrite receipt
  writer for the tour.

## 0.4.0 — the scope statement

- **README: "What 0.4 does not yet claim" and "Compatibility and support."** The stability promise is
  stated: what is stable, what is Beta (the engine adapters), what is deprecated and kept until 1.0
  (`protectBestEffort`, `gateInterruptions`), and the five things reviewers keep finding that only
  product decisions close (trust-on-first-use issuer DID, the unshipped schema, the unshipped
  conformance suites, provenance and the repository link). 1.0.0 follows user-acceptance testing.
- **The tour fails closed on an unpinned check.** If the API omits the issuer DID, the tour used to warn
  and still report success; it now fails and cleans up.
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
- **Temporal (Beta): a custom `confirm` may return the gate's confirm outcome** (validated with
  `readConfirmResponse`) and it becomes the step's confirmation instead of being discarded.
- **Transport: every refusal redacts URL userinfo**, including the opaque `scheme:user:secret@` spelling,
  and Unicode space and format characters (NBSP, ideographic space, zero-width space, …) are refused in
  both runtimes from one explicit list. Four cases joined the shared transport corpus.
- **This file ships** in the tarball (and in the Python sdist), as a deliberate publish-boundary line.

## 0.3.5 — the retest residuals

- **Transport:** any control character or whitespace anywhere in the URL is refused before anything is
  sent; refusals echo a redacted spelling (URL userinfo is a credential).
- **Credential lifecycle:** the quickstart inspects a previous `.env.quickstart` before minting; secret
  files are written temp + fsync + rename; **the token recovery journal** (`.decidio-token-journal`,
  owner-only, append-only) records every minted token id before the credential file exists and retires
  it on a durable write or any proven revoke. Credential creation fails closed if the journal cannot be
  written. `quickstart cleanup` sweeps it; `doctor` lists outstanding entries.
- **Verifiers (all three doors):** the `verificationMethod` must be the issuer's exact `did:key` method
  identifier, and `created` must be a real calendar date-time. Correctly signed receipts naming a
  nonexistent method fragment or an impossible time are now INVALID.
- **Adapter gate:** the same describe validation as the core (a blank action or negative amount is
  refused before signing or posting).
- **Outcomes:** a resume signal that lost the race to a final answer is `already_resolved`; a parked row
  whose payload is gone is `orphaned_state`.
- Upgrade: no action. Custom stores are unaffected.

## 0.3.4 — first-run consistency

- Tour and README pointers, routing-by-default vs the universal-backstop block named as two states, the
  stale "unsafe values park and fail on resume" paragraph corrected, cleanup discloses the durable
  store, help never loads `.env` (and only when usage will actually print), adapter headers current.
- Upgrade: no action.

## 0.3.2 / 0.3.3 — the transition itself is atomic (COORDINATED UPGRADE)

- **The shipped file stores are an append-only revision chain** (`<key>.rev.<N>`), published with a
  hard link that refuses an existing name: exactly one writer wins each transition, and a loser
  re-validates against what actually happened. This closed the pre-0.3.2 race in which a denial could
  be written and returned and the denied action still run.
- **Upgrade — read this if a directory is shared by more than one worker:** the first 0.3.2+ store
  migrates the older marker layout one way. **Stop every older worker that shares the directory before
  the first 0.3.2+ process starts**, then upgrade them together. An older worker writing into an
  upgraded directory leaves a marker beside the chain, and that decision reads as unreadable by design.
  Nothing deletes a revision; each decision keeps a handful of small files (see the README's sizing
  envelope).
- 0.3.3: one snapshot of `describe()`'s answer for signing and posting; the shared id grammar at every
  exported resume door; a compensating revoke when a minted token's credential file fails to write;
  `reconfirm()` on a reported decision tells the truth about confirmation.

## 0.3.1

- The verifier says what it proves (canonical signed claims, not exact bytes); proof options
  (`proofPurpose`, `verificationMethod`, `created`) are part of the claim on every door; duplicate
  `--issuer` flags are refused everywhere; orphaned token ids survive every replacement.

## 0.3.0

- A claim that gates nothing: `reportRecorded` and `executionConfirmed` are distinct, honest booleans.
  A denial is final on every path. The decision-id grammar is defined server-side and mirrored here.
- Upgrade for custom stores: `markDiscarded` is required (a hard construction failure without it).

## 0.2.x

- The execution state machine (`parked → claimed_preinvoke → invoking → executed_unreported |
  indeterminate → reported`), `reconcile()`, `ExecutionContext` with a stable idempotency key, and the
  composite return (`{ value, decisionId, confirmation }`) with `protectBestEffort` keeping the old shape.
