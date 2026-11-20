import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import { DecidioBlockedError, DecidioRejectedError, signBoundProof, signConfirm, assertSafeTransport, carriesCredential, canonicalize, assertDescribed, readConfirmResponse, buildConfirmBody, type GuardConfig, type ApprovalContext, decisionIdProblem, type EvidenceOutcome, bindingMaterial, requestCommitment, idempotencyKey, invocationRequestKey, sendAuthorize, checkApproval, claimApproval, type ApprovalCheck, type ClaimOutcome, type CommittedRequest, type JsonValue } from "../index.js";

/** The ONLY authorization verdicts this SDK understands. A gate answer outside this set means
 *  the SDK does not understand the decision — and an answer you do not understand means NO. */
export const AUTHORIZE_VERDICTS = ["proceed", "route", "block"] as const;
export type AuthorizeVerdict = (typeof AUTHORIZE_VERDICTS)[number];

/** `requestKey` (0.12.0): the request key this authorize sent, when it sent one. `idempotentReplay` / `openTwin`: the gate
 *  answered with a request that already existed (the same key asked again, or the same keyless request another caller is
 *  waiting on). */
export interface GateAuth { decision: AuthorizeVerdict; decisionId: string; /** The record number people see (D·0154), when the gate gives it. */ displayNumber?: string | null; receiptId?: string; reason?: string; requestKey?: string; idempotentReplay?: boolean; openTwin?: boolean; /** Decidio's signature over a proceed, for the coding-agent hook (cli.ts verifyGateAnswer) */ gateAnswer?: unknown }

/** Fail-closed verdict allow-list. Called INSIDE gateAuthorize, so every adapter that authorizes
 *  through the shared gate is protected by construction rather than by remembering — an adapter
 *  that handled `block` and `route` and let everything else fall through to execute is exactly
 *  how an unknown verdict reached a protected action. Version skew (the day the gate learns a
 *  fourth verdict) is the realistic trigger, and it must never mean "run it". */
export function assertAuthorizeVerdict(auth: unknown, fallbackDecisionId = "unknown"): GateAuth {
  const a = auth as Partial<GateAuth> | null;
  const decisionId = typeof a?.decisionId === "string" && a.decisionId ? a.decisionId : fallbackDecisionId;
  if (!a || !(AUTHORIZE_VERDICTS as readonly string[]).includes(a.decision as string)) {
    throw new DecidioBlockedError(
      `unrecognised authorization verdict ${JSON.stringify(a?.decision ?? null)} — refusing to execute. The gate answers ${AUTHORIZE_VERDICTS.join(" | ")}; anything else means this SDK version does not understand the decision (upgrade @decidio/sdk), and an answer you do not understand is never permission.`,
      decisionId,
    );
  }
  const idProblem = decisionIdProblem(a.decisionId);
  if (idProblem) {
    throw new DecidioBlockedError(
      `the gate answered "${a.decision}" with no usable decisionId (${JSON.stringify(a.decisionId ?? null)} — ${idProblem}) — refusing to execute. Every authorized action must be addressable: without an id it cannot be polled, resumed, confirmed or audited.`,
      decisionId,
    );
  }
  return a as GateAuth;
}

/** What an ENGINE door binds a routed approval to (0.7.0): the whole described context, canonicalized
 *  exactly as gateAuthorize canonicalizes it. An adapter cannot see inside its `run()` closure, so the
 *  described request - action, amount, scope and the display details a human approved - is the request.
 *  Recompute it from the SAME describe() the door authorized with. */
export function adapterRequest(ctx: ApprovalContext): CommittedRequest {
  const c = canonicalize<ApprovalContext>(ctx as unknown, "describe(...)");
  return { action: c.action, amount: c.amount, ...(c.scope !== undefined && c.scope !== null ? { scope: c.scope } : {}), ...(c.context !== undefined && c.context !== null ? { context: c.context } : {}) };
}

/** What the OpenAI Agents door binds a routed approval to (#4B review W2): the described context AND the
 *  tool call itself - its name, its call id and its exact argument string, from the interruption's raw
 *  item. describe(item) is the host's summary and need not cover every argument (edit a parked item's
 *  target and it can stay the same), and it never says WHICH call: without the call id one approval could
 *  be applied to a second, identical call whose own decision is still pending. An item with no call id
 *  cannot be bound to one call, so it is refused - nothing routed, nothing approved. (Python twin:
 *  tool_call_request.) */
export function toolCallRequest(item: unknown, ctx: ApprovalContext): CommittedRequest {
  const it = (item && typeof item === "object" ? item : {}) as Record<string, any>;
  const raw = (it.rawItem && typeof it.rawItem === "object" ? it.rawItem : it) as Record<string, any>;
  const callId = raw.callId ?? raw.call_id ?? raw.id;
  if (typeof callId !== "string" || callId === "") {
    throw new Error("[decidio] openai: this tool-approval item carries no call id (rawItem.callId), so an approval could not be bound to this ONE call - nothing was routed or approved. Pass the items state.getInterruptions() returns.");
  }
  const name = raw.name ?? it.name ?? it.toolName;
  const args = raw.arguments ?? it.arguments;
  return { ...adapterRequest(ctx), args: [{ arguments: args === undefined ? null : args, callId, name: typeof name === "string" ? name : null }] };
}

/** THE ONE APPROVAL CHECK on an engine door: GET /agent/status + the request commitment recomputed over
 *  this `ctx` (see checkApproval) - or over `request` when the door binds more than the described context
 *  (the OpenAI door's toolCallRequest). Returns the plain-JSON outcome - an engine that must run HTTP
 *  inside an activity or a step (Temporal, Inngest) memoizes exactly this value. */
export async function gateCheckApproval(config: GuardConfig, decisionId: string, ctx: ApprovalContext, request?: CommittedRequest): Promise<ApprovalCheck> {
  return checkApproval(config, decisionId, request ?? adapterRequest(ctx));
}

/** Validate an approval check that crossed a serialization boundary (a Temporal activity result, an
 *  Inngest step memo). Anything that is not a well-formed check is refused as unverifiable - the same
 *  "an answer you do not understand is never permission" rule the verdict allow-list applies. */
export function assertApprovalCheckShape(raw: unknown, decisionId: string): ApprovalCheck {
  const c = raw as Partial<ApprovalCheck> | null;
  if (!c || typeof c !== "object" || typeof c.ok !== "boolean" || c.decisionId !== decisionId || typeof c.state !== "string") {
    return { ok: false, decisionId, state: "", code: "unverifiable", reason: `the approval check for decision ${decisionId} came back malformed (${JSON.stringify(raw ?? null).slice(0, 120)}) - return checkApproval(...) / gateCheckApproval(...) from your activity unchanged` };
  }
  if (c.ok === true && c.code !== undefined) return { ok: false, decisionId, state: c.state, code: "unverifiable", reason: "the approval check came back contradictory (ok with a refusal code)" };
  return c as ApprovalCheck;
}

/** REFUSAL TWINS: the one answer outside the allow-list, and only for a caller that ASKED for
 *  the check (`twinCheck`). It is not permission - nothing was created; the caller tells the user and re-asks with their
 *  justification. gateAuthorize (every adapter and the core path) never asks, so it can never receive one. */
export interface GateDuplicate { decision: "duplicate"; duplicateOf: { decisionId: string; displayNumber?: string | null; refusedAt?: string | null; reason?: string | null } }
export const isGateDuplicate = (a: unknown): a is GateDuplicate => {
  const d = (a as Partial<GateDuplicate> | null)?.duplicateOf;
  return (a as Partial<GateDuplicate> | null)?.decision === "duplicate" && !!d && typeof d === "object" && typeof d.decisionId === "string" && decisionIdProblem(d.decisionId) === null;
};
/** The hook's door: asks for the refusal-twin check and may carry the re-ask's justification. A `duplicate` answer is returned as
 *  such (never permission); every other answer passes the same allow-list as gateAuthorize. */
export async function gateAuthorizeTwinAware(config: GuardConfig, ctx: ApprovalContext, opts: { idempotencyKey?: string; request?: CommittedRequest; justification?: string; guardSession?: string; guardChallenge?: string } = {}): Promise<GateAuth | GateDuplicate> {
  const { answer: a } = await postAuthorize(config, ctx, { ...opts, twinCheck: true });
  if (isGateDuplicate(a)) return a;
  return assertAuthorizeVerdict(a, "unknown");
}
/** `naturalId` (0.12.0, 11f): the engine's own name for THIS call - an OpenAI tool call id, a Temporal workflow run and
 *  activity, an Inngest run - so the engine retrying the same call is the same request. The request key is keyed over it
 *  and the commitment. Without one (and without `idempotencyKey`) the key is over a fresh id for this call, as on the core
 *  path. No key material: no commitment, so no key - as before. */
export async function gateAuthorize(config: GuardConfig, ctx: ApprovalContext, opts: { idempotencyKey?: string; request?: CommittedRequest; naturalId?: Record<string, JsonValue> } = {}): Promise<GateAuth> {
  const { answer, requestKey } = await postAuthorize(config, ctx, opts);
  const auth = assertAuthorizeVerdict(answer, "unknown");
  return requestKey ? { ...auth, requestKey } : auth;
}
async function postAuthorize(config: GuardConfig, ctx: ApprovalContext, opts: { idempotencyKey?: string; request?: CommittedRequest; naturalId?: Record<string, JsonValue>; twinCheck?: boolean; justification?: string; guardSession?: string; guardChallenge?: string } = {}): Promise<{ answer: unknown; requestKey?: string }> {
  ctx = canonicalize<ApprovalContext>(ctx as unknown, "describe(...)");
  assertDescribed(ctx);
  assertSafeTransport(config.apiUrl, carriesCredential(config));
  const resumeUrl = config.resumeUrl ?? config.resume?.resumeUrl;
  const sign = () => (config.agentKey && config.agentDid)
    ? signBoundProof(config.agentKey, { agentId: config.agentId, did: config.agentDid, action: ctx.action, amount: ctx.amount, scope: ctx.scope, workspaceId: config.workspaceId })
    : undefined;
  const requesterIdentity = sign();
  const material = bindingMaterial(config);
  const commitment = material ? requestCommitment(material, opts.request ?? adapterRequest(ctx)) : undefined;
  const requestKey = opts.idempotencyKey
    ?? (material && commitment
      ? (opts.naturalId ? idempotencyKey(material, { ...opts.naturalId, commitment }) : invocationRequestKey(material, config.invocationId ? String(config.invocationId()) : randomUUID(), commitment))
      : undefined);
  const answer = await sendAuthorize(config, {
    requester: config.agentId, action: ctx.action, amount: ctx.amount, scope: ctx.scope,
    sourceSystem: config.sourceSystem, ...(ctx.context ? { context: ctx.context } : {}),
    ...(requesterIdentity ? { requesterIdentity } : {}), ...(resumeUrl ? { resumeUrl } : {}),
    ...(commitment ? { requestCommitment: commitment } : {}),
    ...(requestKey ? { idempotencyKey: requestKey } : {}),
    ...(opts.twinCheck ? { twinCheck: true } : {}),
    ...(opts.justification ? { justification: opts.justification } : {}),
    ...(opts.guardSession && opts.guardChallenge ? { guardSession: opts.guardSession, guardChallenge: opts.guardChallenge } : {}),
  }, { rateLimit: "http", resign: sign });
  return { answer, ...(requestKey ? { requestKey } : {}) };
}

/** COLLECT A PERSON'S APPROVAL ONCE on an engine door (0.12.0, call 24) - claimApproval, as a plain-JSON value an engine
 *  that must run HTTP in an activity (Temporal) returns unchanged. */
export function gateClaim(config: GuardConfig, decisionId: string, claimKey: string): Promise<ClaimOutcome> {
  return claimApproval(config, decisionId, claimKey);
}

/** Validate a claim outcome that crossed a serialization boundary (a Temporal activity result). Anything that is not a
 *  well-formed outcome for THIS decision is refused - "an answer you do not understand is never permission". */
export function assertClaimShape(raw: unknown, decisionId: string): ClaimOutcome {
  const c = raw as Partial<ClaimOutcome> & Record<string, unknown> | null;
  if (c && typeof c === "object" && c.decisionId === decisionId) {
    if (c.ok === true && typeof c.again === "boolean") return { ok: true, decisionId, again: c.again };
    if (c.ok === false && typeof c.code === "string" && typeof c.reason === "string" && typeof c.final === "boolean") return c as ClaimOutcome;
  }
  return { ok: false, decisionId, code: "unrecognized", final: false, reason: `the claim for decision ${decisionId} came back malformed (${JSON.stringify(raw ?? null).slice(0, 120)}) - return claimApprovalActivity(...) from your activity unchanged. Nothing ran.` };
}

/** Report an adapter-path execution and RETURN what Decidio recorded.
 *
 *  Two 0.2.0 changes, both closing the same gap. It applies the caller's `evidence` mapper — the
 *  warning below tells you to use that option, and on every engine adapter it did nothing, because
 *  the mapper never reached this function. And it RETURNS the outcome instead of swallowing it, so
 *  an adapter can hand its caller the same confirmation the core path now does. */
export async function gateConfirm(config: GuardConfig, decisionId: string, result: unknown, evidence?: (r: any) => unknown): Promise<EvidenceOutcome> {
  const f = config.fetchImpl ?? fetch;
  const failed = (why: string, retryable = true): EvidenceOutcome => ({
    reportRecorded: false, executionConfirmed: false, confirmationRetryable: retryable, reportJournalled: false,
    diagnostic: `your action RAN and Decidio does NOT have its execution report (${why}). Record the outcome from your own system; do NOT re-run the action.`,
  });
  try { assertSafeTransport(config.apiUrl, carriesCredential(config)); } catch (e) { console.warn(`[decidio] confirm failed (action succeeded): ${(e as Error).message}`); return failed((e as Error).message, false); }
  let reported: unknown = null;
  let evidenceProblem: string | undefined;
  try {
    reported = canonicalize((evidence ? evidence(result) : result) ?? null, evidence ? "evidence(result)" : "result");
  } catch (e: any) {
    evidenceProblem = String(e?.message ?? e);
    console.warn(`[decidio] ${decisionId}: the action SUCCEEDED but its result could not be reported as evidence (${evidenceProblem}). Reporting an empty captured response so the execution is still recorded — map the return value with the \`evidence\` option to earn a confirming tier. The action was NOT re-run.`);
  }
  try {
    const requesterIdentity = signConfirm(decisionId, config);
    if (!requesterIdentity) console.warn(`[decidio] execution evidence for ${decisionId} recorded as agent_asserted — no signing key configured, so the report can't be proven to come from this agent. Set DECIDIO_AGENT_KEY/DID to earn application_confirmed.`);
    const res = await f(config.apiUrl.replace(/\/$/, "") + "/agent/confirm", {
      method: "POST",
      headers: { "content-type": "application/json", ...(config.apiToken ? { authorization: `Bearer ${config.apiToken}` } : {}) },
      body: JSON.stringify(buildConfirmBody(config, decisionId, reported, requesterIdentity)),
    });
    if (!res.ok) { console.warn(`[decidio] confirm returned ${res.status} (action succeeded)`); return { ...failed(`HTTP ${res.status}`, res.status === 408 || res.status === 429 || res.status >= 500), evidenceError: evidenceProblem }; }
    const ev = readConfirmResponse(await res.json().catch(() => null), { signed: !!requesterIdentity, capturedResponse: reported });
    if (!ev.reportRecorded) console.warn(`[decidio] ${decisionId}: ${ev.diagnostic}`);
    else if (!ev.executionConfirmed || ev.executionReportVerified === false) console.warn(`[decidio] execution evidence for ${decisionId} recorded as ${ev.evidenceTier} — ${ev.diagnostic}`);
    if (evidenceProblem) console.warn(`[decidio] ${decisionId}: the execution IS recorded, but with an empty captured response — see the evidence note above.`);
    if (evidenceProblem) ev.evidenceError = evidenceProblem;
    return ev;
  } catch (e) {
    console.warn(`[decidio] confirm failed (action succeeded): ${(e as Error).message}`);
    return { ...failed((e as Error).message), evidenceError: evidenceProblem };
  }
}

/** Normalize a resume payload ({verdict} | "approved" | ...) to a verdict string. */
export function verdictFrom(payload: any): string {
  return (payload && typeof payload === "object" ? payload.verdict : payload) ?? "";
}

/** Throw the right error for a non-approving verdict; return for approved/auto_approved. */
export function assertVerdict(verdict: string, decisionId: string, reason?: string): void {
  if (verdict === "approved" || verdict === "auto_approved") return;
  if (verdict === "rejected") throw new DecidioRejectedError(reason ?? "rejected by approver", decisionId);
  throw new DecidioBlockedError(reason ?? "not approved", decisionId);
}

/** Engine versions these adapters are written and tested against. The two engines that ARE declared in
 *  package.json are declared as OPTIONAL peers (peerDependenciesMeta), so a consumer who uses none of them
 *  installs nothing extra; Inngest and the OpenAI Agents SDK are not declared at all. Either way the
 *  contract is CHECKED here at bind time — a mismatch names the version it found, the range it wants, the
 *  beta status and the exact remediation, rather than failing somewhere deep in the engine later. These
 *  ranges and package.json's peer ranges are the SAME numbers (prodsec V040-02: they had drifted). */
export const ENGINE_RANGES: Record<string, { pkg: string; min: string; lessThan: string }> = {
  langgraph: { pkg: "@langchain/langgraph", min: "0.2.0", lessThan: "2.0.0" },
  temporal: { pkg: "@temporalio/workflow", min: "1.9.0", lessThan: "2.0.0" },
  openai: { pkg: "@openai/agents", min: "0.0.1", lessThan: "2.0.0" },
  inngest: { pkg: "inngest", min: "3.0.0", lessThan: "4.0.0" },
};

const cmp = (a: string, b: string): number => {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0), pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) { if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0); }
  return 0;
};

/** Warn (never throw — a working integration must not be broken by a version table) when the
 *  installed engine is outside the tested range. Called by each adapter at bind time. */
export function checkEngineVersion(adapter: keyof typeof ENGINE_RANGES | string): void {
  const spec = ENGINE_RANGES[adapter];
  if (!spec) return;
  let found: string | undefined;
  try {
    const req = createRequire(import.meta.url);
    found = req(`${spec.pkg}/package.json`)?.version;
  } catch { }
  if (!found) return;
  if (cmp(found, spec.min) < 0 || cmp(found, spec.lessThan) >= 0) {
    console.warn(
      `[decidio] ${spec.pkg} ${found} is outside the range this BETA adapter is tested against (>=${spec.min} <${spec.lessThan}). ` +
      `The adapter may still work, but nothing verifies it at this version. Remediation: install a supported version ` +
      `(npm i "${spec.pkg}@>=${spec.min} <${spec.lessThan}"), or use the core guard.protect path, which is not beta and needs no engine.`,
    );
  }
}
