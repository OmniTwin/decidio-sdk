import { randomUUID } from "node:crypto";
import { DecidioSuspendedError, checkApproval, claimApproval, newClaimKey, RETRY_DELAYS_MS } from "./resume.js";
import type { ResumeController, ApprovalCheck, ClaimOutcome } from "./resume.js";
import { signBoundProof, signConfirm, assertSafeTransport, carriesCredential, bindingMaterial, requestCommitment, invocationRequestKey, ownRequestKey, type CommittedRequest } from "./signing.js";
import { canonicalize, canonicalizeArgs, DecidioUnsafeArgumentsError, type JsonValue } from "./canonical.js";
import { readConfirmResponse, buildConfirmBody, EVIDENCE_TIERS, type EvidenceOutcome, type EvidenceTier } from "./evidence.js";
export { DecidioSuspendedError, DecidioDeniedError, DecidioRecoveryUnavailableError, FilePendingStore, MemoryPendingStore, createDecidioResume, assertConfirmRecorded, checkApproval, claimApproval, newClaimKey } from "./resume.js";
export type { PendingAction, PendingStore, ResumeController, ResumeOutcome, ApprovalCheck, ApprovalCheckCode, DecisionStatus, ClaimOutcome, ClaimCode } from "./resume.js";
export { guard, Guard } from "./guard.js";
export type { GuardFacadeConfig, ProtectOptions } from "./guard.js";
export { DecidioHttpError, decisionIdProblem } from "./errors.js";
import { DecidioHttpError, decisionIdProblem } from "./errors.js";
export { generateKeypair, didFromPrivateKey, signBoundProof, signConfirm, signExecutionReport, verifyExecutionReport, resultDigest, assertSafeTransport, carriesCredential, bindingMaterial, boundScope, requestCommitment, idempotencyKey, invocationRequestKey, ownRequestKey, committedRequestJson } from "./signing.js";
export type { BindingMaterial, CommittedRequest } from "./signing.js";
export { canonicalize, canonicalizeArgs, canonicalJson, DecidioUnsafeArgumentsError } from "./canonical.js";
export type { JsonValue, JsonPrimitive } from "./canonical.js";
export { readConfirmResponse, buildConfirmBody, describeTierGap, EVIDENCE_TIERS } from "./evidence.js";
export type { EvidenceOutcome, EvidenceTier } from "./evidence.js";
export type { RequesterIdentity } from "./signing.js";

export interface GuardConfig {
  /** Base URL of the Decidio gate. Decidio is "https://mcp.decidioai.com" (the invite-only lab:
   *  "https://mcp-staging.decidioai.com"); the CLI defaults to Decidio when DECIDIO_API_URL is unset; a self-hosted deployment is your own origin.
   *  (This example named a host the product does not use — it shipped in the .d.ts, so it was the
   *  first URL a typing-aware editor suggested to anyone configuring the SDK.) */
  apiUrl: string;
  /** The agent identity registered with Decidio (onboarding wizard), e.g. "salesforce/SalesforceBot". */
  agentId: string;
  /** Bearer token for the REST floor (a trusted, already-authenticated internal
   *  caller). Lives ONLY in the agent host's environment — never in client code. */
  apiToken?: string;
  /** Source system label sealed onto the receipt (e.g. "salesforce"). */
  sourceSystem?: string;
  /** The agent's PRIVATE signing key (PKCS8 base64), generated locally by `init` and held
   *  ONLY in the agent host's env as DECIDIO_AGENT_KEY. When set (with `agentDid`), the SDK
   *  signs a request-bound identity proof on each authorize so the floor PROVES the requester
   *  instead of trusting the label — required for a registered agent to auto-approve. */
  agentKey?: string;
  /** The agent's PUBLIC did:key (the one registered with Decidio). Pairs with `agentKey`. */
  agentDid?: string;
  /** The workspace this agent acts in (DECIDIO_WORKSPACE_ID, from the owner's agent-token mint).
   *  Bound into the signed proof (D-B3.6) so a captured proof can't be replayed in another tenant.
   *  For a tester's per-workspace agent token this is the tester's workspace id. */
  workspaceId?: string;
  /** Poll cadence + ceiling while a routed action awaits human approval. Used ONLY
   *  by the blocking transport (no `resume` configured). */
  pollIntervalMs?: number;
  pollTimeoutMs?: number;
  /** Optional async notifier so a long human wait surfaces in your logs/UI. */
  onPending?: (info: { decisionId: string; receiptId: string; url: string | null }) => void;
  /** Base URL of the Decidio app (DECIDIO_APP_URL). When set, a routed action can say WHERE to
   *  approve it — `<appUrl>/d/<decisionId>` opens that decision directly, on web or on the phone
   *  build. This link used to be built only inside our own example, so a developer who pasted the
   *  env block set DECIDIO_APP_URL and nothing ever read it. */
  appUrl?: string;
  /** Durable async resume. When set, a routed action SUSPENDS (parks its args in the
   *  store, throws DecidioSuspendedError) instead of blocking — the process may exit
   *  and resume later via the controller's webhook handler or poll worker. This is
   *  the production transport for real (minutes-to-days) human approvals. */
  resume?: ResumeController;
  /** Callback URL Decidio POSTs the verdict to on approval (webhook transport).
   *  Sent on /agent/authorize so the decision carries it. Falls back to
   *  resume.resumeUrl. Omit when using the poll worker. */
  resumeUrl?: string;
  /** Where the per-call id behind the DEFAULT REQUEST KEY comes from (0.12.0, 11f). Every call that sends a request
   *  commitment also sends a request key derived from a fresh random id and that commitment, so this SDK's own retry of
   *  the authorize is the same request. Leave it unset: a fixed id makes every call the SAME request. It exists so a
   *  test or a conformance harness can pin the bytes it compares. */
  invocationId?: () => string;
  fetchImpl?: typeof fetch;
}

export interface ApprovalContext {
  action: string;
  amount: number;
  scope?: string;
  /** Optional human-facing DETAILS of the action (e.g. { Account, "Lead Source", Stage }) shown to
   *  the approver as "what you're approving". Display-only — the policy decides on `amount`/`scope`,
   *  never these. Residual-safe tokenized server-side before persistence. */
  context?: Record<string, string | number>;
}

export class DecidioBlockedError extends Error {
  constructor(public reason: string, public decisionId: string) {
    super(`Decidio blocked the action: ${reason}`);
    this.name = "DecidioBlockedError";
  }
}
export class DecidioRejectedError extends Error {
  constructor(public reason: string, public decisionId: string) {
    super(`A human rejected the action: ${reason}`);
    this.name = "DecidioRejectedError";
  }
}
/** THE REQUEST CHANGED AFTER APPROVAL (0.7.0). Decidio records an approval for `decisionId`, but it is
 *  bound (by a keyed commitment) to a DIFFERENT request than the one about to run — the arguments, the
 *  amount or the described context changed after a human approved, or this agent's key material changed
 *  since it asked. Nothing was executed. A new request needs a new approval: reject this decision and
 *  run the action again. Extends DecidioBlockedError, so code that already treats a block as "did not
 *  run" keeps doing so. */
export class DecidioRequestChangedError extends DecidioBlockedError {
  readonly code = "request_changed" as const;
  constructor(decisionId: string, detail?: string) {
    super(detail ?? `the request changed after approval (decision ${decisionId})`, decisionId);
    this.name = "DecidioRequestChangedError";
    this.message = `[decidio] the request changed after approval: decision ${decisionId} was approved for a different request than the one about to run. Nothing was executed. ${detail && !/^the request changed after approval/.test(detail) ? `(${detail}) ` : ""}A changed request needs its own approval — reject ${decisionId} and run the action again.`;
  }
}

/** An approval that cannot be TIED to this request (0.7.0): Decidio answered without the request
 *  commitment this SDK sent (`commitment_missing` — the gate predates request binding), or holds one
 *  this process cannot recompute (`unverifiable` — no or unreadable key material, or a malformed
 *  answer). Fail closed: nothing was executed. Extends DecidioBlockedError. */
export class DecidioApprovalUnverifiedError extends DecidioBlockedError {
  constructor(decisionId: string, public readonly code: "commitment_missing" | "unverifiable", detail: string) {
    super(detail, decisionId);
    this.name = "DecidioApprovalUnverifiedError";
    this.message = `[decidio] cannot confirm that decision ${decisionId} approved THIS request: ${detail}. Nothing was executed.`;
  }
}

/** The typed refusal for an approval check that did not pass — ONE mapping for every door that throws
 *  (inline, LangGraph, Temporal, Inngest, OpenAI Agents). `pending` is included for the doors that
 *  cannot wait again; the doors that can (LangGraph, Temporal, Inngest) wait instead of calling this. */
export function approvalRefusal(check: ApprovalCheck): Error {
  const id = check.decisionId;
  switch (check.code) {
    case "rejected": return new DecidioRejectedError(check.reason ?? "rejected by approver", id);
    case "blocked": return new DecidioBlockedError(check.reason ?? "blocked by policy", id);
    case "request_changed": return new DecidioRequestChangedError(id, check.reason);
    case "commitment_missing": return new DecidioApprovalUnverifiedError(id, "commitment_missing", check.reason ?? "Decidio answered without the request commitment this SDK sent");
    case "unverifiable": return new DecidioApprovalUnverifiedError(id, "unverifiable", check.reason ?? "the approval could not be tied to this request");
    case "pending": return new DecidioBlockedError(`not approved - ${check.reason ?? `Decidio records ${id} as pending`}`, id);
    case "spent": return new DecidioBlockedError(`not executed - ${check.reason ?? `the approval for ${id} is already spent`}`, id);
    case "expired": return new DecidioBlockedError(`not executed - ${check.reason ?? `the approval for ${id} has expired`}`, id);
    default: return new DecidioBlockedError(check.reason ?? `not approved (Decidio answered ${JSON.stringify(check.state)})`, id);
  }
}

/** What a routed approval must be bound to on the CORE door: exactly what executes — the canonical
 *  argument snapshot plus the described action/amount/scope. The durable resume recomputes the same
 *  shape over the parked payload. */
export function coreRequest(ctx: { action: string; amount: number; scope?: string | null }, args: readonly unknown[]): CommittedRequest {
  return { action: ctx.action, amount: ctx.amount, ...(ctx.scope !== undefined && ctx.scope !== null ? { scope: ctx.scope } : {}), args };
}

export class DecidioTimeoutError extends Error {
  /** `withdrawn` (0.6.4+): true when the SDK told Decidio it gave up and the request was closed as
   *  WITHDRAWN (the queue no longer carries it; a later approval does nothing); false when that
   *  best-effort call failed, so the request may still be open in Decidio. Nothing was executed
   *  locally either way.
   *  `shared` (0.12.0): true when the request was left open on purpose because it may be shared - the authorize
   *  answered an earlier request (`idempotentReplay`) or joined one another caller is waiting on (`openTwin`), or the
   *  withdraw was refused because another caller joined it (409 SHARED_REQUEST). A person still decides it. */
  constructor(public decisionId: string, public withdrawn: boolean = false, public shared: boolean = false) {
    super(`Timed out waiting for human approval (${decisionId})`);
    this.name = "DecidioTimeoutError";
  }
}

type Verdict = "proceed" | "route" | "block";
interface AuthorizeResponse { decision: Verdict; decisionId: string; receiptId: string; reason?: string; idempotentReplay?: boolean; openTwin?: boolean }
interface StatusResponse { state: "pending" | "approved" | "rejected" | "auto_approved" | "blocked"; reason?: string; requestCommitment?: string | null }

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A transport failure with GUIDANCE instead of a raw fetch stack. Carries the endpoint, the
 *  operation, the underlying code, and the safety state a caller cares about most: whether
 *  anything could have executed. */
/** The workspace's governed-action allowance is exhausted (HTTP 429, code AGENT_RATE). The
 *  server says exactly how much and until when — `limit`, `remaining` and `resetAt` relay its
 *  answer verbatim so automation never has to parse a message. Nothing was routed, recorded,
 *  or executed; retry after `resetAt`. */
export class DecidioRateLimitError extends Error {
  /** `code` (0.12.0): the server's own code - `AGENT_RATE` for the workspace's hourly allowance, which is never retried;
   *  a 429 without it is a transport throttle the SDK retries before it gives up. */
  constructor(public limit: number | undefined, public remaining: number | undefined, public resetAt: string | undefined, serverMessage?: string, public code?: string) {
    super(`[decidio] governed-action rate limit reached${limit != null ? ` (${limit}/hour on this workspace)` : ""}${resetAt ? ` — resets ${resetAt}` : ""}. ` +
      `${serverMessage ? serverMessage + " " : ""}Nothing was routed or executed; retry after the reset.`);
    this.name = "DecidioRateLimitError";
  }
}

export class DecidioNetworkError extends Error {
  constructor(public endpoint: string, public op: string, public code: string | undefined, cause: unknown) {
    super(`[decidio] could not reach ${endpoint} during ${op}${code ? ` (${code})` : ""}. ` +
      (/localhost|127\.0\.0\.1/.test(endpoint) && code === "ECONNREFUSED"
        ? `A refused localhost connection usually means the SDK never saw your config: if your settings live in .env, run node with --env-file=.env (or export DECIDIO_API_URL — Decidio is https://mcp.decidioai.com). `
        : "") +
      `Nothing was executed locally and no verdict was received — if a request reached Decidio it is ` +
      `visible in your queue. ` +
      (/\/agent\/authorize/.test(op) ? `This SDK already retried it with the same request key. ` : "") +
      `Check the network/URL (DECIDIO_API_URL) and retry; retrying is safe — it can never double-execute.`);
    this.name = "DecidioNetworkError";
    (this as any).cause = cause;
  }
}
async function reach(f: typeof fetch, url: string, op: string, init?: any): Promise<Response> {
  try { return await f(url, init); }
  catch (e: any) { throw new DecidioNetworkError(url, op, e?.cause?.code ?? e?.code, e); }
}
/** THE ONE DESCRIBE VALIDATION (prodsec V033-05). The core wrapper refused a blank `action` and a
 *  negative / non-finite `amount` before routing; the adapter gate canonicalized and posted them, so
 *  every engine door reached the mock authorization path with a request the core would have refused.
 *  Exported so `adapters/_gate.ts` calls the same function rather than a second copy that can drift. */
export function assertDescribed(ctx: ApprovalContext): void {
  if (typeof ctx?.action !== "string" || ctx.action.trim().length === 0) {
    throw new Error(`[decidio] describe(...) must return an \`action\` string naming what is being asked (got ${JSON.stringify(ctx?.action ?? null)}). Nothing was routed or executed.`);
  }
  if (typeof ctx.amount !== "number" || !Number.isFinite(ctx.amount) || ctx.amount < 0) {
    throw new Error(`[decidio] describe(...) must return a finite, non-negative \`amount\` — the policy decides on it, so a request without one is not a request Decidio can rule on (got ${JSON.stringify(ctx.amount ?? null)}). Use 0 for an action with no monetary value. Nothing was routed or executed.`);
  }
}

async function post(cfg: GuardConfig, path: string, body: unknown): Promise<any> {
  const f = cfg.fetchImpl ?? fetch;
  assertSafeTransport(cfg.apiUrl, carriesCredential(cfg));
  const res = await reach(f, cfg.apiUrl.replace(/\/$/, "") + path, `POST ${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(cfg.apiToken ? { authorization: `Bearer ${cfg.apiToken}` } : {}) },
    body: JSON.stringify(body),
  });
  if (res.status === 429) {
    const b: any = await res.json().catch(() => null);
    throw new DecidioRateLimitError(b?.limit, b?.remaining, b?.resetAt, b?.message, typeof b?.code === "string" ? b.code : undefined);
  }
  if (!res.ok) {
    const raw = await res.text().catch(() => "");
    let parsed: unknown = raw; try { parsed = raw ? JSON.parse(raw) : undefined; } catch { }
    throw new DecidioHttpError(res.status, path, parsed);
  }
  return res.json();
}
function retriesSafely(e: unknown): boolean {
  if (e instanceof DecidioNetworkError) return true;
  if (e instanceof DecidioRateLimitError) return e.code !== "AGENT_RATE";
  if (e instanceof DecidioHttpError) return (e.status >= 500 && e.status !== 501) || (e.status === 429 && (e.body as { code?: unknown } | undefined)?.code !== "AGENT_RATE");
  return false;
}

/** THE ONE AUTHORIZE POST (0.12.0, 11f) - the core wrapper and every engine adapter send through here. A network failure
 *  or a transient answer is retried a bounded number of times with the SAME body: under a request key that is the same
 *  request (the gate answers the decision it already made, `idempotentReplay`), and a keyless request asked again while
 *  it waits joins the one waiting (`openTwin`). A body that carries a commitment WITHOUT a key is never retried - nothing
 *  would make the retry the same request. `rateLimit: "http"` keeps an adapter's 429 a DecidioHttpError, as it always was. */
export async function sendAuthorize(config: GuardConfig, first: Record<string, unknown>, opts: { rateLimit?: "typed" | "http"; resign?: () => unknown } = {}): Promise<any> {
  const mayRetry = !!first.idempotencyKey || !first.requestCommitment;
  let body = first;
  const once = async (): Promise<any> => {
    if ((opts.rateLimit ?? "typed") === "typed") return post(config, "/agent/authorize", body);
    const f = config.fetchImpl ?? fetch;
    assertSafeTransport(config.apiUrl, carriesCredential(config));
    const res = await reach(f, config.apiUrl.replace(/\/$/, "") + "/agent/authorize", "POST /agent/authorize", {
      method: "POST",
      headers: { "content-type": "application/json", ...(config.apiToken ? { authorization: `Bearer ${config.apiToken}` } : {}) },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const raw = await res.text().catch(() => "");
      let parsed: unknown = raw; try { parsed = raw ? JSON.parse(raw) : undefined; } catch { }
      throw new DecidioHttpError(res.status, "/agent/authorize", parsed);
    }
    return res.json();
  };
  for (let attempt = 0; ; attempt++) {
    try { return await once(); }
    catch (e) {
      if (!mayRetry || attempt >= RETRY_DELAYS_MS.length || !retriesSafely(e)) throw e;
      await sleep(RETRY_DELAYS_MS[attempt]!);
      const fresh = first.requesterIdentity && opts.resign ? opts.resign() : undefined;
      if (fresh) body = { ...first, requesterIdentity: fresh };
    }
  }
}

/** The typed refusal for a claim that did not let this run go ahead (0.12.0) - DecidioBlockedError, so code that treats
 *  a block as "did not run" keeps doing so; the words say what happened and what to do ("ask again"). */
export function claimRefusal(claim: ClaimOutcome): DecidioBlockedError {
  return new DecidioBlockedError(claim.ok ? "the approval was collected" : claim.reason, claim.decisionId);
}

async function get(cfg: GuardConfig, path: string): Promise<any> {
  const f = cfg.fetchImpl ?? fetch;
  assertSafeTransport(cfg.apiUrl, carriesCredential(cfg));
  const res = await reach(f, cfg.apiUrl.replace(/\/$/, "") + path, `GET ${path}`, {
    headers: { ...(cfg.apiToken ? { authorization: `Bearer ${cfg.apiToken}` } : {}) },
  });
  if (!res.ok) throw new DecidioHttpError(res.status, path);
  return res.json();
}

/**
 * Wrap an async action behind the Decidio gate. `describe` extracts the approval
 * context (action, amount, scope) from the call arguments. Returns a function with
 * the SAME signature as `fn` — drop-in.
 */
/** `<appUrl>/d/<decisionId>` — the deep link that opens this decision directly, on the web app or
 *  the phone build. Null when DECIDIO_APP_URL is not configured, never a half-built URL. */
export function decisionUrl(appUrl: string | undefined, decisionId: string): string | null {
  if (!appUrl) return null;
  return `${appUrl.replace(/\/$/, "")}/d/${encodeURIComponent(decisionId)}`;
}

/** What a protected call returns in 0.2.0: your function's value, the decision it was authorized
 *  under, and what Decidio actually recorded about the execution.
 *
 *  Through 0.1.x this was just `R`. The SDK computed the full confirmation outcome — tier, whether
 *  the report was recorded, whether the signed execution report verified, whether the evidence
 *  mapper failed — and then dropped it on the floor, surfacing it only as a console warning. For a
 *  product whose value IS the record, the one thing a caller could not do was find out what got
 *  recorded. Returning it makes "my action ran but was logged as an unproven assertion" something
 *  code can branch on instead of something a human might notice in a log.
 *
 *  `protectBestEffort` keeps the old value-only shape for callers that genuinely do not care. */
export interface ProtectedExecution<R> {
  /** Exactly what your function returned — unchanged, uncanonicalized, your object. */
  value: R;
  /** The decision this execution was authorized under. Use it as your downstream idempotency key. */
  decisionId: string;
  /** What Decidio recorded. `reportRecorded` false means the execution happened and Decidio does
   *  NOT know; `executionConfirmed` false means it knows but could not attest a commit. */
  confirmation: EvidenceOutcome;
  /** The request key this call sent with its authorize (0.12.0, 11f) - absent when none was sent (no key material, so no
   *  commitment). It names the REQUEST to Decidio; your downstream idempotency key stays `decisionId`. */
  requestKey?: string;
}

export function withApproval<A extends any[], R>(
  fn: (...args: A) => Promise<R>,
  describe: (...args: A) => ApprovalContext,
  config: GuardConfig,
  opts?: {
    /** Map YOUR function's natural return value to the evidence Decidio records. The gate awards
     *  its strongest wrapper tier (application_confirmed) only for a committed record id plus a
     *  success indication — this lets a real API keep its own shape instead of being forced into
     *  magic field names: `evidence: (r) => ({ recordId: r.transactionId, success: r.status === "committed" })`. */
    evidence?: (result: R) => unknown;
    /** Hand the action an `ExecutionContext` as its FIRST argument: `{ decisionId, attemptId,
     *  idempotencyKey }`. Opt-in, never inferred from the function's arity — guessing wrong means
     *  passing a context object as someone's first business argument. */
    withContext?: boolean;
    /** YOUR OWN REQUEST KEY for a call (0.12.0, 11f), from its arguments - an order or invoice id - so the same call asked
     *  again, even from a new process, is the same request. Keyed with this agent's material before it is sent (your id
     *  never reaches Decidio in the clear). The same key for a CHANGED request is refused by the gate (409
     *  IDEMPOTENCY_CONFLICT), never a silent second request. Without it each call sends a fresh random key. */
    requestKey?: (...args: A) => string;
  },
): (...args: A) => Promise<ProtectedExecution<R>> {
  const pollInterval = config.pollIntervalMs ?? 2_000;
  const pollTimeout = config.pollTimeoutMs ?? 600_000;

  const resumeUrl = config.resumeUrl ?? config.resume?.resumeUrl;

  return async (...rawArgs: A): Promise<ProtectedExecution<R>> => {
    const args = canonicalizeArgs(rawArgs) as unknown as A;
    let ctx: ApprovalContext;
    try {
      ctx = describe(...args);
    } catch (e: any) {
      if (e instanceof TypeError && /read only|not extensible|object is not extensible|frozen/i.test(e.message ?? "")) {
        throw new TypeError(
          `[decidio] your describe() callback tried to MODIFY the call arguments (${e.message}). ` +
          `Those arguments are the approved value: they are what a human sees, what the signature covers, ` +
          `what is parked for a durable resume, and what your function ultimately runs on — so changing them ` +
          `here would mean the action that executes is not the action that was approved. Read from the ` +
          `arguments and RETURN the context instead: (inv) => ({ action: "pay", amount: inv.amount }). ` +
          `If you need a modified value at execution time, compute it inside your function. ` +
          `Nothing was routed or executed.`,
        );
      }
      throw e;
    }
    ctx = canonicalize<ApprovalContext>(ctx as unknown, "describe(...)");
    const requesterIdentity = (config.agentKey && config.agentDid)
      ? signBoundProof(config.agentKey, { agentId: config.agentId, did: config.agentDid, action: ctx.action, amount: ctx.amount, scope: ctx.scope, workspaceId: config.workspaceId })
      : undefined;
    assertDescribed(ctx);
    const material = bindingMaterial(config);
    const committed = coreRequest(ctx, args as readonly unknown[]);
    const sentCommitment = material ? requestCommitment(material, committed) : undefined;
    let requestKey: string | undefined;
    if (opts?.requestKey) {
      const own = opts.requestKey(...args);
      if (typeof own !== "string" || own.length === 0) throw new Error(`[decidio] requestKey(...) must return a non-empty string naming this call (got ${JSON.stringify(own ?? null)}). Nothing was routed or executed.`);
      if (!material) throw new Error("[decidio] requestKey needs this agent's key material (DECIDIO_AGENT_KEY + DECIDIO_AGENT_DID, or DECIDIO_API_TOKEN): a key rides only beside the request commitment that material makes, and Decidio refuses one alone. Nothing was routed or executed.");
      requestKey = ownRequestKey(material, own);
    } else if (material && sentCommitment) {
      requestKey = invocationRequestKey(material, config.invocationId ? String(config.invocationId()) : randomUUID(), sentCommitment);
    }
    const auth: AuthorizeResponse = await sendAuthorize(config, {
      requester: config.agentId, action: ctx.action, amount: ctx.amount,
      scope: ctx.scope, sourceSystem: config.sourceSystem,
      ...(ctx.context ? { context: ctx.context } : {}),
      ...(requesterIdentity ? { requesterIdentity } : {}),
      ...(resumeUrl ? { resumeUrl } : {}),
      ...(sentCommitment ? { requestCommitment: sentCommitment } : {}),
      ...(requestKey ? { idempotencyKey: requestKey } : {}),
    }, {
      resign: () => (config.agentKey && config.agentDid)
        ? signBoundProof(config.agentKey, { agentId: config.agentId, did: config.agentDid, action: ctx.action, amount: ctx.amount, scope: ctx.scope, workspaceId: config.workspaceId })
        : undefined,
    });

    if (auth.decision !== "proceed" && auth.decision !== "route" && auth.decision !== "block")
      throw new DecidioBlockedError(`unrecognized gate verdict: ${String(auth.decision)}`, auth.decisionId);

    const idProblem = decisionIdProblem(auth.decisionId);
    if (idProblem)
      throw new DecidioBlockedError(
        `the gate answered "${auth.decision}" with no usable decisionId (${JSON.stringify(auth.decisionId ?? null)} — ${idProblem}) — refusing to execute. Every authorized action must be addressable: without an id it cannot be polled, resumed, confirmed or audited.`,
        typeof auth.decisionId === "string" ? auth.decisionId : String(auth.decisionId ?? ""),
      );

    if (auth.decision === "block") throw new DecidioBlockedError(auth.reason ?? "blocked by policy", auth.decisionId);

    if (auth.decision === "route") {
      const approvalUrl = decisionUrl(config.appUrl, auth.decisionId);
      if (config.onPending) config.onPending({ decisionId: auth.decisionId, receiptId: auth.receiptId, url: approvalUrl });
      else console.error(`[decidio] ${ctx.action} is awaiting approval (decision ${auth.decisionId}) — approve it ${approvalUrl ? `at ${approvalUrl}` : `in your Decidio queue, or: npx @decidio/sdk approvals approve ${auth.decisionId}`}`);

      if (config.resume) {
        config.resume.agentId ??= config.agentId;
        config.resume.agentKey ??= config.agentKey;
        config.resume.agentDid ??= config.agentDid;
        config.resume.register(ctx.action, fn as (...a: any[]) => Promise<any>, opts?.evidence as ((r: any) => unknown) | undefined);
        await config.resume.park({
          decisionId: auth.decisionId, receiptId: auth.receiptId,
          action: ctx.action, amount: ctx.amount, scope: ctx.scope, args,
          ...(sentCommitment ? { requestCommitment: sentCommitment } : {}),
        });
        throw new DecidioSuspendedError(auth.decisionId, ctx.action);
      }

      const deadline = Date.now() + pollTimeout;
      let approvedStatus: StatusResponse | undefined;
      while (true) {
        const st: StatusResponse = await get(config, `/agent/status/${encodeURIComponent(auth.decisionId)}`);
        if (st.state === "approved" || st.state === "auto_approved") { approvedStatus = st; break; }
        if (st.state === "rejected") throw new DecidioRejectedError(st.reason ?? "rejected by approver", auth.decisionId);
        if (st.state === "blocked") throw new DecidioBlockedError(st.reason ?? "blocked", auth.decisionId);
        if (Date.now() > deadline) {
          let withdrawn = false;
          let lateState: string | null = null;
          let shared = auth.idempotentReplay === true || auth.openTwin === true;
          if (!shared) {
            try { await post(config, `/agent/withdraw/${encodeURIComponent(auth.decisionId)}`, { reason: "timeout" }); withdrawn = true; }
            catch (e) {
              if (e instanceof DecidioHttpError && e.status === 409 && typeof (e.body as { state?: unknown } | undefined)?.state === "string") lateState = (e.body as { state: string }).state;
              else if (e instanceof DecidioHttpError && e.status === 409 && (e.body as { code?: unknown } | undefined)?.code === "SHARED_REQUEST") shared = true;
            }
          }
          if (lateState === "approved" || lateState === "auto_approved") break;
          if (lateState === "rejected") throw new DecidioRejectedError("rejected by approver", auth.decisionId);
          if (lateState === "blocked") throw new DecidioBlockedError("blocked", auth.decisionId);
          console.warn(`[decidio] blocking wait hit its ${Math.round(pollTimeout / 1000)}s limit — decision ${auth.decisionId} ${withdrawn ? "was withdrawn in Decidio (the queue no longer shows it; a later approval does nothing)" : shared ? "is shared with another caller (or an earlier try of this one), so it was left open for a person to decide - this process stopped waiting" : "is still open in Decidio (the withdraw call failed), but this process stopped waiting"} and nothing was executed. Re-run to request again, or use durable resume (guard.worker()) so an approval is never lost.`);
          throw new DecidioTimeoutError(auth.decisionId, withdrawn, shared);
        }
        await sleep(pollInterval);
      }
      const check = await checkApproval(config, auth.decisionId, committed, { sent: !!sentCommitment, ...(approvedStatus ? { status: approvedStatus } : {}) });
      if (!check.ok) throw approvalRefusal(check);
      if (check.state === "approved") {
        const claimed = await claimApproval(config, auth.decisionId, newClaimKey());
        if (!claimed.ok) throw claimRefusal(claimed);
      }
    }

    const result = opts?.withContext
      ? await (fn as unknown as (...a: unknown[]) => Promise<R>)({ decisionId: auth.decisionId, attemptId: null, idempotencyKey: auth.decisionId }, ...args)
      : await fn(...args);

    let reported: unknown = null;
    let evidenceProblem: string | undefined;
    try {
      const evidenceOf = (opts?.evidence ?? ((r: unknown) => r)) as (r: unknown) => unknown;
      reported = canonicalize(evidenceOf(result) ?? null, "evidence(result)");
    } catch (e: any) {
      evidenceProblem = String(e?.message ?? e);
      console.warn(`[decidio] ${auth.decisionId}: the action SUCCEEDED but its result could not be reported as evidence (${evidenceProblem}). Reporting an empty captured response so the execution is still recorded — map the return value with the \`evidence\` option (e.g. evidence: (r) => ({ recordId: String(r.id), success: true })) to earn a confirming tier. The action was NOT re-run.`);
    }
    let confirmation: EvidenceOutcome;
    try {
      const confirmIdentity = signConfirm(auth.decisionId, config);
      const confirmBody = await post(config, "/agent/confirm", buildConfirmBody(config, auth.decisionId, reported, confirmIdentity));
      confirmation = readConfirmResponse(confirmBody, { signed: !!confirmIdentity, capturedResponse: reported, journalled: false });
      if (!confirmation.reportRecorded) console.warn(`[decidio] ${auth.decisionId}: ${confirmation.diagnostic}`);
      else if (!confirmation.executionConfirmed || confirmation.executionReportVerified === false) console.warn(`[decidio] execution evidence for ${auth.decisionId} recorded as ${confirmation.evidenceTier} — ${confirmation.diagnostic}`);
      if (evidenceProblem) console.warn(`[decidio] ${auth.decisionId}: the execution IS recorded, but with an empty captured response — see the evidence note above.`);
    } catch (e: any) {
      const isHttp = e instanceof DecidioHttpError;
      console.warn(`[decidio] confirmation post failed (action succeeded): ${e?.message ?? e}`);
      confirmation = {
        reportRecorded: false,
        executionConfirmed: false,
        confirmationRetryable: isHttp ? (e as DecidioHttpError).retryable : true,
        reportJournalled: false,
        diagnostic: `your action RAN and Decidio does NOT have its execution report (${e?.message ?? e}). This path journals nothing, so there is no local copy to re-send: record the outcome from your own system. Durable mode DOES journal reports, and its recovery path can re-send them — that is the mode to use if this matters to you. Do NOT re-run the action.`,
      };
    }
    if (evidenceProblem) confirmation.evidenceError = evidenceProblem;

    return { value: result, decisionId: auth.decisionId, confirmation, ...(requestKey ? { requestKey } : {}) };
  };
}
