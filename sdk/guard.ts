import { withApproval, type GuardConfig, type ApprovalContext, type ProtectedExecution } from "./index.js";
import { createDecidioResume, FilePendingStore, type ResumeController, type ResumeOutcome } from "./resume.js";
import { join } from "node:path";

export interface GuardFacadeConfig {
  apiUrl: string;
  agentId: string;
  apiToken?: string;
  sourceSystem?: string;
  resumeUrl?: string;
  webhookSecret?: string;
  pendingDir?: string;
  /** Local signing key (DECIDIO_AGENT_KEY) + public did (DECIDIO_AGENT_DID), from `init`.
   *  When present the gate authorizes against a PROVEN identity, not a claimed label. */
  agentKey?: string;
  agentDid?: string;
  /** The workspace this agent acts in (DECIDIO_WORKSPACE_ID). Bound into the signed proof (D-B3.6)
   *  so a captured proof can't be replayed in another tenant. */
  workspaceId?: string;
  /** Base URL of the Decidio app (DECIDIO_APP_URL) — used to deep-link a routed decision. */
  appUrl?: string;
  /** The per-call id behind the default request key (0.12.0) - see GuardConfig.invocationId. Leave it unset. */
  invocationId?: () => string;
  fetchImpl?: typeof fetch;
}

export interface ProtectOptions {
  /** null/"generic" → the core gate; engine adapters (langgraph/openai/temporal/inngest)
   *  live in @decidio/sdk subpaths and take the engine handle.
   *
   *  BETA: the engine adapters share the core's gate semantics (verdict allow-list, canonical
   *  arguments, transport rule and evidence handling are one implementation, conformance-tested
   *  across every door), but their ENGINE integration is verified against structural mocks, not
   *  live engines. Use the core path for production until that changes. */
  adapter?: "generic" | "langgraph" | "openai" | "temporal" | "inngest";
  /** Hand the action an `ExecutionContext` as its FIRST argument: `{ decisionId, attemptId,
   *  idempotencyKey }`. Pass `idempotencyKey` to your downstream API and the one window this SDK
   *  cannot close — the vendor committing twice — closes on their side. Opt-in by design: arity
   *  inspection would have to guess, and guessing wrong hands a payment call a context object
   *  where it expected an invoice. */
  withContext?: boolean;
  /** "durable" (default) suspends for async approval; "blocking" polls (short approvals only). */
  mode?: "durable" | "blocking";
  /** The action name this wrapper produces, declared UP FRONT so the resume registry is populated
   *  at WRAP time rather than on first call. Required for the cold-worker pattern: after a
   *  restart, `guard.worker()` can only re-execute actions registered in THIS process, and
   *  `describe` (which names the action) cannot run without the original call arguments. Declare
   *  it and a restarted process resumes work it never originated. */
  action?: string;
  /** Blocking-mode poll ceiling in ms (default 600000 = 10 min). Set it here so a CI pipeline
   *  fails fast instead of blocking the full 10-minute default while a routed action waits.
   *  Accepted identically by the Python SDK (poll_timeout, seconds). */
  pollTimeoutMs?: number;
  /** Blocking-mode poll interval in ms (default 3000). */
  pollIntervalMs?: number;
  /** Map YOUR function's natural return value to the evidence Decidio records. The gate awards
   *  its strongest wrapper tier (application_confirmed) only for a committed record id plus a
   *  success indication, so instead of forcing your API into magic field names:
   *  `evidence: (r) => ({ recordId: r.transactionId, success: r.status === "committed" })`. */
  evidence?: (result: any) => unknown;
  /** YOUR OWN REQUEST KEY for a call, from its arguments (0.12.0) - e.g. `(inv) => inv.id` - so the same call asked again,
   *  even from a new process, is the same request. Without it each call sends a fresh random key. See withApproval. */
  requestKey?: (...args: any[]) => string;
}

export class Guard {
  private _resume?: ResumeController;
  constructor(public config: GuardFacadeConfig, resume?: ResumeController) {
    this._resume = resume;
  }

  /** The recovery surface — `guard.resume.recover()` / `.reconfirm(id)`. BUILT ON FIRST ACCESS,
   *  because the process that needs to recover is usually a COLD one that never made the original
   *  call, so nothing has lazily constructed the controller yet. As a plain field this read was
   *  `undefined` there and the documented recovery loop crashed on the exact path it exists for.
   *  Unconfigured still fails loud (naming DECIDIO_API_URL), never silently. */
  get resume(): ResumeController { return this.ensureResume(); }
  /** Kept writable: hosts that construct their own controller (custom store, injected fetch)
   *  assign it here, and `new Guard(cfg, controller)` must stay equivalent to that assignment. */
  set resume(r: ResumeController) { this._resume = r; }

  static fromEnv(): Guard {
    return new Guard({
      apiUrl: process.env.DECIDIO_API_URL ?? "",
      agentId: process.env.DECIDIO_AGENT_ID ?? "agent",
      apiToken: process.env.DECIDIO_API_TOKEN,
      sourceSystem: process.env.DECIDIO_SOURCE_SYSTEM,
      resumeUrl: process.env.DECIDIO_RESUME_URL,
      webhookSecret: process.env.DECIDIO_WEBHOOK_SECRET,
      pendingDir: process.env.DECIDIO_PENDING_DIR,
      agentKey: process.env.DECIDIO_AGENT_KEY,
      agentDid: process.env.DECIDIO_AGENT_DID,
      workspaceId: process.env.DECIDIO_WORKSPACE_ID,
      appUrl: process.env.DECIDIO_APP_URL,
    });
  }

  /** Register a raw fn under its action name so a COLD process (one that never made the original
   *  call) can resume it. Call this at startup beside `guard.worker()` — or pass
   *  `{ action }` to `protect(...)`, which does it for you at wrap time. */
  register(action: string, fn: (...a: any[]) => Promise<any>, evidence?: (result: any) => unknown) { this.ensureResume().register(action, fn, evidence); }

  /** Mount on a node/Express/Fastify route: `app.post("/decidio/resume", guard.resumeHandler())`. */
  resumeHandler() { return this.ensureResume().webhookHandler(); }
  /** Mount on a Next.js/Hono/CF/Bun route: `export const POST = (req) => guard.resumeFetchHandler()(req)`. */
  resumeFetchHandler() { return this.ensureResume().fetchHandler(); }
  /** Durable resume with NOTHING to host: a background watcher polls Decidio outward and finishes
   *  any parked approval — so a suspended action survives a process restart. One line at startup.
   *  Production may swap this for the webhook (resumeUrl); the suspend/resume shape is identical. */
  worker(opts?: { intervalMs?: number; timeoutMs?: number; onResolved?: (o: ResumeOutcome) => void }) {
    return this.ensureResume().worker(opts);
  }

  private ensureResume(): ResumeController {
    this.assertConfigured();
    if (!this._resume) {
      const c = this.config;
      this._resume = createDecidioResume({
        apiUrl: c.apiUrl, apiToken: c.apiToken, webhookSecret: c.webhookSecret,
        resumeUrl: c.resumeUrl, store: new FilePendingStore(c.pendingDir ?? ".decidio-pending"),
        agentId: c.agentId, agentKey: c.agentKey, agentDid: c.agentDid, workspaceId: c.workspaceId,
        fetchImpl: c.fetchImpl,
      });
    }
    return this._resume;
  }

  /** Throws when the facade has no gate URL — at USE time, not import time, so `import { guard }`
   *  stays safe in envless contexts. */
  private assertConfigured(): void {
    if (!this.config.apiUrl) throw new Error("[decidio] no gate URL configured — set DECIDIO_API_URL (Decidio is https://mcp.decidioai.com) or run `npx @decidio/sdk init`, then start your process with `node --env-file=.env`. Nothing was routed or executed.");
  }

  /** Wrap a function so every call is authorized, recorded and — in 0.2.0 — REPORTED BACK.
   *
   *  Returns `{ value, decisionId, confirmation }`, not the bare value. Through 0.1.x it returned
   *  `R` and the confirmation outcome went to a console warning, so the one thing a caller of an
   *  authority SDK could not do was find out what Decidio recorded. If you genuinely do not need
   *  it, `protectBestEffort` keeps the old shape. */
  protect<A extends any[], R>(
    fn: (...a: A) => Promise<R>,
    describe: (...a: A) => ApprovalContext,
    opts?: ProtectOptions,
  ): (...a: A) => Promise<ProtectedExecution<R>> {
    this.assertConfigured();
    if (opts?.adapter && opts.adapter !== "generic") {
      const REAL = ["langgraph", "openai", "temporal", "inngest"] as const;
      if ((REAL as readonly string[]).includes(opts.adapter)) {
        throw new Error(`[decidio] adapter "${opts.adapter}" must be bound via the @decidio/sdk/${opts.adapter} subpath (it needs the engine handle). See that adapter's exports.`);
      }
      throw new Error(`[decidio] unknown adapter "${opts.adapter}" — the available engine adapters are ${REAL.map((a) => `"${a}"`).join(", ")} (each via its @decidio/sdk/<name> subpath), or omit the option for the core gate.`);
    }
    const c = this.config;
    const base: GuardConfig = {
      apiUrl: c.apiUrl, agentId: c.agentId, apiToken: c.apiToken,
      sourceSystem: c.sourceSystem, agentKey: c.agentKey, agentDid: c.agentDid, workspaceId: c.workspaceId, appUrl: c.appUrl, fetchImpl: c.fetchImpl,
      ...(c.invocationId ? { invocationId: c.invocationId } : {}),
      pollTimeoutMs: opts?.pollTimeoutMs, pollIntervalMs: opts?.pollIntervalMs,
    };
    if ((opts?.mode ?? "durable") === "blocking") {
      const ceilingMs = opts?.pollTimeoutMs ?? base.pollTimeoutMs ?? 600_000;
      console.warn(`[decidio] WARNING: blocking wait — this call gives up after ${Math.round(ceilingMs / 1000)}s ` +
        `(pollTimeoutMs), and when it does, this process stops waiting and the request is withdrawn in Decidio: ` +
        `a later approval does nothing. Only safe for short, watched approvals — omit mode:"blocking" for ` +
        `durable async resume on real (minutes-to-days) approvals.`);
      return withApproval(fn, describe, base, { ...(opts?.evidence ? { evidence: opts.evidence as (r: R) => unknown } : {}), ...(opts?.withContext ? { withContext: true } : {}), ...(opts?.requestKey ? { requestKey: opts.requestKey as (...a: A) => string } : {}) });
    }
    const resume = this.ensureResume();
    if (opts?.action) resume.register(opts.action, fn as (...a: any[]) => Promise<any>, opts?.evidence as ((r: any) => unknown) | undefined, opts?.withContext);
    return withApproval(fn, describe, { ...base, resumeUrl: c.resumeUrl, resume }, { ...(opts?.evidence ? { evidence: opts.evidence as (r: R) => unknown } : {}), ...(opts?.withContext ? { withContext: true } : {}), ...(opts?.requestKey ? { requestKey: opts.requestKey as (...a: A) => string } : {}) });
  }

  /** @deprecated The 0.1.x shape: resolves to your function's value alone and DISCARDS what
   *  Decidio recorded. Kept because a caller who truly does not care should not have to
   *  destructure — but "the report was not recorded" and "the execution could not be attested"
   *  become invisible again, which is the gap 0.2.0 exists to close. Prefer `protect`. */
  protectBestEffort<A extends any[], R>(
    fn: (...a: A) => Promise<R>,
    describe: (...a: A) => ApprovalContext,
    opts?: ProtectOptions,
  ): (...a: A) => Promise<R> {
    const wrapped = this.protect(fn, describe, opts);
    return async (...a: A): Promise<R> => (await wrapped(...a)).value;
  }
}

/** Preconfigured singleton — `import { guard } from "@decidio/sdk"`. */
export const guard = Guard.fromEnv();
