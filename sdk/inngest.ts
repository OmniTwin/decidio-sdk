import type { IncomingMessage, ServerResponse, RequestListener } from "node:http";
import { verifyResumeSignature, WEBHOOK_SECRET_REMEDY } from "./resume.js";
import { gateAuthorize, gateConfirm, assertAuthorizeVerdict, gateCheckApproval, assertApprovalCheckShape, checkEngineVersion } from "./adapters/_gate.js";
import { approvalRefusal, type GuardConfig, type ApprovalContext, type EvidenceOutcome } from "./index.js";

/** The Inngest event Decidio's verdict is translated into. The waiting function
 *  correlates on `data.decisionId`. */
export const DECIDIO_RESUME_EVENT = "decidio/decision.resolved";

/** The minimal slices of the Inngest step + client APIs we use, typed structurally so
 *  this file doesn't force an `inngest` type dependency on the core build. */
export interface InngestStepLike {
  run<T>(id: string, fn: () => Promise<T>): Promise<T>;
  waitForEvent(
    id: string,
    opts: { event: string; timeout: string; match?: string; if?: string },
  ): Promise<{ name: string; data?: Record<string, any> } | null>;
}
export interface InngestClientLike {
  send(event: { name: string; data: Record<string, any> }): Promise<unknown>;
}

/** ONE RESULT SHAPE ACROSS EVERY DOOR (F-008), with the one field this door genuinely needs on
 *  top of it. `status` stays because Inngest's durable path can legitimately end in `rejected` or
 *  `blocked` without ever calling your action — the other adapters signal that by throwing. What
 *  changed: the value is `value` (not `result`) so it reads the same as every other door, and
 *  `confirmation` is CARRIED rather than discarded. It used to be thrown away inside the confirm
 *  step, which made "it ran and Decidio recorded it" and "it ran and Decidio does not know"
 *  indistinguishable to the caller. */
export type GateStepOutcome<R> =
  /** The action ran: the value AND what Decidio recorded (the step confirms before it returns). Encoded in the
   *  type, not only in prose (prodsec V040-02): narrow on `status` and `confirmation` is there. */
  | { status: "executed"; decisionId: string; value: R; confirmation: EvidenceOutcome; requestKey?: string }
  /** The action never ran — a human said no, or a rule blocked it — so there is nothing to confirm. */
  | { status: "rejected" | "blocked"; decisionId: string; value?: undefined; confirmation?: undefined };

/**
 * Gate an action INSIDE an Inngest function, with durable suspend on routing.
 *   • proceed → run the action (as a step) + confirm.
 *   • route   → `step.waitForEvent` durably suspends until Decidio's resume event for
 *               THIS decision arrives - a WAKE-UP (0.7.0): a memoized step then confirms with
 *               Decidio that THIS request was approved; approved → run + confirm; rejected /
 *               blocked → status; still pending → wait for the next event; the request changed
 *               after approval → DecidioRequestChangedError.
 *   • block   → return blocked (the action never runs).
 * The action runs in YOUR process with YOUR credentials — Decidio only signals.
 * `config.resumeUrl` must point at the bridge endpoint (createInngestResumeBridge),
 * so Decidio's webhook is translated into the event this step waits on.
 */
export async function decidioGateStep<R>(args: {
  step: InngestStepLike;
  config: GuardConfig;
  ctx: ApprovalContext;
  run: () => Promise<R>;
  timeout?: string;
  /** Map your action's return value to the evidence Decidio records — the same option the core
   *  path takes. This door's own confirm chokepoint tells callers to use it; until 0.2.0 no
   *  adapter door accepted one, so the advice was unfollowable everywhere it was printed. */
  evidence?: (result: R) => unknown;
  /** Inngest's id for THIS function run - the handler's `runId` (0.12.0, 11f). The request key is keyed on it, so Inngest
   *  retrying the authorize step is the same request while it waits. Without it the key is
   *  over a fresh id for the call (a retried step may then ask again). */
  runId?: string;
}): Promise<GateStepOutcome<R>> {
  const { step, config, ctx } = args;

  const auth = await step.run("decidio-authorize", async () => gateAuthorize(config, ctx, typeof args.runId === "string" && args.runId ? { naturalId: { engine: "inngest", runId: args.runId, step: "decidio-authorize" } } : {}));
  assertAuthorizeVerdict(auth, auth?.decisionId);

  if (auth.decision === "block") return { status: "blocked", decisionId: auth.decisionId };

  if (auth.decision === "route") {
    for (let n = 0; ; n++) {
      const suffix = n === 0 ? "" : `-${n}`;
      const ev = await step.waitForEvent(`decidio-await-approval${suffix}`, {
        event: DECIDIO_RESUME_EVENT,
        timeout: args.timeout ?? "30d",
        if: `async.data.decisionId == "${auth.decisionId}"`,
      });
      if (!ev) throw new Error(`decidio approval timed out (${auth.decisionId})`);
      const check = assertApprovalCheckShape(
        await step.run(`decidio-verify-approval${suffix}`, async () => gateCheckApproval(config, auth.decisionId, ctx)),
        auth.decisionId,
      );
      if (check.ok) break;
      if (check.code === "rejected") return { status: "rejected", decisionId: auth.decisionId };
      if (check.code === "blocked") return { status: "blocked", decisionId: auth.decisionId };
      if (check.code !== "pending") throw approvalRefusal(check);
    }
  }

  const result = await step.run("agent-action", args.run);
  const confirmation = await step.run("decidio-confirm", async () =>
    gateConfirm(config, auth.decisionId, result, args.evidence as ((r: any) => unknown) | undefined)) as EvidenceOutcome;
  return { status: "executed", decisionId: auth.decisionId, value: result, confirmation, ...(typeof auth.requestKey === "string" ? { requestKey: auth.requestKey } : {}) };
}

/**
 * Decidio → Inngest bridge. Mount as an HTTP endpoint and register it as the agent's
 * `resumeUrl`. It verifies Decidio's signed resume webhook (same HMAC as the core
 * handler) and emits `DECIDIO_RESUME_EVENT` into Inngest, waking the suspended
 * `decidioGateStep`. Fails CLOSED without a configured secret (unless allowUnsigned).
 */
export function createInngestResumeBridge(opts: {
  inngest: InngestClientLike;
  webhookSecret?: string;
  allowUnsigned?: boolean;
  eventName?: string;
}): RequestListener {
  const secret = opts.webhookSecret ?? "";
  const eventName = opts.eventName ?? DECIDIO_RESUME_EVENT;
  if (!secret && opts.allowUnsigned) console.warn("[decidio] inngest resume bridge: allowUnsigned=true and no webhookSecret — resume signals are NOT authenticated; anyone who can reach this endpoint can emit a resume event. Development only.");
  return (req: IncomingMessage, res: ServerResponse) => {
    if (req.method !== "POST") { res.statusCode = 405; return res.end("method not allowed"); }
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", async () => {
      try {
        if (!secret) {
          if (!opts.allowUnsigned) { res.statusCode = 401; return res.end(JSON.stringify({ error: `resume webhook unsigned and no secret configured. ${WEBHOOK_SECRET_REMEDY}` })); }
        } else if (!verifyResumeSignature(secret, raw, req.headers["x-decidio-signature"] as string | undefined)) {
          res.statusCode = 401; return res.end(JSON.stringify({ error: "bad signature" }));
        }
        const body = JSON.parse(raw || "{}");
        await opts.inngest.send({ name: eventName, data: { decisionId: String(body.decisionId), verdict: body.verdict, reason: body.reason ?? null } });
        res.statusCode = 200; res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true, forwarded: eventName, decisionId: body.decisionId }));
      } catch (e: any) {
        res.statusCode = 500; res.end(JSON.stringify({ error: e?.message ?? "bridge failed" }));
      }
    });
  };
}

export { verifyResumeSignature };

checkEngineVersion("inngest");
