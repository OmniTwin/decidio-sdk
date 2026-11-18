import { condition, defineSignal, setHandler, uuid4 } from "@temporalio/workflow";
import { createRequire } from "node:module";
import { DecidioBlockedError, approvalRefusal, claimRefusal, newClaimKey, type GuardConfig, type ApprovalContext, type ProtectedExecution, type EvidenceOutcome, type ApprovalCheck, type ClaimOutcome } from "../index.js";
import { gateAuthorize, gateConfirm, gateCheckApproval, gateClaim, assertApprovalCheckShape, assertClaimShape, type GateAuth, checkEngineVersion, assertAuthorizeVerdict } from "./_gate.js";

/**
 * @decidio/sdk/temporal — durable suspend via Temporal's native `condition()` + a
 * Decidio resume signal. Strongest durability (the workflow survives worker restarts for
 * days); the agent's action runs on resume. Requires @temporalio/workflow (optional peer).
 *
 * Inside your workflow:
 * const verdicts = installDecidioSignal();                 // wires the resume signal
 * const out = await decidioGate(config, ctx, () => createOpp(o), verdicts, {
 * authorize: () => executeActivity(authorizeActivity, ...),   // HTTP belongs in activities; body: return authorizeActivity(config, ctx)
 * verify:    (id) => executeActivity(verifyActivity, id),      // body: return verifyApprovalActivity(config, id, ctx)
 * claim:     (id, key) => executeActivity(claimActivity, id, key), // body: return claimApprovalActivity(config, id, key)
 * confirm:   (id, r) => executeActivity(confirmActivity, ...),
 * });
 * Decidio's webhook bridges to: handle.signal(decidioResumeSignal, decisionId, verdict, reason)
 *
 * THE SIGNAL IS A WAKE-UP (0.7.0). Before 0.7.0 the action ran on the signal alone, so anyone who could
 * signal the workflow with the decisionId approved it. Now the signal only wakes the workflow; `verify`
 * then confirms with Decidio that THIS request was approved (GET /agent/status + the request
 * commitment) before `run()`. Still pending → keep waiting for the next signal; rejected/blocked/changed
 * → the typed refusal. `verify` is HTTP, so it must be an ACTIVITY, never workflow code (determinism) -
 * and it is required whenever `authorize` is.
 *
 * ONE APPROVAL, ONE RUN (0.12.0, founder call 24): once Decidio confirms a PERSON'S approval, the workflow collects
 * it (`claim`, an activity) with a key made from the workflow's own deterministic uuid4 - the same key on a replay or an
 * activity retry, a different one in any other run - and runs only if Decidio says this run collected it. Another run
 * already used it, or it expired → DecidioBlockedError, and the action never runs. `claim` is required whenever
 * `authorize` is. A request key rides with every authorize: `authorizeActivity` keys it on the activity's own workflow,
 * run and activity ids, so Temporal retrying the activity is the same request.
 *
 * (This wiring doc ships in the .d.ts — the README points here.)
 */
export const decidioResumeSignal = defineSignal<[string, string, (string | undefined)?]>("decidioResume");

/** Call inside the workflow to wire the resume signal; returns the signal store. Since 0.7.0 an entry is
 *  a WAKE-UP for its decision - the verdict it carries is informational and is consumed when the gate
 *  checks the approval with Decidio. */
export function installDecidioSignal(): Map<string, { verdict: string; reason?: string }> {
  const verdicts = new Map<string, { verdict: string; reason?: string }>();
  setHandler(decidioResumeSignal, (decisionId, verdict, reason) => { verdicts.set(decisionId, { verdict, reason }); });
  return verdicts;
}

/** The approval check as an ACTIVITY body (0.7.0) - register an activity that returns this, unchanged,
 *  and route `verify` through it. GET /agent/status + the request commitment recomputed over `ctx`, which
 *  must be the same context the gate authorized. Never call it from workflow code (it is HTTP). */
export function verifyApprovalActivity(config: GuardConfig, decisionId: string, ctx: ApprovalContext): Promise<ApprovalCheck> {
  return gateCheckApproval(config, decisionId, ctx);
}

/** The ids that name ONE activity execution across its retries: the workflow, its run, and the activity. */
export interface TemporalActivityIds { workflowId: string; runId: string; activityId: string }

function currentActivityIds(): TemporalActivityIds | undefined {
  try {
    const info = createRequire(import.meta.url)("@temporalio/activity").Context.current().info;
    const ids = { workflowId: info?.workflowExecution?.workflowId, runId: info?.workflowExecution?.runId, activityId: info?.activityId };
    return typeof ids.workflowId === "string" && typeof ids.runId === "string" && typeof ids.activityId === "string" ? ids as TemporalActivityIds : undefined;
  } catch { return undefined; }
}

/** The authorize ACTIVITY body (0.12.0) - register an activity that returns this, unchanged, and route `authorize`
 *  through it. The request key is keyed on Temporal's own ids for this activity (11f): passed as `ids`, or read from the
 *  running activity's context - so Temporal retrying the activity after a timeout is the SAME request while it waits.
 *  Outside an activity, with no `ids`, the key is over a fresh id for the call. */
export function authorizeActivity(config: GuardConfig, ctx: ApprovalContext, ids?: TemporalActivityIds): Promise<GateAuth> {
  const natural = ids ?? currentActivityIds();
  return gateAuthorize(config, ctx, natural ? { naturalId: { engine: "temporal", workflowId: natural.workflowId, runId: natural.runId, activityId: natural.activityId } } : {});
}

/** The claim as an ACTIVITY body (0.12.0, call 24) - register an activity that returns this, unchanged, and route `claim`
 *  through it: POST /agent/claim with the key the workflow made. Never call it from workflow code (it is HTTP). */
export function claimApprovalActivity(config: GuardConfig, decisionId: string, claimKey: string): Promise<ClaimOutcome> {
  return gateClaim(config, decisionId, claimKey);
}

function workflowClaimKey(): string {
  try { return `run_${uuid4()}`; } catch { return newClaimKey(); }
}

let confirmWarned = false;

export interface DecidioGateOpts<R = unknown> {
  authorize?: () => Promise<GateAuth>;
  /** THE APPROVAL CHECK, run after the resume signal and before `run()` (0.7.0). It is HTTP, so route it
   *  through an ACTIVITY whose body is `return verifyApprovalActivity(config, decisionId, ctx)` - the same
   *  `ctx` this gate authorized - and return that value unchanged. Required whenever `authorize` is
   *  supplied; without either it defaults to a direct call (tests only - a workflow must not do I/O). */
  verify?: (decisionId: string) => Promise<ApprovalCheck>;
  /** THE CLAIM (0.12.0, call 24), run after the approval check and before `run()` when a PERSON approved: collect the
   *  approval for this run, once. HTTP, so route it through an ACTIVITY whose body is
   *  `return claimApprovalActivity(config, decisionId, claimKey)` - return that value unchanged. Required whenever
   *  `authorize` is supplied; without either it defaults to a direct call (tests only). */
  claim?: (decisionId: string, claimKey: string) => Promise<ClaimOutcome>;
  /** Reports through YOUR activity. Return the gate's confirm response body (validated with
   *  `readConfirmResponse`) and it becomes the outcome; return nothing and the outcome says the SDK could
   *  not read back what Decidio recorded (prodsec V035-03: a returned outcome used to be discarded). */
  confirm?: (decisionId: string, result: unknown) => Promise<EvidenceOutcome | void>;
  /** Map your action's return value to the evidence Decidio records — the same option the core
   *  path takes. Every adapter's stderr note named it and no adapter accepted one, so on this
   *  path the advice could not be followed. */
  evidence?: (result: R) => unknown;
}

export async function decidioGate<R>(
  config: GuardConfig,
  ctx: ApprovalContext,
  run: () => Promise<R>,
  verdicts: Map<string, { verdict: string; reason?: string }>,
  opts: DecidioGateOpts<R> = {},
): Promise<ProtectedExecution<R>> {
  if (opts.authorize && !opts.verify) {
    throw new Error("[decidio] temporal: `authorize` runs in your activity, so the approval check must too - pass `verify: (decisionId) => executeActivity(verifyActivity, decisionId)`, where the activity returns verifyApprovalActivity(config, decisionId, ctx) (from @decidio/sdk/temporal) unchanged. Since 0.7.0 a resume signal only wakes the workflow; the approval is confirmed with Decidio before your action runs. Nothing was routed or executed.");
  }
  if (opts.authorize && !opts.claim) {
    throw new Error("[decidio] temporal: `authorize` runs in your activity, so the claim must too - pass `claim: (decisionId, claimKey) => executeActivity(claimActivity, decisionId, claimKey)`, where the activity returns claimApprovalActivity(config, decisionId, claimKey) (from @decidio/sdk/temporal) unchanged. Since 0.12.0 a person's approval is collected once, by the run that acts on it, before your action runs. Nothing was routed or executed.");
  }
  const auth = assertAuthorizeVerdict(await (opts.authorize ?? (() => authorizeActivity(config, ctx)))(), "unknown");
  if (auth.decision === "block") throw new DecidioBlockedError(auth.reason ?? "blocked by policy", auth.decisionId);
  if (auth.decision === "route") {
    const verify = opts.verify ?? ((decisionId: string) => gateCheckApproval(config, decisionId, ctx));
    for (;;) {
      await condition(() => verdicts.has(auth.decisionId));
      verdicts.delete(auth.decisionId);
      const check = assertApprovalCheckShape(await verify(auth.decisionId), auth.decisionId);
      if (check.ok) {
        if (check.state === "approved") {
          const claim = opts.claim ?? ((decisionId: string, claimKey: string) => gateClaim(config, decisionId, claimKey));
          const claimed = assertClaimShape(await claim(auth.decisionId, workflowClaimKey()), auth.decisionId);
          if (!claimed.ok) throw claimRefusal(claimed);
        }
        break;
      }
      if (check.code !== "pending") throw approvalRefusal(check);
    }
  } else if (auth.decision !== "proceed") {
    throw new DecidioBlockedError(`unhandled authorization verdict ${JSON.stringify((auth as { decision?: unknown }).decision)} — refusing to execute`, auth.decisionId);
  }
  const result = await run();
  let confirmation: EvidenceOutcome;
  if (opts.confirm) {
    if (opts.evidence) console.warn("[decidio] temporal: `evidence` is ignored when you supply `confirm` — your callback owns the report, so map the result inside it. Remove one of the two to make the intent clear.");
    const returned = await opts.confirm(auth.decisionId, result);
    const usable = !!returned && typeof returned === "object" && typeof (returned as EvidenceOutcome).reportRecorded === "boolean";
    confirmation = usable ? (returned as EvidenceOutcome) : {
      reportRecorded: false, executionConfirmed: false, confirmationRetryable: false, reportJournalled: false,
      diagnostic: "your own `confirm` callback reported this execution, so this SDK cannot read back what Decidio recorded. Check the record, or return the gate's response body from your activity and validate it with readConfirmResponse.",
    };
    if (!usable && !confirmWarned) { confirmWarned = true; console.warn(`[decidio] temporal: a custom \`confirm\` reports through your own activity, so this SDK cannot read back the evidence tier Decidio recorded. Check the record (or return the gate's response body from your activity and validate it with readConfirmResponse) if you need to know whether the execution was CONFIRMED, not merely reported.`); }
  } else {
    confirmation = await gateConfirm(config, auth.decisionId, result, opts?.evidence as ((r: any) => unknown) | undefined);
  }
  return { value: result, decisionId: auth.decisionId, confirmation, ...(typeof auth.requestKey === "string" ? { requestKey: auth.requestKey } : {}) };
}

checkEngineVersion("temporal");
