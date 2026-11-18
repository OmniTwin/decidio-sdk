import { gateAuthorize, gateCheckApproval, gateClaim, toolCallRequest, type GateAuth, checkEngineVersion } from "./_gate.js";
import { DecidioBlockedError, approvalRefusal, claimRefusal, decisionIdProblem, newClaimKey, type GuardConfig, type ApprovalContext } from "../index.js";

type ToolApprovalItem = any;
interface RunStateLike {
  getInterruptions(): ToolApprovalItem[];
  approve(item: ToolApprovalItem): void;
  reject(item: ToolApprovalItem): void;
}

/**
 * @decidio/sdk/openai — gate OpenAI Agents SDK tool-approval interruptions through
 * Decidio, with durable suspend via the SDK's native RunState serialization.
 *
 * The Agents loop surfaces tool approvals on the RunState (state.getInterruptions());
 * you state.approve(item)/reject(item) then resume with run(agent, state). RunState
 * serializes (state.toString() / RunState.fromString(agent, s)) — that's the durability:
 * park the serialized state agent-side on `route`, resume on Decidio's approval.
 *
 * const state = result.state;                       // or RunState from the run
 * const { resolved, pending } = await authorizeInterruptions(config, state, describe);
 * if (pending.length) {                             // suspend: park the state + each {callId, decisionId}
 *   await store.put(runId, { state: state.toString(), pending: pending.map(({ callId, decisionId }) => ({ callId, decisionId })) });
 *   return;
 * }
 * result = await run(agent, state);                 // all resolved → resume
 * // on Decidio's webhook (a wake-up): restore, find EACH parked call in the restored state by its call id,
 * // and let Decidio decide it:
 * //   const parked = await store.get(runId); const state = await RunState.fromString(agent, parked.state);
 * //   for (const { callId, decisionId } of parked.pending) {
 * //     const item = state.getInterruptions().find((i) => i.rawItem?.callId === callId);
 * //     await applyVerifiedResume(config, state, item, decisionId, describe);
 * //   }
 * //   result = await run(agent, state);
 *
 * THE BINDING IS THE TOOL CALL (#4B review W2): a routed approval is bound to the described context AND
 * the call itself - its name, call id and exact argument string (toolCallRequest). An item edited after
 * approval, or a second identical call (another call id), never rides the approval.
 *
 * ONE APPROVAL, ONE RUN (0.12.0, founder call 24): applyVerifiedResume COLLECTS a person's approval before it
 * approves the item (POST /agent/claim, a key random per call), so two concurrent resumes of the same parked state
 * cannot both run the tool - the second is told the approval was already used and the RunState is not modified.
 * A request key rides with every authorize, keyed on the tool call id: the same call asked again is the same request.
 *
 * Duck-typed on the state/item (no hard @openai/agents import) so it stays thin.
 *
 * (This wiring doc ships in the .d.ts — the README points here.)
 */
export interface Resolved { item: ToolApprovalItem; verdict: "approved" | "blocked"; decisionId: string }
/** `callId` (0.7.0) is the tool call the approval is bound to - find the item again by it after
 *  RunState.fromString. */
export interface Pending { item: ToolApprovalItem; decisionId: string; callId: string }

/** THIS DOOR AUTHORIZES; IT DOES NOT CONFIRM. Named `gateInterruptions` it looked like the other
 *  `decidioGate*` functions, which all run the action and report what happened. This one cannot:
 *  the OpenAI Agents runtime executes the tool itself, so the SDK never sees the return value and
 *  has nothing to attest. Every other adapter now returns a `confirmation`; this one deliberately
 *  returns `confirmationSupported: false` instead of an empty one, because an absent confirmation
 *  and a failed confirmation must not look alike.
 *
 *  proceed → state.approve(item); block → state.reject(item); route → pending (a human decides via
 *  Decidio; the host parks state.toString() + resumes via applyVerifiedResume). */
export async function authorizeInterruptions(
  config: GuardConfig,
  state: RunStateLike,
  describe: (item: ToolApprovalItem) => ApprovalContext,
): Promise<{ resolved: Resolved[]; pending: Pending[]; confirmationSupported: false }> {
  const resolved: Resolved[] = [];
  const pending: Pending[] = [];
  const batch = state.getInterruptions().map((item) => { const ctx = describe(item); return { item, ctx, request: toolCallRequest(item, ctx) }; });
  for (const { item, ctx, request } of batch) {
    const auth: GateAuth = await gateAuthorize(config, ctx, { request, naturalId: { engine: "openai-agents", callId: (request.args![0] as { callId: string }).callId } });
    if (auth.decision === "proceed") { state.approve(item); resolved.push({ item, verdict: "approved", decisionId: auth.decisionId }); }
    else if (auth.decision === "block") { state.reject(item); resolved.push({ item, verdict: "blocked", decisionId: auth.decisionId }); }
    else if (auth.decision === "route") pending.push({ item, decisionId: auth.decisionId, callId: (request.args![0] as { callId: string }).callId });
    else throw new DecidioBlockedError(`unhandled authorization verdict ${JSON.stringify(auth.decision)}`, auth.decisionId);
  }
  return { resolved, pending, confirmationSupported: false };
}

/** @deprecated Renamed to `authorizeInterruptions` in 0.3.0 — the old name read like the other
 *  `decidioGate*` doors, which execute and confirm. This one only ever authorized. */
export const gateInterruptions = authorizeInterruptions;

/** Apply Decidio's answer for one routed tool call to a resumed RunState (after RunState.fromString)
 *  - VERIFIED (0.7.0). It asks Decidio: GET /agent/status/:decisionId, and the approval must be bound
 *  to THIS tool call - the commitment Decidio holds is recomputed over the call's name, call id and exact
 *  argument string plus `describe(item)` (toolCallRequest), the same binding the call was authorized
 *  with. A parked RunState is the host's own storage: an item whose arguments were edited there after a
 *  human approved, or another call handed this call's decision id, must not ride that approval.
 *
 *  Approved and bound → state.approve(item), returns "approved". Rejected/blocked by Decidio →
 *  state.reject(item), returns that verdict. Still pending, or approved for a DIFFERENT request, or not
 *  tied to one → throws the typed refusal and the RunState is NOT modified.
 *
 *  A PERSON'S approval is COLLECTED ONCE before the item is approved (0.12.0, call 24): with `opts.claimKey` (yours to
 *  keep for a retry of THIS resume) or a fresh random one. Another run already used it, or it expired, or the claim could
 *  not be made → DecidioBlockedError, saying so, and the RunState is NOT modified. An auto-approval is never claimed.
 *
 *  REPLACES `applyResume(state, item, verdict)`, REMOVED in 0.7.0. It applied a bare verdict string
 *  with no decision attached, so correctness depended entirely on the host routing the right verdict
 *  to the right item. It was removed rather than deprecated: a deprecated function that still approves
 *  keeps the hole open for every integration that never reads the warning, and one that refused
 *  approvals at runtime would fail AFTER a human approved - the removal fails at build time instead. */
export async function applyVerifiedResume(
  config: GuardConfig,
  state: RunStateLike,
  item: ToolApprovalItem,
  decisionId: string,
  describe: (item: ToolApprovalItem) => ApprovalContext,
  opts: { claimKey?: string } = {},
): Promise<"approved" | "rejected" | "blocked"> {
  const idProblem = decisionIdProblem(decisionId);
  if (idProblem) throw new DecidioBlockedError(`applyVerifiedResume needs the decision this item was routed as (${idProblem}) - pass the decisionId authorizeInterruptions returned for it. The RunState was NOT modified.`, typeof decisionId === "string" ? decisionId : "");
  const ctx = describe(item);
  const check = await gateCheckApproval(config, decisionId, ctx, toolCallRequest(item, ctx));
  if (check.ok) {
    if (check.state === "approved") {
      const claimed = await gateClaim(config, decisionId, opts.claimKey ?? newClaimKey());
      if (!claimed.ok) { const refusal = claimRefusal(claimed); refusal.message += " The RunState was NOT modified."; throw refusal; }
    }
    state.approve(item);
    return "approved";
  }
  if (check.code === "rejected" || check.code === "blocked") { state.reject(item); return check.code; }
  const refusal = approvalRefusal(check);
  refusal.message += " The RunState was NOT modified.";
  throw refusal;
}

checkEngineVersion("openai");
