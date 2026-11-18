import { interrupt, Command } from "@langchain/langgraph";
import * as langgraph from "@langchain/langgraph";
import { DecidioBlockedError, approvalRefusal, bindingMaterial, requestCommitment, idempotencyKey, decisionIdProblem, type GuardConfig, type ApprovalContext, type ProtectedExecution } from "../index.js";
import { gateAuthorize, gateConfirm, gateCheckApproval, adapterRequest, checkEngineVersion } from "./_gate.js";

const gatesOpened = new WeakMap<object, number>();

function runIdentity(): { thread: string; ns: string; call: number } | undefined {
  let conf: Record<string, unknown> | undefined;
  try {
    const getConfig = (langgraph as unknown as { getConfig?: () => { configurable?: Record<string, unknown> } | undefined }).getConfig;
    conf = typeof getConfig === "function" ? getConfig()?.configurable : undefined;
  } catch { return undefined; }
  const thread = conf?.["thread_id"], ns = conf?.["checkpoint_ns"];
  if ((typeof thread !== "string" && typeof thread !== "number") || String(thread) === "") return undefined;
  if (typeof ns !== "string" || ns === "") return undefined;
  const scratch = conf?.["__pregel_scratchpad"];
  if (!scratch || typeof scratch !== "object") return undefined;
  const call = gatesOpened.get(scratch) ?? 0;
  gatesOpened.set(scratch, call + 1);
  return { thread: String(thread), ns, call };
}

/** Gate `run()` behind Decidio inside a LangGraph node. */
export async function decidioGate<R>(config: GuardConfig, ctx: ApprovalContext, run: () => Promise<R>, opts?: { evidence?: (r: R) => unknown }): Promise<ProtectedExecution<R>> {
  const material = bindingMaterial(config);
  if (!material) {
    throw new Error("[decidio] the LangGraph adapter binds a routed approval to the exact request with a key only this agent holds, and none is configured - set DECIDIO_AGENT_KEY + DECIDIO_AGENT_DID (npx @decidio/sdk init) or DECIDIO_API_TOKEN. Nothing was routed or executed.");
  }
  const request = adapterRequest(ctx);
  const self = runIdentity();
  const key = self ? idempotencyKey(material, { thread: self.thread, ns: self.ns, call: self.call, commitment: requestCommitment(material, request) }) : undefined;
  const auth = await gateAuthorize(config, ctx, key ? { idempotencyKey: key } : {});
  if (auth.decision === "block") throw new DecidioBlockedError(auth.reason ?? "blocked by policy", auth.decisionId);
  if (auth.decision === "route") {
    if (!self) {
      throw new DecidioBlockedError(`this LangGraph run exposes no thread/task identity (a checkpointer with a thread_id, @langchain/langgraph's getConfig() and the node execution's scratchpad are required), so a resumed node could not recognise decision ${auth.decisionId} as its own. Nothing was executed; ${auth.decisionId} is pending in Decidio - reject it (npx @decidio/sdk approvals reject ${auth.decisionId}).`, auth.decisionId);
    }
    const payload = { decidio: { decisionId: auth.decisionId, action: ctx.action, amount: ctx.amount, scope: ctx.scope } };
    let resumed: any = interrupt(payload);
    for (;;) {
      const named = resumed && typeof resumed === "object" ? resumed.decisionId : undefined;
      if (typeof named !== "string" || named === "") {
        throw new DecidioBlockedError(`the LangGraph resume value names no decision (${JSON.stringify(resumed ?? null).slice(0, 120)}) - refusing to execute. Build it with decidioResumeCommand(webhookBody), which carries the decisionId: an approval that does not say which decision it approves cannot be applied to this one.`, auth.decisionId);
      }
      if (named === auth.decisionId) {
        const check = await gateCheckApproval(config, auth.decisionId, ctx);
        if (check.ok) break;
        if (check.code !== "pending") throw approvalRefusal(check);
      }
      resumed = interrupt(payload);
    }
  }
  const result = await run();
  const confirmation = await gateConfirm(config, auth.decisionId, result, opts?.evidence as ((r: any) => unknown) | undefined);
  return { value: result, decisionId: auth.decisionId, confirmation, ...(typeof auth.requestKey === "string" ? { requestKey: auth.requestKey } : {}) };
}

/** Translate Decidio's signed resume webhook into the LangGraph resume Command. The host
 *  maps decisionId → thread_id and passes this to graph.invoke/stream. Since 0.7.0 the Command
 *  carries the decisionId - the gate refuses a resume value that does not say which decision it
 *  approves - and the verdict in it is informational only: the node confirms the approval with
 *  Decidio. Verify the webhook's signature BEFORE building this (verifyResumeSignature). */
export function decidioResumeCommand(body: { decisionId?: string; verdict?: string; reason?: string }): Command {
  const decisionId = body?.decisionId;
  const problem = decisionIdProblem(decisionId);
  if (problem) throw new Error(`[decidio] decidioResumeCommand needs the webhook's decisionId (${problem}) - the node refuses a resume that does not say which decision it approves. Pass the webhook body verbatim.`);
  return new Command({ resume: { decisionId, verdict: body.verdict, reason: body.reason } });
}

checkEngineVersion("langgraph");
