"""OpenAI Agents SDK adapter — gate tool-approval interruptions through Decidio, with
durable suspend via the SDK's native RunState serialization.

The OpenAI Agents loop surfaces tool-approval interruptions on the RunState
(`state.get_interruptions()` → ToolApprovalItem); you `state.approve(item)` /
`state.reject(item)` then resume with `Runner.run(agent, state)`. RunState serializes
(`state.to_string()` / `RunState.from_string(agent, s)`), which is the durability: park
the serialized state agent-side on `route`, resume on Decidio's approval.

    state = result.to_state()
    resolved, pending, _ = decidio.adapters.openai.authorize_interruptions(guard, state, describe)
    if pending:                         # a human must decide — persist the state + each call's decision
        store.put(run_id, {"state": state.to_string(),
                           "pending": [{"call_id": item.call_id, "decision_id": d} for item, d in pending]})
        return                          # process may exit
    result = await Runner.run(agent, state)   # all resolved → resume the run
    # on Decidio's webhook (a wake-up): restore, find EACH parked call in the restored state by its call
    # id, and let Decidio decide it:
    #   parked = store.get(run_id); state = await RunState.from_string(agent, parked["state"])
    #   for p in parked["pending"]:
    #       item = next(i for i in state.get_interruptions() if i.call_id == p["call_id"])
    #       decidio.adapters.openai.apply_verified_resume(guard, state, item, p["decision_id"], describe)
    #   result = await Runner.run(agent, state)

THE BINDING IS THE TOOL CALL (#4B review W2): a routed approval is bound to the described context AND the
call itself - its name, call id and exact argument string (tool_call_request). An item edited after approval,
or a second identical call (another call id), never rides the approval.

ONE APPROVAL, ONE RUN (0.12.0): apply_verified_resume COLLECTS a person's approval before it approves
the item (POST /agent/claim, a key random per call), so two concurrent resumes of the same parked state cannot both run
the tool - the second is told the approval was already used and the RunState is not modified. A request key rides with
every authorize, keyed on the tool call id: the same call asked again is the same request.

`describe(item)` maps a ToolApprovalItem → {"action","amount","scope"} (e.g.
lambda i: {"action": i.tool_name, "amount": json.loads(i.arguments).get("amount", 0)}).
This adapter is duck-typed on the state/item (no hard `agents` import) so it stays thin.
"""
from __future__ import annotations

from typing import Any, Callable, List, Optional, Tuple

from ..errors import DecidioBlocked, decision_id_problem
from ..resume import approval_refusal, claim_refusal, new_claim_key
from ._common import authorize, check_approval_for, claim_for, tool_call_request


def authorize_interruptions(
    guard: Any,
    state: Any,
    describe: Callable[[Any], dict],
) -> Tuple[List[Tuple[Any, str, str]], List[Tuple[Any, str]], bool]:
    """THIS DOOR AUTHORIZES; IT DOES NOT CONFIRM. Named `gate_interruptions` it looked like the
    other `gate` functions, which all run the action and report what happened. This one cannot:
    the OpenAI Agents runtime executes the tool itself, so the SDK never sees the return value and
    has nothing to attest. Every other adapter now returns a confirmation; this one deliberately
    returns `confirmation_supported=False` as its third element, because an absent confirmation and
    a failed confirmation must not look alike.

    Ask Decidio for each pending tool-approval on `state`.
    proceed → state.approve(item); block → state.reject(item); route → left for a human
    (durable). Returns (resolved, pending):
      resolved = [(item, verdict, decisionId)]  applied to the state now
      pending  = [(item, decisionId)]           awaiting a human decision via Decidio
    If `pending` is non-empty, persist state.to_string() and suspend; resume per
    `apply_verified_resume` when Decidio's webhook arrives.

    BETA: the gate semantics are the shared ones; the OpenAI Agents integration is verified
    against a duck-typed RunState, not a live run."""
    resolved: List[Tuple[Any, str, str]] = []
    pending: List[Tuple[Any, str]] = []



    batch = []
    for item in state.get_interruptions():
        ctx = describe(item)
        batch.append((item, ctx, tool_call_request(item, ctx)))
    for item, ctx, request in batch:


        auth = authorize(guard, ctx, request=request, natural_id={"engine": "openai-agents", "callId": request["args"][0]["callId"]})
        if auth.decision == "proceed":
            state.approve(item)
            resolved.append((item, "approved", auth.decision_id))
        elif auth.decision == "block":
            state.reject(item, rejection_message=auth.reason or "blocked by policy")
            resolved.append((item, "blocked", auth.decision_id))
        elif auth.decision == "route":
            pending.append((item, auth.decision_id))
        else:



            raise DecidioBlocked(f"unhandled authorization verdict {auth.decision!r}", auth.decision_id)
    return resolved, pending, False






gate_interruptions = authorize_interruptions


def apply_verified_resume(guard: Any, state: Any, item: Any, decision_id: str, describe: Callable[[Any], dict], *,
                          rejection_message: Optional[str] = None, claim_key: Optional[str] = None) -> str:
    """Apply Decidio's answer for one routed tool call to a resumed RunState (after RunState.from_string)
    - VERIFIED (0.7.0). It asks Decidio: GET /agent/status/<decision_id>, and the approval must be bound to
    THIS tool call - the commitment Decidio holds is recomputed over the call's name, call id and exact
    argument string plus `describe(item)` (tool_call_request), the same binding the call was authorized
    with. A parked RunState is the host's own storage: an item whose arguments were edited there after a
    human approved, or another call handed this call's decision id, must not ride that approval.

    Approved and bound -> state.approve(item), returns "approved". Rejected/blocked by Decidio ->
    state.reject(item), returns that verdict. Still pending, approved for a DIFFERENT request, or not tied
    to one -> raises the typed refusal and the RunState is NOT modified.

    A PERSON'S approval is COLLECTED ONCE before the item is approved (0.12.0, call 24): with `claim_key` (yours to keep
    for a retry of THIS resume) or a fresh random one. Another run already used it, or it expired, or the claim could not
    be made -> DecidioBlocked, saying so, and the RunState is NOT modified. An auto-approval is never claimed.

    REPLACES `apply_resume(state, item, verdict)`, REMOVED in 0.7.0: it applied a bare verdict string with
    no decision attached, so correctness depended entirely on the host routing the right verdict to the
    right item. Removed rather than deprecated - a deprecated function that still approves keeps the hole
    open for every integration that never reads the warning, and one that refused approvals at runtime
    would fail AFTER a human approved; the removal fails at import time instead. (TS twin:
    applyVerifiedResume.)"""
    problem = decision_id_problem(decision_id)
    if problem:
        raise DecidioBlocked(f"apply_verified_resume needs the decision this item was routed as ({problem}) - pass the decision id "
                             f"authorize_interruptions returned for it. The RunState was NOT modified.",
                             decision_id if isinstance(decision_id, str) else "")
    ctx = describe(item)
    check = check_approval_for(guard, decision_id, ctx, request=tool_call_request(item, ctx))
    if check.get("ok"):
        if check.get("state") == "approved":
            claimed = claim_for(guard, decision_id, claim_key or new_claim_key())
            if not claimed.get("ok"):
                refusal = claim_refusal(claimed)
                refusal.args = (f"{refusal} The RunState was NOT modified.",)
                raise refusal
        state.approve(item)
        return "approved"
    if check.get("code") in ("rejected", "blocked"):
        state.reject(item, rejection_message=rejection_message or check.get("reason") or "rejected by approver")
        return check["code"]
    refusal = approval_refusal(check)
    refusal.args = (f"{refusal} The RunState was NOT modified.",)
    raise refusal
