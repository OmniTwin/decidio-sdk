"""LangGraph adapter — durable suspend via the engine's native `interrupt()`.

`interrupt()` is contextvar-based (it finds the running graph itself), so the Decidio
gate fits LangGraph as a true drop-in: inside a node, `guard.protect(fn, describe,
adapter="langgraph")(...)` authorizes; on `route` it calls `interrupt(...)`, which
durably pauses the graph (the checkpointer persists state — the process can die). When
Decidio's approval webhook resumes the graph with `Command(resume={"decisionId": ...})`,
`interrupt()` returns that payload, the node confirms WITH DECIDIO that this exact request
was approved, and only then runs the agent's own action + confirms.

Decidio is the approval system; the host bridges its webhook to the graph resume:
    cmd = decidio_resume_command(webhook_body)         # build the Command (carries the decisionId)
    graph.invoke(cmd, config={"configurable": {"thread_id": thread_for(decisionId)}})
(The host maps decisionId → thread_id; that mapping is host state, like any LangGraph
human-in-the-loop resume.)

RESUME RE-RUNS THE NODE. LangGraph restarts an interrupted node from its first line, so the gate
authorizes again on every resume. Since 0.7.0 that second authorize is IDEMPOTENT: it carries a key
derived from the run's own identity (thread + task + the request commitment), and Decidio answers with
the SAME decision instead of minting a phantom second one. Edit the graph state and the task - and the
request - change, so the edited request becomes a NEW pending decision for a human; the old approval is
never applied to it. The resume value must name the decision it approves, and even then it is only a
wake-up: the approval that counts is the one Decidio returns for THIS request. (TS twin: langgraph.ts.)

KNOWN LIMIT - ONE GATED ACTION PER NODE (predates 0.7.0). LangGraph re-runs the WHOLE node on resume, so every
gate before the one that paused runs again. A gate whose request auto-approved (and whose action already ran)
replays as `proceed` for a verified agent, so its action runs AGAIN when a later gate in the same node is resumed
(before 0.7.0 it minted a new decision and ran it again). Put each gated action in its own node, or make the
actions idempotent.

KNOWN LIMIT (predates 0.7.0): this door has no single-execution claim. Two concurrent resumes of the same
thread (the host invoking the graph twice with the same Command) can both pass the approval check and both
run the action - LangGraph does not serialize them. Resume each thread from one place (one worker per thread
id, or a lock on the host's decisionId -> thread_id mapping).
"""
from __future__ import annotations

import contextvars
import inspect

from ..resume import _complete, approval_refusal

from typing import Any, Callable, Optional

from langgraph.types import Command, interrupt

from .._client import post as _post
from ..errors import DecidioBlocked, decision_id_problem
from ..signing import binding_material_of, idempotency_key, request_commitment
from ._common import adapter_request, authorize, check_approval_for, confirm





_GATES_OPENED: "contextvars.ContextVar[Optional[tuple]]" = contextvars.ContextVar("decidio_langgraph_gates", default=None)


def _run_identity() -> Optional[dict]:
    """The identity of the node execution that is asking - stable when LangGraph re-runs the node on
    resume, different after the state is edited (a new checkpoint is a new task). None outside a
    checkpointed LangGraph run."""
    try:
        try:
            from langgraph.config import get_config
        except ImportError:
            return None
        conf = (get_config() or {}).get("configurable") or {}
    except Exception:
        return None
    thread, ns = conf.get("thread_id"), conf.get("checkpoint_ns")
    if thread is None or str(thread) == "" or not isinstance(ns, str) or not ns:
        return None



    scratch = conf.get("__pregel_scratchpad")
    if scratch is None:
        return None
    cur = _GATES_OPENED.get()
    call = cur[1] if (cur is not None and cur[0] is scratch) else 0
    _GATES_OPENED.set((scratch, call + 1))
    return {"thread": str(thread), "ns": ns, "call": call}


def gate(guard: Any, ctx: dict, run: Callable[[], Any], evidence: Any = None) -> Any:
    """Run `run()` behind the Decidio gate inside a LangGraph node.

    BETA: the gate semantics here are the shared ones (verdict allow-list, canonical arguments,
    transport rule, evidence handling, the approval check); the engine integration is exercised
    against a real LangGraph graph in adapters_smoke.py."""
    cfg = guard.config



    material = binding_material_of(cfg)
    if material is None:
        raise RuntimeError("[decidio] the LangGraph adapter binds a routed approval to the exact request with a key only this agent holds, "
                           "and none is configured - set DECIDIO_AGENT_KEY + DECIDIO_AGENT_DID (python -m decidio init) or "
                           "DECIDIO_API_TOKEN. Nothing was routed or executed.")
    request = adapter_request(ctx)
    me = _run_identity()
    key = (idempotency_key(material, {"thread": me["thread"], "ns": me["ns"], "call": me["call"],
                                      "commitment": request_commitment(material, request)})
           if me is not None else None)
    auth = authorize(guard, ctx, idempotency_key=key)
    if auth.decision == "block":
        raise DecidioBlocked(auth.reason or "blocked by policy", auth.decision_id)



    if auth.decision not in ("route", "proceed"):
        raise DecidioBlocked(f"unhandled authorization verdict {auth.decision!r}", auth.decision_id)
    if auth.decision == "route":
        if me is None:


            raise DecidioBlocked(f"this LangGraph run exposes no thread/task identity (a checkpointer with a thread_id, "
                                 f"langgraph.config.get_config() and the node execution's scratchpad are required), so a resumed "
                                 f"node could not recognise decision "
                                 f"{auth.decision_id} as its own. Nothing was executed; {auth.decision_id} is pending in Decidio - "
                                 f"reject it (python -m decidio approvals reject {auth.decision_id}).", auth.decision_id)

        payload = {"decidio": {
            "decisionId": auth.decision_id, "action": ctx["action"],
            "amount": ctx["amount"], "scope": ctx.get("scope"),
        }}
        resumed = interrupt(payload)
        while True:
            named = resumed.get("decisionId") if isinstance(resumed, dict) else None
            if not isinstance(named, str) or not named:
                raise DecidioBlocked(f"the LangGraph resume value names no decision ({str(resumed)[:120]}) - refusing to execute. "
                                     f"Build it with decidio_resume_command(webhook_body), which carries the decisionId: an "
                                     f"approval that does not say which decision it approves cannot be applied to this one.",
                                     auth.decision_id)
            if named == auth.decision_id:

                check = check_approval_for(guard, auth.decision_id, ctx)
                if check.get("ok"):
                    break
                if check.get("code") != "pending":
                    raise approval_refusal(check)




            resumed = interrupt(payload)
    result = run()





    if inspect.isawaitable(result):
        result = _complete(result)
    outcome = confirm(guard, auth.decision_id, result, evidence=evidence)




    from ..guard import ProtectedExecution
    return ProtectedExecution(value=result, decision_id=auth.decision_id, confirmation=outcome or {}, request_key=auth.request_key)


def decidio_resume_command(webhook_body: dict) -> Command:
    """Translate Decidio's signed resume webhook into the LangGraph resume Command. Pass it to
    graph.invoke/stream with the paused run's thread_id. Since 0.7.0 the Command carries the decisionId -
    the gate refuses a resume value that does not say which decision it approves - and the verdict in it
    is informational only: the node confirms the approval with Decidio. Verify the webhook's signature
    BEFORE building this (decidio.verify_signature)."""
    decision_id = (webhook_body or {}).get("decisionId")
    problem = decision_id_problem(decision_id)
    if problem:
        raise ValueError(f"[decidio] decidio_resume_command needs the webhook's decisionId ({problem}) - the node refuses a "
                         f"resume that does not say which decision it approves. Pass the webhook body verbatim.")
    return Command(resume={"decisionId": decision_id, "verdict": webhook_body.get("verdict"), "reason": webhook_body.get("reason")})
