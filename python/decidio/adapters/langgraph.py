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

from langgraph.types import Command, interrupt  # verified primitive

from .._client import post as _post  # noqa: F401  (kept for parity; gate uses _common)
from ..errors import DecidioBlocked, decision_id_problem
from ..signing import binding_material_of, idempotency_key, request_commitment
from ._common import adapter_request, authorize, check_approval_for, confirm

# How many gates THIS node execution has opened. LangGraph runs every task execution in its own copied
# context and gives it its own scratchpad; pairing the two means two identical governed calls in one node
# are two decisions (not one approval spent twice), and the count restarts whenever the node re-runs - so
# the n-th gate finds the n-th decision again. (The TS twin keys a WeakMap on the same scratchpad.)
_GATES_OPENED: "contextvars.ContextVar[Optional[tuple]]" = contextvars.ContextVar("decidio_langgraph_gates", default=None)


def _run_identity() -> Optional[dict]:
    """The identity of the node execution that is asking - stable when LangGraph re-runs the node on
    resume, different after the state is edited (a new checkpoint is a new task). None outside a
    checkpointed LangGraph run."""
    try:
        try:
            from langgraph.config import get_config
        except ImportError:  # langgraph without the public accessor
            return None
        conf = (get_config() or {}).get("configurable") or {}
    except Exception:  # noqa: BLE001 - outside a runnable context
        return None
    thread, ns = conf.get("thread_id"), conf.get("checkpoint_ns")
    if thread is None or str(thread) == "" or not isinstance(ns, str) or not ns:
        return None
    # The per-execution scratchpad is what numbers the gates in this node execution. Without it there is no
    # honest call index - a counter keyed on None would keep counting across unrelated executions - so there
    # is no identity, and a routed gate refuses, naming its decision (#4B review N1; TS twin).
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
    # KEY MATERIAL FIRST, before anything is sent: it is what lets a re-run node recognise its own
    # decision and bind the approval to this request (TS twin). An unsigned request can never
    # auto-approve at the gate either, so nothing that could have run is lost by refusing here.
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
    auth = authorize(guard, ctx, idempotency_key=key)   # allow-list enforced inside authorize()
    if auth.decision == "block":
        raise DecidioBlocked(auth.reason or "blocked by policy", auth.decision_id)
    # EXHAUSTIVE, not "everything else runs": proceed is the only remaining arm, and it is
    # named. A verdict this SDK does not understand never reaches here (authorize refuses it),
    # and if one ever did, this would refuse rather than execute.
    if auth.decision not in ("route", "proceed"):
        raise DecidioBlocked(f"unhandled authorization verdict {auth.decision!r}", auth.decision_id)
    if auth.decision == "route":
        if me is None:
            # No run identity: a resumed node could not find this decision again - every resume would
            # ask afresh and wait on a decision nobody approves. Refuse loudly instead.
            raise DecidioBlocked(f"this LangGraph run exposes no thread/task identity (a checkpointer with a thread_id, "
                                 f"langgraph.config.get_config() and the node execution's scratchpad are required), so a resumed "
                                 f"node could not recognise decision "
                                 f"{auth.decision_id} as its own. Nothing was executed; {auth.decision_id} is pending in Decidio - "
                                 f"reject it (python -m decidio approvals reject {auth.decision_id}).", auth.decision_id)
        # Durable pause. On resume, interrupt() returns the Command(resume=...) payload.
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
                # A wake-up for THIS decision. The verdict it carries is not the authority - Decidio is.
                check = check_approval_for(guard, auth.decision_id, ctx)
                if check.get("ok"):
                    break
                if check.get("code") != "pending":
                    raise approval_refusal(check)
                # Decidio records no approval yet: the resume was premature (or forged). Pause again.
            # Otherwise it approves ANOTHER decision - typically one granted before the graph state was
            # edited: the edit made this execution a NEW request, authorized above as a new decision a human
            # has not seen. Never apply an approval across requests; pause again, for THIS decision.
            resumed = interrupt(payload)
    result = run()
    # The core wrapper became async-aware, but adapters are dispatched BEFORE that branch, so
    # this path kept the original bug: an `async def` action returned a coroutine, which was
    # then handed to confirm() and failed json.dumps — printing "action succeeded" for an action
    # that had not started, and stranding the receipt below application_confirmed. temporal.py
    # already awaited; langgraph did not. Every equivalent path, not just the one that was reported.
    if inspect.isawaitable(result):
        result = _complete(result)
    outcome = confirm(guard, auth.decision_id, result, evidence=evidence)
    # The SAME shape the core path returns. `protect(..., adapter="langgraph")` used to hand back
    # the bare value while `protect(...)` handed back ProtectedExecution - one function, two return
    # types, decided by an option. `protect_best_effort` then crashed on the adapter path
    # (`'dict' object has no attribute 'value'`), which is the one path that must never fail.
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
