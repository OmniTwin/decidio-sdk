"""Temporal adapter — durable suspend via the engine's native `workflow.wait_condition`
plus a Decidio resume signal. Temporal gives the strongest durability (the workflow
survives worker restarts for days); the agent's action runs on resume.

Compose `DecidioSignalState` into your workflow and expose a signal that records the
verdict; `gate()` authorizes (via an activity), waits on the signal, then runs + confirms:

    class MyWorkflow(DecidioSignalState):
        @workflow.signal
        def decidio_resume(self, decision_id: str, verdict: str, reason: str | None = None):
            self.decidio_set(decision_id, verdict, reason)
        @workflow.run
        async def run(self, o):
            return await decidio.adapters.temporal.gate(self, guard, ctx, run=lambda: create_opp(o))

Decidio's webhook bridges to `client.get_workflow_handle(wf_id).signal(MyWorkflow.decidio_resume, decisionId, verdict)`.
Run authorize/verify/claim/confirm as ACTIVITIES (HTTP side effects belong in activities, not the
workflow) — `_authorize_activity`/`_verify_activity`/`_claim_activity`/`_confirm_activity` are provided for that.

THE SIGNAL IS A WAKE-UP (0.7.0). Before 0.7.0 the action ran on the signal alone, so anyone who could
signal the workflow with the decisionId approved it. Now the signal only wakes the workflow; `verify_fn`
then confirms with Decidio that THIS request was approved (GET /agent/status + the request commitment)
before `run`. Still pending -> keep waiting for the next signal; rejected/blocked/changed -> the typed
refusal. It is HTTP, so it must be an ACTIVITY, never workflow code (determinism) - and it is required
whenever `authorize_fn` is. (TS twin: temporal.ts.)

ONE APPROVAL, ONE RUN (0.12.0, founder call 24): once Decidio confirms a PERSON'S approval, the workflow collects it
(`claim_fn`, an activity) with a key made from the workflow's own deterministic uuid4 - the same key on a replay or an
activity retry, a different one in any other run - and runs only if Decidio says this run collected it. Another run
already used it, or it expired -> DecidioBlocked, and the action never runs. `claim_fn` is required whenever
`authorize_fn` is. A request key rides with every authorize: `_authorize_activity` keys it on the activity's own
workflow, run and activity ids, so Temporal retrying the activity is the same request.
"""
from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, Optional, Tuple

from ..errors import DecidioBlocked
from ..resume import approval_refusal, claim_refusal, new_claim_key
from ._common import assert_authorize_verdict, assert_check_shape, assert_claim_shape, authorize, check_approval_for, claim_for, confirm


class DecidioSignalState:
    """Mixin: a per-decision signal store a Temporal signal handler writes to. Since 0.7.0 an entry is a
    WAKE-UP for its decision - the verdict it carries is informational and is consumed when the gate
    checks the approval with Decidio."""

    def __init__(self) -> None:
        self._decidio_verdicts: Dict[str, Tuple[str, Optional[str]]] = {}

    def decidio_set(self, decision_id: str, verdict: str, reason: Optional[str] = None) -> None:
        self._decidio_verdicts[decision_id] = (verdict, reason)

    def decidio_resolved(self, decision_id: str) -> bool:
        return decision_id in self._decidio_verdicts


def _current_activity_ids() -> Optional[Dict[str, str]]:
    """The current activity's ids, when this code runs inside a Temporal activity; None anywhere else (TS twin)."""
    try:
        from temporalio import activity
        if not activity.in_activity():
            return None
        info = activity.info()
        ids = {"workflowId": info.workflow_id, "runId": info.workflow_run_id, "activityId": info.activity_id}
        return ids if all(isinstance(v, str) and v for v in ids.values()) else None
    except Exception:  # noqa: BLE001 - temporalio absent, or not an activity: the call keys on a fresh id instead
        return None


# Activity bodies (register these with your worker; they hold the HTTP side effects).
def _authorize_activity(guard: Any, ctx: dict, ids: Optional[Dict[str, str]] = None) -> dict:
    """The authorize ACTIVITY body. The request key (0.12.0, 11f) is keyed on Temporal's own ids for this activity -
    passed as `ids` ({"workflowId", "runId", "activityId"}), or read from the running activity - so Temporal retrying the
    activity after a timeout is the SAME request while it waits. Outside an activity, with
    no `ids`, the key is over a fresh id for the call. (TS twin: authorizeActivity.)"""
    natural = ids or _current_activity_ids()
    a = authorize(guard, ctx, natural_id=({"engine": "temporal", "workflowId": natural["workflowId"], "runId": natural["runId"],
                                           "activityId": natural["activityId"]} if natural else None))
    out = {"decision": a.decision, "decisionId": a.decision_id, "receiptId": a.receipt_id, "reason": a.reason}
    if a.request_key:
        out["requestKey"] = a.request_key
    return out


def _verify_activity(guard: Any, decision_id: str, ctx: dict) -> dict:
    """THE APPROVAL CHECK as an activity body (0.7.0): GET /agent/status + the request commitment
    recomputed over `ctx` - the same ctx the gate authorized. Return its dict unchanged."""
    return check_approval_for(guard, decision_id, ctx)


def _claim_activity(guard: Any, decision_id: str, claim_key: str) -> dict:
    """The claim as an ACTIVITY body (0.12.0, call 24): POST /agent/claim with the key the workflow made. Return its dict
    unchanged. (TS twin: claimApprovalActivity.)"""
    return claim_for(guard, decision_id, claim_key)


def _workflow_claim_key() -> str:
    """The run's claim key, from the workflow's DETERMINISTIC uuid4: the same on a replay and across the claim activity's
    retries, different in every other run. Outside a workflow (a test) a random one. (TS twin.)"""
    try:
        from temporalio import workflow
        return f"run_{workflow.uuid4()}"
    except Exception:  # noqa: BLE001 - not inside a workflow: a random key, never a shared one
        return new_claim_key()


def _confirm_activity(guard: Any, decision_id: str, result: Any, evidence: Any = None) -> dict:
    # RETURN what Decidio recorded (prodsec V035-03): this discarded it, so a 2xx and a 503 both reached
    # the caller as `confirmation == {}`.
    return confirm(guard, decision_id, result, evidence=evidence)


async def gate(
    wf: DecidioSignalState,
    guard: Any,
    ctx: dict,
    run: Callable[[], Any],
    *,
    authorize_fn: Optional[Callable[[], dict]] = None,
    confirm_fn: Optional[Callable[[str, Any], Any]] = None,
    evidence: Any = None,
    verify_fn: Optional[Callable[[str], Any]] = None,
    claim_fn: Optional[Callable[[str, str], Any]] = None,
) -> Any:
    """Gate inside a Temporal workflow. `authorize_fn`/`verify_fn`/`confirm_fn` let you route the
    HTTP through activities (recommended); they default to direct calls for tests. Any may be async.
    `verify_fn(decision_id)` is the approval check run after the resume signal and before `run`
    (0.7.0) - an activity returning `_verify_activity(guard, decision_id, ctx)` unchanged; required
    whenever `authorize_fn` is supplied.
    `claim_fn(decision_id, claim_key)` is the claim run after the check when a PERSON approved (0.12.0) - an activity
    returning `_claim_activity(guard, decision_id, claim_key)` unchanged; required whenever `authorize_fn` is supplied.
    A `confirm_fn` that returns the gate's confirm response body (validated with read_confirm_response)
    makes it the outcome; one that returns nothing yields an outcome saying this SDK could not read back
    what Decidio recorded.

    BETA: the gate semantics are the shared ones; the Temporal integration is verified against
    a mock `wait_condition`, not a live worker."""
    from temporalio import workflow  # lazy: only needed inside a workflow runtime

    # The approval check is HTTP. A host that moved authorize into an activity (the recommended shape)
    # must move the check there too - refused BEFORE anything is routed (TS twin).
    if authorize_fn is not None and verify_fn is None:
        raise ValueError("[decidio] temporal: authorize_fn runs in your activity, so the approval check must too - pass "
                         "verify_fn=lambda decision_id: workflow.execute_activity(verify_activity, ...), where the activity "
                         "returns decidio.adapters.temporal._verify_activity(guard, decision_id, ctx) unchanged. Since 0.7.0 a "
                         "resume signal only wakes the workflow; the approval is confirmed with Decidio before your action "
                         "runs. Nothing was routed or executed.")
    # ...and the claim (0.12.0; TS twin): the same rule, refused before anything is routed.
    if authorize_fn is not None and claim_fn is None:
        raise ValueError("[decidio] temporal: authorize_fn runs in your activity, so the claim must too - pass "
                         "claim_fn=lambda decision_id, claim_key: workflow.execute_activity(claim_activity, ...), where the "
                         "activity returns decidio.adapters.temporal._claim_activity(guard, decision_id, claim_key) unchanged. "
                         "Since 0.12.0 a person's approval is collected once, by the run that acts on it, before your action "
                         "runs. Nothing was routed or executed.")
    # The allow-list is applied to whatever the ACTIVITY returned — a host-supplied
    # authorize_fn (the recommended shape) is outside _common.authorize, so this door would
    # otherwise be the one place an unknown verdict could fall through to execute.
    # ACTIVITY CALLBACKS MAY BE ASYNC (prodsec V035-03): a coroutine-returning authorize_fn was passed
    # to the allow-list un-awaited and refused as an unknown verdict; worse, an async confirm_fn was never
    # awaited, so the action ran and its confirmation body never executed. Await whatever is awaitable.
    _auth_raw = (authorize_fn or (lambda: _authorize_activity(guard, ctx)))()
    if inspect.isawaitable(_auth_raw):
        _auth_raw = await _auth_raw
    checked = assert_authorize_verdict(_auth_raw, "unknown")
    auth = {"decision": checked.decision, "decisionId": checked.decision_id, "reason": checked.reason}
    _request_key = _auth_raw.get("requestKey") if isinstance(_auth_raw, dict) and isinstance(_auth_raw.get("requestKey"), str) else None
    if auth["decision"] == "block":
        raise DecidioBlocked(auth.get("reason") or "blocked by policy", auth["decisionId"])
    if auth["decision"] not in ("route", "proceed"):
        raise DecidioBlocked(f"unhandled authorization verdict {auth['decision']!r}", auth["decisionId"])
    if auth["decision"] == "route":
        decision_id = auth["decisionId"]
        verify = verify_fn or (lambda did: _verify_activity(guard, did, ctx))
        while True:
            await workflow.wait_condition(lambda: wf.decidio_resolved(decision_id))   # a WAKE-UP
            wf._decidio_verdicts.pop(decision_id, None)                                # consumed: the next signal wakes us again
            # What the signal SAID is not the authority; Decidio's answer for THIS request is. The value
            # has crossed an activity boundary, so it is validated like any other rehydrated answer.
            _raw = verify(decision_id)
            if inspect.isawaitable(_raw):
                _raw = await _raw
            check = assert_check_shape(_raw, decision_id)
            if check.get("ok"):
                # COLLECT A PERSON'S APPROVAL ONCE (0.12.0): only the run that collects it runs it. Never an auto-approval.
                if check.get("state") == "approved":
                    _claim = claim_fn or (lambda did, key: _claim_activity(guard, did, key))
                    _c = _claim(decision_id, _workflow_claim_key())
                    if inspect.isawaitable(_c):
                        _c = await _c
                    claimed = assert_claim_shape(_c, decision_id)
                    if not claimed.get("ok"):
                        raise claim_refusal(claimed)
                break
            if check.get("code") != "pending":
                raise approval_refusal(check)
            # Decidio records no approval yet: the signal was premature, or forged. Wait for the next one.
    result = run()
    if inspect.isawaitable(result):   # the agent's action may be async — await it (TS awaits too)
        result = await result
    # A caller-supplied confirm_fn OWNS the reporting, so an `evidence` mapper cannot be applied
    # for them - say so rather than ignoring it. The type comment calls confirm_fn "recommended",
    # so silently dropping the mapper here would hit exactly the callers following the advice.
    if confirm_fn is not None and evidence is not None:
        import sys as _sys_t
        print("[decidio] `evidence` is ignored when you supply confirm_fn - your callback owns the "
              "report, so map the result inside it. Remove one of the two to make the intent clear.",
              file=_sys_t.stderr)
    _outcome = (confirm_fn or (lambda did, r: _confirm_activity(guard, did, r, evidence=evidence)))(auth["decisionId"], result)
    if inspect.isawaitable(_outcome):
        _outcome = await _outcome
    # ONE RESULT SHAPE ACROSS EVERY DOOR (F-008). This returned the bare value and DISCARDED what
    # Decidio recorded, so the two states a caller most needs to tell apart - "it ran and was
    # recorded" and "it ran and Decidio does not know" - were the same return value. A
    # caller-supplied confirm_fn owns the transport and gives us nothing to read back, so that case
    # says exactly that rather than reporting an empty confirmation as if it were a real one.
    # ...unless the callback RETURNED the gate's response (validated with read_confirm_response) - then
    # that is the outcome, exactly as the TS twin keeps it (prodsec V035-03).
    if confirm_fn is not None and not (isinstance(_outcome, dict) and isinstance(_outcome.get("report_recorded"), bool)):
        _outcome = {
            "report_recorded": False, "execution_confirmed": False,
            "confirmation_retryable": False, "report_journalled": False,
            "diagnostic": ("your own `confirm` callback reported this execution, so this SDK cannot "
                           "read back what Decidio recorded. Check the record, or return the gate's "
                           "response body from your activity and validate it with "
                           "read_confirm_response."),
        }
    from ..guard import ProtectedExecution
    return ProtectedExecution(value=result, decision_id=auth["decisionId"], confirmation=_outcome or {}, request_key=_request_key)
