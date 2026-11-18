"""Inngest adapter (Python) — durable suspend via the engine's native
`step.wait_for_event` (mirror of the verified TS Inngest adapter). Decidio keeps its
ONE signed-webhook contract; a bridge translates that webhook into the Inngest event
that wakes the suspended function (see `resume_event`).

Usage inside an Inngest function `async def fn(ctx, step)`:
    out = await decidio.adapters.inngest.gate(step, guard, ctx, run=lambda: create_opp(o))

THE EVENT IS A WAKE-UP (0.7.0). Before, the action ran on any `decidio/decision.resolved` event
carrying the decisionId - anyone holding the Inngest event key could approve. Now a memoized step
confirms with Decidio that THIS request was approved (GET /agent/status + the request commitment)
before the action runs; still pending -> wait for the next event.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..errors import DecidioBlocked
from ..resume import _NO_WEBHOOK_SECRET, approval_refusal, verify_signature
from ._common import assert_authorize_verdict, assert_check_shape, authorize, check_approval_for, confirm

DECIDIO_RESUME_EVENT = "decidio/decision.resolved"


def _authorize_dict(guard: Any, ctx: dict, run_id: Optional[str] = None) -> dict:
    a = authorize(guard, ctx, natural_id=({"engine": "inngest", "runId": run_id, "step": "decidio-authorize"} if run_id else None))
    out = {"decision": a.decision, "decisionId": a.decision_id, "receiptId": a.receipt_id, "reason": a.reason}
    if a.request_key:
        out["requestKey"] = a.request_key
    return out


async def gate(step: Any, guard: Any, ctx: dict, run: Callable[[], Any], timeout: str = "30d", evidence: Any = None,
               run_id: Optional[str] = None) -> Any:
    """BETA: the gate semantics are the shared ones; the Inngest integration is verified
    against a structural mock `step`, not a live Inngest run.

    `run_id`: Inngest's id for THIS function run - the handler context's `run_id` (0.12.0, 11f; TS twin `runId`). The
    request key is keyed on it, so Inngest retrying the authorize step is the same request while it waits. Without it
    the key is over a fresh id for the call (a retried step may then ask again)."""
    # authorize as a memoized step (a replay doesn't re-ask the gate)
    raw = await step.run("decidio-authorize", lambda: _authorize_dict(guard, ctx, run_id if isinstance(run_id, str) and run_id else None))
    # Re-checked AFTER the durable replay: a memoized step hands back whatever the JOURNAL
    # holds, which may have been written by a different SDK version. The allow-list is cheap
    # and the alternative is executing a verdict this build has never heard of.
    checked = assert_authorize_verdict(raw, "unknown")
    auth = {"decision": checked.decision, "decisionId": checked.decision_id, "reason": checked.reason}
    if auth["decision"] == "block":
        raise DecidioBlocked(auth.get("reason") or "blocked by policy", auth["decisionId"])
    if auth["decision"] not in ("route", "proceed"):
        raise DecidioBlocked(f"unhandled authorization verdict {auth['decision']!r}", auth["decisionId"])
    if auth["decision"] == "route":
        n = 0
        while True:
            # Step ids must be deterministic across replays: the first wait keeps its 0.x name, each
            # later one is numbered (TS twin).
            suffix = "" if n == 0 else f"-{n}"
            n += 1
            # durably suspend until the resume event for THIS decision arrives (process may die)
            ev = await step.wait_for_event(
                f"decidio-await-approval{suffix}",
                event=DECIDIO_RESUME_EVENT,
                timeout=timeout,
                if_exp=f'async.data.decisionId == "{auth["decisionId"]}"',
            )
            if ev is None:
                raise TimeoutError(f"decidio approval timed out ({auth['decisionId']})")
            # THE EVENT IS A WAKE-UP (0.7.0): the approval is confirmed with Decidio for THIS request, as
            # a STEP - memoized, so a replay reads the same answer instead of asking again.
            check = assert_check_shape(
                await step.run(f"decidio-verify-approval{suffix}", lambda: check_approval_for(guard, auth["decisionId"], ctx)),
                auth["decisionId"])
            if check.get("ok"):
                break
            if check.get("code") != "pending":
                raise approval_refusal(check)
            # Decidio records no approval yet: the event was premature, or forged. Wait for the next one.
    result = await step.run("agent-action", run)
    # The step RETURNS the outcome rather than None: it is plain JSON, so Inngest memoizes it
    # correctly on a replay, and discarding it was what left the caller unable to tell a recorded
    # execution from an unrecorded one (F-008).
    _outcome = await step.run("decidio-confirm", lambda: confirm(guard, auth["decisionId"], result, evidence=evidence))
    from ..guard import ProtectedExecution
    _rk = raw.get("requestKey") if isinstance(raw, dict) and isinstance(raw.get("requestKey"), str) else None
    return ProtectedExecution(value=result, decision_id=auth["decisionId"], confirmation=_outcome or {}, request_key=_rk)


def resume_event(raw_body: Any, signature: Optional[str], webhook_secret: Optional[str] = None, *,
                 allow_unsigned: bool = False) -> dict:
    """Verify Decidio's signed resume webhook and translate it into the Inngest event payload to send
    (`await inngest_client.send(Event(name=..., data=...))`) — wakes the suspended gate.

    VERIFIES THE HMAC (0.7.0), exactly like the TS bridge (`createInngestResumeBridge`): pass the RAW
    request body and its `x-decidio-signature` header, with `webhook_secret` = DECIDIO_WEBHOOK_SECRET.
    With no secret it raises PermissionError unless `allow_unsigned=True` (a trusted network boundary
    only). Before 0.7.0 this took the PARSED body and verified nothing, so anyone who could reach the
    bridge could emit an approval event. (The gate treats the event as a wake-up and confirms the
    approval with Decidio anyway; this keeps forged wake-ups out.)"""
    if isinstance(raw_body, dict):
        raise TypeError("[decidio] resume_event now takes the RAW webhook body (bytes/str) and its x-decidio-signature header, "
                        "so it can verify the HMAC before emitting anything (0.7.0): resume_event(request_body_bytes, "
                        "headers.get('x-decidio-signature'), webhook_secret=os.environ['DECIDIO_WEBHOOK_SECRET']).")
    body = raw_body.decode("utf-8") if isinstance(raw_body, (bytes, bytearray)) else str(raw_body)
    if not webhook_secret:
        if not allow_unsigned:
            raise PermissionError(_NO_WEBHOOK_SECRET)
    elif not verify_signature(webhook_secret, body, signature):
        raise PermissionError("bad signature")
    import json as _json
    data = _json.loads(body or "{}")
    data = data if isinstance(data, dict) else {}
    return {
        "name": DECIDIO_RESUME_EVENT,
        "data": {
            "decisionId": str(data.get("decisionId")),
            "verdict": data.get("verdict"),
            "reason": data.get("reason"),
        },
    }
