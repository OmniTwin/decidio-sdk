"""Execution evidence - what the SDK knows, said precisely (Python mirror of evidence.ts).

Two different questions were previously answered by one overloaded boolean called
``confirmed``, and the SDK and the hosted record used that same name to mean different
things for the same decision. They are separated here and never merged again:

  report_recorded     - Decidio ACCEPTED our execution report and told us which tier it
                        recorded. (A transport success alone is NOT this: a 2xx with no
                        tier is a failure.)
  execution_confirmed - that recorded tier actually attests a committed execution.

A report can be recorded and still not confirm execution - that is the honest, common
case, and the SDK now explains WHY rather than leaving a developer to guess.

Convention for this file: runtime strings stay ASCII (hyphens, never em-dashes) so they
survive every console encoding a developer might be running.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

# Every tier the gate can record, weakest to strongest. Mirrors the server's enum exactly;
# an answer outside this list means this SDK version does not understand the record, and an
# answer we do not understand is never treated as evidence.
EVIDENCE_TIERS = (
    "pending",
    "execution_unconfirmed",
    "agent_asserted",
    "sensor_observed",
    "application_confirmed",
    "independently_reconciled",
)

# Tiers that attest a COMMITTED execution. `agent_asserted` is deliberately absent: an
# unproven self-report is not evidence of a commit, and `execution_unconfirmed` says so itself.
CONFIRMING = ("sensor_observed", "application_confirmed", "independently_reconciled")


def tombstone_tier(ev: Dict[str, Any]) -> str:
    """The tier a `reported` tombstone records. The server caps a confirming tier whose proof failed
    to `execution_unconfirmed` (apps/api agent-confirm.ts, lint-locked), so a body that says otherwise
    is one the current server cannot emit; the tombstone applies the same rule, so reconfirm() -
    which derives from the tier - can never answer "confirmed" where resolve() answered "not
    confirmed" over the same record (invariant-guard, 0.3.3). Every other tier is stored verbatim."""
    tier = ev.get("evidence_tier")
    if ev.get("execution_report_verified") is False and tier in CONFIRMING:
        return "execution_unconfirmed"
    return tier or "recorded"


def describe_tier_gap(captured_response: Any) -> str:
    """What the gate needs from a captured response to record ``application_confirmed``: a
    record id AND a success indication. This is the SERVER's rule, restated here only to
    explain it."""
    r = captured_response if isinstance(captured_response, dict) else {}
    # Fall through on a MISSING-or-null value, matching the TS `??` chain: a present
    # `success: False` must survive as False (it is an answer), while a null must not.
    rid = r.get("id")
    if rid is None:
        rid = r.get("recordId")
    if rid is None:
        rid = r.get("Id")
    okish = r.get("success")
    if okish is None:
        okish = r.get("ok")
    if okish is None:
        okish = True if rid is not None else None
    missing = []
    if rid is None:
        missing.append("a record id (`id`, `recordId` or `Id`)")
    if okish is None or okish is False:
        missing.append("a success flag (`success` or `ok`)")
    if not missing:
        return "the report was accepted but the gate recorded a weaker tier - check that this agent's registration and signing key still match (`python -m decidio doctor`)."
    return (
        "your protected function's return value carried no " + " and no ".join(missing) +
        ", so Decidio honestly recorded that the execution is UNCONFIRMED - it has no evidence the "
        "downstream write committed. Return the source system's identifiers (e.g. "
        "{\"id\": ..., \"success\": True} or {\"recordId\": ..., \"ok\": True}), or map them with the "
        "`evidence` option, to earn application_confirmed."
    )


def read_confirm_response(body: Any, signed: bool = False, captured: Any = None, journalled: bool = False) -> Dict[str, Any]:
    """Read the gate's confirm response and say precisely what happened. Fail-closed: an
    unknown or missing tier is NOT a recorded report.

    Returns {"report_recorded", "evidence_tier"?, "execution_confirmed", "diagnostic"?}.

    `journalled` distinguishes the DURABLE path (the report is on disk, so reconfirm can re-send
    it) from paths that journal nothing, where pointing the caller at reconfirm would send them to
    a function that can only answer "nothing is journalled for X"."""
    retry = ("re-send the report with guard.resume.reconfirm(decision_id) once connectivity or the service is healthy."
             if journalled else
             "this path journalled no report, so there is nothing to re-send from here - record the outcome from your own "
             "system, or run the action through guard.protect's durable mode, where reports ARE journalled and reconfirm "
             "can replay them.")
    if not isinstance(body, dict) or body.get("ok") is not True or not isinstance(body.get("confirmation"), str):
        # Retryable: a 2xx with no tier is an availability/shape problem, and the same report sent
        # again can succeed.
        return {
            "report_recorded": False,
            "execution_confirmed": False,
            "confirmation_retryable": True,
            "report_journalled": bool(journalled),
            "diagnostic": "the gate answered 2xx but named no evidence tier - the execution report is NOT recorded. Your action DID run; " + retry,
        }
    tier = body["confirmation"]
    if tier not in EVIDENCE_TIERS:
        # NOT retryable: the server will answer with the same unrecognised tier every time. This
        # is a version-skew problem, and re-sending is the one thing that cannot fix it.
        return {
            "report_recorded": False,
            "execution_confirmed": False,
            "confirmation_retryable": False,
            "report_journalled": bool(journalled),
            "diagnostic": f"the gate reported an evidence tier this SDK does not recognise ({tier!r}) - refusing to treat it as evidence. Upgrade the decidio package; your action DID run, and " + retry,
        }
    # THE PROOF VERDICT IS AN INPUT TO "IS THIS CONFIRMED", NOT AN ANNOTATION ON IT.
    #
    # This block used to run AFTER execution_confirmed was derived, and only added a diagnostic. So
    # {"confirmation": "application_confirmed", "executionReport": {"verified": False}} produced
    # execution_confirmed=True alongside execution_report_verified=False, and a caller branching on
    # the boolean - the obvious thing to branch on - got false assurance from a response that
    # contradicted itself. Read the verdict first, then derive.
    #
    # A confirming tier now requires BOTH a recognised confirming tier AND no explicit proof failure.
    # Absent reports are untouched: the report is optional, and not sending one is not a failure to
    # prove. The server applies the same rule at its own end (it caps the recorded tier), so the two
    # ends agree rather than one compensating for the other.
    rpt = body.get("executionReport")
    has_verdict = isinstance(rpt, dict) and isinstance(rpt.get("verified"), bool)
    proof_explicitly_failed = bool(has_verdict and rpt["verified"] is False)

    execution_confirmed = (tier in CONFIRMING) and not proof_explicitly_failed
    out: Dict[str, Any] = {"report_recorded": True, "evidence_tier": tier, "execution_confirmed": execution_confirmed,
                           "report_journalled": bool(journalled)}
    # The tier-gap explanations only make sense when the tier ITSELF is non-confirming. When a
    # confirming tier was refused for proof failure, that refusal is the explanation, and the
    # key-not-configured line would be actively misleading.
    if not execution_confirmed and not proof_explicitly_failed:
        out["diagnostic"] = (
            describe_tier_gap(captured) if signed
            else "no signing key is configured, so the gate capped this report at an unproven agent assertion. Run `python -m decidio init` to generate the agent's key and earn a confirming tier."
        )
    if has_verdict:
        out["execution_report_verified"] = rpt["verified"]
        # WHY it did not verify, as a FIELD. It was folded into prose and nowhere else, so a caller
        # who wanted to branch on the reason - retry vs re-register vs alert - had to regex an
        # English sentence.
        if isinstance(rpt.get("reason"), str) and rpt.get("reason"):
            out["execution_report_reason"] = rpt["reason"]
        if proof_explicitly_failed:
            why = f' ({rpt["reason"]})' if isinstance(rpt.get("reason"), str) and rpt.get("reason") else ""
            out["diagnostic"] = (
                f"the signed execution report did NOT verify{why}, so this is NOT a confirmed execution - "
                f'the gate reported tier "{tier}", and this SDK refuses to read an unproven attestation as '
                f"confirmation. Your action DID run and the report IS recorded at that tier - there is nothing "
                f"to re-send, and re-sending would not change the verdict; the record stands as unverified. "
                f"Check the agent's key/DID/registration (python -m decidio doctor) so the NEXT execution verifies."
            )
    return out


def _cfg(cfg: Any, name: str) -> Any:
    """Read one identity field from either a dataclass-ish config or a plain dict."""
    if isinstance(cfg, dict):
        return cfg.get(name)
    return getattr(cfg, name, None)


def build_confirm_body(
    cfg: Any,
    decision_id: str,
    canonical_result: Any,
    requester_identity: Optional[dict] = None,
    source: str = "wrapper",
) -> Dict[str, Any]:
    """The ONE confirm request shape, shared by every door (inline, durable resume, adapters).

    Carries the identity proof (WHO is reporting) and - when a key is configured - a signed,
    decision-bound ExecutionReport over the canonical response digest (WHAT was reported).
    ``cfg`` may be a GuardConfig, a ResumeController, or a dict with agent_id / agent_key /
    agent_did / workspace_id."""
    agent_key = _cfg(cfg, "agent_key")
    agent_did = _cfg(cfg, "agent_did")
    body: Dict[str, Any] = {
        "decisionId": decision_id,
        "capturedResponse": canonical_result if canonical_result is not None else None,
        "source": source,
    }
    if requester_identity is not None:
        body["requesterIdentity"] = requester_identity
    if agent_key and agent_did:
        from .signing import result_digest, sign_execution_report
        body["executionReport"] = sign_execution_report(
            agent_key,
            decision_id=decision_id,
            agent_id=_cfg(cfg, "agent_id") or "agent",
            did=agent_did,
            workspace_id=_cfg(cfg, "workspace_id"),
            source=source,
            result_digest=result_digest(canonical_result if canonical_result is not None else None),
        )
    return body
