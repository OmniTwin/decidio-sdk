"""Durable async resume — the Python mirror of @decidio/guard's resume.ts.

A routed action SUSPENDS (parks its call args in an AGENT-SIDE store, raises
DecidioSuspended); the process may exit. When a human approves, Decidio POSTs a
signed verdict to the agent's resume URL; the controller re-runs the agent's OWN
function and confirms. Decidio signals — it never executes, and holds none of the
parked payload. Webhook verification is fail-closed.

THE EXECUTION GUARANTEE: once invocation may have begun, this SDK never automatically invokes it
again unless the downstream system provides an idempotency guarantee or an operator explicitly
reconciles it. It holds across processes and restarts, because a durable `invoking` marker is
written to the pending store BEFORE the handler is called. Through 0.1.x the claim was
"single-use - the parked entry is deleted on completion"; deletion was never the guarantee, and
this release exists because that sentence was false whenever a delete failed, a replica lagged,
or a process died mid-flight. Deletion is cleanup now. The state is the guarantee.
"""
from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import sys
import os
import threading
import time
from uuid import uuid4
from dataclasses import dataclass, field, asdict, replace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Protocol

from . import _client
from ._client import Transport, UrllibTransport
from .canonical import canonicalize, canonicalize_args
from .errors import (DecidioApprovalUnverified, DecidioBlocked, DecidioRejected, DecidioRequestChanged,
                     DecidioSuspended, DecidioUnsafeArguments, decision_id_problem, DecidioUnanswered, UNANSWERED_WORDS, unanswered_of)
from .evidence import build_confirm_body, CONFIRMING, tombstone_tier
from .signing import binding_material_of, carries_credential, request_commitment



_re_sid = __import__("re").compile(r"S-1-[0-9-]+")


def windows_principal() -> str:
    """The ACL principal for THIS process, resolved from the token SID rather than the login name.

    Shared by every hardening site (F-009): the durable pending directory AND the `.env` the CLI
    writes. `_write_secret_file` had its own weaker copy that granted `getpass.getuser()` - who
    logged IN, which is not always who is writing. A Windows service, a scheduled task or an
    impersonated thread has a different effective identity, and granting the wrong name while
    /inheritance:r strips every other ACE is how a hardening step locks the writer out of its own
    secrets. A SID also needs no localisation or escaping, where a name can carry spaces, a domain
    prefix, or be renamed out from under the ACE."""
    import subprocess as _sp



    _sysroot = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    for _exe in (os.path.join(_sysroot, "System32", "whoami.exe"), "whoami"):
        try:
            _out = _sp.run([_exe, "/user", "/fo", "csv", "/nh"], check=True,
                           capture_output=True, text=True).stdout
            _m = _re_sid.search(_out)
            if _m:
                return "*" + _m.group(0)
        except Exception:
            pass
    import getpass as _gp
    try:
        return _gp.getuser()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or ""


def harden_file(path: str) -> Optional[str]:
    """Restrict a FILE to its owner on Windows, with the same verify-then-roll-back discipline as
    `harden_dir`. Returns None on success, or the reason it could not be done.

    The verification is the point, and it is what the CLI's own version lacked: a SUCCESSFUL
    icacls that locks this process out of the file it just wrote is more dangerous than a failed
    one, and it printed nothing at all. Here the file is read back, and if that fails the
    inheritance goes back rather than leaving credentials the SDK can no longer read."""
    if os.name != "nt":
        return None
    import subprocess as _sp
    try:
        principal = windows_principal()
        if not principal:
            return "could not determine the current user"


        _sp.run(["icacls", path, "/inheritance:r", "/grant:r", f"{principal}:F",
                 "/grant:r", "*S-1-5-18:F"],
                check=True, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
        try:
            with open(path, encoding="utf-8") as _fh:
                _fh.read()
        except Exception as _ve:
            try:
                _sp.run(["icacls", path, "/inheritance:e"], check=False,
                        stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            except Exception:
                pass
            return f"the restriction applied but this process could no longer read the file ({_ve}), so it was rolled back"
        return None
    except Exception as e:
        return str(e)


def harden_dir(directory: str) -> None:
    """Restrict a directory to its owner. On Windows POSIX modes are a no-op, so strip
    inheritance and grant only the effective user. A FAILURE IS SAID, never swallowed: these
    files hold the arguments of actions awaiting approval (and the reports of actions that
    already ran), and "silently kept the directory's inherited permissions" is exactly the
    outcome an operator must not discover from an auditor."""
    if os.name != "nt":
        return
    import subprocess as _sp

    def _warn(why: str) -> None:
        print(f"[decidio] WARNING: could not restrict {directory} to owner-only ({why}). It keeps the "
              f"directory's inherited permissions, so other accounts on this machine may be able to read "
              f"parked action arguments. Move the pending store to a protected location, or set "
              f"DECIDIO_PENDING_DIR to one.", file=sys.stderr)

    try:






        principal = windows_principal()
        if not principal:
            raise RuntimeError("could not determine the current user")



        _sp.run(["icacls", directory, "/inheritance:r", "/grant:r", f"{principal}:(OI)(CI)F",
                 "/grant:r", "*S-1-5-18:(OI)(CI)F"],
                check=True, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)





        _probe = os.path.join(directory, f".decidio-acl-probe-{os.getpid()}")
        try:
            with open(_probe, "w", encoding="utf-8") as _fh:
                _fh.write("probe")
            with open(_probe, encoding="utf-8") as _fh:
                _fh.read()
            os.remove(_probe)
        except Exception as _ve:
            try:
                _sp.run(["icacls", directory, "/inheritance:e"], check=False,
                        stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            except Exception:
                pass
            try:
                os.remove(_probe)
            except OSError:
                pass
            _warn(f"the restriction applied but this process could no longer write there ({_ve}), so it was rolled back")
    except Exception as e:
        _warn(str(e))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_private(path: str, text: str) -> None:
    """Write owner-only (0600). The parked args and the journalled reports are the most
    sensitive runtime files this SDK writes."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


@dataclass
class ExecutionContext:
    """What the SDK knows about THIS execution, handed to a handler that opts in with
    `with_context=True`.

    The point is `idempotency_key`. This SDK can guarantee it will not invoke your handler twice;
    it cannot guarantee your downstream API only commits once, because that is the vendor's
    property, not ours. Passing this key to Stripe/Salesforce/your own service is what closes the
    remaining window - and until now the handler had no way to reach the decision id at all, so
    the one thing that could close it was the one thing a caller could not get.

    Opt-in, never inferred from a signature. Introspection would have to guess whether a bound
    method, a *args function or a decorated tool wanted the context, and guessing wrong means
    passing a context object as someone's first business argument - in a library whose whole job
    is not doing surprising things to a payment call."""

    decision_id: str


    attempt_id: Optional[str]


    idempotency_key: str


@dataclass
class PendingAction:
    decision_id: str
    action: str
    amount: float
    args: list
    kwargs: dict = field(default_factory=dict)
    scope: Optional[str] = None
    receipt_id: Optional[str] = None
    created_at: Optional[str] = None





    args_sig: Optional[dict] = None






    request_commitment: Optional[str] = None







    claim_key: Optional[str] = None


def _outcome_from_head(head, decision_id: str, action: Optional[str] = None) -> Optional[dict]:
    """ONE mapping from a ledger head to the truthful outcome for a signal that DID NOTHING (prodsec V040-01, first-run
    review of 0.4.1; TS twin outcomeFromHead). None when the head is in none of those states."""
    st = getattr(head, "state", None)
    if head is None or st is None:
        return None
    base = {"decision_id": decision_id, **({"action": action} if action else {})}
    if st == "discarded":
        return {"status": "already_resolved", **base, "reason": f"this decision was DENIED ({getattr(head, 'verdict', None) or 'rejected'}); that answer is final and this signal did nothing"}
    if st in ("executed_unreported", "reported"):
        return {"status": "already_resolved", **base, "reason": f"this decision already ran (durable state {st}); this signal arrived after it and did nothing"}
    if st in ("invoking", "indeterminate"):
        return {"status": "indeterminate", **base, "reason": f'this decision is in durable state {st}: its action may still be running or may have finished without reporting - it may or may not have run. Nothing will retry it; check the worker and the downstream system, then settle it with reconcile("{decision_id}", ...).'}
    if st == "claimed_preinvoke":
        return {"status": "lost_race", **base, "reason": "another attempt holds the pre-invocation claim on this decision; this signal did nothing. If that attempt is alive it will report; if it died, recover() lists the decision and reconcile() can settle it"}
    return None


class DecidioStateCorrupt(Exception):
    """The state on disk could not be read. Never silently treated as "nothing here": an
    unreadable record is the one that proves an action already ran."""

    def __init__(self, decision_id: str, details: List[str]):
        super().__init__(
            f"[decidio] {decision_id}: durable execution state is unreadable ({'; '.join(details)}). "
            f"Refusing to guess whether this action ran - inspect these files; reconcile() once you know."
        )
        self.decision_id = decision_id
        self.details = details





















EXECUTION_STATES = ("parked", "claimed_preinvoke", "discarded", "invoking", "executed_unreported", "indeterminate", "reported")

NON_REPLAYABLE = ("discarded", "invoking", "executed_unreported", "indeterminate", "reported")


def _rank(state: str) -> int:
    """Ordered weakest->strongest. Resolution ALWAYS takes the strongest state present, which is
    what makes a partially-failed transition safe: if a crash leaves both the old and the new
    marker on disk, the stronger one wins and an executed action can never read back as parked."""
    return EXECUTION_STATES.index(state)










def _evidence_binding_bytes(decision_id: str, attempt_id: Optional[str], evidence: Any) -> bytes:
    from .signing import canonicalize as _canon
    return _canon({"decisionId": decision_id, "attemptId": attempt_id, "evidence": evidence}).encode("utf-8")


def sign_evidence(decision_id: str, attempt_id: Optional[str], evidence: Any,
                  agent_key: Optional[str] = None, webhook_secret: Optional[str] = None) -> Optional[dict]:
    data = _evidence_binding_bytes(decision_id, attempt_id, evidence)
    if agent_key:
        try:
            from cryptography.hazmat.primitives.serialization import load_der_private_key
            import base64 as _b64
            key = load_der_private_key(_b64.b64decode(agent_key), password=None)
            return {"kind": "ed25519", "sig": _b64.urlsafe_b64encode(key.sign(data)).rstrip(b"=").decode()}
        except Exception:
            pass
    if webhook_secret:
        import hashlib
        import hmac as _hmac
        return {"kind": "hmac", "sig": _hmac.new(webhook_secret.encode(), data, hashlib.sha256).hexdigest()}
    return None


def verify_evidence(rec: "ExecutionRecord", agent_key: Optional[str] = None,
                    webhook_secret: Optional[str] = None) -> str:
    """"ok" | "mismatch" | "unbound" | "unverifiable" - the same vocabulary as the parked-args
    check, so the two integrity surfaces read alike."""
    if not rec.evidence_sig:
        return "unbound"
    data = _evidence_binding_bytes(rec.decision_id, rec.attempt_id, rec.evidence)
    try:
        if rec.evidence_sig.get("kind") == "ed25519":
            if not agent_key:
                return "unverifiable"
            from cryptography.hazmat.primitives.serialization import load_der_private_key
            import base64 as _b64
            key = load_der_private_key(_b64.b64decode(agent_key), password=None)
            sig = rec.evidence_sig["sig"]
            raw = _b64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
            key.public_key().verify(raw, data)
            return "ok"
        if not webhook_secret:
            return "unverifiable"
        import hashlib
        import hmac as _hmac
        expected = _hmac.new(webhook_secret.encode(), data, hashlib.sha256).hexdigest()
        return "ok" if _hmac.compare_digest(expected, rec.evidence_sig.get("sig", "")) else "mismatch"
    except Exception:
        return "mismatch"


SETTLE_OUTCOMES = ("committed", "not_committed")


class DecidioStaleAttempt(RuntimeError):
    """The ledger row is owned by a NEWER attempt. Typed for the same reason DecidioAlreadySettled
    is: _report_after_execution must keep going when the ledger fails, so a bare error here read as
    "the disk write failed" and the stale attempt went on to POST - a second authority report for
    one decision. Reachable through the SDK's own documented flow: reconcile(id, "not_committed")
    releases a decision whose original attempt is still alive (recover() invites exactly that, since
    it says the process "died" when it may not have), the release is legitimate and the new attempt
    SHOULD run - but the old attempt's report must not be sent."""

    def __init__(self, decision_id: str, owner: Optional[str], state: str):
        super().__init__(
            f"[decidio] {decision_id}: this attempt no longer owns the decision - attempt "
            f"{owner or '(unknown)'} holds it in state {state}. Refusing a state write from a "
            f"superseded attempt.")
        self.decision_id = decision_id


class DecidioAlreadySettled(RuntimeError):
    """TYPED, because the reporting stage has to tell this apart from a disk failure. Raised as a
    generic error it read as "the ledger write failed", and that stage's whole job is to keep going
    when the ledger fails - so it went on to POST, and Decidio received a second execution report
    for one decision."""

    def __init__(self, decision_id: str):
        super().__init__(
            f"[decidio] {decision_id}: an operator already settled this decision as committed and its report is "
            f"recorded - refusing a second execution report. Nothing was re-run; this write is the duplicate, "
            f"not the execution.")
        self.decision_id = decision_id


class DecidioRecoveryUnavailable(RuntimeError):
    """`recover()` could not enumerate the ledger. It RAISES rather than returning an empty list,
    because those two are the same value to a caller and mean opposite things: `[]` is "you owe
    nothing", and this is "I cannot tell you what you owe". The old code printed to stderr and
    returned `[]`, so a script reading `if not resume.recover(): all_clear()` treated an unreadable
    store - a permissions change, a mounted volume gone, a corrupt directory - as proof that no
    action was left outstanding. A crash is the correct failure here; silence is not."""

    def __init__(self, cause: Exception):
        self.cause = cause
        super().__init__(f'[decidio] recover(): the execution ledger could not be read ({cause}). Refusing to return an empty recovery list, which would read as "nothing is outstanding" - inspect the store; some actions may be awaiting a report.')


class DecidioDenied(RuntimeError):
    """A DENIAL IS TERMINAL, and that has to be enforced where the state is WRITTEN - not only where
    it is reconciled. Refusing `settle` from `discarded` closed the operator's door and left three
    others open, each of which walked a refused action all the way to execution:
      - `discarded` sits mid-rank in EXECUTION_STATES, so the advance-only rule happily accepted
        `discarded -> invoking -> executed_unreported`;
      - `mark_discarded` leaves the record UNOWNED (attempt_id "") when nothing had claimed it, so
        the ownership fence - which skips when there is no owner - did not stop that walk either;
      - reachable through the shipped controller, not just the store API: an `approved` signal
        claims, a `rejected` signal writes the tombstone, and the first call then invokes anyway.
    Typed, for the same reason DecidioAlreadySettled is: the reporting stage deliberately keeps
    going when the ledger fails, so a generic error here would read as "the disk write failed" and
    send an authority report for an action a human refused."""

    def __init__(self, decision_id: str, verdict: str):
        self.decision_id = decision_id
        self.verdict = verdict
        super().__init__(f"[decidio] {decision_id}: this decision was DENIED ({verdict}) and a denial is terminal - refusing a state write that would move it back toward execution. Nothing may advance out of a denial; if this action should now proceed it needs a NEW request and a new approval.")


def assert_not_denied(decision_id: str, cur: "ExecutionRecord", nxt: str) -> None:
    if cur.state == "discarded" and nxt != "discarded":
        raise DecidioDenied(decision_id, cur.verdict or "rejected")


def assert_claimed_by(decision_id: str, cur: "ExecutionRecord", attempt_id: str) -> None:
    """OWNERSHIP IS ACQUIRED ONLY THROUGH `claim()`. The ownership fence compares against an
    EXISTING owner, so it says nothing about a record that has none - and `mark_invoking` on an
    unclaimed decision was therefore accepted, which made the atomic claim decorative: a process
    that never entered the race could cross the invocation boundary. The boundary now requires a
    claim THIS attempt holds, which is the only way to acquire one."""
    if cur.state != "claimed_preinvoke" or cur.attempt_id != attempt_id:
        raise RuntimeError(f"[decidio] {decision_id}: refusing to cross the invocation boundary - attempt {attempt_id} does not hold a claim on this decision (state {cur.state}, held by {cur.attempt_id or 'nobody'}). A claim is the only way to acquire ownership; call claim() and act on its result.")


def assert_not_settled(decision_id: str, cur: "ExecutionRecord", nxt: str) -> None:
    """A decision an operator SETTLED as committed is finished: its report is recorded and sent. A
    late write from the attempt that was still running would produce a second authority report for
    one decision, so it is refused here rather than in each store. `not_committed` settlements are
    deliberately not covered - that outcome exists so a new attempt can run and record."""
    if (cur.reconciled or {}).get("outcome") == "committed" and nxt in ("executed_unreported", "indeterminate"):
        raise DecidioAlreadySettled(decision_id)


def assert_settlable(decision_id: str, state: str, outcome: str, has_observed_evidence: bool = True,
                     worker_stopped: bool = False) -> None:
    """Refuse a reconciliation that would be a fabrication. Shared by every store so the rule
    cannot drift between implementations - a store that allowed `committed` from `parked` would
    let an operator mint an execution report for an action nothing ever invoked."""
    if outcome not in SETTLE_OUTCOMES:
        raise ValueError(f'[decidio] {decision_id}: outcome must be "committed" or "not_committed", not {outcome!r}.')







    if state == "discarded":
        raise RuntimeError(f"[decidio] {decision_id}: this decision was DENIED by a human or a policy, and a denial is final - it cannot be reconciled, released or retried. Nothing ran, so there is no outcome to record. If this action should now proceed it needs a NEW request and a new approval.")
    if outcome == "committed":
        if state == "reported":
            raise RuntimeError(f"[decidio] {decision_id}: already reported - there is nothing left to reconcile.")











        if state == "executed_unreported" and has_observed_evidence:
            raise RuntimeError(f'[decidio] {decision_id}: this decision already holds evidence this SDK OBSERVED - an operator assertion must not replace a captured result. If the report simply has not reached Decidio, re-send the real one: reconfirm("{decision_id}").')
        if _rank(state) < _rank("invoking"):
            raise RuntimeError(f'[decidio] {decision_id}: refusing to record a COMMITTED outcome from state {state} - the handler was never invoked, so no downstream write can have happened. If you mean "run it", let it resume normally.')
    else:
        if state == "reported":
            raise RuntimeError(f"[decidio] {decision_id}: already reported - releasing it would re-run an execution Decidio has already recorded.")
        if state == "executed_unreported":
            raise RuntimeError(f'[decidio] {decision_id}: this decision holds CAPTURED EVIDENCE of an execution - releasing it would re-run a proven write. Re-send the evidence with reconfirm("{decision_id}") instead.')
        if state == "parked":
            raise RuntimeError(f"[decidio] {decision_id}: already parked - nothing to release.")









        if state == "invoking" and worker_stopped is not True:
            raise RuntimeError(f'[decidio] {decision_id}: this decision is still INVOKING - the worker that claimed it may be running the action right now, and releasing it would let a second worker run the same approved action. Stop or confirm the death of that worker first, then say so explicitly: reconcile("{decision_id}", outcome="not_committed", reason=..., worker_stopped=True). If you cannot confirm it stopped, treat the decision as possibly executed and reconcile it as "committed" once you have checked the downstream system.')


@dataclass
class ExecutionRecord:
    decision_id: str
    state: str


    attempt_id: Optional[str] = None
    action: Optional[str] = None



    evidence: Any = None
    has_evidence: bool = False

    error: Optional[str] = None

    confirmation: Optional[str] = None






    evidence_sig: Optional[dict] = None


    verdict: Optional[str] = None
    discard_reason: Optional[str] = None




    migrated_from: Optional[str] = None




    evidence_error: Optional[str] = None
    reconciled: Optional[dict] = None







    execution_despite_denial: Optional[dict] = None
    at: str = ""


@dataclass
class ClaimResult:

    ok: bool


    state: Optional[str] = None
    reason: Optional[str] = None


class PendingStore(Protocol):
    """Agent-side durable state. The shipped stores are file- and memory-backed; swap in
    Redis/Postgres/your queue for production. AGENT-SIDE only - Decidio never sees this.

    v2 (0.2.0) makes the state machine MANDATORY. The 0.1.x contract left claim() optional and
    fell back to a process-local set, which cannot survive a restart and therefore could not carry
    a single-execution guarantee across processes at all. Every method must be atomic against
    concurrent callers - compare-and-swap, a transaction, or an equivalent fencing token."""

    def put(self, p: PendingAction) -> None: ...
    def get(self, decision_id: str) -> Optional[PendingAction]: ...

    def delete(self, decision_id: str, attempt_id: Optional[str] = None) -> None:
        """CLEANUP ONLY. Removing a row must never be what prevents a second execution.

        `attempt_id` scopes the cleanup to its OWNER. A superseded attempt tidies up on its way out
        (see the stale-attempt branch of the reporting stage), and without this it deleted the
        payload of the attempt that had legitimately taken over - the live worker's own recovery
        data, removed by the dead one. Omit it for housekeeping not attributable to an attempt."""
        ...

    def list(self) -> List[PendingAction]: ...


    def claim(self, decision_id: str, attempt_id: str) -> ClaimResult: ...


    def mark_invoking(self, decision_id: str, attempt_id: str) -> None: ...

    def record_executed(self, decision_id: str, attempt_id: str, evidence: Any, evidence_sig: Optional[dict] = None, evidence_error: Optional[str] = None) -> None: ...

    def mark_indeterminate(self, decision_id: str, attempt_id: str, error: str) -> None: ...

    def mark_reported(self, decision_id: str, attempt_id: str, confirmation: str) -> None: ...
    def mark_discarded(self, decision_id: str, verdict: str, reason: Optional[str] = None) -> None:
        """A human or policy DENIED this decision - write the terminal tombstone.

        Must be persisted BEFORE any payload cleanup: cleanup is best-effort and a store that
        swallows its failure would otherwise leave the row readable as `parked`. Idempotent.
        """
        ...

    def get_execution(self, decision_id: str) -> Optional[ExecutionRecord]: ...

    def list_executions(self) -> List[ExecutionRecord]: ...









    def settle(self, decision_id: str, outcome: str, evidence: Any = None, reason: Optional[str] = None, evidence_sig: Optional[dict] = None, worker_stopped: bool = False) -> None: ...


    def release_preinvoke(self, decision_id: str, attempt_id: str) -> None: ...


class MemoryPendingStore:
    """In-memory store. Single-process only BY CONSTRUCTION - the right choice for tests and for a
    worker that owns its queue, the wrong one for two processes sharing work, which is what
    FilePendingStore (atomic links on one volume) or a real database is for."""

    def __init__(self) -> None:
        self._m: Dict[str, PendingAction] = {}
        self._x: Dict[str, ExecutionRecord] = {}

    def _rec(self, decision_id: str) -> ExecutionRecord:
        return self._x.get(decision_id) or ExecutionRecord(
            decision_id=decision_id, state="parked", attempt_id=None, at=_now_iso())

    def _advance(self, decision_id: str, attempt_id: str, state: str, _takeover: bool = False, **patch: Any) -> None:
        """Advance only. A write from a stale attempt, or one that would move the state
        BACKWARDS, is refused - the in-memory expression of the same rule the file store gets
        from strongest-wins resolution."""
        cur = self._rec(decision_id)







        if not _takeover and cur.attempt_id and cur.attempt_id != attempt_id:
            raise DecidioStaleAttempt(decision_id, cur.attempt_id, cur.state)
        assert_not_denied(decision_id, cur, state)
        assert_not_settled(decision_id, cur, state)
        if _rank(state) < _rank(cur.state):
            raise RuntimeError(f"[decidio] {decision_id}: refusing to move {cur.state} -> {state}; execution state only ever advances.")
        nxt = ExecutionRecord(
            decision_id=decision_id, state=state, attempt_id=attempt_id,
            action=patch.get("action", cur.action),
            evidence=patch.get("evidence", cur.evidence),
            has_evidence=patch.get("has_evidence", cur.has_evidence),
            error=patch.get("error", cur.error),
            confirmation=patch.get("confirmation", cur.confirmation),






            reconciled=patch.get("reconciled", cur.reconciled),
            evidence_sig=patch.get("evidence_sig", cur.evidence_sig),
            migrated_from=patch.get("migrated_from", cur.migrated_from),
            evidence_error=patch.get("evidence_error", cur.evidence_error),
            verdict=patch.get("verdict", cur.verdict),
            discard_reason=patch.get("discard_reason", cur.discard_reason),
            at=_now_iso(),
        )
        self._x[decision_id] = nxt

    def put(self, p: PendingAction) -> None:
        self._m[p.decision_id] = p
        if p.decision_id not in self._x:
            self._x[p.decision_id] = ExecutionRecord(decision_id=p.decision_id, state="parked", attempt_id=None, action=p.action, at=_now_iso())

    def get(self, decision_id: str) -> Optional[PendingAction]:
        return self._m.get(decision_id)

    def delete(self, decision_id: str, attempt_id: Optional[str] = None) -> None:
        """Cleanup only - the execution record STAYS. Scoped to the owning attempt: see
        PendingStore.delete."""
        if attempt_id is not None:
            owner = self._x.get(decision_id)
            if owner is not None and owner.attempt_id and owner.attempt_id != attempt_id:
                return
        self._m.pop(decision_id, None)

    def list(self) -> List[PendingAction]:
        return [p for p in self._m.values() if self._rec(p.decision_id).state == "parked"]

    def claim(self, decision_id: str, attempt_id: str) -> ClaimResult:
        if decision_id not in self._m:
            return ClaimResult(ok=False, reason="no parked entry")
        cur = self._rec(decision_id)
        if cur.state in NON_REPLAYABLE:
            return ClaimResult(ok=False, state=cur.state, reason=f"already {cur.state}")
        if cur.state == "claimed_preinvoke":
            return ClaimResult(ok=False, state=cur.state, reason="claimed by another attempt")
        self._advance(decision_id, attempt_id, "claimed_preinvoke", _takeover=True, action=self._m[decision_id].action)
        return ClaimResult(ok=True)

    def mark_invoking(self, decision_id: str, attempt_id: str) -> None:
        cur = self._rec(decision_id)


        assert_not_denied(decision_id, cur, "invoking")
        assert_claimed_by(decision_id, cur, attempt_id)
        self._advance(decision_id, attempt_id, "invoking")

    def record_executed(self, decision_id: str, attempt_id: str, evidence: Any, evidence_sig: Optional[dict] = None, evidence_error: Optional[str] = None) -> None:
        self._advance(decision_id, attempt_id, "executed_unreported", evidence=evidence, has_evidence=True, evidence_sig=evidence_sig, evidence_error=evidence_error)

    def mark_indeterminate(self, decision_id: str, attempt_id: str, error: str) -> None:
        self._advance(decision_id, attempt_id, "indeterminate", error=error)

    def mark_reported(self, decision_id: str, attempt_id: str, confirmation: str) -> None:
        self._advance(decision_id, attempt_id, "reported", confirmation=confirmation)

    def mark_discarded(self, decision_id: str, verdict: str, reason: Optional[str] = None) -> None:
        cur = self._x.get(decision_id)
        self._advance(decision_id, (cur.attempt_id if cur else None) or "", "discarded",
                      verdict=verdict, **({"discard_reason": reason} if reason else {}))

    def get_execution(self, decision_id: str) -> Optional[ExecutionRecord]:
        return self._x.get(decision_id)

    def list_executions(self) -> List[ExecutionRecord]:
        return list(self._x.values())

    def settle(self, decision_id: str, outcome: str, evidence: Any = None, reason: Optional[str] = None, evidence_sig: Optional[dict] = None, worker_stopped: bool = False) -> None:
        """OPERATOR RECONCILIATION - the ONE legal backwards transition, and the only exit from
        `indeterminate` or a stalled claim. It is legal only because a human asserted the
        downstream truth this machine cannot observe, so no automatic path may call it.

        `committed`     -> `executed_unreported` carrying the operator's evidence, so the ordinary
                           reporting path can send it. The handler is NEVER invoked.
        `not_committed` -> back to `parked`, permitting exactly one more ordinary attempt."""
        cur = self._rec(decision_id)



        assert_settlable(decision_id, cur.state, outcome, not cur.evidence_error, worker_stopped)
        at = _now_iso()



        reconciled = {"outcome": outcome, "reason": reason, "at": at}
        if worker_stopped:
            reconciled["workerStopped"] = True
        if outcome == "committed":
















            self._x[decision_id] = replace(
                cur, state="executed_unreported", evidence=evidence, has_evidence=True,
                evidence_sig=evidence_sig, evidence_error=None, reconciled=reconciled, at=at)
        else:
            self._x[decision_id] = replace(
                cur, state="parked", attempt_id=None, error=None, reconciled=reconciled, at=at)

    def release_preinvoke(self, decision_id: str, attempt_id: str) -> None:
        cur = self._rec(decision_id)



        if cur.state in NON_REPLAYABLE:
            raise RuntimeError(f"[decidio] {decision_id}: refusing to release this decision - its durable state is {cur.state}, which is terminal or past the invocation boundary. release_preinvoke only ever releases a claim nothing has acted on.")
        if cur.attempt_id and cur.attempt_id != attempt_id:
            return
        self._x[decision_id] = replace(cur, state="parked", attempt_id=None, at=_now_iso())


class FilePendingStore:
    """File-backed so a COLD process (the original requester long gone) can resume - the proof
    that nothing is 'kept alive'.

    One payload file per decision plus an APPEND-ONLY REVISION CHAIN for its execution record:
    `<key>.rev.<N>`, head = highest N. See the TypeScript twin for the full account; the short
    version is that the 0.2/0.3 one-marker-per-state layout made a transition in three separate
    steps (read markers, write the new one, sweep the weaker ones), so every rule ran against a
    SNAPSHOT and the write happened later regardless. A process holding `claimed_preinvoke` could
    lose to a durably-written-and-returned denial and then write `invoking` anyway, sweeping the
    tombstone - the SDK reported a denial as final and ran the denied action (retest V030-01, both
    languages, two OS processes). A transition now reads head N, validates against exactly that,
    writes the successor to a temp file and PUBLISHES it with os.link to `<key>.rev.<N+1>` - which
    fails if that name exists, so exactly one writer wins each revision and a loser re-validates
    against what actually happened.

    NO REVISION FILE IS EVER DELETED. The first cut garbage-collected revisions below the head after
    each publish, and a review broke it within the hour: a writer paused between validating
    and os.link targets `rev.N+1`; if the rival publishes N+1 and then ONE more transition, GC
    deletes N+1 - and the paused writer's os.link SUCCEEDS on the recycled name, publishing a stray
    below the head and returning success without a single rule re-running. A CAS whose target name
    can be reused is not a CAS. The chain is genuinely append-only; compaction, if ever wanted, is an
    offline operation that requires no writers. This is the atomicity the PendingStore contract has
    claimed since 0.2.0; the shipped store now honors it."""

    def __init__(self, directory: str) -> None:
        self.dir = directory
        os.makedirs(directory, exist_ok=True)


        harden_dir(directory)
        self.migrate_legacy()

    def _key(self, decision_id: str) -> str:
        return "".join(c if (c.isalnum() or c in "._-") else "_" for c in str(decision_id))

    def _path(self, decision_id: str) -> str:
        return os.path.join(self.dir, self._key(decision_id) + ".json")

    def _rev_path(self, key: str, n: int) -> str:
        return os.path.join(self.dir, f"{key}.rev.{n}")

    def _marker_path(self, key: str, state: str) -> str:
        """Legacy (0.2/0.3) marker path - read for migration, never written."""
        return os.path.join(self.dir, key + "." + state)

    def _list_revs(self, key: str, names: Optional[List[str]] = None) -> List[int]:
        prefix = f"{key}.rev."
        out: List[int] = []
        if names is None:
            try:
                names = os.listdir(self.dir)
            except FileNotFoundError:
                return out
            except OSError as e:

                raise DecidioStateCorrupt(key, [f"{self.dir}: {e}"]) from None
        for name in names:
            if name.startswith(prefix):
                tail = name[len(prefix):]
                if tail.isdigit():
                    out.append(int(tail))
        return out

    def _legacy_markers(self, key: str, names: Optional[List[str]] = None) -> List[str]:
        if names is not None:
            return [s for s in EXECUTION_STATES if f"{key}.{s}" in names]
        return [s for s in EXECUTION_STATES if os.path.exists(self._marker_path(key, s))]

    def _write_temp(self, target: str, text: str) -> str:
        """Write `text` to a fresh temp file beside `target`, fsynced. Returns the temp path."""
        tmp = f"{target}.{os.getpid()}.{uuid4().hex}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.remove(tmp)
            except Exception:
                pass
            raise
        return tmp

    def _write_atomic(self, path: str, text: str) -> None:
        """Durable write for the PAYLOAD file (not the chain): temp -> fsync -> atomic replace."""
        tmp = self._write_temp(path, text)
        os.replace(tmp, path)

    def _rec_to_json(self, r: ExecutionRecord) -> str:
        d = {"decisionId": r.decision_id, "state": r.state, "attemptId": r.attempt_id,
             "action": r.action, "error": r.error, "confirmation": r.confirmation, "at": r.at}


        if r.reconciled is not None:
            d["reconciled"] = r.reconciled
        if r.has_evidence:
            d["evidence"] = r.evidence
            d["hasEvidence"] = True
        if r.evidence_sig is not None:
            d["evidenceSig"] = r.evidence_sig
        if r.migrated_from is not None:
            d["migratedFrom"] = r.migrated_from
        if r.evidence_error is not None:
            d["evidenceError"] = r.evidence_error

        if r.verdict is not None:
            d["verdict"] = r.verdict
        if r.discard_reason is not None:
            d["discardReason"] = r.discard_reason



        if r.execution_despite_denial is not None:
            d["executionDespiteDenial"] = r.execution_despite_denial
        return json.dumps(d, indent=2)

    def _json_to_rec(self, raw: dict, state: str) -> ExecutionRecord:
        return ExecutionRecord(
            decision_id=raw.get("decisionId", ""), state=state, attempt_id=raw.get("attemptId"),
            action=raw.get("action"), evidence=raw.get("evidence"),
            has_evidence=bool(raw.get("hasEvidence")), error=raw.get("error"),
            confirmation=raw.get("confirmation"), reconciled=raw.get("reconciled"),
            evidence_sig=raw.get("evidenceSig"), migrated_from=raw.get("migratedFrom"),
            evidence_error=raw.get("evidenceError"),
            verdict=raw.get("verdict"), discard_reason=raw.get("discardReason"),
            execution_despite_denial=raw.get("executionDespiteDenial"),
            at=raw.get("at", ""))

    def _read_head(self, decision_id: str, names: Optional[List[str]] = None):
        """The head of the chain, or the migrated reading of a legacy layout that has not been
        upgraded. Returns (record-or-None, revision, corrupt-list). Corruption is REPORTED, never
        treated as absent: an unreadable record is the one that proves an action already ran.
        `names` lets list()/list_executions() read the directory ONCE for every decision instead of
        once per decision; a retry always re-lists fresh."""
        key = self._key(decision_id)
        for _try in range(4):
            revs = self._list_revs(key, names)
            markers = self._legacy_markers(key, names)
            names = None
            if not revs:
                if not markers:
                    return None, 0, []


                rec, corrupt = self._resolve_legacy_markers(key)
                return rec, 0, corrupt
            if markers:




                return None, max(revs), [f"{self._marker_path(key, s)}: a legacy state marker beside the revision chain - written by an older SDK after this directory was upgraded, or left by an interrupted upgrade; the two cannot be reconciled automatically" for s in markers]
            top = max(revs)
            f = self._rev_path(key, top)
            try:
                with open(f, encoding="utf-8") as fh:
                    raw = json.load(fh)



                if not isinstance(raw, dict) or raw.get("state") not in EXECUTION_STATES:
                    return None, top, [f"{f}: the record carries no recognised state ({json.dumps(raw.get('state') if isinstance(raw, dict) else None)})"]
                return self._json_to_rec(raw, raw.get("state")), top, []
            except FileNotFoundError:
                continue
            except Exception as e:
                return None, top, [f"{f}: {e}"]
        return None, 0, [f"{key}: the revision chain changed under every read attempt"]

    def _barrier(self, op: str, decision_id: str, state: str) -> None:
        """TEST SEAM, a no-op in production. Called with the operation name and the state about to
        be published, AFTER validation and BEFORE the publish - the exact window a concurrent
        writer can land in. The deterministic two-process suites subclass the store and block
        here, so the race the retest found is reproduced on purpose, every run, not by luck."""
        return None

    def _transition(self, decision_id: str, op: str, compute) -> Optional[ExecutionRecord]:
        """ONE TRANSITION = read head -> compute successor -> publish with os.link. `compute`
        receives (current record or None, revision) and returns the successor, or None for
        "nothing to write" (a refusal that is a return value, like a lost claim). Every rule runs
        INSIDE compute, against the revision about to be superseded; if a rival publishes first,
        compute runs again against the rival's record."""
        key = self._key(decision_id)
        for _attempt in range(16):
            rec, rev, corrupt = self._read_head(decision_id)
            if corrupt:
                raise DecidioStateCorrupt(decision_id, corrupt)
            nxt = compute(rec, rev)
            if nxt is None:
                return None
            self._barrier(op, decision_id, nxt.state)
            target = self._rev_path(key, rev + 1)
            tmp = self._write_temp(target, self._rec_to_json(nxt))
            try:
                os.link(tmp, target)
            except FileExistsError:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
                continue
            except Exception:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
                raise
            try:
                os.remove(tmp)
            except Exception:
                pass
            return nxt
        raise RuntimeError(f"[decidio] {decision_id}: could not publish a state transition after 16 attempts - another writer kept winning the next revision. Retry, or look for a process writing this decision in a loop.")

    def _resolve_legacy_markers(self, key: str):
        """The 0.2/0.3 reading of a marker layout - strongest marker wins, a denial marker wins at
        any rank, and a denial beside an execution marker is reported as both. Used ONLY to
        migrate an older directory and to report one that could not be migrated."""
        corrupt: List[str] = []
        best: Optional[ExecutionRecord] = None
        denial: Optional[ExecutionRecord] = None
        for st in EXECUTION_STATES:
            f = self._marker_path(key, st)
            if not os.path.exists(f):
                continue
            try:
                with open(f, encoding="utf-8") as fh:
                    raw = json.load(fh)
                r = self._json_to_rec(raw, st)
                if best is None or _rank(r.state) >= _rank(best.state):
                    best = r
                if st == "discarded":
                    denial = r
            except Exception as e:
                corrupt.append(f"{f}: {e}")
        if denial is None:
            return best, corrupt
        ran = best if (best is not None and _rank(best.state) >= _rank("invoking")) else None
        if ran is not None:
            denial.execution_despite_denial = {"state": ran.state, "at": ran.at, "hasEvidence": bool(ran.has_evidence)}
        return denial, corrupt

    def _set_state(self, decision_id: str, attempt_id: str, state: str, pre=None, **patch: Any) -> None:
        """The generic ADVANCE, with every fence evaluated against the head the publish will
        supersede. `pre` is a per-method check (mark_invoking's claim requirement) that must ALSO
        run inside the transition - a check that runs before it is a check against a snapshot."""
        def compute(rec, _rev):
            cur = rec or ExecutionRecord(decision_id=decision_id, state="parked", attempt_id=None, at=_now_iso())
            if pre is not None:
                pre(cur)


            if cur.attempt_id and cur.attempt_id != attempt_id:
                raise DecidioStaleAttempt(decision_id, cur.attempt_id, cur.state)
            assert_not_denied(decision_id, cur, state)
            assert_not_settled(decision_id, cur, state)
            if _rank(state) < _rank(cur.state):
                raise RuntimeError(f"[decidio] {decision_id}: refusing to move {cur.state} -> {state}; execution state only ever advances.")

            return replace(cur, state=state, attempt_id=attempt_id, at=_now_iso(), **patch)
        self._transition(decision_id, "advance", compute)

    def put(self, p: PendingAction) -> None:
        self._write_atomic(self._path(p.decision_id), json.dumps(asdict(p), indent=2))


        self._transition(p.decision_id, "put", lambda cur, _rev: None if cur is not None else
                         ExecutionRecord(decision_id=p.decision_id, state="parked", attempt_id=None, action=p.action, at=_now_iso()))

    def get(self, decision_id: str) -> Optional[PendingAction]:
        f = self._path(decision_id)
        if not os.path.exists(f):
            return None
        with open(f, encoding="utf-8") as fh:
            return PendingAction(**json.load(fh))

    def delete(self, decision_id: str, attempt_id: Optional[str] = None) -> None:
        """CLEANUP ONLY - the payload goes, the execution record STAYS. That is the whole point of
        the v2 model: a failed or skipped delete can no longer make an executed action runnable.

        Scoped to the owning attempt: a superseded attempt does not clean up the live one's
        payload. See PendingStore.delete."""
        if attempt_id is not None:
            owner, _rev, _corrupt = self._read_head(decision_id)
            if owner is not None and owner.attempt_id and owner.attempt_id != attempt_id:
                return
        try:
            f = self._path(decision_id)
            if os.path.exists(f):
                os.remove(f)
        except Exception:
            pass

    def list(self) -> List[PendingAction]:
        if not os.path.isdir(self.dir):
            return []
        out: List[PendingAction] = []
        names = os.listdir(self.dir)
        for name in names:
            if not name.endswith(".json"):
                continue


            try:
                with open(os.path.join(self.dir, name), encoding="utf-8") as fh:
                    p = PendingAction(**json.load(fh))
            except Exception as e:
                print(f"[decidio] skipping unreadable parked entry {name} ({e}) - the other parked actions still resume; inspect or delete this file.", file=sys.stderr)
                continue
            rec, _rev, _c = self._read_head(p.decision_id, names)
            if rec is None or rec.state == "parked":
                out.append(p)
        return out

    def claim(self, decision_id: str, attempt_id: str) -> ClaimResult:
        if not os.path.exists(self._path(decision_id)):
            return ClaimResult(ok=False, reason="no parked entry")
        refusal: Dict[str, Any] = {}





        def compute(cur, _rev):
            state = cur.state if cur else "parked"
            if state in NON_REPLAYABLE:
                refusal["r"] = ClaimResult(ok=False, state=state, reason=f"already {state}")
                return None
            if state == "claimed_preinvoke":
                refusal["r"] = ClaimResult(ok=False, state=state, reason="claimed by another attempt")
                return None


            if cur is not None:
                return replace(cur, state="claimed_preinvoke", attempt_id=attempt_id, at=_now_iso())
            return ExecutionRecord(decision_id=decision_id, state="claimed_preinvoke", attempt_id=attempt_id, at=_now_iso())
        self._transition(decision_id, "claim", compute)
        return refusal.get("r") or ClaimResult(ok=True)

    def mark_invoking(self, decision_id: str, attempt_id: str) -> None:


        def pre(cur):
            assert_not_denied(decision_id, cur, "invoking")
            assert_claimed_by(decision_id, cur, attempt_id)
        self._set_state(decision_id, attempt_id, "invoking", pre=pre)

    def record_executed(self, decision_id: str, attempt_id: str, evidence: Any, evidence_sig: Optional[dict] = None, evidence_error: Optional[str] = None) -> None:
        self._set_state(decision_id, attempt_id, "executed_unreported", evidence=evidence, has_evidence=True, evidence_sig=evidence_sig, evidence_error=evidence_error)

    def mark_indeterminate(self, decision_id: str, attempt_id: str, error: str) -> None:
        self._set_state(decision_id, attempt_id, "indeterminate", error=error)

    def mark_reported(self, decision_id: str, attempt_id: str, confirmation: str) -> None:
        self._set_state(decision_id, attempt_id, "reported", confirmation=confirmation)

    def mark_discarded(self, decision_id: str, verdict: str, reason: Optional[str] = None) -> None:


        def compute(rec, _rev):
            cur = rec or ExecutionRecord(decision_id=decision_id, state="parked", attempt_id=None, at=_now_iso())
            assert_not_settled(decision_id, cur, "discarded")
            if _rank("discarded") < _rank(cur.state):
                raise RuntimeError(f"[decidio] {decision_id}: refusing to move {cur.state} -> discarded; execution state only ever advances.")
            return replace(cur, state="discarded", attempt_id=cur.attempt_id or "", verdict=verdict,
                           discard_reason=(reason if reason else cur.discard_reason), at=_now_iso())
        self._transition(decision_id, "discard", compute)

    def get_execution(self, decision_id: str) -> Optional[ExecutionRecord]:
        rec, _rev, corrupt = self._read_head(decision_id)
        if corrupt:
            raise DecidioStateCorrupt(decision_id, corrupt)
        return rec

    def list_executions(self) -> List[ExecutionRecord]:
        if not os.path.isdir(self.dir):
            return []
        keys = set()
        names = os.listdir(self.dir)
        for name in names:
            if ".rev." in name:
                base, _sep, tail = name.rpartition(".rev.")
                if tail.isdigit():
                    keys.add(base)
                    continue
            if "." not in name:
                continue
            base, suffix = name.rsplit(".", 1)
            if suffix in EXECUTION_STATES:
                keys.add(base)
        out: List[ExecutionRecord] = []
        for key in keys:
            rec, _rev, corrupt = self._read_head(key, names)


            if corrupt:
                out.append(ExecutionRecord(decision_id=(rec.decision_id if rec else key), state="indeterminate", attempt_id=None,
                                           error=f"state files unreadable - {'; '.join(corrupt)}", at=_now_iso()))
                continue
            if rec:
                out.append(rec)
        return out

    def settle(self, decision_id: str, outcome: str, evidence: Any = None, reason: Optional[str] = None, evidence_sig: Optional[dict] = None, worker_stopped: bool = False) -> None:
        """OPERATOR RECONCILIATION - see MemoryPendingStore.settle. The one legal backwards move,
        and now a transition like any other: two conflicting settlements both validate, both try
        to publish the next revision, exactly one wins, and the loser re-validates against the
        winner's record - where assert_settlable refuses it. Before this, both won and the second
        erased the first."""
        def compute(rec, _rev):
            cur = rec or ExecutionRecord(decision_id=decision_id, state="parked", attempt_id=None, at=_now_iso())

            assert_settlable(decision_id, cur.state, outcome, not cur.evidence_error, worker_stopped)
            at = _now_iso()
            reconciled = {"outcome": outcome, "reason": reason, "at": at}
            if worker_stopped:
                reconciled["workerStopped"] = True
            if outcome == "committed":

                return replace(cur, state="executed_unreported", evidence=evidence, has_evidence=True,
                               evidence_sig=evidence_sig, evidence_error=None, reconciled=reconciled, at=at)
            return replace(cur, state="parked", attempt_id=None, error=None, reconciled=reconciled, at=at)
        self._transition(decision_id, "settle", compute)

    def release_preinvoke(self, decision_id: str, attempt_id: str) -> None:
        def compute(rec, _rev):
            state = rec.state if rec else "parked"

            if state in NON_REPLAYABLE:
                raise RuntimeError(f"[decidio] {decision_id}: refusing to release this decision - its durable state is {state}, which is terminal or past the invocation boundary. release_preinvoke only ever releases a claim nothing has acted on.")
            if rec and rec.attempt_id and rec.attempt_id != attempt_id:
                return None
            if state == "parked":
                return None
            return replace(rec, state="parked", attempt_id=None, at=_now_iso())
        self._transition(decision_id, "release", compute)

    def migrate_legacy(self) -> dict:
        """ONE-WAY MIGRATION of older layouts, run at construction.
            0.2/0.3 one-marker-per-state  -> the head of a fresh revision chain (markers removed)
            0.1.x `<id>.json` with no state -> parked
            0.1.x `<id>.claimed`           -> INDETERMINATE, never parked (a claimed 0.1.x entry
                                              may have been mid-flight; assuming it did not run is
                                              the assumption that duplicates a payment)
            0.1.x `reports/<id>.json`      -> executed_unreported (the report can be re-sent)
        Nothing ambiguous is made executable by an upgrade, and nothing unreadable is silently
        dropped: a key whose markers cannot be parsed is left exactly as found and reads as corrupt."""
        if not os.path.isdir(self.dir):
            return {"migrated": 0, "indeterminate": 0, "reports": 0, "chained": 0}
        migrated = indeterminate = chained = 0


        marker_keys = set()
        for name in os.listdir(self.dir):
            if "." not in name:
                continue
            base, suffix = name.rsplit(".", 1)
            if suffix in EXECUTION_STATES:
                marker_keys.add(base)
        for key in sorted(marker_keys):
            if self._list_revs(key):
                continue
            present = self._legacy_markers(key)
            rec, corrupt = self._resolve_legacy_markers(key)
            if corrupt or rec is None:
                print(f"[decidio] {key}: the older state marker(s) for this decision could not be read ({'; '.join(corrupt) or 'no readable marker'}) - left in place; the decision reads as unreadable until a person inspects it.", file=sys.stderr)
                continue


            target = self._rev_path(key, 1)
            tmp = self._write_temp(target, self._rec_to_json(rec))
            try:
                os.link(tmp, target)
                chained += 1
            except FileExistsError:
                pass
            except Exception:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
                raise
            try:
                os.remove(tmp)
            except Exception:
                pass



            for st in present:
                try:
                    os.remove(self._marker_path(key, st))
                except Exception:
                    pass
        if chained:
            print(f"[decidio] upgraded {chained} decision{'' if chained == 1 else 's'} from the one-marker-per-state layout to the revision chain. Do not run an older SDK against this directory again: it would write markers this layout refuses to read.", file=sys.stderr)


        for name in list(os.listdir(self.dir)):
            if name.endswith(".claimed"):
                try:
                    with open(os.path.join(self.dir, name), encoding="utf-8") as fh:
                        p = PendingAction(**json.load(fh))







                    _pa = p

                    def _mig_claimed(cur, _rev, _pa=_pa):
                        if cur is not None and cur.state in NON_REPLAYABLE:
                            return None
                        if cur is not None:
                            return replace(cur, state="indeterminate", attempt_id=None, action=_pa.action,
                                           error="upgraded from 0.1.x while claimed - whether it ran is not knowable; reconcile it", at=_now_iso())
                        return ExecutionRecord(decision_id=_pa.decision_id, state="indeterminate", attempt_id=None, action=_pa.action,
                                               error="upgraded from 0.1.x while claimed - whether it ran is not knowable; reconcile it", at=_now_iso())
                    published = self._transition(p.decision_id, "migrate", _mig_claimed)
                    if published is None:
                        os.replace(os.path.join(self.dir, name), os.path.join(self.dir, name + ".migrated"))
                        continue
                    self._write_atomic(self._path(p.decision_id), json.dumps(asdict(p), indent=2))
                    os.replace(os.path.join(self.dir, name), os.path.join(self.dir, name + ".migrated"))
                    indeterminate += 1
                except Exception:
                    print(f"[decidio] could not migrate legacy claimed entry {name} - inspect it by hand.", file=sys.stderr)
                continue
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.dir, name), encoding="utf-8") as fh:
                    p = PendingAction(**json.load(fh))
                if not p.decision_id or self._read_head(p.decision_id)[0] is not None:
                    continue
                _pb = p
                self._transition(p.decision_id, "migrate", lambda cur, _rev, _pb=_pb: None if cur is not None else
                                 ExecutionRecord(decision_id=_pb.decision_id, state="parked", attempt_id=None, action=_pb.action, at=_now_iso()))
                migrated += 1
            except Exception:
                pass
        if indeterminate:
            print(f"[decidio] upgraded {indeterminate} in-flight 0.1.x entr{'y' if indeterminate == 1 else 'ies'} to INDETERMINATE - they will not auto-run; review them with guard.resume.recover().", file=sys.stderr)
        reports = self._migrate_legacy_reports()
        return {"migrated": migrated, "indeterminate": indeterminate, "reports": reports, "chained": chained}

    def _migrate_legacy_reports(self) -> int:
        """0.1.x wrote execution reports to `<pending dir>/reports/<id>.json` - evidence that an
        action ALREADY RAN and still owes Decidio a report. 0.2.0 keeps that in the ledger, so
        without this those files become invisible: recover() returns nothing and reconfirm()
        answers "nothing is recorded for X ... or this process never executed it" about an action
        that demonstrably did. The reports are pulled into `executed_unreported` rows where
        reconfirm() can re-send them. The file is CONSUMED (renamed to `.migrated`), not deleted."""
        reports_dir = os.path.join(self.dir, "reports")
        if not os.path.isdir(reports_dir):
            return 0
        moved = 0
        for name in os.listdir(reports_dir):
            if not name.endswith(".json"):
                continue
            path = os.path.join(reports_dir, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    e = json.load(fh)
                did = e.get("decision_id") or e.get("decisionId")
                if not did:
                    continue



                _e = e

                def _mig_report(cur, _rev, _e=_e, _did=did):
                    if cur is not None and (cur.state == "discarded" or _rank(cur.state) >= _rank("executed_unreported")):
                        return None
                    base = cur if cur is not None else ExecutionRecord(decision_id=_did, state="parked", attempt_id=None, at=_now_iso())
                    return replace(base, state="executed_unreported", attempt_id=None, action=_e.get("action"), evidence=_e.get("reported"),
                                   has_evidence=True, migrated_from="0.1.x report journal", at=_e.get("at") or _now_iso())
                published = self._transition(did, "migrate", _mig_report)
                os.replace(path, path + ".migrated")
                if published is None:
                    head = self._read_head(did)[0]
                    if head is not None and head.state == "discarded":
                        print(f"[decidio] {did}: a 0.1.x execution report was found for a decision that was DENIED ({head.verdict or 'rejected'}). It has NOT been added to the ledger - a denial is terminal and this report will not be sent. The file is kept as {path}.migrated: if that action really ran, check the downstream system and correct it there.", file=sys.stderr)
                    continue
                moved += 1
            except Exception:
                print(f"[decidio] could not migrate the 0.1.x execution report {path} - it records an action that RAN. Inspect it by hand before deleting it.", file=sys.stderr)
        if moved:
            print(f"[decidio] recovered {moved} execution report{'' if moved == 1 else 's'} written by 0.1.x into the execution ledger - re-send them with guard.resume.recover() / reconfirm(). The original files are kept alongside as .migrated.", file=sys.stderr)
        return moved


def _complete(awaitable: Any) -> Any:
    """Run an awaitable to completion from sync code — the agent's action may be async.
    Uses asyncio.run when no loop is running, else a one-shot worker thread."""
    import asyncio
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, awaitable).result()


def sign_body(secret: str, body: str) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(secret: str, body: str, header: Optional[str]) -> bool:
    if not header:
        return False
    return hmac.compare_digest(sign_body(secret, body), header)







V2_STORE_METHODS = ("put", "get", "delete", "list", "claim", "mark_invoking", "record_executed",
                    "mark_indeterminate", "mark_reported", "mark_discarded",
                    "get_execution", "list_executions", "settle",
                    "release_preinvoke")


def _assert_store_v2(store: Any) -> None:
    """A store that cannot record that invocation BEGAN cannot prevent a committed action from
    running twice. Checked at construction, so a custom store fails on the first line of the
    program rather than on the first duplicate payment."""
    missing = [m for m in V2_STORE_METHODS if not callable(getattr(store, m, None))]
    if not missing:
        return
    raise TypeError(
        f"[decidio] this PendingStore is missing {len(missing)} required method"
        f"{'' if len(missing) == 1 else 's'}: {', '.join(missing)}.\n"
        f"  The durable execution state machine is MANDATORY (parked -> claimed_preinvoke -> invoking -> executed_unreported | indeterminate -> reported, plus the terminal 'discarded' that a denial writes).\n"
        f"  The 0.1.x contract left claim() optional and fell back to a process-local guard, which cannot survive a restart - so it never carried the single-execution guarantee it appeared to.\n"
        f"  Fix: implement the missing methods (see the PendingStore docs), or use the shipped FilePendingStore / MemoryPendingStore. Nothing was started."
    )


_REPORT_DIR_WARNED = False

_COMMITMENT_HEX = __import__("re").compile(r"[0-9a-f]{64}")


def _parse_iso_ms(s: str) -> Optional[float]:
    """An ISO-8601 instant as epoch milliseconds, or None when it is not one (the gate's `grantExpiresAt`)."""
    try:
        from datetime import datetime, timezone
        t = s[:-1] + "+00:00" if s.endswith("Z") else s
        d = datetime.fromisoformat(t)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.timestamp() * 1000
    except (ValueError, TypeError):
        return None


def check_approval(transport: Transport, cfg: Any, decision_id: str, request: Dict[str, Any], *,
                   sent: Optional[bool] = None, status: Optional[dict] = None) -> dict:
    """CONFIRM WITH DECIDIO THAT *THIS* REQUEST WAS APPROVED (0.7.0) - the check every door runs right
    before it executes a routed approval: the blocking wait, the durable resume (webhook AND worker), and
    each engine adapter (LangGraph, Temporal, Inngest, OpenAI Agents). A resume signal is a wake-up; it is
    never the authority. Mirrors the TS twin `checkApproval`.

    Approved means: GET /agent/status/<id> answers approved/auto_approved AND the commitment it returns
    equals a FRESH recompute over `request` - the exact request about to run. The fail-closed rules:
      - Decidio holds a commitment -> it must match; no key material to recompute it -> refused.
      - Decidio holds none, but this SDK bound the request (`sent`; default: `cfg` has key material, so it
        would have sent one) -> refused: the gate predates request binding.
      - Decidio holds none and nothing was bound (a keyless agent, an entry parked before 0.7.0) -> the
        state alone decides - nothing on either side could say more.
    A transport failure RAISES (it is not an answer); every other outcome is a plain dict:
    {"ok", "decision_id", "state", "code"?, "reason"?}. `status` lets a caller that has just read the
    status (the blocking poll, the worker) pass it in instead of reading twice."""
    st = status if status is not None else _client.status_of(
        transport, cfg.api_url, getattr(cfg, "api_token", None), decision_id, has_credential=carries_credential(cfg))
    st = st if isinstance(st, dict) else {}
    state = st.get("state") if isinstance(st.get("state"), str) else ""
    server_reason = st.get("reason") if isinstance(st.get("reason"), str) and st.get("reason") else None

    def no(code: str, reason: Optional[str] = None) -> dict:
        out = {"ok": False, "decision_id": decision_id, "state": state, "code": code}
        if reason:
            out["reason"] = reason
        return out


    _unanswered = unanswered_of(st) if state == "rejected" else None
    if _unanswered is not None:
        out = no("unanswered", UNANSWERED_WORDS)
        out["deadline"] = _unanswered["deadline"]
        return out
    if state == "rejected":
        return no("rejected", server_reason)
    if state == "blocked":
        return no("blocked", server_reason)
    if state == "pending":
        return no("pending", f"Decidio records decision {decision_id} as pending - no human has approved it")
    if state not in ("approved", "auto_approved"):
        return no("unrecognized_state", f"Decidio answered state {st.get('state')!r} for decision {decision_id}, which is not an "
                                        f"approval this SDK recognises (an answer it does not understand is never permission)")




    if st.get("spent") is True:
        return no("spent", f"decision {decision_id} was approved once and that approval is already spent (an execution is "
                           f"recorded on it) - ask again for a fresh approval; nothing was executed")
    until_raw = st.get("grantExpiresAt")
    if isinstance(until_raw, str):
        until = _parse_iso_ms(until_raw)
        if until is None:
            return no("unverifiable", f"Decidio answered a malformed grant expiry for decision {decision_id} ({until_raw!r}), so the "
                                      f"approval cannot be known to be in force")
        if until <= time.time() * 1000:
            return no("expired", f"decision {decision_id}'s approval expired at {until_raw} before anything ran - ask again for a "
                                 f"fresh approval; nothing was executed")
    elif isinstance(st.get("spent"), bool) and "grantExpiresAt" in st and st.get("grantExpiresAt") is None:


        return no("expired", f"decision {decision_id} is approved but Decidio names no expiry for its grant (its age is unknown) - "
                             f"ask again for a fresh approval; nothing was executed")
    server = st.get("requestCommitment")
    if server is not None:
        if not isinstance(server, str) or not _COMMITMENT_HEX.fullmatch(server):
            return no("unverifiable", f"Decidio answered a malformed request commitment for decision {decision_id}, so the approval cannot be tied to this request")
        try:
            material = binding_material_of(cfg)
        except Exception as e:
            return no("unverifiable", str(e))
        if material is None:
            return no("unverifiable", f"Decidio bound decision {decision_id} to a request commitment, but this process has no key material to "
                                      f"recompute it (DECIDIO_AGENT_KEY + DECIDIO_AGENT_DID, or DECIDIO_API_TOKEN) - restore the agent's environment")
        try:
            fresh = request_commitment(material, request)
        except Exception as e:
            return no("unverifiable", f"the request about to run could not be canonicalized for the commitment check ({e})")
        if not hmac.compare_digest(fresh, server):
            return no("request_changed", f"the request changed after approval: decision {decision_id} was approved for a different request than "
                                         f"the one about to run (or this agent's key material changed since it asked)")
        return {"ok": True, "decision_id": decision_id, "state": state}


    would_bind = bool((getattr(cfg, "agent_key", None) and getattr(cfg, "agent_did", None)) or getattr(cfg, "api_token", None))
    if sent if sent is not None else would_bind:
        return no("commitment_missing", f"Decidio answered for decision {decision_id} without the request commitment this SDK sent, so it cannot "
                                        f"confirm the approval covers THIS request - the gate predates request binding (upgrade the Decidio gate; nothing was executed)")
    return {"ok": True, "decision_id": decision_id, "state": state}





RETRY_DELAYS = (0.3, 1.0)

REQUEST_KEY_RE = __import__("re").compile(r"[A-Za-z0-9._:-]{16,128}")


def new_claim_key() -> str:
    """A claim key: RANDOM PER RUN (two workers with one key would be one run to Decidio, and both would run). The
    durable path makes one when it parks an action and keeps it there; the blocking wait and the OpenAI resume make one
    per call. TS twin: newClaimKey."""
    import base64
    import secrets
    return "run_" + base64.urlsafe_b64encode(secrets.token_bytes(18)).decode("ascii").rstrip("=")


_FINAL_CLAIM_CODES = ("already_used", "expired", "not_claimable")


def claim_approval(transport: Transport, cfg: Any, decision_id: str, claim_key: str) -> dict:
    """COLLECT A PERSON'S APPROVAL FOR THIS RUN, ONCE (POST /agent/claim/<decision_id>; TS twin claimApproval) - the step
    every door that RUNS on a person's approval takes right before it runs: the blocking wait, the durable resume,
    Temporal and the OpenAI resume. The first claim wins; the same key claiming again is the same run retrying
    (`again`); any other key is told the approval was already used. Reading the status claims nothing. An auto-approval
    is never claimed. Retried with the SAME key on a network failure or a 5xx; every answer other than a 200 that says
    `claimed: true` means DO NOT RUN. Never raises for an answer - a refusal is a plain dict:
      {"ok": True, "decision_id", "again"} or {"ok": False, "decision_id", "code", "final", "reason", "status"?}.
    `final` marks Decidio's final answers (already_used / expired / not_claimable, a 409): this approval will never run
    here. not_found (404), refused (another 4xx), unreachable and unrecognized may change - nothing ran."""
    def no(code: str, reason: str, status: Optional[int] = None) -> dict:
        out = {"ok": False, "decision_id": decision_id, "code": code, "final": code in _FINAL_CLAIM_CODES, "reason": reason}
        if status is not None:
            out["status"] = status
        return out

    if not isinstance(claim_key, str) or not REQUEST_KEY_RE.fullmatch(claim_key):
        return no("refused", "this run's claim key is not one Decidio accepts (16-128 letters, digits, dot, colon, underscore or dash). Nothing ran.")
    from .signing import assert_safe_transport
    api_url = cfg.api_url
    api_token = getattr(cfg, "api_token", None)
    assert_safe_transport(api_url, carries_credential(cfg))
    from urllib.parse import quote as _quote
    url = api_url.rstrip("/") + "/agent/claim/" + _quote(decision_id, safe="")
    last = ""
    attempt = 0
    while True:
        status = None
        text = ""
        try:
            status, text = transport.request("POST", url, _client._headers(api_token), json.dumps({"claimKey": claim_key}))
        except OSError as e:
            last = f"could not reach Decidio: {e}"
        if status is not None:
            try:
                body = json.loads(text) if text else None
            except Exception:
                body = None
            body = body if isinstance(body, dict) else {}
            if status == 200:
                if body.get("ok") is True and body.get("claimed") is True:
                    return {"ok": True, "decision_id": decision_id, "again": body.get("again") is True}
                return no("unrecognized", "Decidio answered the claim with HTTP 200 but did not say this run collected the approval, and an "
                                          "answer this SDK does not understand is never permission. Nothing ran.", 200)
            if status == 409:
                code = body.get("code")
                if code == "ALREADY_USED":
                    return no("already_used", "this approval was already used by another run. Ask again for a new approval. Nothing ran.", 409)
                if code == "EXPIRED":
                    return no("expired", "this approval has expired. Ask again for a new approval. Nothing ran.", 409)
                if code == "NOT_CLAIMABLE":
                    return no("not_claimable", "Decidio says this approval can't be collected by a run (only a person's approval is, and a "
                                               "deploy approval belongs to its deploy job). Nothing ran.", 409)
                return no("unrecognized", f"Decidio refused the claim with a code this SDK does not know ({json.dumps(code)}). Nothing ran.", 409)
            if status == 404:
                return no("not_found", "Decidio did not let this agent collect the approval (HTTP 404: it does not know this decision for this "
                                       "credential, or it predates approval claims). Nothing ran.", 404)
            if not (status == 429 or (status >= 500 and status != 501)):
                return no("refused", f"Decidio refused to let this run collect the approval (HTTP {status}). Nothing ran.", status)
            last = f"HTTP {status}"
        if attempt >= len(RETRY_DELAYS):
            return no("unreachable", f"could not collect the approval from Decidio after {attempt + 1} tries ({last}). Nothing ran.")
        time.sleep(RETRY_DELAYS[attempt])
        attempt += 1


def claim_refusal(claim: dict) -> Exception:
    """The typed refusal for a claim that did not let this run go ahead (0.12.0; TS twin claimRefusal) - DecidioBlocked,
    so code that treats a block as "did not run" keeps doing so; the words say what happened and what to do."""
    return DecidioBlocked(claim.get("reason") or "the approval could not be collected for this run. Nothing ran.",
                          claim.get("decision_id") or "")


def approval_refusal(check: dict) -> Exception:
    """The typed refusal for an approval check that did not pass - ONE mapping for every door that raises
    (blocking wait, LangGraph, Temporal, Inngest, OpenAI Agents). Mirrors the TS `approvalRefusal`."""
    did = check.get("decision_id") or ""
    code, reason = check.get("code"), check.get("reason")
    if code == "rejected":
        return DecidioRejected(reason or "rejected by approver", did)

    if code == "unanswered":
        return DecidioUnanswered(did, check.get("deadline"))
    if code == "blocked":
        return DecidioBlocked(reason or "blocked by policy", did)
    if code == "request_changed":
        return DecidioRequestChanged(did, reason)
    if code in ("commitment_missing", "unverifiable"):
        return DecidioApprovalUnverified(did, code, reason or "the approval could not be tied to this request")
    if code == "pending":
        return DecidioBlocked(f"not approved - {reason or f'Decidio records {did} as pending'}", did)

    if code == "spent":
        return DecidioBlocked(f"not executed - {reason or f'the approval for {did} is already spent'}", did)
    if code == "expired":
        return DecidioBlocked(f"not executed - {reason or f'the approval for {did} has expired'}", did)
    return DecidioBlocked(reason or f"not approved (Decidio answered {check.get('state')!r})", did)


def core_request(action: str, amount: Any, scope: Optional[str], args: list, kwargs: dict) -> dict:
    """What a routed approval is bound to on the CORE door: exactly what executes - the canonical argument
    snapshot plus the described action/amount/scope. The durable resume recomputes the same shape over the
    parked payload. Keyword arguments are committed when there are any; a call with none commits no
    `kwargs` member, so it binds the SAME bytes as the TS twin (which has no kwargs) and the authorize
    body stays one wire contract across languages (conformance/run.mjs)."""
    r: Dict[str, Any] = {"action": action, "amount": amount, "args": list(args)}
    if kwargs:
        r["kwargs"] = dict(kwargs)
    if scope is not None:
        r["scope"] = scope
    return r





WEBHOOK_SECRET_REMEDY = ("Set webhook_secret (DECIDIO_WEBHOOK_SECRET) to the dedicated secret your Decidio deployment signs resume "
                         "webhooks with - never the server's API_AUTH_TOKEN (its admin bearer, which must not be copied onto an agent "
                         "host) - or use the poll worker (guard.worker()), which needs no inbound secret.")
_NO_WEBHOOK_SECRET = ("resume webhook refused: no webhook_secret is configured (and allow_unsigned is off). Since 0.7.0 the API "
                      "token is no longer accepted as the webhook key. " + WEBHOOK_SECRET_REMEDY)


class ResumeController:
    """Re-executes the agent's own fn on approval, confirms, and clears the parked
    entry. Bound to a store + a registry of raw fns (registered on the hot path by
    `protect`; register at startup for cold resume)."""

    def __init__(
        self,
        api_url: str,
        store: PendingStore,
        api_token: Optional[str] = None,
        webhook_secret: Optional[str] = None,
        resume_url: Optional[str] = None,
        allow_unsigned: bool = False,
        on_resolved: Optional[Callable[[dict], None]] = None,
        transport: Optional[Transport] = None,
        agent_id: Optional[str] = None,
        agent_key: Optional[str] = None,
        agent_did: Optional[str] = None,
        workspace_id: Optional[str] = None,
        report_dir: Optional[str] = None,
        evidence: Optional[Callable[[Any], Any]] = None,
    ):
        import os
        self.api_url = api_url
        _assert_store_v2(store)
        self.store = store
        self.api_token = api_token





        self.webhook_secret = webhook_secret or ""
        self.resume_url = resume_url
        self.allow_unsigned = allow_unsigned

        if allow_unsigned:
            print('[decidio] WARNING: allow_unsigned is ON - this controller will accept UNSIGNED resume webhooks. Anyone who can reach the endpoint can signal work (parked-payload integrity still gates execution). Use this only behind a trusted network boundary, never on an internet-reachable endpoint.', file=sys.stderr)
        self.on_resolved = on_resolved



        self._refusal_warned: set = set()
        self.transport: Transport = transport or UrllibTransport()


        self.agent_id = agent_id or os.environ.get("DECIDIO_AGENT_ID")
        self.agent_key = agent_key or os.environ.get("DECIDIO_AGENT_KEY")
        self.agent_did = agent_did or os.environ.get("DECIDIO_AGENT_DID")
        self.workspace_id = workspace_id or os.environ.get("DECIDIO_WORKSPACE_ID")



        self.evidence = evidence



        global _REPORT_DIR_WARNED
        if report_dir and not _REPORT_DIR_WARNED:
            _REPORT_DIR_WARNED = True
            print("[decidio] report_dir is ignored since 0.2.0 - execution evidence now lives in the PendingStore's own execution ledger, beside the state that makes a decision non-replayable. Reports written by 0.1.x under <pending dir>/reports are migrated into that ledger on first use of a FilePendingStore, so nothing is lost; remove the option when convenient.", file=sys.stderr)










        self._registry: Dict[str, dict] = {}
        self._stop = False

    def _integrity_key(self) -> str:
        """The parked-payload / execution-evidence integrity HMAC key: the webhook secret, else the API token
        (unchanged since 0.1.x). It detects a locally edited pending file; it never authenticates a signal."""
        return self.webhook_secret or self.api_token or ""

    def register(self, action: str, fn: Callable[..., Any], evidence: Optional[Callable[[Any], Any]] = None, with_context: bool = False) -> None:



        prev = self._registry.get(action)
        if prev is not None and prev["fn"] is not fn:
            print(f'[decidio] action "{action}" is being registered again with a DIFFERENT function - the latest one wins, and a resumed decision would run IT. Give each protected function its own action name.', file=sys.stderr)
        if prev is not None and prev.get("evidence") is not None and evidence is not None and prev["evidence"] is not evidence:
            print(f'[decidio] action "{action}" is being registered again with a DIFFERENT evidence mapper - the latest one wins, and a resumed decision\'s record would carry ITS output. Give each protected function its own action name.', file=sys.stderr)
        self._registry[action] = {"fn": fn, "evidence": evidence if evidence is not None else (prev or {}).get("evidence"),
                                  "with_context": with_context or bool((prev or {}).get("with_context"))}

    def _args_binding_bytes(self, p: PendingAction) -> bytes:
        from .signing import canonicalize
        payload = {"decisionId": p.decision_id, "action": p.action, "amount": p.amount, "args": p.args, "kwargs": p.kwargs}
        if p.scope is not None:
            payload["scope"] = p.scope

        if getattr(p, "request_commitment", None) is not None:
            payload["requestCommitment"] = p.request_commitment

        if getattr(p, "claim_key", None) is not None:
            payload["claimKey"] = p.claim_key
        return canonicalize(payload).encode("utf-8")


    def _sign_args(self, p: PendingAction) -> Optional[dict]:
        data = self._args_binding_bytes(p)
        if self.agent_key:
            try:
                from cryptography.hazmat.primitives.serialization import load_der_private_key
                import base64 as _b64
                key = load_der_private_key(_b64.b64decode(self.agent_key), password=None)
                sig = key.sign(data)
                return {"kind": "ed25519", "sig": _b64.urlsafe_b64encode(sig).rstrip(b"=").decode()}
            except Exception:
                pass
        if self._integrity_key():
            import hashlib
            import hmac as _hmac
            return {"kind": "hmac", "sig": _hmac.new(self._integrity_key().encode(), data, hashlib.sha256).hexdigest()}
        return None

    def _verify_args(self, p: PendingAction) -> str:
        if not p.args_sig:
            return "unbound"
        data = self._args_binding_bytes(p)
        try:
            if p.args_sig.get("kind") == "ed25519":
                if not self.agent_key:
                    return "unverifiable"
                from cryptography.hazmat.primitives.serialization import load_der_private_key
                import base64 as _b64
                key = load_der_private_key(_b64.b64decode(self.agent_key), password=None)
                sig_b64 = p.args_sig["sig"]
                sig = _b64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
                key.public_key().verify(sig, data)
                return "ok"
            if not self._integrity_key():
                return "unverifiable"
            import hashlib
            import hmac as _hmac
            expected = _hmac.new(self._integrity_key().encode(), data, hashlib.sha256).hexdigest()
            return "ok" if _hmac.compare_digest(expected, str(p.args_sig.get("sig", ""))) else "mismatch"
        except Exception:
            return "mismatch"

    def park(self, p: PendingAction) -> None:
        """Park a routed action WITH its integrity binding (prefer this over store.put - the
        binding is what lets resolve() refuse a tampered payload)."""



        _idp = decision_id_problem(p.decision_id)
        if _idp:
            raise DecidioUnsafeArguments(f"[decidio] refusing to park {p.decision_id!r}: it is not a decision id this SDK will act on ({_idp}). Nothing was parked and nothing will execute - a decision id comes from the gate's answer, verbatim.", p.decision_id if isinstance(p.decision_id, str) else None)






        try:
            p.args, p.kwargs = canonicalize_args(p.args, p.kwargs)
        except DecidioUnsafeArguments as e:
            raise DecidioUnsafeArguments(f"{e} NOT parked and NOT executable - but decision {p.decision_id} may already be routed; reject it in your queue: python -m decidio approvals reject {p.decision_id}", p.decision_id) from None


        if not getattr(p, "claim_key", None):
            p.claim_key = new_claim_key()
        p.args_sig = self._sign_args(p)
        if not p.args_sig:
            print(f"[decidio] parking {p.decision_id} UNBOUND - no agent key or webhook secret to sign the payload with, so a modified pending file could not be detected. Run `python -m decidio init` to configure keys.", file=sys.stderr)
        self.store.put(p)

    def resolve(self, decision_id: str, verdict: str, reason: Optional[str] = None) -> dict:
        """Drive a parked decision to completion once a verdict is known (idempotent; see the TS twin).

        `verdict="approved"` is a REQUEST to execute, never the authority (0.7.0): right before the action
        runs, resolve() confirms with Decidio that THIS parked request was approved (GET /agent/status +
        the request commitment - check_approval). Decidio still pending -> "not_approved"; Decidio says
        rejected/blocked -> recorded as that denial; an approval that cannot be tied to these arguments ->
        "request_unverified". A transport failure during that check raises (nothing ran). A
        "rejected"/"blocked" verdict is applied as given - it can only ever prevent execution.

        A PERSON'S approval is then COLLECTED ONCE (0.12.0, claim_approval) with the claim key parked with the action:
        another run already used it, or it expired -> "blocked" with the reason (recorded like a block; nothing ran);
        a 404 or a claim that could not be sent -> raises (nothing ran; the entry stays parked for the next signal)."""
        return self._resolve_core(decision_id, verdict, reason)

    def _resolve_core(self, decision_id: str, verdict: str, reason: Optional[str] = None, status: Optional[dict] = None) -> dict:
        """resolve()'s body, with the one thing a public caller must never supply: a status ALREADY read from
        Decidio (the worker's poll, the webhook wake-up), reused by the approval check instead of reading
        twice. Internal on purpose - a caller-supplied status would be a way around the check."""


        _idp = decision_id_problem(decision_id)
        if _idp:
            return {"status": "unknown", "decision_id": str(decision_id if decision_id is not None else ""), "reason": f"not a decision id this SDK will act on ({_idp})"}
        pending = self.store.get(decision_id)

        def finish(outcome: dict) -> dict:
            if outcome["status"] != "unknown" and self.on_resolved:
                self.on_resolved(outcome)
            return outcome

        if pending is None:



            _mapped = _outcome_from_head(self.store.get_execution(decision_id), decision_id)
            if _mapped is not None:
                return finish(_mapped)
            return {"status": "unknown", "decision_id": decision_id}











        if verdict == "rejected" and unanswered_of(status) is not None:
            self.store.mark_discarded(decision_id, "rejected", UNANSWERED_WORDS)
            self.store.delete(decision_id)
            return finish({"status": "unanswered", "decision_id": decision_id, "action": pending.action, "reason": UNANSWERED_WORDS})
        if verdict in ("rejected", "blocked"):
            self.store.mark_discarded(decision_id, verdict, reason)
            self.store.delete(decision_id)
            return finish({"status": verdict, "decision_id": decision_id, "action": pending.action, "reason": reason})


        if verdict not in ("approved", "auto_approved"):
            return {"status": "unknown", "decision_id": decision_id}



        if pending.decision_id != decision_id:
            self._refuse_once(decision_id, f"[decidio] REFUSING to execute {decision_id}: the parked entry in this slot belongs to a DIFFERENT decision ({pending.decision_id}) - the pending file was moved or swapped. Delete it and re-run the action.")
            return finish({"status": "no_handler", "decision_id": decision_id, "action": pending.action, "reason": "parked payload decision-id mismatch"})




        can_bind = bool(self.agent_key)
        integrity = self._verify_args(pending)
        if integrity == "mismatch":
            self._refuse_once(decision_id, f"[decidio] REFUSING to execute {decision_id}: the parked payload FAILED its integrity check - the arguments on disk are not the arguments that were routed for approval. The pending file is untouched for inspection; delete it and re-run the action to request a fresh approval.")
            return finish({"status": "no_handler", "decision_id": decision_id, "action": pending.action, "reason": "parked payload integrity check failed"})
        if integrity == "unverifiable":
            self._refuse_once(decision_id, f"[decidio] REFUSING to execute {decision_id}: the parked payload is signed but this process lacks the key material to verify it (DECIDIO_AGENT_KEY / DECIDIO_WEBHOOK_SECRET). Restore the agent's env and retry.")
            return finish({"status": "no_handler", "decision_id": decision_id, "action": pending.action, "reason": "parked payload unverifiable"})
        if integrity == "unbound" and can_bind:


            self._refuse_once(decision_id, f"[decidio] REFUSING to execute {decision_id}: the parked payload has NO integrity signature, but this agent has keys and would have signed it - a missing signature means the file was tampered with. Delete it and re-run the action.")
            return finish({"status": "no_handler", "decision_id": decision_id, "action": pending.action, "reason": "parked payload unsigned (expected a signature)"})
        if integrity == "unbound":
            print(f"[decidio] executing {decision_id} from an UNBOUND parked entry (this agent has no key material to bind or verify payloads) - its arguments cannot be integrity-checked. Run `python -m decidio init` to enable binding.", file=sys.stderr)
        fn = (self._registry.get(pending.action) or {}).get("fn")
        if fn is None:


            print(f'[decidio] cannot resume {decision_id}: no function is registered for action "{pending.action}" in THIS process.', file=sys.stderr)
            print(f'  A worker only re-executes actions registered where it runs. At startup, either declare the action on the wrapper:', file=sys.stderr)
            print(f'      do_it = guard.protect(do_it_raw, describe, action="{pending.action}")', file=sys.stderr)
            print(f'  or register the raw function directly:', file=sys.stderr)
            print(f'      guard.register("{pending.action}", do_it_raw)', file=sys.stderr)
            print(f'  then start the worker. The approved action stays parked until then - nothing is lost.', file=sys.stderr)
            return finish({"status": "no_handler", "decision_id": decision_id, "action": pending.action,
                           "reason": f'no fn registered for action "{pending.action}" in this process - declare action= on protect(), or call guard.register("{pending.action}", fn) at startup'})




        attempt_id = uuid4().hex
        claim = self.store.claim(decision_id, attempt_id)
        if not claim.ok:



            if claim.state in NON_REPLAYABLE:




                if claim.state == "discarded":
                    _rec = self.store.get_execution(decision_id)
                    _v = (_rec.verdict if _rec and _rec.verdict else "rejected")
                    self._refuse_once(decision_id, f'[decidio] REFUSING to execute {decision_id}: it was DENIED ({_v}) and that answer is final. Nothing ran. A denial cannot be reconciled or retried - if this action should now proceed, it needs a NEW request and a new approval.', ' (This prints once per worker process. The decision is closed - no action is needed.)')
                else:
                    self._refuse_once(decision_id, f'[decidio] REFUSING to execute {decision_id}: its durable state is {claim.state} - invocation already began, so re-running it could duplicate a committed effect. Inspect it with guard.resume.recover(); settle it with guard.resume.reconcile("{decision_id}", ...).')




                if claim.state in ("invoking", "indeterminate"):
                    _why = (f'this decision is in durable state invoking: its action may still be running, may have crashed before any effect, or may have finished without reporting - it may or may not have run. Nothing will retry it; check the worker and the downstream system, then settle it with reconcile("{decision_id}", ...).'
                            if claim.state == "invoking" else claim.reason)
                    return finish({"status": "indeterminate", "decision_id": decision_id, "action": pending.action, "reason": _why})
                _rec2 = self.store.get_execution(decision_id) if claim.state == "discarded" else None
                _why = (f'this decision was already DENIED ({(_rec2.verdict if _rec2 and _rec2.verdict else "rejected")}); that answer is final and this signal lost the race to it'
                        if claim.state == "discarded" else f"this decision already ran (durable state {claim.state}); this signal lost the race to it")
                return finish({"status": "already_resolved", "decision_id": decision_id, "action": pending.action, "reason": _why})


            _mapped = _outcome_from_head(self.store.get_execution(decision_id), decision_id, pending.action)
            if _mapped is not None:
                return finish(_mapped)
            _ds = f" (durable state {claim.state})" if claim.state else ""
            return finish({"status": "lost_race", "decision_id": decision_id, "action": pending.action,
                           "reason": f"another attempt holds the pre-invocation claim on this decision{_ds}; this signal lost the race and did nothing. If that attempt is alive it will report; if it died, recover() lists the decision and reconcile() can settle it"})






        try:
            check = check_approval(self.transport, self, decision_id,
                                   core_request(pending.action, pending.amount, pending.scope, pending.args, pending.kwargs),
                                   sent=bool(getattr(pending, "request_commitment", None)), status=status)
        except Exception:


            try:
                self.store.release_preinvoke(decision_id, attempt_id)
            except Exception:
                pass
            raise
        if not check.get("ok"):
            if check.get("code") == "unanswered":

                self.store.mark_discarded(decision_id, "rejected", UNANSWERED_WORDS)
                self.store.delete(decision_id)
                return finish({"status": "unanswered", "decision_id": decision_id, "action": pending.action, "reason": UNANSWERED_WORDS})
            if check.get("code") in ("rejected", "blocked"):


                self.store.mark_discarded(decision_id, check["code"], check.get("reason"))
                self.store.delete(decision_id)
                return finish({"status": check["code"], "decision_id": decision_id, "action": pending.action,
                               **({"reason": check["reason"]} if check.get("reason") else {})})
            try:
                self.store.release_preinvoke(decision_id, attempt_id)
            except Exception:
                pass
            if check.get("code") in ("pending", "unrecognized_state"):
                return {"status": "not_approved", "decision_id": decision_id, "action": pending.action,
                        "reason": f"{check.get('reason')}. This signal was a wake-up, not an approval: nothing ran, and the entry stays parked for the real answer."}
            self._refuse_once(decision_id, f"[decidio] REFUSING to execute {decision_id}: {check.get('reason')}. Nothing ran; the parked entry is untouched for inspection. If the request really changed, reject this decision and re-run the action to request a fresh approval.")
            return finish({"status": "request_unverified", "decision_id": decision_id, "action": pending.action, "reason": check.get("reason")})








        if check.get("state") == "approved":
            try:
                claimed = claim_approval(self.transport, self, decision_id, getattr(pending, "claim_key", None) or new_claim_key())
            except Exception:
                try:
                    self.store.release_preinvoke(decision_id, attempt_id)
                except Exception:
                    pass
                raise
            if not claimed.get("ok"):
                if claimed.get("final"):


                    self.store.mark_discarded(decision_id, "blocked", claimed.get("reason"))
                    self.store.delete(decision_id)
                    return finish({"status": "blocked", "decision_id": decision_id, "action": pending.action, "reason": claimed.get("reason")})


                try:
                    self.store.release_preinvoke(decision_id, attempt_id)
                except Exception:
                    pass
                raise RuntimeError(f"[decidio] {decision_id}: {claimed.get('reason')} The entry stays parked; the next signal tries again with the same claim key.")




        try:
            self.store.mark_invoking(decision_id, attempt_id)
        except Exception as e:


            try:
                self.store.release_preinvoke(decision_id, attempt_id)
            except Exception:
                pass
            print(f"[decidio] {decision_id}: could not record the invocation boundary ({e}) - refusing to run the action rather than run it unrecorded.", file=sys.stderr)



            _mapped = _outcome_from_head(self.store.get_execution(decision_id), decision_id, pending.action)
            if _mapped is not None:
                return finish(_mapped)
            return finish({"status": "lost_race", "decision_id": decision_id, "action": pending.action,
                           "reason": f"could not durably record the invocation boundary ({e}); nothing ran, the entry stays parked, and a later signal may retry"})

        try:


            if (self._registry.get(pending.action) or {}).get("with_context"):
                result = fn(ExecutionContext(decision_id=decision_id, attempt_id=attempt_id,
                                             idempotency_key=decision_id), *pending.args, **pending.kwargs)
            else:
                result = fn(*pending.args, **pending.kwargs)
            if inspect.isawaitable(result):
                result = _complete(result)
        except Exception as e:






            why = str(e)
            try:
                self.store.mark_indeterminate(decision_id, attempt_id, why)
            except Exception as se:
                print(f"[decidio] {decision_id}: could not record INDETERMINATE ({se}) - treat this decision as possibly executed.", file=sys.stderr)
            print(f'[decidio] {decision_id}: "{pending.action}" was INVOKED and then raised ({why}). Whether the downstream effect committed is not knowable from here, so it will NOT be retried automatically. Check the downstream system, then: guard.resume.reconcile("{decision_id}", outcome="committed", evidence=...) or outcome="not_committed".', file=sys.stderr)
            return finish({"status": "indeterminate", "decision_id": decision_id, "action": pending.action, "reason": why})



        return finish(self._report_after_execution(decision_id, pending.action, result, attempt_id))

    def _report_after_execution(self, decision_id: str, action: str, result: Any, attempt_id: str) -> dict:
        """Everything that happens AFTER the agent's action returned. It NEVER raises, by
        design: resolve()'s failure path releases the claim so a failed execution can be
        retried, and once the action has actually run, reaching that path would re-run a
        committed write. An evidence gap is recoverable; a double write is not.

        RECORD BEFORE REPORTING: the window between "the action succeeded" and "Decidio
        recorded it" is the one place a crash loses evidence forever, so the REPORTED VALUE is
        written to durable storage FIRST - before any signing, before any send. It goes to the
        store's own execution ledger, BESIDE the state, not to a separate local directory (0.1.x
        put it outside the store, so two workers sharing Redis kept two disjoint journals and
        neither could reconfirm the other's work). The record carries no handler binding:
        replaying it can only re-send a report, never re-run the action.

        It stores the reported value rather than the signed request ON PURPOSE. Both proofs on a
        confirm are short-lived (identity 120s, execution report 5 minutes) and the server refuses
        a stale one, so a journal of signed envelopes produced a recovery path that expired
        minutes into the outage it existed for. reconfirm() re-signs over these same bytes."""
        out: Dict[str, Any] = {"status": "executed", "decision_id": decision_id, "action": action,
                               "result": result, "report_recorded": False, "execution_confirmed": False}



        evidence_error = None
        try:


            mapper = (self._registry.get(action) or {}).get("evidence") or self.evidence
            reported = canonicalize(mapper(result) if mapper else result, "evidence(result)")
        except Exception as e:
            reported, evidence_error = None, str(e)
            print(f"[decidio] {decision_id}: the action SUCCEEDED but its result could not be reported as evidence ({e}). "
                  f"Reporting a null captured response so the execution is still recorded - map the return value with the "
                  f"`evidence` option (e.g. evidence=lambda r: {{\"recordId\": r.id, \"success\": True}}) to earn a confirming "
                  f"tier. The action was NOT re-run.", file=sys.stderr)








        journalled = False
        try:
            self.store.record_executed(decision_id, attempt_id, reported,
                                       sign_evidence(decision_id, attempt_id, reported, self.agent_key, self._integrity_key()),
                                       evidence_error)
            journalled = True
        except DecidioStaleAttempt:




            print(f"[decidio] {decision_id}: this action finished, but the decision is now owned by a newer attempt - "
                  f"it was released for retry while this one was still running. This attempt's report is NOT being "
                  f"sent; the owning attempt reports. Your action DID run: if that means it ran twice, the release "
                  f"was premature.", file=sys.stderr)
            try:
                self.store.delete(decision_id, attempt_id)
            except Exception:
                pass
            out["diagnostic"] = (f"{decision_id} was released to a newer attempt while this one was running; this "
                                 f"attempt's report was not sent. If your action is not idempotent, note that it has "
                                 f"now run more than once.")
            return out
        except DecidioAlreadySettled:





            print(f"[decidio] {decision_id}: this action finished, but an operator had already reconciled the "
                  f"decision as committed and Decidio has that report. This attempt's own report is NOT being sent - "
                  f"one decision, one report. If your result differs from what was reconciled, correct it in Decidio; "
                  f"do NOT re-run the action.", file=sys.stderr)
            try:
                self.store.delete(decision_id, attempt_id)
            except Exception:
                pass
            out["report_recorded"] = True
            out["diagnostic"] = (f"an operator settled {decision_id} as committed while this attempt was running; "
                                 f"their report stands and this one was not sent.")
            return out
        except DecidioDenied:






            print(f"[decidio] {decision_id}: this decision is DENIED, so no execution report will be sent. If your "
                  f"action nevertheless ran, your store let a refused decision reach the handler - treat that as a "
                  f"defect in the store, and correct the downstream effect by hand.", file=sys.stderr)
            out["diagnostic"] = f"{decision_id} is denied; no report was sent."
            return out
        except Exception as e:
            print(f"[decidio] {decision_id}: the action RAN but its execution report could NOT be recorded ({e}). "
                  f"If the report also fails to send, this execution is NOT locally recoverable - record the outcome "
                  f"from your own system.", file=sys.stderr)
        confirm_request = None
        try:
            confirm_request = self._build_confirm_request(decision_id, reported)
        except Exception as e:





            recovery = (f'The reported value IS recorded, so fix the agent\'s signing config '
                        f'(python -m decidio doctor) and re-send it with reconfirm("{decision_id}").'
                        if journalled else
                        "The reported value could not be recorded either, so nothing here can re-send it - "
                        "record the outcome from your own system.")
            out["diagnostic"] = (f'"{action}" EXECUTED, but no execution report could be built ({e}). Nothing will '
                                 f"re-run it. {recovery}")
            print(f'[decidio] {decision_id}: {out["diagnostic"]}', file=sys.stderr)




        try:
            self.store.delete(decision_id, attempt_id)
        except Exception as e:
            print(f"[decidio] {decision_id}: the parked payload could not be removed ({e}). This is cleanup only - "
                  f"the execution ledger already records this decision as executed, so no process can run it again; "
                  f"remove the row at your convenience.", file=sys.stderr)
        if confirm_request is not None:
            try:
                ev = _client.post_confirm(self.transport, self.api_url, self.api_token, confirm_request, journalled=journalled, has_credential=carries_credential(self))
            except Exception as e:
                ev = {"report_recorded": False, "execution_confirmed": False,
                      "diagnostic": (f'the execution report did not reach Decidio ({e}). Your action DID run and the report is journalled - re-send it with reconfirm("{decision_id}").'
                                     if journalled else
                                     f"the execution report did not reach Decidio ({e}) AND could not be journalled locally, so nothing here can re-send it. Your action DID run - record the outcome from your own system.")}
            if ev["report_recorded"]:




                try:
                    self.store.mark_reported(decision_id, attempt_id, tombstone_tier(ev))
                except Exception:
                    pass
                if not ev["execution_confirmed"] or ev.get("execution_report_verified") is False:
                    print(f'[decidio] execution evidence for {decision_id} recorded as {ev.get("evidence_tier")} - {ev.get("diagnostic")}', file=sys.stderr)
            else:
                print(f'[decidio] {decision_id}: {ev.get("diagnostic")}', file=sys.stderr)


            out["report_recorded"] = ev["report_recorded"]
            out["execution_confirmed"] = ev["execution_confirmed"]
            if ev.get("evidence_tier"):
                out["evidence_tier"] = ev["evidence_tier"]
            if ev.get("execution_report_verified") is not None:
                out["execution_report_verified"] = ev["execution_report_verified"]




            if ev.get("execution_report_reason"):
                out["execution_report_reason"] = ev["execution_report_reason"]
            if ev.get("confirmation_retryable") is not None:
                out["confirmation_retryable"] = ev["confirmation_retryable"]
            out["report_journalled"] = bool(journalled)
            if ev.get("diagnostic"):
                out["diagnostic"] = ev["diagnostic"]
        if evidence_error:
            out["evidence_error"] = evidence_error
        return out

    def _build_confirm_request(self, decision_id: str, canonical_result: Any) -> dict:
        """Build the EXACT confirm request for a decision, ONCE, so it can be journalled before
        the first attempt and replayed byte-identically afterwards."""
        ri = None
        if self.agent_key and self.agent_did:
            from .signing import sign_bound_proof
            ri = sign_bound_proof(self.agent_key, agent_id=self.agent_id, did=self.agent_did,
                                  action="confirm", amount=0, scope=decision_id, workspace_id=self.workspace_id)
        else:


            print(f"[decidio] execution evidence for {decision_id} will be recorded as an unproven agent assertion - no signing key configured. Set DECIDIO_AGENT_KEY/DID (python -m decidio init writes them) to earn a confirming tier.", file=sys.stderr)
        return build_confirm_body(self, decision_id, canonical_result, ri)

    def reconcile(self, decision_id: str, outcome: str, evidence: Any = None, reason: Optional[str] = None, worker_stopped: bool = False) -> dict:
        """Settle a decision an operator has checked downstream - the ONLY exit from
        `indeterminate` and from a claim that stalled before invocation, and the only backwards
        transition in the machine. It exists because the SDK genuinely cannot know whether a
        downstream write committed: a human looks, and then tells it. Three rules make that safe to
        expose:
          1. This path never resolves a handler. There is no registry lookup here at all, so it is
             structurally incapable of re-running the action, whatever the operator passes.
          2. `committed` is refused where nothing was ever invoked, and `not_committed` is refused
             where captured evidence or a recorded report already exists (assert_settlable).
          3. A DENIED decision is refused on both outcomes, and releasing an `invoking` one takes an
             explicit `worker_stopped=True` - an operator may correct the record, but may not undo a
             human's refusal, and may not hand a live worker's action to a second worker by
             accident.

        `committed`     records and reports the evidence you supply WITHOUT invoking the handler.
        `not_committed` parks the decision so exactly one more ordinary attempt can run."""
        _idp = decision_id_problem(decision_id)
        if _idp:
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f"{decision_id!r} is not a decision id this SDK will act on ({_idp}). Nothing was settled."}
        try:
            entry = self.store.get_execution(decision_id)
        except Exception as e:
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f"the durable state for {decision_id} could not be read ({e}). Refusing to settle a decision whose state is unknown - inspect the store first."}
        if entry is None:
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f"nothing is recorded for {decision_id} in this store, so there is nothing to reconcile. Check the decision id, or the store this worker is configured with."}





        try:
            _settle_evidence = canonicalize(evidence, "reconcile(evidence)") if outcome == "committed" else None
        except Exception as e:
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f'the evidence you passed to reconcile("{decision_id}") is not reportable as-is ({e}). Nothing was settled. Pass plain JSON - the same rule your action return value follows.'}


        _settle_sig = (sign_evidence(decision_id, entry.attempt_id, _settle_evidence, self.agent_key, self._integrity_key())
                       if outcome == "committed" else None)
        try:
            self.store.settle(decision_id, outcome, evidence=_settle_evidence, reason=reason, evidence_sig=_settle_sig, worker_stopped=worker_stopped)
        except Exception as e:
            return {"report_recorded": False, "execution_confirmed": False, "diagnostic": str(e)}


        if outcome != "committed":


            print(f"[decidio] {decision_id}: released for one more attempt on your assertion that nothing committed"
                  f"{f' ({reason})' if reason else ''}. The next resume signal will run it.", file=sys.stderr)
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f"{decision_id} is parked again and may run once more. Nothing was reported, because on your account nothing executed."}











        try:
            request = self._build_confirm_request(decision_id, _settle_evidence)
        except Exception as e:
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f'the reconciled report for {decision_id} could not be signed ({e}). The evidence IS recorded locally - fix the agent\'s signing config (python -m decidio doctor) and re-send it with reconfirm("{decision_id}").'}
        try:
            ev = _client.post_confirm(self.transport, self.api_url, self.api_token, request,
                                      journalled=True, has_credential=carries_credential(self))
        except Exception as e:
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f'the reconciled report for {decision_id} did not reach Decidio ({e}). The evidence IS recorded locally - call reconfirm("{decision_id}") when the service is healthy. Do NOT re-run the action.'}
        if ev.get("report_recorded"):
            try:
                self.store.mark_reported(decision_id, entry.attempt_id or "reconcile", tombstone_tier(ev))
            except Exception:
                pass
        ev = dict(ev)
        ev["diagnostic"] = (f"{ev['diagnostic']} " if ev.get("diagnostic") else "") + (
            f"This report was RECONCILED BY AN OPERATOR{f' ({reason})' if reason else ''}, not observed by the SDK: "
            f"its tier reflects the evidence you supplied, not a return value this process saw.")
        return ev

    def reconfirm(self, decision_id: str, accept_unbound: bool = False) -> dict:
        """Re-send a journalled execution report, IDEMPOTENTLY. RE-SIGNS over the journalled
        reported value rather than replaying a stored envelope (both confirm proofs are
        short-lived, so a replay is refused exactly when recovery matters) - same bytes, same
        digest, fresh single-use nonce. It can NEVER re-run the business action, because the
        journal holds no handler binding. A decision with nothing journalled returns
        report_recorded False with guidance rather than pretending."""
        _idp = decision_id_problem(decision_id)
        if _idp:
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f"{decision_id!r} is not a decision id this SDK will act on ({_idp}). Nothing was sent."}


        try:
            entry = self.store.get_execution(decision_id)
        except Exception as e:
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f"the durable state for {decision_id} could not be read ({e}). Refusing to guess whether it executed - inspect the store; do NOT re-run the action to find out."}
        if entry is not None and entry.state == "reported":

            _confirmed = entry.confirmation in CONFIRMING
            return {"report_recorded": True, "execution_confirmed": _confirmed, "evidence_tier": entry.confirmation,
                    "diagnostic": f'{decision_id} was already reported ({entry.confirmation or "recorded"}{", a confirming tier" if _confirmed else ", not a confirming tier"}) - nothing to re-send.'}
        if entry is not None and entry.state == "indeterminate":
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f'{decision_id} is INDETERMINATE: it was invoked and its outcome is unknown, so there is no captured result to re-send. Settle it with reconcile("{decision_id}", ...) once you have checked the downstream system.'}



        if entry is not None and entry.state == "discarded":
            _e = entry.execution_despite_denial
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": (f'{decision_id} was DENIED ({entry.verdict or "rejected"}), and this store ALSO holds an execution marker for it ({_e["state"]} at {_e["at"]}). A denial is terminal, so no report will be sent for it - but something may have run. Check the downstream system and correct it there; do NOT re-run the action.'
                                   if _e else
                                   f'{decision_id} was DENIED ({entry.verdict or "rejected"}) and nothing ran, so there is no execution report to send. A denial cannot be reconciled or retried.')}
        if entry is None or not entry.has_evidence:
            return {
                "report_recorded": False, "execution_confirmed": False,
                "diagnostic": f"nothing is recorded for {decision_id}: either its report was already recorded (nothing to do) or this process never executed it. Check the record in Decidio - do NOT re-run the action to find out.",
            }











        _ev_strict = bool(self.agent_key)
        _ev_status = verify_evidence(entry, self.agent_key, self._integrity_key())
        if _ev_status == "mismatch":
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f'the recorded evidence for {decision_id} does not match its integrity binding - it was altered after this agent wrote it. REFUSING to attest it. Inspect the pending store; if you know the true outcome, settle it with reconcile("{decision_id}", ...).'}






        if _ev_status != "ok" and _ev_strict and not accept_unbound:
            _why = (f"it was migrated from {entry.migrated_from}, which predates evidence binding - that is expected, "
                    f"and it is why this call has an override"
                    if entry.migrated_from else
                    "this agent signs its evidence, so a record without a usable binding did not come from this agent")
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f'the recorded evidence for {decision_id} carries {"NO integrity binding" if _ev_status == "unbound" else "a binding this agent key cannot verify"} ({_why}). REFUSING to attest it by default. If you have checked what this row claims and want it sent anyway: reconfirm("{decision_id}", accept_unbound=True). If you do not trust it, settle the decision instead: reconcile("{decision_id}", ...).'}
        if _ev_status != "ok" and _ev_strict:
            print(f"[decidio] {decision_id}: attesting evidence with "
                  f"{'NO integrity binding' if _ev_status == 'unbound' else 'an unverifiable binding'} because "
                  f"accept_unbound was passed"
                  f"{f' (row migrated from {entry.migrated_from})' if entry.migrated_from else ''}. You are vouching "
                  f"for this row; the agent signature will say it came from here.", file=sys.stderr)
        if _ev_status != "ok":
            print(f"[decidio] {decision_id}: re-sending an execution report whose evidence is "
                  f"{'UNBOUND (written without agent key material, so it cannot be integrity-checked)' if _ev_status == 'unbound' else 'UNVERIFIABLE with this agent current key material'}. "
                  f"{f' - it was migrated from {entry.migrated_from}, which predates evidence binding' if entry.migrated_from else ''}. "
                  f"Run `python -m decidio init` to enable binding.", file=sys.stderr)
        try:
            request = self._build_confirm_request(decision_id, entry.evidence)
        except Exception as e:
            return {
                "report_recorded": False, "execution_confirmed": False,
                "diagnostic": f"the recorded report for {decision_id} could not be re-signed ({e}). The entry is kept; "
                              f"fix the agent's signing config (DECIDIO_AGENT_KEY/DID) and retry.",
            }



        try:
            ev = _client.post_confirm(self.transport, self.api_url, self.api_token, request, journalled=True, has_credential=carries_credential(self))
        except Exception as e:
            return {"report_recorded": False, "execution_confirmed": False,
                    "diagnostic": f'the execution report for {decision_id} still did not reach Decidio ({e}). The recorded evidence is KEPT - call reconfirm("{decision_id}") again when the service is healthy. Your action already ran; do NOT re-run it.'}
        if ev["report_recorded"]:
            try:
                self.store.mark_reported(decision_id, entry.attempt_id or "reconfirm", tombstone_tier(ev))
            except Exception:
                pass
        return ev

    def recover(self) -> List[dict]:
        """Every durable item that needs a human's attention, with its state NAMED. Never
        executes or retries anything; it reports.

        ONE ROW PER DECISION, from ONE ledger. The 0.1.x version merged a separate journal, a
        claimed list and the parked list, and could emit TWO CONTRADICTORY rows for the same
        decision - `executed_unreported` followed by `parked ... Nothing has executed.` - because
        the dedupe covered only the claimed loop. There is nothing to merge now: the store's
        execution record IS the state."""
        items: List[dict] = []
        try:
            execs = self.store.list_executions()
        except Exception as e:
            raise DecidioRecoveryUnavailable(e) from e
        for r in execs:
            a = r.action or "(unknown action)"
            if r.state == "executed_unreported":
                items.append({"decision_id": r.decision_id, "action": r.action, "state": "executed_unreported",
                              "guidance": f'"{a}" executed at {r.at} and its execution report has not been recorded. Re-send it safely: guard.resume.reconfirm("{r.decision_id}") - this replays the saved report and cannot re-run the action.'})
            elif r.state == "indeterminate":
                items.append({"decision_id": r.decision_id, "action": r.action, "state": "indeterminate",
                              "guidance": f'"{a}" was INVOKED and its outcome is unknown{f" ({r.error})" if r.error else ""}. It will NOT be retried automatically. Check the downstream system, then settle it: guard.resume.reconcile("{r.decision_id}", outcome="committed", evidence=...) or outcome="not_committed".'})
            elif r.state == "invoking":
                items.append({"decision_id": r.decision_id, "action": r.action, "state": "indeterminate",





                              "guidance": f'"{a}" was invoked at {r.at} by attempt {r.attempt_id or "(unknown)"} and no outcome has been recorded since. That does NOT mean the worker died - it may still be running this action. It will not be retried automatically. Check that worker first: if it is gone, settle it with outcome="committed" and evidence once you have checked the downstream system, or release it with outcome="not_committed", reason=..., worker_stopped=True.'})
            elif r.state == "claimed_preinvoke":





                items.append({"decision_id": r.decision_id, "action": r.action, "state": "claimed_stalled",
                              "guidance": f'"{a}" was claimed at {r.at} by attempt {r.attempt_id or "(unknown)"} which never reached the invocation boundary - the handler provably did not run, and nothing will retry it on its own. Release it: guard.resume.reconcile("{r.decision_id}", outcome="not_committed", reason="claimed but never invoked").'})
            elif r.state == "discarded":



                if r.execution_despite_denial:
                    _e = r.execution_despite_denial
                    items.append({"decision_id": r.decision_id, "action": r.action, "state": "denied_with_evidence",
                                  "guidance": f'"{a}" was DENIED ({r.verdict or "rejected"})' + (f" - {r.discard_reason}" if r.discard_reason else "") + f', but this store also holds an execution marker for it ({_e["state"]} at {_e["at"]}' + (", with a captured result" if _e["hasEvidence"] else "") + f'). Nothing will run it and nothing will report it - a denial is terminal and cannot be reconciled. CHECK THE DOWNSTREAM SYSTEM: if the action really ran, correct it there.'})
            elif r.state == "parked":
                items.append({"decision_id": r.decision_id, "action": r.action, "state": "parked",
                              "guidance": (f'"{a}" is recorded as parked but its payload is gone, so nothing can execute it - an orphaned row (usually a legacy denial whose state was never written), not work awaiting a human. Nothing will run. It needs no action; remove its revision files if you want the listing clean.'
                                           if self.store.get(r.decision_id) is None else
                                           f'"{a}" is parked awaiting a human decision. Nothing has executed.'),
                              **({"state": "orphaned_state"} if self.store.get(r.decision_id) is None else {})})

        return items

    def handle(self, raw_body, signature: Optional[str]) -> dict:
        """Transport-agnostic webhook core: verify the signature (fail-closed; with webhook_secret ONLY -
        never the API token, 0.7.0), then treat the webhook as a WAKE-UP: only its decision id is read,
        and the outcome follows Decidio's own state for that decision. Wrap this in your framework's route
        (FastAPI/Flask adapters do)."""
        body = raw_body.decode("utf-8") if isinstance(raw_body, (bytes, bytearray)) else str(raw_body)
        if not self.webhook_secret:
            if not self.allow_unsigned:
                raise PermissionError(_NO_WEBHOOK_SECRET)
        elif not verify_signature(self.webhook_secret, body, signature):
            raise PermissionError("bad signature")
        data = json.loads(body or "{}")


        return self._wake(data.get("decisionId") if isinstance(data, dict) else None)

    def _wake(self, decision_id: Any) -> dict:
        """A resume WEBHOOK is a wake-up (0.7.0): the verdict in its body is ignored and Decidio's own state
        decides, read here. A decision this store never parked costs no network call (the ledger answers).
        Before 0.7.0 the handler executed on the body's verdict, so whoever could sign a webhook - and the
        key fell back to the agent's API token - could approve. (TS twin: wake.)"""
        _idp = decision_id_problem(decision_id)
        if _idp:
            return {"status": "unknown", "decision_id": str(decision_id if decision_id is not None else ""), "reason": f"not a decision id this SDK will act on ({_idp})"}
        pending = self.store.get(decision_id)
        if pending is None:
            return self._resolve_core(decision_id, "approved")
        st = _client.status_of(self.transport, self.api_url, self.api_token, decision_id, has_credential=carries_credential(self))
        st = st if isinstance(st, dict) else {}
        state = st.get("state") if isinstance(st.get("state"), str) else ""
        reason = st.get("reason") if isinstance(st.get("reason"), str) and st.get("reason") else None
        if state in ("approved", "auto_approved"):
            return self._resolve_core(decision_id, "approved", None, status=st)
        if state in ("rejected", "blocked"):
            return self._resolve_core(decision_id, state, reason, status=st)
        return {"status": "not_approved", "decision_id": decision_id, "action": pending.action,
                "reason": f"Decidio records decision {decision_id} as {state or None!r}; a webhook is a wake-up, not an approval, so nothing ran and the entry stays parked"}

    def _refuse_once(self, decision_id: str, msg: str, tail: Optional[str] = None) -> None:
        if decision_id in self._refusal_warned:
            return
        self._refusal_warned.add(decision_id)
        print(msg + (tail if tail is not None else " (This prints once per worker process - the entry stays parked until you act.)"), file=sys.stderr)

    def worker(self, interval: float = 2.5, timeout: Optional[float] = None,
               on_resolved: Optional[Callable[[dict], None]] = None) -> Callable[[], None]:
        """Poll-based resume for hosts with no inbound URL (CLI/laptop). A durable
        WORKER, not the request path blocking. Returns a stop() callable."""
        self._stop = False
        deadline = (time.time() + timeout) if timeout else None

        def loop() -> None:
            while not self._stop:
                try:
                    pendings = self.store.list()
                except Exception as e:
                    if not getattr(self, "_list_warned", False):
                        self._list_warned = True
                        print(f"[decidio] the durable store could not be listed ({e}) - this worker resumes nothing until it can be read again.", file=sys.stderr)
                    pendings = []
                for p in pendings:
                    try:
                        st = _client.status_of(self.transport, self.api_url, self.api_token, p.decision_id, has_credential=carries_credential(self))
                    except Exception:
                        continue
                    state = st.get("state")
                    verdict = ("approved" if state in ("approved", "auto_approved")
                               else "rejected" if state == "rejected"
                               else "blocked" if state == "blocked" else None)
                    if not verdict:
                        continue


                    try:
                        try:

                            outcome = self._resolve_core(p.decision_id, verdict, st.get("reason"), status=st)
                        except DecidioStateCorrupt as _corrupt:


                            self._refuse_once(p.decision_id, f"[decidio] LEDGER CORRUPT for {p.decision_id}: {_corrupt} - this worker will not touch it until the ledger is repaired; the other parked actions still resume.", "")
                            continue



                        if outcome.get("status") == "executed" and outcome.get("report_recorded"):
                            unconfirmed = "" if outcome.get("execution_confirmed") else " (execution NOT confirmed - see the warning above)"
                            print(f'[decidio] resumed {p.decision_id}: approved -> "{p.action}" executed; evidence recorded as {outcome.get("evidence_tier")}{unconfirmed}.', file=sys.stderr)
                        elif outcome.get("status") == "executed":
                            print(f'[decidio] resumed {p.decision_id}: approved -> "{p.action}" executed, but its execution report did NOT reach Decidio - recover with: guard.resume.reconfirm("{p.decision_id}")', file=sys.stderr)
                        elif outcome.get("status") == "rejected":
                            print(f'[decidio] resumed {p.decision_id}: REJECTED - the parked "{p.action}" was discarded, nothing executed.', file=sys.stderr)
                        elif outcome.get("status") == "unanswered":
                            print(f'[decidio] resumed {p.decision_id}: UNANSWERED - nobody decided it by its deadline, so no authority was granted; the parked "{p.action}" was discarded, nothing executed. Ask again if it is still needed.', file=sys.stderr)
                        elif outcome.get("status") == "blocked":
                            _why = f"({outcome.get('reason')})" if outcome.get("reason") else "by policy"
                            print(f'[decidio] resumed {p.decision_id}: BLOCKED {_why} - the parked "{p.action}" was discarded, nothing executed.', file=sys.stderr)
                        if on_resolved:
                            on_resolved(outcome)
                    except Exception as e:
                        print(f"[decidio] resume failed for {p.decision_id}, will retry: {e}", file=sys.stderr)
                if deadline and time.time() > deadline:
                    break
                time.sleep(interval)

        t = threading.Thread(target=loop, daemon=False)






        t.start()

        def stop() -> None:
            self._stop = True

        return stop
