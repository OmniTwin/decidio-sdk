"""Shared adapter core — the thin-adapter rule in code. Every engine adapter reuses
these gate calls; only the *suspend/resume* translation differs per engine. Policy,
sealing, and the record live in Decidio (the core), never in an adapter."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .. import _client
from ..canonical import canonicalize
from ..errors import DecidioBlocked, decision_id_problem
from ..evidence import build_confirm_body
from ..signing import binding_material_of, carries_credential, invocation_request_key, request_commitment
from ..signing import idempotency_key as idempotency_key_of

# The ONLY authorization verdicts this SDK understands. A gate answer outside this set means
# the SDK does not understand the decision — and an answer you do not understand means NO.
AUTHORIZE_VERDICTS = ("proceed", "route", "block")


@dataclass
class AuthResult:
    decision: str          # "proceed" | "route" | "block"
    decision_id: str
    receipt_id: Optional[str] = None
    reason: Optional[str] = None
    # The request key this authorize sent, when it sent one (0.12.0, 11f).
    request_key: Optional[str] = None


def assert_authorize_verdict(auth: Any, fallback_id: str = "unknown") -> AuthResult:
    """Fail-closed verdict allow-list. Called INSIDE authorize(), so every adapter that goes
    through the shared gate is protected BY CONSTRUCTION rather than by remembering — an
    adapter that handled `block` and `route` and let everything else fall through to execute is
    exactly how an unknown verdict reaches a protected action. Version skew (the day the gate
    learns a fourth verdict) is the realistic trigger, and it must never mean "run it"."""
    a = auth if isinstance(auth, dict) else {}
    decision = a.get("decision")
    raw_id = a.get("decisionId")
    # fallback_id names the ERROR only — it is never fabricated into a returned AuthResult.
    error_id = raw_id if isinstance(raw_id, str) and raw_id else fallback_id
    if decision not in AUTHORIZE_VERDICTS:
        raise DecidioBlocked(
            f"unrecognised authorization verdict {decision!r} - refusing to execute. The gate answers "
            f"{' | '.join(AUTHORIZE_VERDICTS)}; anything else means this SDK version does not understand the "
            f"decision (upgrade the decidio package), and an answer you do not understand is never permission.",
            error_id,
        )
    # A recognized verdict with no usable id is not permission either (verdict check stays
    # first so unknown-verdict callers keep their message). Without an id the decision cannot
    # be polled, parked, confirmed or audited.
    # The SAME rule as the core path, from the one leaf module every door can import - the four
    # copies of this check were truthiness-only and had drifted to accepting a whitespace-only id.
    _id_problem = decision_id_problem(raw_id)
    if _id_problem:
        raise DecidioBlocked(
            f"the gate answered \"{decision}\" with no usable decisionId ({raw_id!r} - {_id_problem}) - refusing to execute. "
            f"Every authorized action must be addressable: without an id it cannot be polled, resumed, "
            f"confirmed or audited.",
            error_id,
        )
    return AuthResult(decision, raw_id, a.get("receiptId"), a.get("reason"))


def adapter_request(ctx: dict) -> dict:
    """What an ENGINE door binds a routed approval to (0.7.0): the whole described context, canonicalized
    exactly as authorize() canonicalizes it. An adapter cannot see inside its `run` callable, so the
    described request - action, amount, scope and the display details a human approved - is the request.
    Recompute it from the SAME describe() the door authorized with. (TS twin: adapterRequest.)"""
    c = canonicalize(ctx, "describe(...)")
    r = {"action": c.get("action"), "amount": c.get("amount")}
    if c.get("scope") is not None:
        r["scope"] = c["scope"]
    if c.get("context") is not None:
        r["context"] = c["context"]
    return r


def _field(obj: Any, *names: str) -> Any:
    for n in names:
        v = obj.get(n) if isinstance(obj, dict) else getattr(obj, n, None)
        if v is not None:
            return v
    return None


def tool_call_request(item: Any, ctx: dict) -> dict:
    """What the OpenAI Agents door binds a routed approval to (#4B review W2): the described context AND the
    tool call itself - its name, its call id and its exact argument string, from the interruption's raw
    item. describe(item) is the host's summary and need not cover every argument (edit a parked item's
    target and it can stay the same), and it never says WHICH call: without the call id one approval could
    be applied to a second, identical call whose own decision is still pending. An item with no call id
    cannot be bound to one call, so it is refused - nothing routed, nothing approved. (TS twin:
    toolCallRequest.)"""
    raw = _field(item, "raw_item", "rawItem")
    if raw is None:
        raw = item
    # The SAME lookup order as the TS twin (callId, call_id, id) - one raw item names one call in both.
    call_id = _field(raw, "callId", "call_id", "id")
    if not isinstance(call_id, str) or not call_id:
        raise ValueError("[decidio] openai: this tool-approval item carries no call id (raw_item.call_id), so an approval "
                         "could not be bound to this ONE call - nothing was routed or approved. Pass the items "
                         "state.get_interruptions() returns.")
    name = _field(raw, "name")
    if name is None:
        name = _field(item, "tool_name", "name")
    args = _field(raw, "arguments")
    if args is None:
        args = _field(item, "arguments")
    r = adapter_request(ctx)
    r["args"] = [{"arguments": args, "callId": call_id, "name": name if isinstance(name, str) else None}]
    return r


def check_approval_for(guard: Any, decision_id: str, ctx: dict, request: Optional[dict] = None) -> dict:
    """THE ONE APPROVAL CHECK on an engine door: GET /agent/status + the request commitment recomputed
    over this `ctx` (resume.check_approval) - or over `request` when the door binds more than the described
    context (the OpenAI door's tool_call_request). Returns the plain dict an engine that must run HTTP inside
    an activity or a step (Temporal, Inngest) memoizes. (TS twin: gateCheckApproval.)"""
    from ..resume import check_approval
    return check_approval(guard.transport, guard.config, decision_id, request if request is not None else adapter_request(ctx))


def assert_check_shape(raw: Any, decision_id: str) -> dict:
    """Validate an approval check that crossed a serialization boundary (a Temporal activity result, an
    Inngest step memo). Anything that is not a well-formed check is refused as unverifiable - "an answer
    you do not understand is never permission". (TS twin: assertApprovalCheckShape.)"""
    c = raw if isinstance(raw, dict) else None
    if c is None or not isinstance(c.get("ok"), bool) or c.get("decision_id") != decision_id or not isinstance(c.get("state"), str):
        return {"ok": False, "decision_id": decision_id, "state": "", "code": "unverifiable",
                "reason": f"the approval check for decision {decision_id} came back malformed ({str(raw)[:120]}) - return "
                          f"check_approval_for(...) from your activity unchanged"}
    if c.get("ok") is True and c.get("code") is not None:
        return {"ok": False, "decision_id": decision_id, "state": c["state"], "code": "unverifiable",
                "reason": "the approval check came back contradictory (ok with a refusal code)"}
    return c


def authorize(guard: Any, ctx: dict, resume_url: Optional[str] = None, idempotency_key: Optional[str] = None,
              request: Optional[dict] = None, natural_id: Optional[dict] = None) -> AuthResult:
    """`natural_id` (0.12.0, 11f; TS twin naturalId): the engine's own name for THIS call - an OpenAI tool call id, a
    Temporal workflow run and activity, an Inngest run - so the engine retrying the same call is the same request. The
    request key is keyed over it and the commitment. Without one (and without `idempotency_key`) the key is over a fresh
    id for this call, as on the core path. No key material: no commitment, so no key - as before."""
    cfg = guard.config
    # SAME canonical model as the core wrapper: the adapter door skipped it, and the server's
    # amount coercion turns a drifted NaN into a $0 request a human would approve without
    # knowing. Checked on the whole ctx, so a display-only field drifts no more quietly.
    # ...and the SNAPSHOT is what everything below reads (retest V030-03; see the TS twin).
    ctx = canonicalize(ctx, "describe(...)")
    # Omit None optionals — the server's zod schema rejects null for optional fields.
    body = {"requester": cfg.agent_id, "action": ctx["action"], "amount": ctx["amount"]}
    if ctx.get("scope") is not None:
        body["scope"] = ctx["scope"]
    if cfg.source_system is not None:
        body["sourceSystem"] = cfg.source_system
    # Sign the bound proof so an adapter-path agent can prove its identity + auto-approve.
    if cfg.agent_key and cfg.agent_did:
        from ..signing import sign_bound_proof
        body["requesterIdentity"] = sign_bound_proof(cfg.agent_key, agent_id=cfg.agent_id, did=cfg.agent_did, action=ctx["action"], amount=ctx["amount"], scope=ctx.get("scope"), workspace_id=getattr(cfg, "workspace_id", None))
    url = resume_url or cfg.resume_url
    if url:
        body["resumeUrl"] = url
    # BIND THE APPROVAL TO THIS EXACT REQUEST (0.7.0) - the same keyed commitment the core wrapper sends,
    # over the described context (adapter_request). Every engine door authorizes here, so every engine
    # door is bound by construction. `idempotency_key` lets a door whose engine RE-RUNS the authorizing
    # code on resume (LangGraph) get the SAME decision back instead of minting a phantom second one. `request`
    # lets a door bind more than the described context (the OpenAI door binds the tool call itself).
    material = binding_material_of(cfg)
    commitment = None
    if material is not None:
        commitment = request_commitment(material, request if request is not None else adapter_request(ctx))
        body["requestCommitment"] = commitment
    # A REQUEST KEY BY DEFAULT (0.12.0, 11f): beside every commitment - the caller's own key when it has one (LangGraph's
    # run identity, the hook's), else one over the engine's own id for this call, else one over a fresh id for this call.
    key = idempotency_key
    if not key and material is not None and commitment:
        if natural_id:
            key = idempotency_key_of(material, {**natural_id, "commitment": commitment})
        else:
            import uuid as _uuid
            _inv = getattr(cfg, "invocation_id", None)
            key = invocation_request_key(material, str(_inv()) if _inv else _uuid.uuid4().hex, commitment)
    if key:
        body["idempotencyKey"] = key
    # SAME chokepoint as the core wrapper (this door posted raw,
    # skipping BOTH the JSON-safety gate and the typed 429 — and the server's amount coercion
    # turns a drifted NaN into a $0 request a human would approve without knowing).
    from ..guard import _post_authorize

    def _resign() -> Any:
        if not (cfg.agent_key and cfg.agent_did):
            return None
        from ..signing import sign_bound_proof as _sbp
        return _sbp(cfg.agent_key, agent_id=cfg.agent_id, did=cfg.agent_did, action=ctx["action"], amount=ctx["amount"],
                    scope=ctx.get("scope"), workspace_id=getattr(cfg, "workspace_id", None))
    # RETRIED with the same request (11f) through the ONE authorize POST the core wrapper uses (a fresh proof per try).
    auth = _post_authorize(guard.transport, cfg.api_url, body, cfg.api_token, has_credential=carries_credential(cfg), resign=_resign)
    # FAIL-CLOSED at the chokepoint: the allow-list runs HERE so no adapter can skip it.
    checked = assert_authorize_verdict(auth, "unknown")
    if key:
        checked.request_key = key
    return checked


def claim_for(guard: Any, decision_id: str, claim_key: str) -> dict:
    """COLLECT A PERSON'S APPROVAL ONCE on an engine door (0.12.0, call 24; TS twin gateClaim) - resume.claim_approval, as
    the plain dict an engine that must run HTTP in an activity (Temporal) returns unchanged."""
    from ..resume import claim_approval
    return claim_approval(guard.transport, guard.config, decision_id, claim_key)


def assert_claim_shape(raw: Any, decision_id: str) -> dict:
    """Validate a claim outcome that crossed a serialization boundary (a Temporal activity result; TS twin
    assertClaimShape). Anything that is not a well-formed outcome for THIS decision is refused."""
    c = raw if isinstance(raw, dict) else None
    if c is not None and c.get("decision_id") == decision_id:
        if c.get("ok") is True and isinstance(c.get("again"), bool):
            return {"ok": True, "decision_id": decision_id, "again": c["again"]}
        if c.get("ok") is False and isinstance(c.get("code"), str) and isinstance(c.get("reason"), str) and isinstance(c.get("final"), bool):
            return c
    return {"ok": False, "decision_id": decision_id, "code": "unrecognized", "final": False,
            "reason": f"the claim for decision {decision_id} came back malformed ({str(raw)[:120]}) - return "
                      f"_claim_activity(...) from your activity unchanged. Nothing ran."}


def confirm(guard: Any, decision_id: str, result: Any, evidence: Any = None) -> dict:
    """Report an adapter-path execution and RETURN what Decidio recorded.

    Two 0.2.0 changes, both closing the same gap. It now applies the caller's `evidence` mapper -
    a mapper passed to `guard.protect(..., adapter=...)` reached `bind()` and stopped there, so
    the option the stderr note tells you to use was silently ignored on every engine adapter. And
    it RETURNS the outcome instead of discarding it, so an adapter can hand its caller the same
    confirmation the core path now does."""
    cfg = guard.config
    import sys as _sys0
    # Shape the evidence OUTSIDE the confirm try - the same rule as the inline and durable doors
    # (0.1.12). This is the chokepoint EVERY engine adapter confirms through, and with the
    # canonicalize inside the try a result the model refuses (a datetime, a set, a 64-bit id)
    # skipped the whole POST, so the execution went unrecorded with only a "confirm failed" line
    # to show for it. A value we cannot REPORT must never cost the RECORD.
    evidence_problem = None
    try:
        reported = canonicalize(evidence(result) if evidence else result, "evidence(result)" if evidence else "result")
    except Exception as e:  # noqa: BLE001 - the action SUCCEEDED; only its value is unreportable
        reported, evidence_problem = None, str(e)
        print(f"[decidio] {decision_id}: the action SUCCEEDED but its result could not be reported as "
              f"evidence ({e}). Reporting a null captured response so the execution is still recorded - "
              f"map the return value with the `evidence` option to earn a confirming tier. The action "
              f"was NOT re-run.", file=_sys0.stderr)
    try:
        # Sign the confirm (bound to {action:"confirm", scope:decisionId}) so the adapter path
        # earns application_confirmed; without a key the server caps it at agent_asserted.
        ri = None
        if cfg.agent_key and cfg.agent_did:
            from ..signing import sign_bound_proof
            ri = sign_bound_proof(cfg.agent_key, agent_id=cfg.agent_id, did=cfg.agent_did, action="confirm", amount=0, scope=decision_id, workspace_id=getattr(cfg, "workspace_id", None))
        # Same no-silent-downgrade rule as the inline wrap.
        if not ri:
            import sys as _sys
            print(f"[decidio] execution evidence for {decision_id} recorded as agent_asserted - no signing key configured, so the report can't be proven to come from this agent. Set DECIDIO_AGENT_KEY/DID to earn application_confirmed.", file=_sys.stderr)
        # SAME confirm body + SAME evidence rule as every other door (inline, durable resume):
        # the signed execution report rides along when a key is configured, transport success is
        # not a recorded report, and a recorded report is not necessarily a confirmed execution.
        ev = _client.post_confirm(guard.transport, cfg.api_url, cfg.api_token,
                                  build_confirm_body(cfg, decision_id, reported, ri),
                                  has_credential=carries_credential(cfg))
        import sys as _sys3
        if not ev["report_recorded"]:
            print(f'[decidio] {decision_id}: {ev.get("diagnostic")}', file=_sys3.stderr)
        elif not ev["execution_confirmed"] or ev.get("execution_report_verified") is False:
            print(f'[decidio] execution evidence for {decision_id} recorded as {ev.get("evidence_tier")} - {ev.get("diagnostic")}', file=_sys3.stderr)
        if evidence_problem:
            print(f'[decidio] {decision_id}: the execution IS recorded, but with an empty captured response - see the evidence note above.', file=_sys3.stderr)
        if evidence_problem:
            ev = dict(ev)
            ev["evidence_error"] = evidence_problem
        return ev
    except Exception as e:  # noqa: BLE001 — best-effort; the action already happened
        import sys as _sys2
        print(f"[decidio] confirm failed (action succeeded): {e}", file=_sys2.stderr)
        # A value, not a raise, and not silence: the adapter path answers like every other door.
        return {"report_recorded": False, "execution_confirmed": False,
                "confirmation_retryable": bool(getattr(e, "retryable", True)),
                "report_journalled": False, "evidence_error": evidence_problem,
                "diagnostic": f"your action RAN and Decidio does NOT have its execution report ({e}). "
                              f"Record the outcome from your own system; do NOT re-run the action."}
