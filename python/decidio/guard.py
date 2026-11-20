"""The Guard facade — `guard.protect(fn, describe)`, the one agnostic line.

Mirrors @decidio/guard (TS): authorize → proceed | route | block. On route, durable
mode SUSPENDS (parks args, raises DecidioSuspended); blocking mode polls (opt-in,
short approvals only). The agent executes its own action; Decidio gates + records +
signals — it never executes and holds no downstream credentials.
"""
from __future__ import annotations

import asyncio
import functools
import json
import sys
import threading
from urllib.parse import quote
import inspect
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from . import _client
from ._client import Transport, UrllibTransport
from copy import deepcopy as _deepcopy

from .canonical import canonicalize, canonicalize_args
from .errors import DecidioBlocked, DecidioError, DecidioRejected, DecidioSuspended, DecidioTimeout, DecidioUnanswered, DecidioUnsafeArguments, decision_id_problem, unanswered_of
from .evidence import build_confirm_body
from .signing import binding_material_of, carries_credential, invocation_request_key, own_request_key, request_commitment
from .resume import RETRY_DELAYS, ExecutionContext, FilePendingStore, PendingAction, ResumeController, _complete, approval_refusal, check_approval, claim_approval, claim_refusal, core_request, new_claim_key


ApprovalContext = Dict[str, Any]


class DecidioRateLimitError(DecidioError):
    """The workspace's governed-action allowance is exhausted (HTTP 429, code AGENT_RATE). The
    server says exactly how much and until when — limit/remaining/reset_at relay its answer
    verbatim, so automation never has to parse a message and a rate-limited run can never be
    misdiagnosed as a connectivity failure. Nothing was routed,
    recorded, or executed; retry after `reset_at`. Mirrors DecidioRateLimitError in the TS SDK."""



    def __init__(self, limit: Optional[int], remaining: Optional[int], reset_at: Optional[str], server_message: Optional[str] = None,
                 code: Optional[str] = None):
        super().__init__(
            "[decidio] governed-action rate limit reached"
            + (f" ({limit}/hour on this workspace)" if limit is not None else "")
            + (f" — resets {reset_at}" if reset_at else "")
            + ". "
            + (f"{server_message} " if server_message else "")
            + "Nothing was routed or executed; retry after the reset."
        )
        self.limit = limit
        self.remaining = remaining
        self.reset_at = reset_at
        self.code = code


def _retries_safely(e: BaseException) -> bool:
    """May this failure be retried with the SAME request (11f; TS twin retriesSafely)? A network failure (OSError: urllib's
    URLError, a timeout, a reset connection), a 5xx (not 501), and a 429 that is not the workspace's hourly allowance
    (AGENT_RATE: retrying in a second cannot help, and the server says when it resets). Never another 4xx."""
    from .errors import DecidioHttpError
    if isinstance(e, DecidioRateLimitError):
        return e.code != "AGENT_RATE"
    if isinstance(e, DecidioHttpError):
        _code = e.body.get("code") if isinstance(e.body, dict) else None
        return (e.status >= 500 and e.status != 501) or (e.status == 429 and _code != "AGENT_RATE")
    return isinstance(e, OSError)


def _post_authorize(transport: Transport, api_url: str, body: Dict[str, Any], api_token: Optional[str], has_credential: Optional[bool] = None,
                    resign: Optional[Callable[[], Any]] = None) -> Any:
    """THE ONE AUTHORIZE POST (0.12.0, 11f; TS twin sendAuthorize) - the core wrapper and every engine adapter send through
    here. A network failure or a transient answer is retried a bounded number of times with the SAME request: under a
    request key that is the same request (the gate answers the decision it already made, `idempotentReplay`), and a
    keyless request asked again while it waits joins the one waiting (`openTwin`). A body that carries a commitment
    WITHOUT a key is never retried. Every field stays the same across tries except the signed identity proof: its nonce
    is single-use, so a retry signs a fresh one (`resign`) - the same proof again would be read as unverified."""
    may_retry = bool(body.get("idempotencyKey")) or not body.get("requestCommitment")
    attempt = 0
    current = body
    while True:
        try:
            return _post_authorize_once(transport, api_url, current, api_token, has_credential)
        except Exception as e:
            if not may_retry or attempt >= len(RETRY_DELAYS) or not _retries_safely(e):
                raise
            time.sleep(RETRY_DELAYS[attempt])
            attempt += 1
            fresh = resign() if (resign is not None and body.get("requesterIdentity")) else None
            if fresh:
                current = {**body, "requesterIdentity": fresh}


def _post_authorize_once(transport: Transport, api_url: str, body: Dict[str, Any], api_token: Optional[str], has_credential: Optional[bool] = None) -> Any:
    """POST /agent/authorize with the 429 branch the generic `_client.post` lacks: a rate-limited
    gate answers HTTP 429 with {code, message, limit, remaining, resetAt}, and that refusal must
    surface TYPED with the server's own numbers, never as a bare non-2xx error (parity with the
    TS SDK's post()). Only the authorize path carries this branch — status/confirm ride the
    shared transport untouched."""



    canonicalize(body, "describe(...)")




    _act = body.get("action")
    if not isinstance(_act, str) or not _act.strip():
        raise DecidioUnsafeArguments(
            f"[decidio] describe(...) must return an `action` string naming what is being asked "
            f"(got {_act!r}). Nothing was routed or executed.")
    _amt = body.get("amount")
    if isinstance(_amt, bool) or not isinstance(_amt, (int, float)) or _amt != _amt or _amt in (float("inf"), float("-inf")) or _amt < 0:
        raise DecidioUnsafeArguments(
            f"[decidio] describe(...) must return a finite, non-negative `amount` - the policy decides "
            f"on it, so a request without one is not a request Decidio can rule on (got {_amt!r}). Use 0 "
            f"for an action with no monetary value. Nothing was routed or executed.")
    from .signing import assert_safe_transport

    if has_credential is None:
        has_credential = bool(api_token) or bool(body.get("requesterIdentity"))
    assert_safe_transport(api_url, has_credential)
    status, text = transport.request("POST", api_url.rstrip("/") + "/agent/authorize", _client._headers(api_token), json.dumps(body))
    if status == 429:
        try:
            b = json.loads(text) if text else None
        except Exception:
            b = None
        b = b if isinstance(b, dict) else {}
        raise DecidioRateLimitError(b.get("limit"), b.get("remaining"), b.get("resetAt"), b.get("message"),
                                    b.get("code") if isinstance(b.get("code"), str) else None)
    if not (200 <= status < 300):
        from .errors import DecidioHttpError
        try:
            _b = json.loads(text) if text else None
        except Exception:
            _b = text
        raise DecidioHttpError(status, "/agent/authorize", _b)
    return json.loads(text) if text else {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def decision_url(app_url: Optional[str], decision_id: str) -> Optional[str]:
    """"<app_url>/d/<decision_id>" — the deep link that opens this decision directly, on the web
    app or the phone build. None when DECIDIO_APP_URL is not configured, never a half-built URL."""
    if not app_url:
        return None
    return f"{app_url.rstrip('/')}/d/{quote(decision_id, safe='')}"


@dataclass
class ProtectedExecution:
    """What a protected call returns in 0.2.0: your function's value, the decision it was
    authorized under, and what Decidio actually recorded about the execution.

    Through 0.1.x this was just the value. The SDK computed the full confirmation outcome - tier,
    whether the report was recorded, whether the signed execution report verified, whether the
    evidence mapper failed - and then dropped it, surfacing it only on stderr. For a product whose
    value IS the record, the one thing a caller could not do was find out what got recorded.

    `protect_best_effort` keeps the old value-only shape for callers that genuinely do not care."""


    value: Any

    decision_id: str


    confirmation: Dict[str, Any]


    request_key: Optional[str] = None





_DOTENV_INJECTED: Dict[str, str] = {}


@dataclass
class GuardConfig:
    api_url: str
    agent_id: str
    api_token: Optional[str] = None
    source_system: Optional[str] = None
    resume_url: Optional[str] = None
    webhook_secret: Optional[str] = None
    poll_interval: float = 2.0
    poll_timeout: float = 600.0



    agent_key: Optional[str] = None
    agent_did: Optional[str] = None


    workspace_id: Optional[str] = None




    app_url: Optional[str] = None






    pending_dir: Optional[str] = None


    on_pending: Optional[Callable[[Dict[str, Any]], None]] = None




    invocation_id: Optional[Callable[[], str]] = None


class Guard:
    def __init__(self, config: GuardConfig, resume: Optional[ResumeController] = None, transport: Optional[Transport] = None):
        self.config = config
        self.transport: Transport = transport or UrllibTransport()


        self._resume = resume
        self._resume_lock = threading.RLock()

    @property
    def resume(self) -> ResumeController:
        """The recovery surface - `guard.resume.recover()` / `.reconfirm(id)`. BUILT ON FIRST
        ACCESS, because the process that needs to recover is usually a COLD one that never made
        the original call, so nothing has lazily constructed the controller yet. As a plain
        attribute this read was None there and the documented recovery loop raised
        AttributeError on the exact path it exists for. Unconfigured still fails loud (naming
        DECIDIO_API_URL), never silently."""
        return self._ensure_resume()

    @resume.setter
    def resume(self, controller: Optional[ResumeController]) -> None:


        self._resume = controller

    @classmethod
    def from_env(cls) -> "Guard":






        try:
            import os as _os
            import re as _re
            if _os.path.exists(".env"):
                for line in open(".env", encoding="utf-8"):
                    m = _re.match(r"^\s*([A-Z_]+)=(.*)$", line)
                    if m and m.group(1) != "DECIDIO_SESSION_TOKEN" and m.group(1) not in _os.environ:
                        _os.environ[m.group(1)] = m.group(2).strip()
                        _DOTENV_INJECTED[m.group(1)] = m.group(2).strip()
        except Exception:
            pass
        cfg = GuardConfig(




            api_url=os.environ.get("DECIDIO_API_URL", ""),
            agent_id=os.environ.get("DECIDIO_AGENT_ID", "agent"),
            api_token=os.environ.get("DECIDIO_API_TOKEN"),
            source_system=os.environ.get("DECIDIO_SOURCE_SYSTEM"),
            resume_url=os.environ.get("DECIDIO_RESUME_URL"),
            webhook_secret=os.environ.get("DECIDIO_WEBHOOK_SECRET"),
            agent_key=os.environ.get("DECIDIO_AGENT_KEY"),
            agent_did=os.environ.get("DECIDIO_AGENT_DID"),
            workspace_id=os.environ.get("DECIDIO_WORKSPACE_ID"),
            app_url=os.environ.get("DECIDIO_APP_URL"),
            pending_dir=os.environ.get("DECIDIO_PENDING_DIR"),
        )
        return cls(cfg)

    def _assert_configured(self) -> None:
        """Fail loud at USE time when the facade has no gate URL (import stays safe)."""
        if not self.config.api_url:
            raise RuntimeError("[decidio] no gate URL configured - set DECIDIO_API_URL (Decidio is https://mcp.decidioai.com) or run `python -m decidio init`, then load .env into your process environment. Nothing was routed or executed.")

    def _ensure_resume(self) -> ResumeController:






        self._assert_configured()
        with self._resume_lock:
            if self._resume is None:
                self._resume = ResumeController(
                    api_url=self.config.api_url,
                    store=FilePendingStore(self.config.pending_dir or os.environ.get("DECIDIO_PENDING_DIR", ".decidio-pending")),
                    api_token=self.config.api_token,
                    webhook_secret=self.config.webhook_secret,
                    resume_url=self.config.resume_url,
                    transport=self.transport,

                    agent_id=self.config.agent_id,
                    agent_key=self.config.agent_key,
                    agent_did=self.config.agent_did,
                    workspace_id=self.config.workspace_id,
                )
            return self._resume

    def worker(self, interval: float = 2.5, timeout: Optional[float] = None,
               on_resolved: Optional[Callable[[dict], None]] = None) -> Callable[[], None]:
        """Durable resume with NOTHING to host: a background watcher polls Decidio outward and
        finishes any parked approval — so a suspended action survives a process restart. One line
        at startup. Production may swap this for the webhook (DECIDIO_RESUME_URL); the
        suspend/resume shape is identical. Returns a stop() callable."""
        return self._ensure_resume().worker(interval=interval, timeout=timeout, on_resolved=on_resolved)

    def register(self, action: str, fn: Callable[..., Any], evidence: Optional[Callable[[Any], Any]] = None, with_context: bool = False) -> None:
        """Register a raw fn under its action name so a COLD process (one that never made the
        original call) can resume it. Call at startup beside `guard.worker()` — or pass
        `action="..."` to `protect(...)`, which does it for you at wrap time. The evidence
        mapper travels WITH the fn it maps (A5, 0.1.12)."""
        self._ensure_resume().register(action, fn, evidence, with_context=with_context)

    def protect(
        self,
        fn: Callable[..., Any],
        describe: Callable[..., ApprovalContext],
        adapter: Optional[str] = None,
        mode: str = "durable",
        action: Optional[str] = None,
        poll_timeout: Optional[float] = None,
        poll_interval: Optional[float] = None,
        evidence: Optional[Callable[[Any], Any]] = None,
        with_context: bool = False,
        request_key: Optional[Callable[..., str]] = None,
    ) -> Callable[..., Any]:
        """Wrap an action behind the gate. Returns a drop-in with fn's signature.

        adapter: None/"generic" → core gate (this module). Engine adapters
        (langgraph/openai/temporal/inngest) live in decidio.adapters.* and take the
        engine handle; `protect` dispatches to them when `adapter` names one.

        BETA (adapters): the engine adapters share the core's gate semantics — the verdict
        allow-list, the canonical argument model, the transport rule and evidence handling are
        ONE implementation, exercised across every door — but their ENGINE integration is
        verified against structural mocks, not live engines. Use the core path for production
        until that changes.

        evidence: map YOUR function's natural return value to the evidence Decidio records.
        The gate awards its strongest wrapper tier (application_confirmed) only for a committed
        record id plus a success indication, so instead of forcing your API into magic field
        names: `evidence=lambda r: {"recordId": r["transactionId"], "success": r["status"] == "committed"}`.
        Threaded to BOTH transports — the durable resume reports exactly what the inline path would.

        action: the action name this wrapper produces, declared UP FRONT so the resume registry
        is populated at WRAP time rather than on first call — required for the cold-worker
        pattern (a restarted process can only resume actions registered in THAT process, and
        `describe` cannot run without the original call arguments).

        poll_timeout / poll_interval: blocking-mode poll ceiling / interval in SECONDS
        (defaults: GuardConfig's 600 / 2.0). Documented since 0.1.0 but only reachable via
        GuardConfig until now (passing them here raised TypeError — while
        the TS twin silently swallowed the same knob and CI pipelines blocked the full
        10-minute default instead of failing fast, a twin divergence; both facades now accept
        them here).

        request_key: YOUR OWN REQUEST KEY for a call, from its arguments (0.12.0, 11f) - an order or invoice id,
        `request_key=lambda inv: inv["id"]` - so the same call asked again, even from a new process, is the same
        request. Keyed with this agent's material before it is sent (your id never reaches Decidio in the clear). The
        same key for a CHANGED request is refused by the gate (409 IDEMPOTENCY_CONFLICT), never a silent second request.
        Without it each call sends a fresh random key. (TS twin: `requestKey`.)"""
        self._assert_configured()
        if adapter and adapter not in ("generic",):
            from . import adapters



            return adapters.bind(adapter, self, fn, describe, evidence=evidence)



        if action and mode == "durable":
            self.register(action, fn, evidence, with_context=with_context)

        cfg = self.config

        def _gate(*args: Any, **kwargs: Any) -> Any:








            try:
                c_args, c_kwargs = canonicalize_args(args, kwargs)
            except DecidioUnsafeArguments as e:
                raise DecidioUnsafeArguments(f"{e} The decision was NOT routed; nothing reached Decidio.") from None












            _probe_args, _probe_kwargs = _deepcopy(c_args), _deepcopy(c_kwargs)
            ctx = describe(*_probe_args, **_probe_kwargs)
            if _probe_args != list(c_args) or _probe_kwargs != dict(c_kwargs):
                raise DecidioUnsafeArguments(
                    "[decidio] your describe() callback MODIFIED the call arguments. Those arguments are "
                    "the approved value: they are what a human sees, what the signature covers, what is "
                    "parked for a durable resume, and what your function ultimately runs on - so changing "
                    "them there would mean the action that executes is not the action that was approved. "
                    "Read from the arguments and RETURN the context instead: "
                    "lambda inv: {\"action\": \"pay\", \"amount\": inv[\"amount\"]}. If you need a modified "
                    "value at execution time, compute it inside your function. "
                    "Nothing was routed or executed."
                )





            ctx = canonicalize(ctx, "describe(...)")


            body: Dict[str, Any] = {"requester": cfg.agent_id, "action": ctx["action"], "amount": ctx["amount"]}
            if ctx.get("scope") is not None:
                body["scope"] = ctx["scope"]
            if cfg.source_system is not None:
                body["sourceSystem"] = cfg.source_system



            if cfg.agent_key and cfg.agent_did:
                from .signing import sign_bound_proof
                body["requesterIdentity"] = sign_bound_proof(
                    cfg.agent_key, agent_id=cfg.agent_id, did=cfg.agent_did,
                    action=ctx["action"], amount=ctx["amount"], scope=ctx.get("scope"),
                    workspace_id=cfg.workspace_id,
                )


            resume_url = cfg.resume_url or (self._resume.resume_url if self._resume else None)
            if resume_url and mode != "blocking":
                body["resumeUrl"] = resume_url






            committed = core_request(ctx["action"], ctx["amount"], ctx.get("scope"), list(c_args), dict(c_kwargs))
            material = binding_material_of(cfg)
            sent_commitment = request_commitment(material, committed) if material is not None else None
            if sent_commitment:
                body["requestCommitment"] = sent_commitment




            sent_key = None
            if request_key is not None:
                own = request_key(*c_args, **c_kwargs)
                if not isinstance(own, str) or not own:
                    raise DecidioUnsafeArguments(f"[decidio] request_key(...) must return a non-empty string naming this call (got {own!r}). "
                                                 f"Nothing was routed or executed.")
                if material is None:
                    raise DecidioUnsafeArguments("[decidio] request_key needs this agent's key material (DECIDIO_AGENT_KEY + DECIDIO_AGENT_DID, "
                                                 "or DECIDIO_API_TOKEN): a key rides only beside the request commitment that material "
                                                 "makes, and Decidio refuses one alone. Nothing was routed or executed.")
                sent_key = own_request_key(material, own)
            elif material is not None and sent_commitment:
                import uuid as _uuid
                sent_key = invocation_request_key(material, str(cfg.invocation_id()) if cfg.invocation_id else _uuid.uuid4().hex, sent_commitment)
            if sent_key:
                body["idempotencyKey"] = sent_key

            def _resign() -> Any:
                if not (cfg.agent_key and cfg.agent_did):
                    return None
                from .signing import sign_bound_proof as _sbp
                return _sbp(cfg.agent_key, agent_id=cfg.agent_id, did=cfg.agent_did, action=ctx["action"], amount=ctx["amount"],
                            scope=ctx.get("scope"), workspace_id=cfg.workspace_id)
            auth = _post_authorize(self.transport, cfg.api_url, body, cfg.api_token, has_credential=carries_credential(cfg), resign=_resign)


            auth = auth if isinstance(auth, dict) else {}
            decision, decision_id = auth.get("decision"), auth.get("decisionId")




            if decision not in ("proceed", "route", "block"):
                raise DecidioBlocked(f"unrecognized gate verdict: {decision!r}", decision_id)




            _id_problem = decision_id_problem(decision_id)
            if _id_problem:
                raise DecidioBlocked(
                    f"the gate answered \"{decision}\" with no usable decisionId ({decision_id!r} - {_id_problem}) - "
                    f"refusing to execute. Every authorized action must be addressable: without an id it "
                    f"cannot be polled, resumed, confirmed or audited.",
                    decision_id,
                )

            if decision == "block":
                raise DecidioBlocked(auth.get("reason", "blocked by policy"), decision_id)

            if decision == "route":






                approval_url = decision_url(cfg.app_url, decision_id)
                if cfg.on_pending:
                    cfg.on_pending({"decisionId": decision_id, "receiptId": auth.get("receiptId"), "url": approval_url})
                elif approval_url:
                    print(f"[decidio] {ctx['action']} is awaiting approval (decision {decision_id}) - approve it at {approval_url}", file=sys.stderr)
                else:
                    print(f"[decidio] {ctx['action']} is awaiting approval (decision {decision_id}) - approve it in your Decidio queue, or: python -m decidio approvals approve {decision_id}", file=sys.stderr)

                if mode == "blocking":


                    eff_timeout = cfg.poll_timeout if poll_timeout is None else poll_timeout
                    eff_interval = cfg.poll_interval if poll_interval is None else poll_interval



                    print(f"[decidio] WARNING: blocking wait - this call gives up after {int(eff_timeout)}s "
                          f"(poll_timeout), and when it does, this process stops waiting and the request is "
                          f"withdrawn in Decidio: a later approval does nothing. "
                          f"Only safe for short, watched approvals - omit mode=\"blocking\" for durable async "
                          f"resume on real (minutes-to-days) approvals.", file=sys.stderr)
                    deadline = time.time() + eff_timeout
                    approved_status = None
                    while True:
                        st = _client.status_of(self.transport, cfg.api_url, cfg.api_token, decision_id, has_credential=carries_credential(cfg))
                        state = st.get("state")
                        if state in ("approved", "auto_approved"):
                            approved_status = st
                            break

                        if state == "rejected" and unanswered_of(st) is not None:
                            raise DecidioUnanswered(decision_id, unanswered_of(st)["deadline"])
                        if state == "rejected":
                            raise DecidioRejected(st.get("reason", "rejected by approver"), decision_id)
                        if state == "blocked":
                            raise DecidioBlocked(st.get("reason", "blocked"), decision_id)
                        if time.time() > deadline:









                            from urllib.parse import quote as _quote
                            from .errors import DecidioHttpError as _HttpErr
                            withdrawn = False
                            late_state = None
                            late_unanswered = None





                            shared = auth.get("idempotentReplay") is True or auth.get("openTwin") is True
                            if not shared:
                                try:
                                    _client.post(self.transport, cfg.api_url, f"/agent/withdraw/{_quote(decision_id, safe='')}",
                                                 {"reason": "timeout"}, cfg.api_token, has_credential=carries_credential(cfg))
                                    withdrawn = True
                                except _HttpErr as e:



                                    _body = e.body if isinstance(e.body, dict) else {}
                                    if e.status == 409 and isinstance(_body.get("state"), str):
                                        late_state = _body["state"]
                                        late_unanswered = unanswered_of(_body)

                                    elif e.status == 409 and _body.get("code") == "SHARED_REQUEST":
                                        shared = True
                                except Exception:
                                    pass
                            if late_state in ("approved", "auto_approved"):
                                break
                            if late_state == "rejected" and late_unanswered is not None:
                                raise DecidioUnanswered(decision_id, late_unanswered["deadline"])
                            if late_state == "rejected":
                                raise DecidioRejected("rejected by approver", decision_id)
                            if late_state == "blocked":
                                raise DecidioBlocked("blocked", decision_id)
                            _where = ("was withdrawn in Decidio (the queue no longer shows it; a later approval does nothing)"
                                      if withdrawn else
                                      "is shared with another caller (or an earlier try of this one), so it was left open for a person to decide - this process stopped waiting"
                                      if shared else
                                      "is still open in Decidio (the withdraw call failed), but this process stopped waiting")
                            print(f"[decidio] blocking wait hit its {int(eff_timeout)}s limit - decision {decision_id} {_where} and nothing was executed. Re-run to request again, or use durable resume (guard.worker()) so an approval is never lost.", file=sys.stderr)
                            raise DecidioTimeout(decision_id, withdrawn, shared)
                        time.sleep(eff_interval)



                    _check = check_approval(self.transport, cfg, decision_id, committed,
                                            sent=bool(sent_commitment), status=approved_status)
                    if not _check.get("ok"):
                        raise approval_refusal(_check)



                    if _check.get("state") == "approved":
                        _claimed = claim_approval(self.transport, cfg, decision_id, new_claim_key())
                        if not _claimed.get("ok"):
                            raise claim_refusal(_claimed)
                else:


                    resume = self._ensure_resume()



                    resume.agent_id = resume.agent_id or cfg.agent_id
                    resume.agent_key = resume.agent_key or cfg.agent_key
                    resume.agent_did = resume.agent_did or cfg.agent_did



                    resume.register(ctx["action"], fn, evidence, with_context=with_context)
                    resume.park(PendingAction(
                        decision_id=decision_id, action=ctx["action"], amount=ctx["amount"],
                        args=list(c_args), kwargs=dict(c_kwargs), scope=ctx.get("scope"),
                        receipt_id=auth.get("receiptId"), created_at=_now_iso(),

                        request_commitment=sent_commitment,
                    ))
                    raise DecidioSuspended(decision_id, ctx["action"])



            return ctx, decision_id, c_args, c_kwargs, sent_key

        def _confirm(decision_id: str, result: Any) -> Dict[str, Any]:






            evidence_error = None
            try:
                reported = canonicalize(evidence(result) if evidence else result, "evidence(result)")
            except Exception as e:
                reported, evidence_error = None, str(e)
                print(f"[decidio] {decision_id}: the action SUCCEEDED but its result could not be reported as "
                      f"evidence ({e}). Reporting a null captured response so the execution is still recorded - "
                      f"map the return value with the `evidence` option (e.g. "
                      f"evidence=lambda r: {{\"recordId\": str(r[\"id\"]), \"success\": True}}) to earn a confirming "
                      f"tier. The action was NOT re-run.", file=sys.stderr)
            try:



                confirm_identity = None
                if cfg.agent_key and cfg.agent_did:
                    from .signing import sign_bound_proof
                    confirm_identity = sign_bound_proof(cfg.agent_key, agent_id=cfg.agent_id, did=cfg.agent_did, action="confirm", amount=0, scope=decision_id, workspace_id=cfg.workspace_id)
                body = build_confirm_body(cfg, decision_id, reported, confirm_identity)
                ev = _client.post_confirm(self.transport, cfg.api_url, cfg.api_token, body, has_credential=carries_credential(cfg))


                if not ev["report_recorded"]:
                    print(f'[decidio] {decision_id}: {ev.get("diagnostic")}', file=sys.stderr)
                elif not ev["execution_confirmed"] or ev.get("execution_report_verified") is False:
                    print(f'[decidio] execution evidence for {decision_id} recorded as {ev.get("evidence_tier")} - {ev.get("diagnostic")}', file=sys.stderr)
                if evidence_error:
                    print(f"[decidio] {decision_id}: the execution IS recorded, but with an empty captured "
                          f"response - see the evidence note above.", file=sys.stderr)
                if evidence_error:
                    ev = dict(ev)
                    ev["evidence_error"] = evidence_error
                return ev
            except Exception as e:




                print(f"[decidio] confirmation post failed (action succeeded): {e}", file=sys.stderr)
                _retryable = getattr(e, "retryable", True)
                return {"report_recorded": False, "execution_confirmed": False,
                        "confirmation_retryable": bool(_retryable), "report_journalled": False,
                        "evidence_error": evidence_error,
                        "diagnostic": f"your action RAN and Decidio does NOT have its execution report ({e}). "
                                      f"This path journals nothing, so there is no local copy to re-send: record "
                                      f"the outcome from your own system. Durable mode DOES journal reports, and "
                                      f"its recovery path can re-send them - that is the mode to use if this "
                                      f"matters to you. Do NOT re-run the action."}








        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def wrapped_async(*args: Any, **kwargs: Any) -> Any:
                _ctx, decision_id, c_args, c_kwargs, sent_key = await asyncio.to_thread(_gate, *args, **kwargs)




                result = (await fn(ExecutionContext(decision_id=decision_id, attempt_id=None,
                                                    idempotency_key=decision_id), *c_args, **c_kwargs)
                          if with_context else await fn(*c_args, **c_kwargs))
                confirmation = await asyncio.to_thread(_confirm, decision_id, result)
                return ProtectedExecution(value=result, decision_id=decision_id,
                                          confirmation=confirmation or {}, request_key=sent_key)
            return wrapped_async





        @functools.wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            _ctx, decision_id, c_args, c_kwargs, sent_key = _gate(*args, **kwargs)
            result = (fn(ExecutionContext(decision_id=decision_id, attempt_id=None,
                                          idempotency_key=decision_id), *c_args, **c_kwargs)
                      if with_context else fn(*c_args, **c_kwargs))
            if inspect.isawaitable(result):
                result = _complete(result)
            confirmation = _confirm(decision_id, result)
            return ProtectedExecution(value=result, decision_id=decision_id,
                                      confirmation=confirmation or {}, request_key=sent_key)

        return wrapped

    def protect_best_effort(self, fn: Callable[..., Any], describe: Callable[..., ApprovalContext], **opts: Any) -> Callable[..., Any]:
        """DEPRECATED. The 0.1.x shape: returns your function's value alone and DISCARDS what
        Decidio recorded. Kept because a caller who truly does not care should not have to unpack
        a result - but "the report was not recorded" and "the execution could not be attested"
        become invisible again, which is the gap 0.2.0 exists to close. Prefer `protect`.

        Async-aware for the same reason `protect` is: an `async def` must stay awaitable."""
        wrapped = self.protect(fn, describe, **opts)
        if inspect.iscoroutinefunction(wrapped):
            @functools.wraps(fn)
            async def best_effort_async(*a: Any, **k: Any) -> Any:
                return (await wrapped(*a, **k)).value
            return best_effort_async

        @functools.wraps(fn)
        def best_effort(*a: Any, **k: Any) -> Any:
            return wrapped(*a, **k).value
        return best_effort

    def approve(self, describe: Callable[..., ApprovalContext], **opts: Any) -> Callable[..., Any]:
        """Decorator form — `@guard.approve(describe)` directly above the function.

        Python rebinds the decorated name in place at definition time, so unlike the JavaScript
        wrap there is NO rename and NO call-site change: the function keeps its name, its
        signature and its docstring, and every existing caller and tool registration keeps
        working untouched. JS has no equivalent for plain functions, which is the entire reason
        the TypeScript form costs a rename."""
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return self.protect(fn, describe, **opts)
        return decorator



guard = Guard.from_env()


def protect(fn: Callable[..., Any], describe: Callable[..., ApprovalContext], **opts: Any) -> Callable[..., Any]:
    """Module-level convenience over the singleton: `from decidio import protect`."""
    return guard.protect(fn, describe, **opts)


def protect_best_effort(fn: Callable[..., Any], describe: Callable[..., ApprovalContext], **opts: Any) -> Callable[..., Any]:
    """Module-level convenience over the singleton: `from decidio import protect_best_effort`."""
    return guard.protect_best_effort(fn, describe, **opts)


def approve(describe: Callable[..., ApprovalContext], **opts: Any) -> Callable[..., Any]:
    """Module-level decorator over the singleton: `from decidio import approve`."""
    return guard.approve(describe, **opts)
