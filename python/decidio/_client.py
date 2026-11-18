"""Low-level gate transport — the HTTP calls to Decidio's agent floor.

Pluggable `Transport` so the SDK is testable offline (inject a fake) and so a host
can swap in its own HTTP stack. Default uses urllib (stdlib — the core stays
dependency-free). Shared by the gate (authorize) and the resume controller
(status/confirm) so there's one transport contract.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import quote
from typing import Any, Optional, Protocol, Tuple


class Transport(Protocol):
    def request(self, method: str, url: str, headers: dict, body: Optional[str]) -> Tuple[int, str]:
        ...


class UrllibTransport:
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    def request(self, method: str, url: str, headers: dict, body: Optional[str]) -> Tuple[int, str]:
        data = body.encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:  # 4xx/5xx still carry a body
            return e.code, e.read().decode("utf-8")


def _headers(api_token: Optional[str]) -> dict:
    h = {"content-type": "application/json"}
    if api_token:
        h["authorization"] = f"Bearer {api_token}"
    return h


def post(transport: Transport, api_url: str, path: str, body: dict, api_token: Optional[str], has_credential: Optional[bool] = None) -> Any:
    from .signing import assert_safe_transport
    # A signed proof riding the BODY is a credential too (A6, 0.1.12); a caller with a full
    # config passes the carries_credential predicate instead.
    if has_credential is None:
        has_credential = bool(api_token) or bool(isinstance(body, dict) and (body.get("requesterIdentity") or body.get("executionReport")))
    assert_safe_transport(api_url, has_credential)
    status, text = transport.request("POST", api_url.rstrip("/") + path, _headers(api_token), json.dumps(body))
    if not (200 <= status < 300):
        from .errors import DecidioHttpError
        try:
            _body = json.loads(text) if text else None
        except Exception:  # noqa: BLE001 - keep the raw text when it is not JSON
            _body = text
        raise DecidioHttpError(status, path, _body)
    return json.loads(text) if text else {}


def get(transport: Transport, api_url: str, path: str, api_token: Optional[str], has_credential: Optional[bool] = None) -> Any:
    from .signing import assert_safe_transport
    assert_safe_transport(api_url, bool(api_token) if has_credential is None else has_credential)
    status, text = transport.request("GET", api_url.rstrip("/") + path, _headers(api_token), None)
    if not (200 <= status < 300):
        from .errors import DecidioHttpError
        raise DecidioHttpError(status, path)
    return json.loads(text) if text else {}


def post_confirm(transport: Transport, api_url: str, api_token: Optional[str], body: dict, journalled: bool = False, has_credential: Optional[bool] = None) -> dict:
    """POST a PREBUILT confirm request and read what the gate actually recorded.

    The ONE confirm door every path goes through (inline wrap, durable resume, adapters), so
    the evidence rule is applied once rather than remembered three times: transport success is
    not a recorded report, and a recorded report is not necessarily a confirmed execution.
    Returns the EvidenceOutcome dict from evidence.read_confirm_response; raises only on a
    transport/non-2xx failure, which the caller turns into recovery guidance.

    It replaced a `confirm(...)` helper that built its own body: that second door could not
    carry the signed execution report, so whichever caller used it silently reported weaker
    evidence than the others. The body is now built ONCE by evidence.build_confirm_body and
    handed here, and there is no other way to confirm."""
    from .evidence import read_confirm_response

    resp = post(transport, api_url, "/agent/confirm", body, api_token, has_credential=has_credential)
    return read_confirm_response(resp, signed=body.get("requesterIdentity") is not None,
                                 captured=body.get("capturedResponse"), journalled=journalled)


def status_of(transport: Transport, api_url: str, api_token: Optional[str], decision_id: str, has_credential: Optional[bool] = None) -> dict:
    return get(transport, api_url, "/agent/status/" + quote(decision_id, safe=""), api_token, has_credential=has_credential)
