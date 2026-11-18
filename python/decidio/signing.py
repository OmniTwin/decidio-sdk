"""Client-side agent identity (§13 P0-8) — Python parity with @decidio/guard signing.ts.

The agent generates its Ed25519 keypair LOCALLY (the private key never crosses the wire —
`init` registers only the public did:key) and signs a REQUEST-BOUND proof on each authorize:
a detached Ed25519 JWS over canonical({agentId,did,action,amount,scope,nonce,exp}). Decidio's
floor verifies the signature, binds it to the exact request, burns the single-use nonce, and
checks the did against the registry — so the gate PROVES who is calling, not a label.

`cryptography` is a BASE dependency (still lazy-imported here, so an import of this module
cannot fail at load time). It is not optional: without it a signed agent cannot produce a
request-bound proof and can never reach a confirming tier, which is the whole point of the
signing path. canonicalize is byte-identical to apps/api/src/canonical.ts so a proof signed here
verifies there.
"""
from __future__ import annotations

import base64
import re as _re
import json
import time
from typing import Any, Dict, Optional
from uuid import uuid4

from .canonical import canonical_json

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    # preserve leading-zero bytes as '1'
    for byte in b:
        if byte == 0:
            out = "1" + out
        else:
            break
    return out


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def canonicalize(v: Any) -> str:
    """Sorted-key JCS — must match apps/api/src/canonical.ts byte-for-byte.

    ONE implementation, shared with canonical.canonical_json: the digest an execution report
    binds and the bytes a bound proof signs have to be the same function, or the two
    languages drift apart in exactly the place nobody looks."""
    return canonical_json(v)


def generate_keypair() -> Dict[str, str]:
    """Generate a fresh Ed25519 keypair LOCALLY. Returns the public ``did`` (register this)
    and the PKCS8 private key base64 (keep as DECIDIO_AGENT_KEY in the host env)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

    sk = Ed25519PrivateKey.generate()
    raw_pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    did = "did:key:z" + _b58encode(bytes([0xED, 0x01]) + raw_pub)
    pkcs8 = sk.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    return {"did": did, "private_key_base64": base64.b64encode(pkcs8).decode("ascii")}


def sign_bound_proof(
    private_key_base64: str,
    *,
    agent_id: str,
    did: str,
    action: str,
    amount: float,
    scope: Optional[str] = None,
    workspace_id: Optional[str] = None,
    nonce: Optional[str] = None,
    ttl_ms: int = 120_000,
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Sign a request-bound identity proof. The returned dict is sent verbatim as the
    ``requesterIdentity`` field of /agent/authorize."""
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    sk = load_der_private_key(base64.b64decode(private_key_base64), password=None)
    nonce = nonce or uuid4().hex
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    exp = now + ttl_ms
    # OMIT scope/workspaceId when absent (no key) so the canonical bytes match the server + the TS SDK
    # — a key with a null/undefined value would not round-trip identically across languages, and a
    # legacy (no-workspace) proof must stay byte-identical. workspaceId (D-B3.6) binds the proof to the
    # tenant so a captured proof can't be replayed in another workspace; the server's reconstruction
    # (a2a/identity.ts) omits it the same way when absent.
    payload_obj: Dict[str, Any] = {"agentId": agent_id, "did": did, "action": action, "amount": amount, "nonce": nonce, "exp": exp}
    if scope is not None:
        payload_obj["scope"] = scope
    if workspace_id is not None:
        payload_obj["workspaceId"] = workspace_id
    payload_b64 = _b64url(canonicalize(payload_obj).encode("utf-8"))
    # protected header is used verbatim by the server (not re-parsed), so it only needs to be
    # internally consistent; we match the TS shape {"alg":"EdDSA","kid":did}.
    protected_b64 = _b64url(json.dumps({"alg": "EdDSA", "kid": did}, separators=(",", ":")).encode("utf-8"))
    sig = sk.sign((protected_b64 + "." + payload_b64).encode("ascii"))
    out: Dict[str, Any] = {"agentId": agent_id, "did": did, "action": action, "amount": amount, "nonce": nonce, "exp": exp, "proof": {"protected": protected_b64, "signature": _b64url(sig)}}
    if scope is not None:
        out["scope"] = scope
    if workspace_id is not None:
        out["workspaceId"] = workspace_id
    return out


def assert_json_safe(value, path: str = "args") -> None:
    """Refuse values that do not survive JSON with their meaning intact, BEFORE anything is
    routed, signed, or parked (NaN canonicalized to null and a Map to {} in the
    TS SDK, so the integrity signature matched the drifted bytes and the function EXECUTED with
    arguments that meant something else). Python's own drift shapes are refused too: a tuple
    silently becomes a list, a non-string dict key becomes a string, and json.dumps writes
    NaN/Infinity as literals that are not valid JSON at all. The supported data model is plain
    JSON: None, bool, str, finite int/float, list, dict with string keys. Raises ValueError
    naming the offending path; the decision is NOT routed."""
    import math

    seen: set = set()

    def walk(v, p):
        if v is None or isinstance(v, (bool, str)):
            return
        if isinstance(v, float):
            if not math.isfinite(v):
                raise ValueError(f"[decidio] {p} is {v!r} - a non-finite number does not survive JSON, so what a human approves would not be what executes. The decision was NOT routed; pass a finite number or a string.")
            return
        if isinstance(v, int):
            return
        if isinstance(v, tuple):
            raise ValueError(f"[decidio] {p} is a tuple - JSON silently turns it into a list, so what a human approves would not be what executes. The decision was NOT routed; pass a list.")
        if isinstance(v, (set, frozenset)):
            raise ValueError(f"[decidio] {p} is a {type(v).__name__} - it cannot be serialized for approval. The decision was NOT routed; pass a list.")
        if isinstance(v, (bytes, bytearray)):
            raise ValueError(f"[decidio] {p} is {type(v).__name__} - it cannot be serialized for approval. The decision was NOT routed; encode it as a string first.")
        if isinstance(v, list):
            vid = id(v)
            if vid in seen:
                raise ValueError(f"[decidio] {p} is part of a circular structure - it cannot be serialized for approval. The decision was NOT routed.")
            seen.add(vid)
            for i, x in enumerate(v):
                walk(x, f"{p}[{i}]")
            seen.discard(vid)
            return
        if isinstance(v, dict):
            vid = id(v)
            if vid in seen:
                raise ValueError(f"[decidio] {p} is part of a circular structure - it cannot be serialized for approval. The decision was NOT routed.")
            seen.add(vid)
            for k, x in v.items():
                if not isinstance(k, str):
                    raise ValueError(f"[decidio] {p} has a non-string key {k!r} - JSON silently coerces it to a string, so what a human approves would not be what executes. The decision was NOT routed; use string keys.")
                walk(x, f"{p}.{k}")
            seen.discard(vid)
            return
        raise ValueError(f"[decidio] {p} is a {type(v).__name__} - only plain JSON values survive serialization with their meaning intact. The decision was NOT routed; convert it to plain JSON first.")

    walk(value, path)


# ---- execution report (agent-attested) ---------------------------------------------------
# A signed, DOMAIN-SEPARATED, versioned attestation that THIS agent reported THIS captured
# response for THIS decision. Distinct from the identity proof (sign_bound_proof) in every
# field that matters, so a report can never be lifted from one decision onto another: the
# decision id, the workspace, the agent's did, the source, the response digest, the digest
# algorithm, the canonicalization version, a nonce and an expiry are ALL inside the signed
# bytes.
#
# HONEST SCOPE - say it out loud rather than let a reader assume more: this proves integrity
# and agent attribution of the REPORT. It does not prove the downstream system committed
# anything; only the source system can attest that, and the gate's evidence tier is what
# records how strong that attestation is.
#
# The envelope is byte-identical to signExecutionReport() in the TS SDK: same canonical JSON
# (canonical.canonical_json), same protected header, same base64url-without-padding. A report
# signed here verifies with verifyExecutionReport() there, and vice versa.


def result_digest(canonical_value: Any) -> str:
    """sha-256 hex over the canonical JSON of an already-canonical value - the digest an
    ExecutionReport binds. Both languages produce identical bytes for identical values."""
    import hashlib

    return hashlib.sha256(canonical_json(canonical_value).encode("utf-8")).hexdigest()


def sign_execution_report(
    private_key_base64: str,
    *,
    decision_id: str,
    agent_id: str,
    did: str,
    workspace_id: Optional[str] = None,
    source: str,
    result_digest: str,
    ttl_ms: int = 300_000,
    now_ms: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Sign an ExecutionReport for ``decision_id`` over ``result_digest``."""
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    sk = load_der_private_key(base64.b64decode(private_key_base64), password=None)
    nonce = nonce or str(uuid4())
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    body: Dict[str, Any] = {
        "v": 1,
        "purpose": "decidio.execution-report",
        "decisionId": decision_id,
        "agentId": agent_id,
        "did": did,
    }
    # OMIT workspaceId when absent so the canonical bytes match the TS SDK and the server - a
    # key with a null value would not round-trip identically across languages.
    if workspace_id is not None:
        body["workspaceId"] = workspace_id
    body["source"] = source
    body["resultDigest"] = result_digest
    body["digestAlg"] = "sha-256"
    body["canonicalization"] = "decidio-jcs-1"
    body["nonce"] = nonce
    body["exp"] = now + ttl_ms
    payload_b64 = _b64url(canonical_json(body).encode("utf-8"))
    protected_b64 = _b64url(json.dumps({"alg": "EdDSA", "kid": did, "typ": "decidio-execution-report+jws"}, separators=(",", ":")).encode("utf-8"))
    sig = sk.sign((protected_b64 + "." + payload_b64).encode("ascii"))
    return {**body, "proof": {"protected": protected_b64, "signature": _b64url(sig)}}


def _b58decode(s: str) -> bytes:
    """base58btc decode for did:key - local so this module stays dependency-light."""
    num = 0
    for ch in s:
        idx = _B58.find(ch)
        if idx < 0:
            raise ValueError("bad base58 character")
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading = 0
    for ch in s:
        if ch == _B58[0]:
            leading += 1
        else:
            break
    return b"\x00" * leading + body


def verify_execution_report(
    report: Any,
    decision_id: str,
    did: Optional[str] = None,
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Verify an ExecutionReport LOCALLY - the same rules the server applies before
    persisting it. Returns {"valid": bool, "reason"?: str}: WHY it failed, never a bare
    False, so a caller can say something useful."""
    r = report if isinstance(report, dict) else None
    if not r or r.get("purpose") != "decidio.execution-report" or r.get("v") != 1:
        return {"valid": False, "reason": "not a v1 decidio execution report"}
    if r.get("decisionId") != decision_id:
        return {"valid": False, "reason": "report is bound to a DIFFERENT decision"}
    if did and r.get("did") != did:
        return {"valid": False, "reason": "report was signed by a different agent key"}
    exp = r.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return {"valid": False, "reason": "report expired"}
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    if now > exp:
        return {"valid": False, "reason": "report expired"}
    if r.get("digestAlg") != "sha-256" or r.get("canonicalization") != "decidio-jcs-1":
        return {"valid": False, "reason": "unsupported digest/canonicalization"}
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        proof = r.get("proof") or {}
        body = {k: v for k, v in r.items() if k != "proof"}
        payload_b64 = _b64url(canonical_json(body).encode("utf-8"))
        issuer = str(r.get("did") or "")
        if not issuer.startswith("did:key:z"):
            return {"valid": False, "reason": "issuer did is not a did:key"}
        mc = _b58decode(issuer[len("did:key:z"):])
        if len(mc) < 3 or mc[0] != 0xED or mc[1] != 0x01:
            return {"valid": False, "reason": "issuer did is not Ed25519"}
        pub = Ed25519PublicKey.from_public_bytes(bytes(mc[2:]))
        sig_b64 = str(proof.get("signature", ""))
        sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        pub.verify(sig, (str(proof.get("protected", "")) + "." + payload_b64).encode("ascii"))
        return {"valid": True}
    except Exception as e:  # noqa: BLE001 - any verification error is a refusal, with the reason
        # str(InvalidSignature()) is EMPTY and the exception object is still truthy, so `e or
        # type(e)` printed "( )" - the reason has to name the class when the message is blank.
        return {"valid": False, "reason": f"signature does not verify against the agent did ({str(e) or type(e).__name__})"}


def _redact_url(u: str) -> str:
    """The URL as it may be ECHOED in a refusal: userinfo masked - every branch of assert_safe_transport
    echoes through this, never the raw string. Covers the OPAQUE spelling too (`https:user:secret@`, no
    `//`), which used to be echoed verbatim (prodsec V035-04; TS twin redactUrl)."""
    # Both rules run to the LAST `@` before a delimiter (`user@h:secret@x` is ONE userinfo to a parser), and
    # the opaque rule skips the leading slashes of a one-slash typo (`https:/u:secret@h`) - TS twin.
    u = _re.sub(r"//[^/?#]*@", "//***@", u)                              # `//userinfo@` wherever it sits
    return _re.sub(r"^([^/?#@:]*:)(?!//)[/\\]*[^/?#]*@", r"\1***@", u)   # the opaque `scheme:userinfo@`


# Unicode SPACE and FORMAT characters a URL must never contain - the same explicit list as the TS twin, so
# the two runtimes cannot drift with a library's notion of whitespace (urlsplit strips a leading NBSP;
# WHATWG does not; prodsec V035-04).
_URL_UNICODE_SPACE = _re.compile("[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\u200b-\u200d\u2060]")


def assert_safe_transport(url: str, has_credential: bool) -> None:
    """The wire rule: a credentialed request must never ride plaintext http to a remote host -
    the rule is about the WIRE, not which credential. localhost/127.0.0.1/[::1] stay allowed for
    local dev; https always allowed. Raises before anything is sent.

    Parsed with the SAME parser the transport uses (A6, 0.1.12): urlsplit(unwrap(url)) is
    exactly what urllib.request.Request.full_url applies, and urlsplit additionally strips
    embedded tab/CR/LF - strictly fail-closed relative to urllib. A raw-string regex checked a
    different URL grammar, so spellings that normalize to remote plaintext http:// passed it."""
    from urllib.parse import unwrap, urlsplit
    # NO CONTROL CHARACTER OR WHITESPACE, ANYWHERE, FIRST (prodsec V033-01; see the TypeScript twin):
    # what is SENT must equal what was CHECKED, and a spelling that needs normalizing to be read is
    # not one this gate can vouch for. Refused as written.
    if not isinstance(url, str):
        raise RuntimeError(f"[decidio] the gate URL is {type(url).__name__}, not a string, so there is no host to send to. Decidio needs a full https URL (or http://localhost for local dev). Nothing was sent.")
    for _ch in url:
        _cp = ord(_ch)
        if _cp <= 0x20 or 0x7F <= _cp <= 0x9F or _cp == 0xFEFF or _URL_UNICODE_SPACE.match(_ch):
            # Echo a REDACTED spelling: this check runs before the userinfo rule (TS twin).
            _shown = _re.sub(r"//[^/@]*@", "//***@", url)
            raise RuntimeError(f"[decidio] the gate URL {_redact_url(url)!r} contains whitespace or a control character (U+{_cp:04X}) - a validator and a transport can read such a spelling differently, so it is refused as written. Remove it. Nothing was sent.")
    # ALWAYS PARSE. `if not has_credential: return` asked the credential question too narrowly: a
    # URL spelled http://user:pass@remote/ carries a credential IN ITSELF, so "no separate api
    # token" meant the one case where the URL is the secret went completely unchecked. It also let
    # ftp://, a bare hostname and a relative path through - none of which can ever reach Decidio.
    # PARSE FIRST, ALWAYS (F-005). `has_credential` describes the CONFIG, not the URL, so gating
    # the parse on it asked the wrong question: with no bearer and no signing key, ftp://, a bare
    # hostname and a relative path all reached a custom transport unexamined. None of them can ever
    # be a Decidio endpoint, so the honest answer is the same either way. What the credential DOES
    # decide is only the WORDING of the plaintext-http refusal, which is about disclosure.
    # An http-SPELLED string the parser does not recognize AS http is still dangerous, because
    # the guard sees `api_url` while the transport is handed `api_url + the request path`:
    # "http://" + "/agent/authorize" becomes the remote origin http://agent. Normalize the way
    # the parsers do (TAB/CR/LF anywhere, then leading whitespace/C0/U+0085/BOM) so this door
    # and the TypeScript one give byte-identical answers on every spelling.
    _spelled = url.replace("\t", "").replace("\r", "").replace("\n", "")
    _lead = 0
    while _lead < len(_spelled) and (ord(_spelled[_lead]) <= 0x20 or ord(_spelled[_lead]) in (0x85, 0xFEFF)):
        _lead += 1
    _http_spelled = _spelled[_lead:_lead + 5].lower() == "http:"
    try:
        u = urlsplit(unwrap(url))
        hostname = u.hostname  # can raise ValueError on an invalid IPv6 authority
    except ValueError:
        if _http_spelled:
            _what = "send credentials" if has_credential else "send a request"
            raise RuntimeError(f"[decidio] refusing to {_what} over plaintext http to {_redact_url(url)!r} - that is not a complete absolute URL, so where the request would actually connect is undefined (the path is appended to it, which can turn it into a remote host). Set a full https URL, or http://localhost for local dev. Nothing was sent.") from None
        # A PARSE FAILURE IS A REFUSAL, whatever the spelling (prodsec V030-04). This used to
        # `return` for anything not http-spelled, so `https://[` - which raises ValueError on the
        # invalid IPv6 authority - sailed through to a custom transport CARRYING THE BEARER, while
        # the TypeScript twin refused it. A string this parser cannot read is not a string this
        # gate can vouch for, and "the shipped transport would refuse it anyway" is the exact
        # reasoning F-005 retired: fetch/transport is a documented extension point.
        raise RuntimeError(f"[decidio] the gate URL {_redact_url(url)!r} is not an absolute URL this parser can read, so there is no host to send to - where a request would actually connect depends entirely on whichever transport resolves it. Decidio needs a full https URL (or http://localhost for local dev). Nothing was sent.") from None
    _scheme = u.scheme.lower()
    # A RELATIVE OR SCHEME-LESS STRING IS NOT SAFE JUST BECAUSE THE SHIPPED TRANSPORT REFUSES IT -
    # see the TypeScript twin. urlsplit does not raise on a relative URL, it just returns an empty
    # scheme, so this is where Python has to say it.
    if not _scheme:
        raise RuntimeError(f"[decidio] the gate URL {_redact_url(url)!r} is not an absolute URL, so there is no host to send to - where a request would actually connect depends entirely on whichever transport resolves it. Decidio needs a full https URL (or http://localhost for local dev). Nothing was sent.")
    # Only https and http are ever a Decidio endpoint. Anything else (ftp:, file:, a custom
    # scheme) can never reach the gate, so it is a misconfiguration worth naming rather than a
    # request worth attempting.
    if _scheme and _scheme not in ("http", "https"):
        raise RuntimeError(
            f"[decidio] the gate URL uses the {_scheme} scheme, which is not a Decidio endpoint - "
            f"use https (or http://localhost for local dev). Nothing was sent.")
    # A credential in the URL is a credential, whatever the scheme.
    if u.username or u.password:
        raise RuntimeError(
            f"[decidio] the gate URL carries credentials in the URL itself ({_scheme}://user:***@{u.hostname}). "
            f"Decidio authenticates with a bearer token; remove the user:password from the URL. Nothing was sent.")
    # A HOST IS REQUIRED, AND IT MUST LOOK LIKE ONE (prodsec V030-04). urlsplit parses VERBATIM -
    # it never grows missing slashes or splits at a backslash the way WHATWG does - so the
    # divergent spellings the TypeScript gate closes with its origin-prefix rule surface here as a
    # missing or malformed hostname instead: `https:///path` and `https:trusted.example` both parse
    # with an EMPTY netloc, and `https://%` / a backslash authority parse with junk in the
    # hostname. Two rules give this door the same verdicts as the TS one on every shared vector:
    # the host must be present, and its characters must be ones a hostname can contain (letters,
    # digits, dot, dash, underscore, tilde - or an IPv6 literal, which urlsplit already validated).
    # PARITY NOTE: no prefix rule here on purpose; verbatim parsing means the raw string IS what
    # was validated, which is the property the TS rule exists to recover.
    if not hostname:
        raise RuntimeError(f"[decidio] the gate URL {_redact_url(url)!r} has no host - there is nowhere for the request to go. Decidio needs a full https URL (or http://localhost for local dev). Nothing was sent.")
    _host_l = hostname.lower()
    if ":" not in _host_l and not _re.fullmatch(r"[a-z0-9._~-]+", _host_l):
        raise RuntimeError(f"[decidio] the gate URL {_redact_url(url)!r} does not name a valid host - its authority contains characters no hostname can ({_host_l!r}), so different parsers can read it as different destinations. Write the canonical https URL. Nothing was sent.")
    if _scheme != "http":
        if _http_spelled:
            _what = "send credentials" if has_credential else "send a request"
            raise RuntimeError(f"[decidio] refusing to {_what} over plaintext http to {_redact_url(url)!r} - that is not a complete absolute URL, so where the request would actually connect is undefined (the path is appended to it, which can turn it into a remote host). Set a full https URL, or http://localhost for local dev. Nothing was sent.")
        return
    host = (hostname or "").lower()
    local = host in ("localhost", "127.0.0.1", "::1")
    if local:
        return   # userinfo already refused above, for every scheme
    # Say the TRUE reason for each case. "Refusing to send credentials" is false when there are
    # none - and the request is still refused, because remote plaintext is not a Decidio endpoint
    # and the reply carries an authority decision nobody can vouch for.
    if has_credential:
        raise RuntimeError(f"[decidio] refusing to send credentials over plaintext http to {u.scheme}://{u.netloc} - use https, or localhost for local dev. Nothing was sent.")
    raise RuntimeError(f"[decidio] refusing to talk to {u.scheme}://{u.netloc} over plaintext http - Decidio is https, and an unauthenticated plaintext reply cannot be trusted to carry an authority decision. Use https, or localhost for local dev. Nothing was sent.")


def carries_credential(cfg: Any) -> bool:
    """The ONE answer to "does this request carry a credential worth protecting?" (A6, 0.1.12).
    A signed identity proof is a credential too: sending it over remote plaintext disclosed
    request context and replay/front-run material even with no bearer configured."""
    return bool(getattr(cfg, "api_token", None)) or bool(getattr(cfg, "agent_key", None) and getattr(cfg, "agent_did", None))


# ---- request binding (0.7.0) --------------------------------------------------------------------
# An approval is for ONE exact request. Before 0.7.0 nothing tied the two together: every engine door
# executed on a resume signal that said "approved" and named (at most) a decision, and LangGraph re-ran
# the interrupted node on resume, so an approval was applied to whatever the node computed the second
# time. The fix is a COMMITMENT to the exact canonical request, sent with /agent/authorize, stored with
# the decision, returned by /agent/status, and recomputed by the SDK over the request it is about to run.
#
# KEYED, NEVER A PLAIN DIGEST: a sha256 over the request would sit in Decidio's database as a
# dictionary-attackable fingerprint of the request content (invariant I5). The commitment is an HMAC
# under a key only the AGENT holds - derived from its Ed25519 signing key when signing is configured,
# else from its API token. Byte-identical to the TypeScript twin (signing.ts; the shared vectors are
# packages/conformance/vectors/canonical.json `commitments`).


def binding_material(agent_key: Optional[str] = None, agent_did: Optional[str] = None,
                     api_token: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """The key material this configuration binds approvals with: the Ed25519 signing key when signing is
    configured (agent_key AND agent_did - the identity proof's predicate), else the API token, else None.
    Raises on a signing key that cannot be read (the identity proof refuses the same key)."""
    if agent_key and agent_did:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_der_private_key
            sk = load_der_private_key(base64.b64decode(agent_key), password=None)
        except Exception as e:  # noqa: BLE001 - named, never swallowed
            raise ValueError(f"[decidio] DECIDIO_AGENT_KEY is not a readable private key (PKCS8, base64): {e}. It binds this "
                             f"agent's approvals to their requests; restore the key `init` wrote, or unset "
                             f"DECIDIO_AGENT_KEY/DECIDIO_AGENT_DID. Nothing was sent or executed.") from None
        if not isinstance(sk, Ed25519PrivateKey):
            raise ValueError("[decidio] DECIDIO_AGENT_KEY is not an Ed25519 private key. Restore the key `init` wrote. "
                             "Nothing was sent or executed.")
        return {"kind": "ed25519", "secret": sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())}
    if api_token:
        return {"kind": "api-token", "secret": api_token.encode("utf-8")}
    return None


def binding_material_of(cfg: Any) -> Optional[Dict[str, Any]]:
    """binding_material() over any config/controller carrying agent_key / agent_did / api_token."""
    return binding_material(getattr(cfg, "agent_key", None), getattr(cfg, "agent_did", None), getattr(cfg, "api_token", None))


def _binding_subkey(material: Dict[str, Any], label: str) -> bytes:
    import hashlib
    import hmac as _hmac
    return _hmac.new(material["secret"], f"{label}/{material['kind']}".encode("utf-8"), hashlib.sha256).digest()


def committed_request_json(request: Dict[str, Any]) -> str:
    """The canonical bytes a commitment covers: {action, amount, scope?, context?, args?, kwargs?} with
    optional members OMITTED when absent or None, so both languages hash the same bytes."""
    r: Dict[str, Any] = {"action": request.get("action"), "amount": request.get("amount")}
    for k in ("scope", "context", "args", "kwargs"):
        if request.get(k) is not None:
            r[k] = request[k]
    return canonical_json(r)


def request_commitment(material: Dict[str, Any], request: Dict[str, Any]) -> str:
    """lowercase-hex HMAC-SHA256 over the canonical request, under the agent-held key."""
    import hashlib
    import hmac as _hmac
    return _hmac.new(_binding_subkey(material, "decidio.request-commitment.v1"),
                     committed_request_json(request).encode("utf-8"), hashlib.sha256).hexdigest()


def idempotency_key(material: Dict[str, Any], identity: Dict[str, Any]) -> str:
    """lowercase-hex idempotency key over an execution identity (e.g. LangGraph's thread + task +
    commitment), keyed so the host's thread ids never reach Decidio in the clear."""
    import hashlib
    import hmac as _hmac
    return _hmac.new(_binding_subkey(material, "decidio.idempotency-key.v1"),
                     canonical_json(identity).encode("utf-8"), hashlib.sha256).hexdigest()


def invocation_request_key(material: Dict[str, Any], invocation_id: str, commitment: str) -> str:
    """THE REQUEST KEY A CALL SENDS BY DEFAULT (11f, founder 2026-10-30): an idempotency key over a per-call random id and
    the request's commitment, so the SDK's own retry of one call is the same request (the gate answers the decision it
    already made) while two calls stay two requests. TS twin: invocationRequestKey."""
    return idempotency_key(material, {"invocation": invocation_id, "commitment": commitment})


def own_request_key(material: Dict[str, Any], key: str) -> str:
    """A CALLER'S OWN REQUEST KEY (11f), e.g. an order id: keyed like every other identity, so the caller's id never reaches
    Decidio in the clear. Deliberately NOT over the commitment: the same key for a changed request is the gate's 409
    IDEMPOTENCY_CONFLICT, never a silent second request. TS twin: ownRequestKey."""
    return idempotency_key(material, {"requestKey": key})
