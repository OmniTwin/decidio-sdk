"""Standalone open verifier (Python) — parity with @decidio/verify (TS).

Verifies a Decidio Authority Receipt OFFLINE, using only the public DID embedded in it. No
network, no DID resolver, no context fetching, no Decidio dependency. Needs `cryptography`
for Ed25519 — a BASE dependency, so a bare `pip install decidio` never ships a
product whose advertised built-in verifier crashed (the [verify] extra remains as an alias so
documented installs keep working).

    python -m decidio.verify [--issuer <did:key>] receipt.json [more.json ...]

THE RECEIPT FORMAT is a W3C Verifiable Credential secured with a `DataIntegrityProof` using the
`eddsa-jcs-2022` cryptosuite (Data Integrity EdDSA Cryptosuites v1.0 — W3C Recommendation,
15 May 2025). Verifying it needs only SHA-256, Ed25519, base58 and RFC 8785 canonicalisation.

WHAT THIS CHECKS, in this order (the order matters only for WHICH reason you get back, but that
reason is what an auditor reads, so it is pinned to the TS verifier's order deliberately):
  1. issuer — the DID is a did:key Ed25519 and, when you pin one, is the issuer you expected.
     A valid signature by SOME key is not proof of WHO issued it, so pinning is the real check.
  2. content binding (Decidio-specific, in ADDITION to the standard proof) — re-derive
     sha256((prevHash or "") + recordCanonical) and require it to equal the receipt's
     contentHash. The standard signature already covers the whole document; this proves the
     document's contentHash is genuinely derivable from the canonical payload shipped beside it.
     It has its own failure reason because "the content was changed" and "the signature is
     broken" are different findings for whoever is holding the receipt.
  3. signature — the standard eddsa-jcs-2022 proof over the whole document AND the proof options.
Chain ordering is checked by verify_chain(). Revocation/status needs the network and is out of
scope by design: a receipt is tamper-evidence, not a liveness check.

WHY THIS FILE IS A DELIBERATE MIRROR of packages/decidio-verify/verify.ts, rule for rule: a
cross-language conformance gate asserts both CLIs accept the same signed receipt. If they ever
disagree, an auditor gets two different answers about the same record and "verify it yourself,
in your own language" stops being true. Every place where Python's defaults would have diverged
from JavaScript's is called out below as a PARITY note. RFC 8785 canonicalisation is NOT
re-implemented here — it is `decidio.jcs`, which is diffed byte-for-byte against the TypeScript
signer's canonicaliser by jcs_smoke.py.

CROSS-LANGUAGE PARITY, and how it was earned. Running both verifiers over a 79-case adversarial
corpus found three cases where TypeScript ACCEPTED what this file REFUSED — and Python was right in
all three. **All three are now CLOSED on the TypeScript side (2026-08-04), in the same change that
introduced this file**, so the corpus is kept as a description of what the checks below are FOR, not
as a list of open holes:
  1. proofValue as a one-element ARRAY. TS coerced it with `String(...)`; both sides now require a
     string. proofValue is the only proof field outside the signed bytes, so accepting a coerced form
     was receipt malleability: two byte-different files, one signature, both VALID.
  2. prevHash as a JSON array/object whose contentHash was derived from JavaScript's stringification
     of it ("1,2", "[object Object]"). Both sides now type-check it. See _prev_hash_prefix.
  3. any number in the document beyond 2^53. JS's JSON.parse silently rounds it, so TS verified a
     hand-edited file whose displayed number differed from the SIGNED one — tamper-blind. Both sides
     now refuse. (This is jcs.py's PY-TRAP 8; Decidio receipts carry no numeric fields at all.)
  4. an extra entry appended to the document's @context. The REC leaves DOCUMENT @context entries
     unsigned, so appending one to a genuine receipt kept it VALID. All three verifiers now require
     the document's @context to EQUAL the proof's — stricter than the REC, and safe because the
     issuer always copies it across unchanged.
"""
from __future__ import annotations

import hashlib
import json
import re as _re_mod
import sys
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .jcs import jcs_bytes

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# The one suite we accept. `eddsa-2022` — the name Decidio's pre-2026-08-04 test receipts carry —
# is NOT a suite the Recommendation defines (it was a pre-REC working-draft name) and is reported
# separately below so an obsolete receipt is never misreported as a tampered one.
CRYPTOSUITE = "eddsa-jcs-2022"
_LEGACY_CRYPTOSUITE = "eddsa-2022"
# XSD dateTimeStamp - the shape Data Integrity requires of `proof.created`. BYTE-IDENTICAL to the
# TypeScript twin's XSD_DATE_TIME_STAMP, because a shape both languages can check exactly is the
# only kind of rule that cannot drift.
# `\Z`, NOT `$` (invariant-guard, 0.3.5): in Python `$` also matches before a trailing newline, so a signed
# `created` of "2026-01-01T00:00:00Z\n" read as a valid timestamp here while both TS doors refused it - a
# three-door divergence on the exact field these checks tighten. `\Z` is the true end of the string.
# re.ASCII, because Python's `\d` matches every Unicode decimal digit (Arabic-Indic, Devanagari, full-width)
# and int() accepts them too, while the TS twins' `\d` is ASCII-only - a three-door divergence on this very
# field (invariant-guard, 0.3.5). With ASCII the two spellings mean the same thing.
_XSD_DATE_TIME_STAMP = _re_mod.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})\Z", _re_mod.ASCII)
_XSD_FIELDS = _re_mod.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|([+-])(\d{2}):(\d{2}))\Z", _re_mod.ASCII)


def _is_calendrical_date_time_stamp(s: str) -> bool:
    """XSD dateTimeStamp, CALENDRICALLY (prodsec V033-04): the regex holds the shape, this holds the
    fields - month 1-12, a real day for that month and year, hour 0-23, minute 0-59, second 0-59, an
    offset within -14:00..+14:00. Spelled the same way in all three verifiers; no datetime construction
    (its leniency differs by runtime)."""
    m = _XSD_FIELDS.match(s)
    if not m:
        return False
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    if y < 1 or mo < 1 or mo > 12 or d < 1 or h > 23 or mi > 59 or se > 59:
        return False
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    dim = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    if d > dim:
        return False
    if m.group(8) != "Z":
        oh, om = int(m.group(10)), int(m.group(11))
        if oh > 14 or om > 59 or (oh == 14 and om != 0):
            return False
    return True


def _b58decode(s: str) -> bytes:
    out = [0]
    for ch in s:
        val = _B58.find(ch)
        if val < 0:
            raise ValueError("invalid base58")
        carry = val
        for i in range(len(out)):
            carry += out[i] * 58
            out[i] = carry & 0xFF
            carry >>= 8
        while carry:
            out.append(carry & 0xFF)
            carry >>= 8
    for ch in s:
        if ch == _B58[0]:
            out.append(0)
        else:
            break
    return bytes(reversed(out))


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _prev_hash_prefix(prev: Optional[str]) -> str:
    """Content-binding prefix. Contract is `prevHash: string | null` — callers must type-check
    before this. Matches TS `sha256((prevHash ?? "") + canonical)` for the in-contract cases."""
    return "" if prev is None else prev


def _derive_hash(canonical: str, prev: Optional[str]) -> str:
    return _sha256(_prev_hash_prefix(prev) + canonical)


def _field(obj: Any, key: str) -> Any:
    """PARITY: TS reads `vc?.issuer` — optional chaining yields undefined for a non-object instead
    of throwing. `obj.get(...)` on a non-dict would raise and surface an exception message as the
    reason, so a receipt that is not a JSON object lands on the same reason as in TS."""
    return obj.get(key) if isinstance(obj, dict) else None


def _hash_data(unsecured_document: Dict[str, Any], proof_config: Dict[str, Any]) -> bytes:
    """Data Integrity §3.3.4 — the 64-byte signing input: SHA-256 of the canonical proof config,
    then SHA-256 of the canonical document. CONFIG FIRST; the order is normative. The 64 bytes are
    signed directly (Ed25519 hashes internally — they are not hashed again)."""
    return (
        hashlib.sha256(jcs_bytes(proof_config)).digest()
        + hashlib.sha256(jcs_bytes(unsecured_document)).digest()
    )


def _as_context_list(value: Any) -> List[Any]:
    """PARITY: TS uses `[].concat(v)`, which wraps a scalar and flattens an array by exactly one
    level — including `[].concat(undefined) === [undefined]`, so a document with NO @context still
    produces a one-element list and fails the prefix check rather than passing vacuously."""
    return list(value) if isinstance(value, list) else [value]


def _same_context_entry(proof_entry: Any, doc_entry: Any) -> bool:
    """PARITY, and the subtlest one in this file. TS compares @context entries with `!==`, which is
    REFERENCE equality for objects/arrays. Two structurally-identical objects parsed out of the same
    JSON text are never the same reference, so the TS verifier rejects ANY non-scalar @context entry
    in a receipt read from a file — which is every receipt either CLI is ever handed. Python's `==`
    is structural and would ACCEPT those, i.e. the two languages would disagree on accept/reject.
    We therefore refuse non-scalar entries, matching TS's observable behaviour on the JSON path.
    (Decidio's issuer only ever emits string entries, so nothing real is refused by this.)
    The bool/int guard is a second Python-only trap: JS says `1 !== true`, Python says `1 == True`.
    """
    if isinstance(proof_entry, (dict, list)) or isinstance(doc_entry, (dict, list)):
        return False
    if isinstance(proof_entry, bool) != isinstance(doc_entry, bool):
        return False
    return bool(proof_entry == doc_entry)


def read_record_kind(record_canonical: str) -> Optional[str]:
    """The record kind sealed into the canonical record (approval / denial / decision), or None. Read from the
    receipt's own bytes, never fetched (TS twin readRecordKind)."""
    try:
        p = json.loads(record_canonical)
    except Exception:  # noqa: BLE001 - not JSON: no kind to read
        return None
    kind = p.get("recordKind") if isinstance(p, dict) else None
    return kind if isinstance(kind, str) else None


def read_sealed_state(record_canonical: str) -> Optional[Dict[str, Any]]:
    """Read the decision-state fields back out of the sealed canonical payload.

    The twin of `readSealedState` in the TS verifier, down to the key names, because this module's
    doctrine is that an auditor comparing the two languages must not see them disagree.

    A receipt for an approved, executed action can still read ``result: routed_to_human`` with
    ``confirmation: pending``: confirmation lands AFTER the seal and a sealed record is immutable,
    so it is never written back. That is correct behaviour, not staleness — but "VALID" reads as
    "approved and executed" unless the boundary is stated, so these fields are surfaced rather than
    left in the JSON for the reader to infer.

    FAILS SOFT BY DESIGN. This is a reporting aid, never a verification input: `recordCanonical` is
    content-bound against `contentHash` before this is called, so nothing here can change a verdict.
    An unparseable payload, or one of a kind carrying no authority block, reports nothing rather
    than degrading a VALID receipt over a display concern.
    """
    try:
        p = json.loads(record_canonical)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(p, dict):
        return None
    authority = p.get("authority") if isinstance(p.get("authority"), dict) else None
    confirmation = p.get("confirmation") if isinstance(p.get("confirmation"), dict) else None
    s: Dict[str, Any] = {}
    if authority is not None and (isinstance(authority.get("result"), str) or authority.get("result") is None):
        s["result"] = authority.get("result")
    if confirmation is not None and (isinstance(confirmation.get("status"), str) or confirmation.get("status") is None):
        s["confirmation"] = confirmation.get("status")
    if "ratifiedBy" in p:
        s["ratified"] = p.get("ratifiedBy") is not None
    nominated = p.get("nominatedDeciders", p.get("deciders"))   # schemaVersion 2 name, then the v1 name
    if isinstance(nominated, list):
        s["nominated_deciders"] = len(nominated)
    return s or None


def verify_receipt(vc: Dict[str, Any], expected_issuer: Optional[str] = None) -> Dict[str, Any]:
    # AN EXPLICIT EMPTY PIN IS AN ERROR, NOT "UNPINNED" - twin of the TS guard. expected_issuer was
    # tested for truthiness, so verify_receipt(vc, "") silently ran an UNPINNED check and returned
    # valid, and "" is exactly what an unset environment variable interpolates to. Omission (None)
    # still means deliberately unpinned; a supplied-but-blank pin is refused.
    if expected_issuer is not None and expected_issuer.strip() == "":
        return {"valid": False, "issuer": str(vc.get("issuer") or ""), "content_bound": False, "record_id": None,
                "reason": 'an empty --issuer/expected_issuer was supplied - that is not an unpinned check, it is a '
                          'missing pin (an unset environment variable interpolates to ""). Omit the argument entirely '
                          'to verify unpinned on purpose.'}
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as e:  # pre-base-dependency installs only (cryptography ships with decidio now)
        # Belt and braces for old installs: a raw ModuleNotFoundError traceback here reads as a
        # crash in the product's advertised built-in verifier. One clean line naming the exact
        # fix — and OUTSIDE the guard below, so a broken environment is never dressed as an
        # INVALID verdict.
        raise ImportError("verifying needs the `cryptography` package — it ships with decidio now; upgrade or reinstall: pip install --upgrade decidio") from e

    try:
        issuer_raw = _field(vc, "issuer")
        did = "" if issuer_raw is None else str(issuer_raw)
        if not did.startswith("did:key:z"):
            return {"valid": False, "issuer": did, "content_bound": False, "reason": "unsupported issuer DID (expected did:key Ed25519)"}
        if expected_issuer and did != expected_issuer:
            # Issuer-pin failure must not throw away what was learned (parity
            # with the TS verifier): report the record id and the true content-binding result so
            # a wrong pin doesn't read as content tampering.
            cs0 = _field(vc, "credentialSubject") or {}
            rc0 = _field(cs0, "recordCanonical")
            ch0 = _field(cs0, "contentHash")
            ph0 = _field(cs0, "prevHash")
            bound0 = isinstance(rc0, str) and isinstance(ch0, str) and _derive_hash(rc0, ph0 if isinstance(ph0, str) else None) == ch0
            rid0 = _field(cs0, "recordId")
            return {"valid": False, "issuer": did, "content_bound": bound0,
                    "record_id": rid0 if isinstance(rid0, str) else None,
                    "reason": "issuer DID is not the expected issuer (the receipt itself may be internally consistent - it was just not issued by who you pinned)"}
        # did:key Ed25519 = multicodec 0xed01 followed by the 32-byte key (CID v1.0 §2.2.2). The key
        # is read straight out of the identifier, which is why no resolver and no network are needed.
        mc = _b58decode(did[len("did:key:z"):])
        if len(mc) < 2 or mc[0] != 0xED or mc[1] != 0x01:
            return {"valid": False, "issuer": did, "content_bound": False, "reason": "issuer DID is not Ed25519"}
        pub = Ed25519PublicKey.from_public_bytes(bytes(mc[2:]))

        cs = _field(vc, "credentialSubject")
        cs = {} if cs is None else cs
        # TYPE discipline FIRST — match both TypeScript verifiers. A bool/number/array prevHash must
        # be reported as malformed, never coerced into content-binding (JS ToString would silently
        # accept out-of-contract files Python used to accept while TS rejected — guard NEEDS-HUMAN
        # 2026-08-07). Decidio's issuer only ever emits string|null.
        prev = _field(cs, "prevHash")
        if prev is not None and not isinstance(prev, str):
            return {"valid": False, "issuer": did, "content_bound": False, "record_id": _field(cs, "recordId"),
                    "reason": "prevHash must be a string or null (an array/object cannot be hashed unambiguously)"}
        if not isinstance(_field(cs, "contentHash"), str) or not isinstance(_field(cs, "recordId"), str):
            return {"valid": False, "issuer": did, "content_bound": False,
                    "reason": "recordId and contentHash must be strings"}
        # There is deliberately NO check here that recordId/dNumber avoid a '|' character. The old
        # format signed a pipe-delimited tuple, so a '|' inside a field made the signed message
        # ambiguous and had to be rejected by hand. Under eddsa-jcs-2022 the signing input is the
        # RFC 8785 canonical form of the whole document, in which every string is JSON-quoted and
        # escaped — the unambiguous-signing-input rule the old guard encoded is now satisfied
        # STRUCTURALLY by canonicalisation, for every field, not just the two we remembered to check.
        canonical = _field(cs, "recordCanonical")
        content_bound = isinstance(canonical, str) and _derive_hash(canonical, prev) == _field(cs, "contentHash")
        if not content_bound:
            return {"valid": False, "issuer": did, "content_bound": False, "record_id": _field(cs, "recordId"),
                    "reason": "contentHash does not match recordCanonical (content tampered)"}

        proof = _field(vc, "proof")
        proof = {} if proof is None else proof
        base = {"issuer": did, "content_bound": content_bound, "record_id": _field(cs, "recordId")}
        if _field(proof, "type") != "DataIntegrityProof":
            return {"valid": False, **base, "reason": "unsupported proof (expected DataIntegrityProof)"}
        # Receipts sealed before 2026-08-04 used a pre-standard Decidio format under the name
        # `eddsa-2022` (a pre-Recommendation working-draft name) whose signature covered a bespoke
        # delimited string rather than the canonical document. Say so plainly — reporting it as an
        # invalid signature would misrepresent an obsolete format as evidence of tampering.
        if _field(proof, "cryptosuite") == _LEGACY_CRYPTOSUITE:
            return {"valid": False, **base, "reason": "receipt uses Decidio's pre-standard format (eddsa-2022); not verifiable under the published spec — ask for a re-sealed receipt"}
        if _field(proof, "cryptosuite") != CRYPTOSUITE:
            return {"valid": False, **base, "reason": f"unsupported cryptosuite (expected {CRYPTOSUITE})"}
        # THE PROOF OPTIONS ARE PART OF THE CLAIM, not decoration - see the TypeScript twin. This
        # checked that the signature was made by the issuer's key and stopped there, so a document
        # whose own proof said it was made for a DIFFERENT purpose, by an UNRELATED key id, with no
        # time at all, still read as an issuance. "A valid signature" and "an assertion by this
        # issuer, about this credential, at a stated time" are different statements, and only the
        # second is what a receipt claims to be. All three fields sit inside the signed proof
        # config, so this cannot break a genuine receipt.
        _purpose = _field(proof, "proofPurpose")
        if _purpose != "assertionMethod":
            return {"valid": False, **base,
                    "reason": f'proofPurpose is {_purpose!r}, not "assertionMethod" - this proof was made for a different purpose, so it is not an issuance of this credential'}
        _vm = _field(proof, "verificationMethod")
        if not isinstance(_vm, str) or not _vm.startswith(f"{did}#"):
            return {"valid": False, **base,
                    "reason": f"verificationMethod {_vm!r} does not identify a key of the issuer ({did}) - the signature was checked against the issuer's key, but the proof names a different one"}
        # did:key has exactly ONE method identifier (the fragment repeats the multibase key id); a proof
        # naming any other fragment is not conforming, whoever signed it (prodsec V033-03; TS twin).
        _msid = did[len("did:key:"):]
        if _vm != f"{did}#{_msid}":
            return {"valid": False, **base,
                    "reason": f"verificationMethod {_vm!r} is not the issuer's did:key method identifier (expected {did}#{_msid}) - did:key has exactly one verification method, and this proof names a fragment that does not exist"}
        # SHAPE-CHECKED, not `.strip()`. The first version of this used `Date.parse` in TypeScript
        # and a bare `.strip()` here, so the two doors disagreed on "banana", "   x   " and
        # "20260830" - TS refused them, this one called them VALID, which is the class the check
        # exists to close. Both smokes tested only a REMOVED `created`, which both halves catch
        # identically, so nothing saw it. XSD dateTimeStamp is what the spec asks for and what a
        # regex can hold both doors to exactly. Keep this pattern byte-identical to the TS twin.
        _created = _field(proof, "created")
        if not isinstance(_created, str) or not _XSD_DATE_TIME_STAMP.match(_created):
            return {"valid": False, **base,
                    "reason": f'proof has no usable "created" timestamp ({_created!r}) - a sealed assertion must say when it was made'}
        if not _is_calendrical_date_time_stamp(_created):
            return {"valid": False, **base,
                    "reason": f'proof "created" timestamp {_created!r} is not a real date-time (a field is out of range) - a sealed assertion cannot have been made at a time that does not exist'}
        # DELIBERATE STRICTNESS — the one place this verifier is knowingly *stricter* than the TS one.
        # proofValue must BE a string, never coerced. Because proofValue is the ONLY proof field NOT
        # covered by the signature (it is stripped out to form the proof config), a coercing check
        # let a rewritten JSON type — ["z…"] instead of "z…" — yield a DIFFERENT receipt file that
        # still carried a passing signature. Two byte-different files that both read VALID is a
        # malleability hole. Both TypeScript verifiers now type-check it the same way (closed
        # 2026-08-04); this check is what keeps the three implementations agreeing.
        pv = _field(proof, "proofValue")
        if not isinstance(pv, str) or not pv.startswith("z"):
            return {"valid": False, **base, "reason": "missing/invalid proofValue (expected base58-btc multibase)"}

        # §3.3.2: strip `proof` from the document and `proofValue` from the proof options. When the
        # proof carries @context it must be a PREFIX of the document's, and the proof's version is
        # then the one canonicalised — that check stops a forger substituting a different context.
        # Both copies are SHALLOW and fresh, exactly like TS object rest: the caller's receipt is
        # never mutated, even though we reassign @context below.
        unsecured_document = {k: v for k, v in vc.items() if k != "proof"}
        proof_config = {k: v for k, v in proof.items() if k != "proofValue"}
        if proof_config.get("@context") is not None:
            pc = _as_context_list(proof_config.get("@context"))
            dc = _as_context_list(unsecured_document.get("@context"))
            # STRICTER THAN THE REC, matching the TypeScript verifiers. §3.3.2 requires only that the
            # document's @context START WITH the proof's, then replaces it before hashing — leaving
            # any extra document entries unsigned. That is exploitable with no key: append an entry
            # (or an inline term-redefining object) to a genuine receipt and it still reads VALID, so
            # a JSON-LD consumer can be shown a remapped record this verifier certified. Requiring
            # equal length closes it and can never reject a genuine Decidio receipt, because the
            # issuer always copies the document's @context into the proof unchanged.
            if len(dc) != len(pc):
                return {"valid": False, **base, "reason": "@context does not match between document and proof (one carries entries the other does not cover)"}
            for i, want in enumerate(pc):
                if not _same_context_entry(want, dc[i]):
                    return {"valid": False, **base, "reason": "proof @context does not match the document @context"}
            unsecured_document["@context"] = proof_config.get("@context")

        signature = _b58decode(pv[1:])
        # Canonicalise OUTSIDE the verify guard on purpose. A document JCS cannot represent (e.g. an
        # integer past 2^53 — decidio.jcs refuses to guess which double the signer meant) is a
        # different finding from a signature that does not match, and squashing it into "signature
        # does not verify" would misreport the cause exactly the way the eddsa-2022 case must not.
        try:
            signing_input = _hash_data(unsecured_document, proof_config)
        except ValueError as e:
            # DIAGNOSTIC PARITY with the TS verifiers: the number-precision
            # refusal (an integer beyond 2^53 / not exactly representable — jcs PY-TRAP 8) fires
            # AFTER content binding passed and the record id was read, so reporting
            # `record: ?  content-bound: False` here was factually wrong about both. Keep the
            # refusal as the reason; report what was actually learned, exactly like the
            # wrong-issuer branch. Any other canonicalisation failure (e.g. a lone surrogate)
            # still falls through to the generic handler, matching TS's outer catch.
            if str(e).startswith("JCS: integer"):
                # SAME reason string as the Node verifiers, not the internal JCS text — this
                # module's doctrine is normalised reason strings, and wording that diverges
                # across languages breaks an auditor's diff.
                return {"valid": False, **base, "reason": "receipt contains an integer beyond 2^53 - its exact signed value cannot be reproduced, so it is not verifiable"}
            raise
        try:
            # The 64 bytes are signed DIRECTLY — no second hash. `cryptography` raises
            # InvalidSignature (and ValueError for a wrong-length signature) where node's
            # crypto.verify returns false, so every failure is normalised to the same reason string
            # the TS verifier gives; an auditor comparing the two must not see a stack-trace text
            # in one language and a plain sentence in the other.
            pub.verify(bytes(signature), signing_input)
            valid = True
        except Exception:  # noqa: BLE001
            valid = False
        # Read the sealed decision state only once the content is bound and the signature checked,
        # so what we report back is what the ISSUER signed — never an attacker-supplied field on an
        # otherwise-rejected document. Same ordering as the TS twin.
        rc = _field(cs, "recordCanonical")
        sealed_state = read_sealed_state(rc) if (valid and content_bound and isinstance(rc, str)) else None
        return {"valid": valid, **base, "d_number": _field(cs, "dNumber"), "prev_hash": _field(cs, "prevHash"),
                "reason": None if valid else "signature does not verify against issuer DID",
                "sealed_state": sealed_state,
                "record_kind": (read_record_kind(rc) if (valid and content_bound and isinstance(rc, str)) else None)}   # never an attacker-supplied field on a rejected document
    except Exception as e:  # noqa: BLE001
        return {"valid": False, "issuer": str(_field(vc, "issuer") or ""), "content_bound": False, "reason": str(e)}


def verify_chain(vcs: List[Dict[str, Any]], expected_issuer: Optional[str] = None) -> Dict[str, Any]:
    """Verify an ordered chain: each receipt's prevHash must equal the prior contentHash, and every
    receipt must independently verify. Proves tamper-evident ordering."""
    if not vcs:
        return {"valid": False, "length": 0, "reason": "no receipts supplied"}
    # ONE ISSUER END TO END, even unpinned (parity with the TS verifier): hash linkage alone would
    # let a second issuer splice its receipts onto a genuine prefix and still read "intact".
    issuers = {str(_field(vc, "issuer") or "") for vc in vcs}
    if len(issuers) > 1:
        return {"valid": False, "length": 0, "reason": f"these receipts come from {len(issuers)} DIFFERENT issuers - a chain must be issued end to end by one issuer"}
    prev: Optional[str] = None
    anchor = "segment"
    for i, vc in enumerate(vcs):
        r = verify_receipt(vc, expected_issuer)
        if not r["valid"]:
            return {"valid": False, "length": i, "reason": f'receipt {i} ({r.get("record_id") or "?"}) invalid: {r.get("reason")}'}
        cs = _field(vc, "credentialSubject")
        cs = {} if cs is None else cs
        # SEGMENT semantics: the FIRST receipt supplied is the anchor (demanding genesis made two
        # consecutive REAL receipts report "broken"). genesis = None/missing; "" is a real value.
        if i == 0:
            anchor = "genesis" if _field(cs, "prevHash") is None else "segment"
        elif _field(cs, "prevHash") != prev:
            # Both receipts verified INDIVIDUALLY by this point, so a prevHash mismatch has two
            # honest readings — a gap (receipts between them are simply not in this set: the
            # common case) or a wrong order/content. Blaming "the chain is broken" alone read as
            # tampering; say what is actually known.
            return {"valid": False, "length": i, "reason": f"receipt {i} does not follow receipt {i - 1} directly (prevHash mismatch - either receipts between them are missing from this set, or the order/content is wrong; each receipt shown above verified individually)"}
        prev = _field(cs, "contentHash")
    return {"valid": True, "length": len(vcs), "anchor": anchor}


def _parse_strict(text: str, path: str) -> Dict[str, Any]:
    """Parse a receipt, REFUSING duplicate object keys.

    RFC 8785 §3.1 requires duplicate-free input, and every mainstream parser silently keeps ONE of
    the duplicates — Python's and JavaScript's both keep the LAST. So a file containing
    `"issuer":"did:key:zEVIL","issuer":"<real>"` verifies while a human reading the file top-down,
    or any parser that keeps the FIRST, sees the attacker's value. Same bytes, two answers: refuse.
    `object_pairs_hook` sees the pairs BEFORE they are collapsed, which is why it can detect this at
    all. Mirrors parseReceiptStrict in packages/decidio-verify/verify.ts.
    """
    def no_duplicates(pairs: List[Any]) -> Dict[str, Any]:
        seen = set()
        for key, _value in pairs:
            if key in seen:
                # ASCII only: this string is printed by a CLI an auditor may run on a console whose
                # encoding is not UTF-8 (a Windows cp1252 terminal renders an em dash as mojibake),
                # and a garbled refusal reason undermines the very thing the tool exists to convey.
                raise ValueError(
                    f"{path}: duplicate JSON key {key!r} - RFC 8785 requires duplicate-free input, "
                    "and different parsers disagree on which value is real"
                )
            seen.add(key)
        return dict(pairs)

    return json.loads(text, object_pairs_hook=no_duplicates)


def _load_strict(path: str) -> Dict[str, Any]:
    """File-path convenience over _parse_strict, kept for library callers. The CLI reads files
    itself first — an unreadable file is an I/O problem, not a verdict — then parses the text."""
    with open(path, encoding="utf-8") as fh:
        return _parse_strict(fh.read(), path)


# THE BUILT-IN TRUST ANCHORS (founder-approved 2026-09-24; twin of KNOWN_ISSUERS in packages/decidio-verify/verify.ts,
# and the three-door conformance gate fails if the doors disagree). A receipt names its own issuer, so pinning to that
# field is circular - any key can sign a file that names itself - and until now the only alternative was asking every
# reader to paste a DID. These are the issuers every CLI door trusts out of the box: Decidio's own deployments, each of
# which publishes its DID at https://<host>/api/did - staging (the lab) and production (launch plan L9; production's DID
# read from its live endpoint on 2026-11-10, its key Ed25519 in AWS KMS, never exported - F-1110-L4). The TS twin's `alsoAt` (a deployment's other API addresses) serves only the TS sdk's grant check, so
# it is not carried here; the release workflow compares the two lists by host and DID. NEVER the verification kit's published SAMPLE issuer: its
# private key is public on purpose, so trusting it by default would verify any forgery signed with it. A self-hosted
# deployment is not listed by design - its DID is pinned with --issuer (or remembered by the SDK at sign-in).
KNOWN_ISSUERS: Tuple[Mapping[str, str], ...] = (
    MappingProxyType({"did": "did:key:z6MkmLGeR5NjJ87a1yU5ygqju49CtnUrt38esqM54Y9tXnKq", "host": "decidio-api.onrender.com", "label": "Decidio staging lab"}),
    MappingProxyType({"did": "did:key:z6MkpBwpAT98VAqg2UpiSGJZieg7DGQpoNkdioDUEo4kQXnJ", "host": "decidio-prod-api.onrender.com", "label": "Decidio production"}),
)


USAGE = """decidio.verify — verify Decidio Authority Receipts OFFLINE (no network, no account)

usage: python -m decidio.verify [--issuer <did:key>] <receipt.json> [more.json ...]

  One file  -> verify that receipt (signature + content binding).
  Many files -> verify each AND their chain order (segment semantics).
  Every run prints its TRUST ANCHOR first - the issuer the verdict is pinned to:
  (no flag)            the built-in Decidio issuer: """ + "; ".join(f'{k["did"]} ({k["label"]}, {k["host"]})' for k in KNOWN_ISSUERS) + """.
                       A receipt from any other issuer is refused (exit 2) until you pin one - its own
                       issuer field is a claim, never a trust anchor.
  --issuer <did:key>   pin the expected issuer yourself (a self-hosted Decidio: take the DID from that
                       host's /api/did, never from the receipt). Wins over the built-in anchor.
  --allow-unpinned     structural check only; the verdict carries the UNPINNED warning.

Exit codes: 0 all verified / 1 verification failed or file unreadable / 2 usage error, or no trust
anchor for these receipts.
The same implementation runs as `python -m decidio verify` (the sdk door)."""


def main(argv: Optional[List[str]] = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    # An auditor's first two commands are --help and --version (the auditor
    # tool had neither). Handled before anything else — before flags, before files; both exit 0
    # on stdout. NO ARGS gets the same usage block on stderr, exit 2 (mirrors decidio-verify's
    # cli.ts exactly).
    if args and args[0] in ("--version", "-v", "-V", "version"):
        from . import __version__
        print(__version__)
        return 0
    if args and args[0] in ("--help", "-h", "help"):
        print(USAGE)
        return 0
    if not args:
        print(USAGE, file=sys.stderr)
        return 2
    return run(args)


def built_in_anchor(files: List[str], read_text: Callable[[str], str], known: Sequence[Mapping[str, str]] = KNOWN_ISSUERS) -> Dict[str, Any]:
    """No --issuer given: the built-in anchor these receipts select ({"anchor": entry}), or why none applies
    ({"refusal": text}). The receipts' own `issuer` fields only CHOOSE among `known` - a claim can never add an anchor -
    and every receipt is then verified against the chosen DID exactly as with --issuer, so a file naming a built-in DID
    without holding its key still fails on the signature. Files that do not parse are left to the verdict, which names
    them. `known` is a parameter for the smokes only. Twin of builtInAnchor in the TS verifier."""
    claimed: List[str] = []
    for f in files:
        try:
            vc = _parse_strict(read_text(f), f)
        except Exception:  # noqa: BLE001 - unparseable: the verdict below reports it as INVALID
            continue
        d = str(_field(vc, "issuer") or "") if isinstance(vc, dict) else ""
        if d not in claimed:
            claimed.append(d)
    outside = [d for d in claimed if not any(k["did"] == d for k in known)]
    if outside:
        who = "the receipt names" if len(claimed) == 1 else "these receipts name"
        return {"refusal": f"{who} {', '.join(d or '(no issuer)' for d in outside)} as issuer, which is not a built-in Decidio issuer"}
    if len(claimed) > 1:
        return {"refusal": f"these receipts name {len(claimed)} different issuers - verify each issuer's receipts separately"}
    anchor = next((k for k in known if k["did"] in claimed), known[0] if known else None)
    return {"anchor": anchor} if anchor is not None else {"refusal": "no built-in issuer is configured"}


def pin_required_message(command: str, why: Optional[str] = None) -> str:
    """The refusal every CLI door prints when no trust anchor applies (0.5.0; 3A: the built-in anchors are tried first,
    so this now fires for a receipt from an issuer this verifier does not know). Twin of the TS `pinRequiredMessage`."""
    built_in = "; ".join(f'{k["did"]} ({k["label"]}, {k["host"]})' for k in KNOWN_ISSUERS)
    return "\n".join([
        f"✘ {command} needs --issuer <did:key>" + (f" here: {why}" if why else "") + " — without a pin, VALID only proves the file agrees with itself (any keyholder could have issued it).",
        f"  Built in (used when no --issuer is given): {built_in}.",
        "  A receipt's own issuer field is a claim, never a trust anchor. For any other Decidio (self-hosted), take its DID from",
        "  that host's /api/did - not from the receipt - and pin it:",
        f"    {command} --issuer <did:key:...> <receipt.json>",
        "  To check structure only, say so: --allow-unpinned (the verdict then carries the UNPINNED warning).",
    ])


def run(args: List[str], command: str = "python -m decidio.verify",
        remembered: Optional[Callable[[], Optional[Tuple[str, str]]]] = None,
        no_anchor_hint: Optional[str] = None) -> int:
    """The flag/file grammar + verdict rendering, SHARED by both doors. `python -m decidio
    verify` enters here directly (its own usage/help live in cli.py), so a file that happens to
    be named "version" stays a FILE on that door — exactly as in the TS sdk door; only the
    standalone `python -m decidio.verify` door answers --version/--help, via main() above.

    With no --issuer the trust anchor is `remembered()` - the sdk door passes the DID this computer remembered for
    its configured host, as (did, where-it-came-from), or None; it raises ValueError(message) when that store cannot
    be read - and then the built-in KNOWN_ISSUERS; `no_anchor_hint` is the door's extra line when neither applies."""
    # STRICT flags, mirroring packages/decidio-verify/cli.ts (a mistyped or
    # `=`-form flag was silently dropped, so `--issuer=did:...` ran an UNPINNED check and reported
    # VALID exit 0 — the exact outcome the flag existed to prevent). On a verifier, a swallowed
    # flag is a forged green light: refuse anything not understood, before reading any file.
    # `--issuer` asserts the receipt was issued by THIS DID (Decidio's published issuer), not
    # merely validly self-signed by some key.
    # (see _parse_strict for the duplicate-key refusal, also mirrored from the TS CLI)
    usage = f"usage: {command} [--issuer <did:key>] <receipt.json> [more.json ...]   (or --allow-unpinned)"
    expected_issuer: Optional[str] = None
    allow_unpinned = False
    files: List[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--allow-unpinned":
            allow_unpinned = True
            i += 1
            continue
        if a == "--":
            # `--` ends option parsing: everything after it is a FILE, dash-leading names included
            # (parity with both TS doors; first-run review of 0.3.5).
            files.extend(args[i + 1:])
            break
        if a == "--issuer":
            v = args[i + 1] if i + 1 < len(args) else None
            # An EMPTY value is the unset-CI-variable case: silently verifying unpinned and
            # exiting 0 would hand a forged receipt a green light.
            if v is None or v == "" or v.startswith("-"):
                print("✘ --issuer needs a did:key value (a bare or EMPTY --issuer must not silently verify unpinned).", file=sys.stderr)
                return 2
            # A REPEATED PIN IS AN AMBIGUOUS PIN (F-014). Last-one-wins is the wrong rule on a
            # verifier: a script that appends --issuer from two sources (a config default and a CI
            # override) silently checks against ONE of them and reports VALID, which is a green
            # light nobody chose. Identical repeats are harmless and stay allowed.
            if expected_issuer is not None and expected_issuer != v:
                print(f"✘ --issuer given twice with different values ({expected_issuer} then {v}) — refusing to choose which one you meant to pin to.", file=sys.stderr)
                return 2
            expected_issuer = v
            i += 2
            continue
        if a.startswith("--issuer="):
            v = a[len("--issuer="):]
            if not v:
                print("✘ --issuer needs a did:key value (a bare or EMPTY --issuer must not silently verify unpinned).", file=sys.stderr)
                return 2
            if expected_issuer is not None and expected_issuer != v:
                print(f"✘ --issuer given twice with different values ({expected_issuer} then {v}) — refusing to choose which one you meant to pin to.", file=sys.stderr)
                return 2
            expected_issuer = v
        elif a.startswith("-"):
            print(f'✘ unknown option "{a}" — refusing to guess (a flag you meant to matter must never be silently ignored).', file=sys.stderr)
            print(usage, file=sys.stderr)
            return 2
        else:
            files.append(a)
        i += 1
    if not files:
        print(usage, file=sys.stderr)
        return 2
    # PINS BY DEFAULT (0.5.0). An unpinned run is a deliberate, named choice - never the thing that happens when a
    # variable is unset. Both at once is an ambiguous instruction, refused like a disagreeing repeated pin.
    if expected_issuer is not None and allow_unpinned:
        print("✘ --allow-unpinned and --issuer together — an unpinned check and a pinned one are different questions; ask one.", file=sys.stderr)
        return 2
    # An unreadable file is an I/O problem, not a cryptographic verdict (a
    # typo'd filename got the same "INVALID" a forged receipt gets).
    texts: Dict[str, str] = {}
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                texts[f] = fh.read()
        except OSError as e:
            detail = "no such file" if isinstance(e, FileNotFoundError) else (e.strerror or str(e))
            print(f"✘ cannot read {f}: {detail} (nothing was verified)", file=sys.stderr)
            return 1
    # NO --issuer: THE TRUST ANCHOR (3A). The sdk door's remembered DID for its host, else the built-in anchor - never the
    # receipt's own issuer field (circular: any key can sign a file that names itself). A receipt from an issuer
    # outside both is refused here, as an unpinned run always was.
    anchor_note: Optional[str] = "--issuer" if expected_issuer is not None else None
    if expected_issuer is None and not allow_unpinned:
        mem: Optional[Tuple[str, str]] = None
        if remembered is not None:
            try:
                mem = remembered()
            except ValueError as e:
                print(f"✘ {e}", file=sys.stderr)
                return 2
        if mem:
            expected_issuer, anchor_note = mem
        else:
            pick = built_in_anchor(files, texts.__getitem__)
            if "refusal" in pick:
                print(pin_required_message(command, pick["refusal"]), file=sys.stderr)
                if no_anchor_hint:
                    print(no_anchor_hint, file=sys.stderr)
                return 2
            expected_issuer = pick["anchor"]["did"]
            anchor_note = f'built in: {pick["anchor"]["label"]}, {pick["anchor"]["host"]}'
    try:
        import cryptography  # noqa: F401 — Ed25519; ships with the base package (old installs listed it as an extra)
    except ImportError:
        print("✘ the open verifier needs the `cryptography` package — it ships with decidio now; upgrade or reinstall: pip install --upgrade decidio", file=sys.stderr)
        return 1
    # PER-FILE isolation (parity with the TS verifiers): one corrupt receipt must never abort
    # the batch or hide the other verdicts — an auditor sweeping fifty files deserves forty-nine
    # answers and ONE named failure. Parse refusals are verdicts and stay on stdout.
    # THE TRUST ANCHOR FIRST (3A; twin of runVerify): a verdict is never read without knowing what it was pinned to.
    if expected_issuer:
        print(f"trust anchor: {expected_issuer}  ({anchor_note or '--issuer'})")
    else:
        print("trust anchor: NONE - unpinned, a structural check only (any keyholder could have issued these files)")
    vcs = []
    parsed_files = []
    any_parse_failed = False
    for f in files:
        try:
            vcs.append(_parse_strict(texts[f], f))
            parsed_files.append(f)
        except ValueError as e:
            any_parse_failed = True
            msg = str(e)
            print(f"INVALID  {f}{msg[len(f):] if msg.startswith(f) else ': ' + msg}")
    if not vcs:
        return 1
    all_ok = not any_parse_failed
    any_valid = False
    for f, vc in zip(parsed_files, vcs):
        r = verify_receipt(vc, expected_issuer)
        all_ok = all_ok and r["valid"]
        any_valid = any_valid or r["valid"]
        print(f'{"VALID  " if r["valid"] else "INVALID"}  {f}')
        # The louder caveat matches runVerify in the TS twin: an unpinned VALID is a much weaker
        # claim than it reads, and the old one-liner undersold that.
        unpinned = "" if expected_issuer else "  (UNPINNED - this only proves internal consistency; ANY keyholder could have issued it. Pass --issuer <your workspace DID> to verify WHO)"
        print(f'    record: {r.get("record_id") or "?"}   kind: {r.get("record_kind") or "?"}   issuer: {r["issuer"]}{unpinned}')
        # "true"/"false", not Python's True/False repr — the two CLIs' result lines must DIFF
        # cleanly against each other.
        bound = "true" if r["content_bound"] else "false"
        print(f'    content-bound: {bound}' + (f'   reason: {r.get("reason")}' if r.get("reason") else ""))
        # AS SEALED, and labelled as such. See read_sealed_state's docstring for why this is printed
        # rather than left in the JSON for the reader to find. Field order matches the TS twin.
        s = r.get("sealed_state")
        if s:
            bits: List[str] = []
            if "result" in s:
                bits.append(f'gate: {s["result"] if s["result"] is not None else "-"}')
            if "confirmation" in s:
                bits.append(f'confirmation: {s["confirmation"] if s["confirmation"] is not None else "-"}')
            if "ratified" in s:
                bits.append(f'ratified: {"yes" if s["ratified"] else "no"}')
            if "nominated_deciders" in s:
                bits.append(f'nominated deciders: {s["nominated_deciders"]}')
            if bits:
                print("    as sealed - " + "   ".join(bits))
            # "ratified: yes, deciders: 0" is CORRECT and reads as a contradiction - see the
            # TypeScript twin. `deciders` is the list nominated in ADVANCE (empty when an agent's
            # request is routed rather than pre-assigned); the person who actually decided is the
            # RATIFIER. The record was never missing the human; the field names do not say which is
            # which, and evidence that needs a footnote is evidence not yet doing its job.
            # SAYS ONLY WHAT THE PAIR SUPPORTS - see the TypeScript twin. The first version added
            # "this was routed, and a human ratified it"; neither clause follows from
            # `ratified && not deciders`, and both are FALSE on records this verifier is handed (a
            # Slack-captured human decision was never routed; a sealed DENIAL carries a ratifier
            # too, so it printed "a human ratified it" beside `gate: blocked`).
            if s.get("ratified") is True and s.get("nominated_deciders") == 0:
                print('      ("nominated deciders" lists anyone nominated in ADVANCE - none here; the person '
                      'who adjudicated is recorded separately, as the ratifier)')
    if any_parse_failed and len(files) > 1:
        print(f"\nchain: not checked - {len(files) - len(vcs)} file(s) failed to parse (see above); re-run with readable receipts to verify ordering.")
    elif len(vcs) > 1:
        c = verify_chain(vcs, expected_issuer)
        all_ok = all_ok and c["valid"]
        if c["valid"] and c.get("anchor") == "segment":
            note = " - segment: ordering proven from the FIRST file forward; history before it is not covered by these receipts"
        elif c["valid"]:
            note = " - from genesis"
        else:
            note = ""
        print(f'\nchain: {"intact" if c["valid"] else "broken"} ({c["length"]}/{len(vcs)})' + note
              + (f' - {c["reason"]}' if c.get("reason") else ""))
    # WHAT VALID MEANS, stated rather than left to inference. Twin of runVerify's closing block.
    #
    # A genuine, issuer-pinned receipt verifies VALID for an action that never executed - correctly,
    # because the seal covers the approval, not the outcome. Every individual claim the verifier
    # makes is true; the trap is what it does NOT say, which an engineer fills in as "approved and
    # executed". One paragraph removes the whole class.
    if any_valid:
        print("\nwhat VALID proves: the CLAIMS in this record were sealed by that issuer and none of"
              "\n  them has changed since. NOT the bytes: the signature covers the record's CANONICAL"
              "\n  form (JCS), so reformatting the file - reindenting, minifying, reordering keys -"
              "\n  still verifies, and should, because none of that alters a single claim. If you need"
              "\n  byte-for-byte custody, hash the file yourself and keep that hash; this proves the"
              "\n  CONTENT, which is what an auditor is actually asking about."
              "\nwhat it does NOT prove: that the approved action ran. Execution is confirmed AFTER the"
              "\n  seal, and a sealed receipt is immutable, so the \"as sealed\" fields above are a snapshot"
              "\n  taken when the record was sealed - not current status. Ask the issuer for that."
              "\n  This check is cryptographic, not semantic: it does not evaluate business rules, timestamp"
              "\n  plausibility, or whether the record was later superseded or revoked.")
    return 0 if all_ok else 1


if __name__ == "__main__":
    # UTF-8 out on THIS door too (`python -m decidio.verify` never runs __main__.py's
    # reconfigure) — deliberately duplicated, not shared: this file stays zero-coupled to cli.py,
    # whose import would drag in the .env autoload the offline verifier must never touch.
    for _stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(_stream, "reconfigure"):
                _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — a non-reconfigurable stream keeps its encoding
            pass
    raise SystemExit(main())
