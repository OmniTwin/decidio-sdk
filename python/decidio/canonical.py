"""The canonical data model - ONE snapshot, validated once, used everywhere.

Python mirror of @decidio/guard's canonical.ts. The contract it enforces: *what a human
approves is byte-for-byte what executes*. Two failures make a naive version unsafe, and
both have a Python-specific shape:

  1. A type check is not a validator. ``isinstance(v, dict)`` is True for an OrderedDict,
     a defaultdict and any user subclass whose ``__getitem__`` does something else
     entirely; ``isinstance(v, int)`` is True for ``True``. Membership in a family is not
     membership in the model, so this module checks the EXACT type
     (``type(v) is dict``) and refuses everything else by construction.
  2. Validating a snapshot and then executing the ORIGINAL object leaves the race open: a
     ``describe`` callback (or any other caller-held reference) can mutate an argument
     between approval and execution. So we do not validate-and-hope; we take a deep
     canonical CLONE and hand that same clone to ``describe``, to the signature, to the
     store, and to the action. The approved value and the executed value are one object
     graph.

Documented consequence: canonicalization preserves VALUE semantics, not Python object
identity. ``{"a": x, "b": x}`` becomes two structurally-equal but distinct objects, and a
mutation the action makes to its arguments is not visible to the caller. That is the price
of the guarantee, and it is a contract, not an accident.

Judgment calls, said out loud rather than left for a reader to discover:

  * dict/list SUBCLASSES are REFUSED, not silently flattened. An OrderedDict's ordering
    semantics and a defaultdict's factory do not survive the round trip; a Counter's
    arithmetic does not either. Silently converting them would make the approved value a
    different KIND of value from the one the caller passed, which is the same class of bug
    as a Map serializing to ``{}`` in JavaScript. Pass ``dict(value)`` / ``list(value)``
    and the intent is explicit.
  * NamedTuples are refused under the tuple rule (they are tuples): JSON turns them into a
    list and every field name disappears.
  * ``-0.0`` is refused: it serializes as ``0`` and parses back as ``+0``, so the sign is
    lost silently.
  * Ints that are not exactly representable as an IEEE-754 double are REFUSED (A7, 0.1.12,
    delegating to the signer's ``_int_number`` rule). Python carries them exactly and so does
    JSON text - but the reader here is not "some reader": it is Decidio's own Node floor,
    whose ``JSON.parse`` reads ``9007199254740993`` as ``...992``, so the human approves the
    ROUNDED value while the action executes on the exact snapshot. The gate and the signer
    now enforce the same rule; pass the exact digits as a string if you need them.

The refusal message names the path and the fix. It deliberately does NOT append "The
decision was NOT routed" - only the CALLER knows whether anything was routed yet, and the
gate (nothing routed) and ``park`` (a decision may already exist) say different true
things. They append their own sentence.
"""
from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Tuple, Union

from .errors import DecidioUnsafeArguments


JsonValue = Union[None, bool, int, float, str, List[Any], Dict[str, Any]]

_PREFIX = "the approval payload must be plain JSON so that what a human approves is exactly what executes;"


def _refuse(path: str, what: str, fix: str) -> "DecidioUnsafeArguments":
    return DecidioUnsafeArguments(f"[decidio] {path} {what} - {_PREFIX} {fix}")


def _type_name(v: Any) -> str:
    return type(v).__name__


def _assert_no_lone_surrogate(s: str, p: str) -> None:
    """A lone (unpaired) surrogate cannot be encoded as UTF-8 at all, so it cannot ride the wire
    or be sealed - and the SIGNER (jcs.py, RFC 8785) already refuses it, so accepting it here
    split the paths: this SDK crashed at the transport encode AFTER /agent/authorize had routed
    (a phantom approval) while the TS twin shipped escaped-but-non-canonical bytes. One value
    model, one answer, refused before anything is sent (0.1.12; found by the Part B
    byte-identity gate).

    EVERY surrogate, including an adjacent pair. The pair-aware version skipped high+low on the
    theory that it was "an astral character a surrogatepass decode may legitimately carry" - it is
    not. In Python those are two code points, and the resulting str still cannot be UTF-8 encoded:
    canonical_json produced a value that raised UnicodeEncodeError at the transport, AFTER the
    gate had already approved the request.

    It is also where the twins part company. In JavaScript a high+low pair written in a string
    literal IS the astral character - the language combines it - so TypeScript signs one code
    point where Python holds two broken ones. They are not the same input, and treating them as
    one is what let a Python caller believe they had sent what a TS caller would have sent.

    We refuse rather than recombine, for the same reason a decision id is never silently trimmed:
    an SDK that quietly rewrites the caller's data can send something the caller never wrote. A
    Python string holding surrogates is almost always UTF-16 decoded with `surrogatepass`, and the
    message says so."""
    for i, ch in enumerate(s):
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            paired = (0xD800 <= cp <= 0xDBFF and i + 1 < len(s)
                      and 0xDC00 <= ord(s[i + 1]) <= 0xDFFF)
            what = "a surrogate PAIR" if paired else f"an unpaired surrogate (U+{cp:04X})"
            raise _refuse(p, f"contains {what}",
                          "no surrogate can be encoded as UTF-8, so no wire or seal can carry it. In "
                          "Python a surrogate pair is TWO code points, not one character - if this came "
                          "from UTF-16 decoded with `surrogatepass`, decode it properly instead "
                          "(bytes.decode('utf-16')); if it is a split emoji, repair the string. The same "
                          "text in the TypeScript SDK is a single character, so letting this through "
                          "would make the two SDKs sign different bytes.")


def _walk(v: Any, p: str, seen: set) -> JsonValue:

    if v is None:
        return None



    if v is True or v is False:
        return v
    t = type(v)
    if t is str:
        _assert_no_lone_surrogate(v, p)
        return v
    if t is int:




        from .jcs import _int_number
        try:
            _int_number(v)
        except ValueError as e:
            raise _refuse(p, f"is {v}", f"{e} - pass it as a string if you need the exact digits.") from None
        return v
    if t is float:
        if not math.isfinite(v):
            raise _refuse(p, f"is {v}", "a non-finite number becomes null (or invalid JSON) on the wire, so the approver and your function would see different values - pass a finite number or a string.")

        if v == 0.0 and math.copysign(1.0, v) < 0:
            raise _refuse(p, "is -0.0", "negative zero is indistinguishable from 0 after serialization - pass 0.0 if that is what you mean.")
        return v


    if isinstance(v, tuple):
        extra = "" if t is tuple else f" ({_type_name(v)}, a tuple subclass)"
        raise _refuse(p, f"is a tuple{extra}", "JSON turns it into a list (and a NamedTuple loses every field name), so the approved value would not be the executed one - pass a list or a dict.")
    if isinstance(v, (set, frozenset)):
        raise _refuse(p, f"is a {_type_name(v)}", "it has no JSON form and no stable order - pass a list.")
    if isinstance(v, (bytes, bytearray, memoryview)):
        raise _refuse(p, f"is {_type_name(v)}", "JSON cannot carry raw bytes - encode it as a string (base64/hex) first.")
    if isinstance(v, complex):
        raise _refuse(p, "is a complex number", "JSON has no complex type - pass the real and imaginary parts as numbers, or a string.")
    if callable(v):
        raise _refuse(p, f"is callable ({_type_name(v)})", "a function cannot be serialized for approval - call it and pass the result.")


    if t is list or t is dict:
        vid = id(v)
        if vid in seen:
            raise _refuse(p, "is part of a circular structure", "JSON cannot represent cycles - break the cycle or pass an id instead.")
        seen.add(vid)
        try:
            if t is list:
                return [_walk(x, f"{p}[{i}]", seen) for i, x in enumerate(v)]
            out: Dict[str, Any] = {}
            for k, x in v.items():


                if type(k) is not str:
                    raise _refuse(p, f"has a non-string key {k!r}", "JSON silently coerces it to a string (and two keys can collide into one), so what a human approves would not be what executes - use string keys.")
                _assert_no_lone_surrogate(k, f"{p}.{k}")
                out[k] = _walk(x, f"{p}.{k}", seen)
            return out
        finally:


            seen.discard(vid)


    if isinstance(v, dict):
        raise _refuse(p, f"is a {_type_name(v)} (a dict subclass)", "only a plain dict round-trips with its behaviour intact (an OrderedDict's ordering semantics, a defaultdict's factory and a Counter's arithmetic are all lost) - pass dict(value).")
    if isinstance(v, list):
        raise _refuse(p, f"is a {_type_name(v)} (a list subclass)", "only a plain list round-trips with its behaviour intact - pass list(value).")


    raise _refuse(p, f"is a {_type_name(v)}", "only plain JSON values (None, bool, str, finite int/float, list, dict with string keys) survive serialization with their meaning intact - convert it to plain JSON first (e.g. str(value) for a datetime, float(value) for a Decimal, value.value for an Enum, dataclasses.asdict(value)).")


def canonicalize(value: Any, path: str = "args") -> JsonValue:
    """Deep-clone ``value`` into the canonical model, REFUSING anything that cannot be
    carried losslessly. Returns a fresh structure; the input is never referenced by the
    result. Raises :class:`DecidioUnsafeArguments` (a ValueError) naming the path + the fix."""
    return _walk(value, path, set())


def canonicalize_args(args: Any, kwargs: Any = None) -> Tuple[list, dict]:
    """Canonicalize a call's arguments ONCE. The returned pair is what ``describe`` sees,
    what gets signed and parked, and what the action ultimately runs on."""
    seen: set = set()
    c_args = [_walk(a, f"args[{i}]", seen) for i, a in enumerate(args or [])]
    c_kwargs: Dict[str, Any] = {}
    for k, v in (kwargs or {}).items():
        if type(k) is not str:
            raise _refuse("kwargs", f"has a non-string key {k!r}", "keyword names must be strings - use string keys.")





        _assert_no_lone_surrogate(k, "kwargs key")
        c_kwargs[k] = _walk(v, f"kwargs.{k}", seen)
    return c_args, c_kwargs




def _sort_key(key: str) -> bytes:
    """UTF-16 code-unit collation, matching JavaScript's default string comparison (and
    therefore ``Object.keys(o).sort()`` in canonical.ts / apps/api). Big-endian UTF-16 bytes
    compare in exactly code-unit order, and Python treats a prefix as smaller, same as JS."""
    return key.encode("utf-16-be", "surrogatepass")


def _number(v: Any) -> str:
    """Serialize a number exactly as ``Number.prototype.toString`` does, by DELEGATING to the
    one implementation that already gets it right.

    This used to be a second, home-rolled serializer, and it measurably disagreed with the TS
    canonicaliser at ordinary values: 1e21 (JS "1e+21" vs Python's 22 digits), 1e-7 ("1e-7" vs
    "1e-07"), 1e-6 ("0.000001" vs "1e-06"). Every Python signature and digest routes through
    here, so a Python agent whose result contained such a number had its attestation silently
    refused by the server's re-hash. The correct ECMAScript algorithm lives in jcs._es_number
    (with the §3.2.2.3 21/-6 exponent bounds) and jcs_smoke pins exactly these vectors — but
    that module was only reachable from verify.py, so the green gate covered the copy that was
    NOT on the signing path. One implementation, one gate."""
    from .jcs import _es_number, _int_number

    if isinstance(v, bool):
        raise TypeError("bool is not a number")




    try:
        return _int_number(v) if isinstance(v, int) else _es_number(v)
    except ValueError as e:
        raise _refuse("a number", f"is {v!r}", f"{e} - pass it as a string if you need the exact digits.") from None


def canonical_json(value: Any) -> str:
    """RFC 8785-shaped canonical JSON of an already-canonical value - the exact bytes hashed
    for an execution report, byte-identical to canonicalJson()/canonicalize() in the TS SDK
    and apps/api, so both languages produce the same digest and the same signature."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"






    if isinstance(value, str):
        _assert_no_lone_surrogate(value, "canonical_json(...)")
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(x) for x in value) + "]"
    if isinstance(value, dict):
        for _k in value:
            if isinstance(_k, str):
                _assert_no_lone_surrogate(_k, "canonical_json(...) key")
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonical_json(value[k])
            for k in sorted(value.keys(), key=_sort_key)
        ) + "}"
    return json.dumps(value)
