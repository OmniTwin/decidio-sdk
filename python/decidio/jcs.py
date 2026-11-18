"""JSON Canonicalization Scheme (RFC 8785) — Python port, BYTE-IDENTICAL to apps/api/src/jcs.ts.

WHY THIS EXISTS: the receipt spec we publish promises an auditor can canonicalise a receipt and
verify its Ed25519 signature with standard tools, in THEIR language. That promise is only kept if
the open Python verifier reproduces the exact same canonical bytes as the TypeScript signer — one
byte of drift and the same receipt verifies in one language and fails in the other, which is worse
than no verifier at all. So this is a deliberate mirror of apps/api/src/jcs.ts, not an independent
implementation, and jcs_smoke.py proves the byte-identity by DIFFING against the TS one.

Stdlib only, like the rest of the guard core (`json` is used for nothing load-bearing).

RFC 8785 mapping, so a reviewer can check each rule (same order as jcs.ts):
 §3.2.1 whitespace   — none emitted anywhere.
 §3.2.2 literals     — null/true/false verbatim (NOT Python's None/True/False — see PY-TRAP 4).
 §3.2.2.3 numbers    — ECMAScript Number::toString, which is exactly what JSON.stringify emits
                       for a finite number (shortest round-tripping form: 1e+30, 1e-7, 0.000001).
                       Non-finite (NaN/±Infinity) is NOT valid JSON and raises.
 §3.2.2.2 strings    — minimal escaping (only ", \\ and C0 controls), UTF-8 output with no
                       \\u escaping of non-ASCII. JSON.stringify does precisely this. Lone
                       surrogates MUST terminate with an error (see PY-TRAP 7) — JSON.stringify
                       does NOT do that, so both implementations check explicitly.
 §3.2.3 object keys  — sorted by UTF-16 CODE UNIT of the raw (unescaped) key. JavaScript's
                       default Array#sort compares strings by UTF-16 code unit, so `.sort()` is
                       correct there — and deliberately NOT localeCompare, which would sort by
                       collation and silently produce a different, unverifiable byte string.
                       Consequence worth knowing: an astral character (surrogate pair, e.g.
                       U+1F600 → D83D DE00) sorts BEFORE U+FFFD, which is code-unit order, not
                       code-point order. That is the specified behaviour.
 arrays              — element order preserved (never sorted).

WHERE PYTHON SILENTLY BREAKS BYTE-IDENTITY. Each of these is a place a naive port passes its own
tests and still produces different bytes from the TS signer. They are the reason this file is
longer than the 30-line TS original, and each has a vector in jcs_smoke.py:

 PY-TRAP 1  KEY SORT.  `sorted()` on `str` compares CODE POINTS; JavaScript compares UTF-16 CODE
            UNITS. They disagree for every astral character: U+1F600 is the pair D83D DE00, so
            D83D < FFFD by code unit (emoji key first) but U+1F600 > U+FFFD by code point (emoji
            key last). We therefore sort on `k.encode("utf-16-be", "surrogatepass")` — big-endian
            code units compare bytewise in exactly code-unit order, and a shorter key that is a
            prefix of a longer one sorts first, matching JS. `surrogatepass` keeps the sort total
            even for keys holding unpaired surrogates (plain utf-16-be would raise on those).
 PY-TRAP 2  NUMBERS.  `repr(float)` is shortest-round-tripping but its FORMAT is not ES's:
            repr(1.0)="1.0" (ES: "1"), repr(1e-7)="1e-07" (ES: "1e-7" — the two-digit exponent is
            the trap), repr(1e16)="1e+16" (ES: "10000000000000000"), repr(1e-5)="1e-05" (ES:
            "0.00001"), repr(-0.0)="-0.0" (ES: "0"). The positional/exponential thresholds differ
            too. So we take only the DIGITS from repr() and re-format them with the ES
            Number::toString algorithm ourselves — see _es_number.
 PY-TRAP 3  ESCAPING.  `json.dumps` defaults to ensure_ascii=True, which \\u-escapes every
            non-ASCII character — a completely different byte string. Switching to
            ensure_ascii=False fixes that but then emits raw unpaired surrogates, which JCS
            requires us to REJECT (PY-TRAP 7) and which .encode("utf-8") cannot even represent.
            Neither flag setting is correct, so we do the escaping ourselves (_json_string) and
            the rule stays auditable in one place instead of delegated to a flag.
 PY-TRAP 4  LITERALS.  str(True) is "True". Emit "true"/"false"/"null".
 PY-TRAP 5  NON-FINITE.  Must raise, not emit NaN/Infinity (which are not JSON at all).
 PY-TRAP 6  bool IS AN int.  `isinstance(True, int)` is True, so the bool branch MUST come before
            the int branch or True canonicalises as `1` — a silent, signature-breaking corruption.
 PY-TRAP 7  SURROGATES / THE TWO STRING MODELS.  §3.2.2.2 requires a lone surrogate to TERMINATE
            the canonicaliser with an error, so both implementations refuse it. Neither language
            does that for free: JS's JSON.stringify quietly emits "\\ud800" (well-formed JSON but
            NOT the canonical form), and Python's json.dumps(ensure_ascii=False) emits the raw
            surrogate, producing a str whose .encode("utf-8") then refuses outright ("surrogates
            not allowed") — a crash at the byte-emitting step the seal path actually needs. So
            jcs.ts has assertNoLoneSurrogate and _json_string raises on the same input.
            The wrinkle is that "lone" means different things in the two string models: JS strings
            are UTF-16 CODE UNIT sequences, so the pair D83D DE00 *is* U+1F600 and JS cannot hold
            it as anything else; Python strings are CODE POINT sequences, so '\\ud83d\\ude00' is
            two surrogate code points — a value with no JS equivalent. We therefore mirror jcs.ts's
            scan exactly: an adjacent high+low pair is the astral character (recombined and emitted
            as raw UTF-8, jcs.ts's "valid pair — skip its low half" branch), anything else in
            D800-DFFF is lone and raises.
            That pair case is belt-and-braces, not a parser fix: `json.loads` combines escaped
            pairs exactly like JSON.parse does ('"\\ud83d\\ude00"' -> U+1F600 in both), so there
            is NO parser divergence to compensate for — verified in jcs_smoke.py, which pins it as
            a negative finding so we notice if it ever changes. It matters only for a str that
            reached us another way (e.g. decoded with `surrogatepass`).
 PY-TRAP 8  int PRECISION.  Python ints are unbounded; RFC 8785 §3.2.2.3 numbers are IEEE-754
            doubles, so a JS document can never hold an int that a double cannot represent. We
            canonicalise ints through the double they would have been (so 10**21 gives "1e+21",
            not "1000000000000000000000") and RAISE if the value does not survive that round trip.
            This is a DELIBERATE divergence: JS would silently round huge integers like 12345678901234567890 to
            12345678901234567000, and silently signing a different number than the caller passed
            is not something a seal should do.

There is no `undefined` in Python, so the TS rule "a key whose value is `undefined` is dropped"
has no analogue: `None` is `null` and is always PRESERVED, never dropped. Any type that is not a
JSON value raises rather than silently canonicalising to something a verifier cannot reproduce.
"""
from __future__ import annotations

import math
from typing import Any

# §3.2.2.2 — the ONLY characters JSON.stringify gives a short escape to.
_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _sort_key(key: str) -> bytes:
    """PY-TRAP 1 — UTF-16 code-unit collation, matching JavaScript's default string comparison.

    Big-endian UTF-16 bytes compare in exactly code-unit order (the high byte of each unit comes
    first, so a bytewise comparison is a code-unit-wise comparison), and Python's bytes comparison
    treats a prefix as smaller — same as JS. `surrogatepass` keeps a malformed key from raising a
    UnicodeEncodeError HERE, so it reaches _json_string and fails with the proper JCS lone-surrogate
    error instead — mirroring jcs.ts, which likewise sorts first and checks the keys after.
    """
    return key.encode("utf-16-be", "surrogatepass")


def _json_string(s: str) -> str:
    """§3.2.2.2 + PY-TRAP 3/7 — minimal escaping; non-ASCII stays literal UTF-8 text."""
    out = ['"']
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        cp = ord(ch)
        short = _SHORT_ESCAPES.get(ch)
        if short is not None:
            out.append(short)
        elif cp < 0x20:
            # Remaining C0 controls: \u00xx, LOWERCASE hex (JSON.stringify uses lowercase).
            # Note 0x7F (DEL) is deliberately NOT escaped — JSON.stringify leaves it raw.
            out.append("\\u%04x" % cp)
        elif 0xD800 <= cp <= 0xDBFF and i + 1 < n and 0xDC00 <= ord(s[i + 1]) <= 0xDFFF:
            # PY-TRAP 7. A high surrogate directly followed by a low one is the only thing JS could
            # read as an astral character, so recombine and emit it raw — jcs.ts's "valid pair" arm.
            out.append(chr(0x10000 + ((cp - 0xD800) << 10) + (ord(s[i + 1]) - 0xDC00)))
            i += 2
            continue
        elif 0xD800 <= cp <= 0xDFFF:
            # §3.2.2.2: a lone surrogate MUST terminate the canonicaliser. Escaping it (which is
            # what JSON.stringify and json.dumps would do) yields bytes a conformant verifier will
            # not reproduce, so the signature would fail looking like a crypto bug. Refuse instead.
            raise ValueError(f"JCS: unpaired {'high' if cp <= 0xDBFF else 'low'} surrogate U+{cp:04X}")
        else:
            out.append(ch)
        i += 1
    out.append('"')
    return "".join(out)


def _es_number(x: float) -> str:
    """§3.2.2.3 + PY-TRAP 2 — ECMAScript Number::toString(x, 10), i.e. what JSON.stringify emits.

    ECMA-262 defines the output in terms of the SHORTEST decimal digit string `s` (k digits) and a
    decimal-point position `n` such that s x 10**(n-k) == x. Python's repr() already gives us the
    shortest round-tripping digits — it just formats them by different rules — so we harvest the
    digits and n from repr() and then apply ES's four output cases verbatim.
    """
    if math.isnan(x) or math.isinf(x):  # PY-TRAP 5
        raise ValueError("JCS: non-finite numbers are not valid JSON")
    if x == 0:
        return "0"  # covers -0.0: ES Number::toString maps both zeros to "0"
    if x < 0:
        return "-" + _es_number(-x)

    r = repr(x)
    mantissa, _, exp_part = r.partition("e")
    exp10 = int(exp_part) if exp_part else 0
    int_part, _, frac_part = mantissa.partition(".")
    digits = int_part + frac_part
    # n = how many digits sit left of the decimal point, counted from the first digit of `digits`.
    n = len(int_part) + exp10
    stripped = digits.lstrip("0")
    n -= len(digits) - len(stripped)          # each dropped leading zero shifts the point left
    digits = stripped.rstrip("0")             # trailing zeros are not significant (k must be minimal)
    k = len(digits)

    # ES Number::toString, step for step. The 21 and -6 bounds are literal spec constants and are
    # exactly why 1e20/1e21 and 1e-6/1e-7 are the two boundary vectors worth pinning in tests.
    if k <= n <= 21:
        return digits + "0" * (n - k)          # 1e20 -> 100000000000000000000
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]   # 1.5 -> 1.5
    if -6 < n <= 0:
        return "0." + "0" * -n + digits        # 1e-6 -> 0.000001
    e = n - 1                                  # exponential form; e is never 0 in this branch
    sign = "+" if e > 0 else "-"
    lead = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{lead}e{sign}{abs(e)}"            # 1e30 -> 1e+30, 1e-7 -> 1e-7 (NOT repr's 1e-07)


def _int_number(v: int) -> str:
    """PY-TRAP 8 — canonicalise a Python int as the IEEE-754 double RFC 8785 says numbers are."""
    try:
        as_double = float(v)
    except OverflowError:
        raise ValueError(f"JCS: integer {v} exceeds IEEE-754 double range") from None
    if int(as_double) != v:
        raise ValueError(
            f"JCS: integer {v} is not exactly representable as an IEEE-754 double "
            "(RFC 8785 numbers are doubles); canonicalising it would silently sign a different value"
        )
    return _es_number(as_double)


def jcs_canonicalize(value: Any) -> str:
    """Canonicalise a JSON value to its RFC 8785 form. Raises on non-JSON input.

    Byte-identical to jcsCanonicalize in apps/api/src/jcs.ts — see jcs_smoke.py for the proof.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):        # PY-TRAP 6 — MUST precede the int branch
        return "true" if value else "false"
    if isinstance(value, int):
        return _int_number(value)
    if isinstance(value, float):
        return _es_number(value)
    if isinstance(value, str):
        return _json_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jcs_canonicalize(x) for x in value) + "]"
    if isinstance(value, dict):
        for k in value:
            # JS object keys are always strings; coercing 1 -> "1" here could collide with a real
            # "1" key and make the canonical form ambiguous, so refuse instead.
            if not isinstance(k, str):
                raise TypeError(f"JCS: object keys must be strings, got {type(k).__name__}")
        keys = sorted(value, key=_sort_key)   # §3.2.3, PY-TRAP 1
        return "{" + ",".join(f"{_json_string(k)}:{jcs_canonicalize(value[k])}" for k in keys) + "}"
    raise TypeError(f"JCS: cannot canonicalise type {type(value).__name__}")


def jcs_bytes(value: Any) -> bytes:
    """The canonical form as UTF-8 bytes — what actually gets hashed."""
    return jcs_canonicalize(value).encode("utf-8")
