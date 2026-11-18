"""decidio CLI (Python) — parity with the TS `npx @decidio/sdk` CLI.
    python -m decidio init [agentId]
    python -m decidio doctor
    python -m decidio approvals [approve|reject <id> [reason]]
    python -m decidio dev [--target URL] [--port N]
"""
from __future__ import annotations

import json
import os
import re as _re_did
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional, Tuple

ENV_PATH = ".env"


# Errors and usage guidance go to STDERR (error text on stdout corrupts every
# `--json | jq` pipeline — and any consumer of a CLI's stdout). Verdict output (verify's VALID/
# INVALID lines) is the product and stays on stdout, as does informational ✔/•/⚠ tour narration.
def _err(*a: Any) -> None:
    print(*a, file=sys.stderr)


# NEVER a crash: an unreadable .env (EPERM, a DIRECTORY named .env, a mangled volume) is that
# file's problem, not this command's — warn once on stderr and continue (it was
# an unhandled traceback).
_env_warned = False


def _warn_env_unreadable(e: Exception) -> None:
    global _env_warned
    if _env_warned:
        return
    _env_warned = True
    import errno as _errno
    code = _errno.errorcode.get(e.errno) if isinstance(e, OSError) and e.errno is not None else None
    _err(f"⚠ could not read .env ({code or e}).")


_env_unreadable = False


def _load_env_file() -> None:
    """Load the CWD .env into the process env FIRST (parity with the TS CLI — without it,
    init writes .env but the next command ignored it and pointed at localhost). Process env
    always wins — .env only fills gaps. NEVER autoloads DECIDIO_SESSION_TOKEN: session tokens
    are memory-only by design; honoring one from disk would reward the credential-at-rest the
    session/agent-token split exists to prevent."""
    import re as _re

    try:
        if not os.path.exists(ENV_PATH):
            return
        text = open(ENV_PATH, encoding="utf-8").read()
    except Exception as e:  # noqa: BLE001 — warn-not-crash; see _warn_env_unreadable
        global _env_unreadable
        _env_unreadable = True
        _warn_env_unreadable(e)
        return
    for line in text.splitlines():
        m = _re.match(r"^\s*([A-Z_]+)=(.*)$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if k == "DECIDIO_SESSION_TOKEN":
            # stderr, not stdout: this warning can fire on a --json code path, and a warning line
            # inside piped JSON corrupts the consumer.
            _err("⚠ ignoring DECIDIO_SESSION_TOKEN found in .env — session tokens belong in your shell or CI secret store, never on disk. Remove that line; export it in the shell instead.")
            continue
        # A PROJECT .env CONFIGURES DECIDIO — IT DOES NOT RECONFIGURE THE OS, TOOLCHAIN OR NETWORK STACK (3A follow-up;
        # TS twin). Promote only the app's own DECIDIO_* namespace. A cloned repo's .env used to be able to inject ANY
        # uppercase variable into os.environ, and a network command then ran with it: HTTP(S)_PROXY/NO_PROXY (route this
        # CLI's authenticated urllib calls, bearer token and all, through the repo's server), SSL_CERT_FILE/
        # REQUESTS_CA_BUNDLE/PYTHONHTTPSVERIFY (make it trust the repo's certificate), PYTHONPATH/PYTHONSTARTUP/GIT_*
        # (run the repo's code in this process or the git we shell out to), XDG_CONFIG_HOME/LOCALAPPDATA/HOME (redirect
        # where the session token and the trust store are read and written). None belong to a directory file. A switch
        # genuinely wanted is set in the shell — which still wins, since _SHELL_ENV was snapshotted before this ran.
        # DECIDIO_UPDATE_* is exempt-in-name-only: it may be promoted, but the update gate reads it from _SHELL_ENV.
        if not k.startswith("DECIDIO_"):
            continue
        os.environ.setdefault(k, v)


# OFFLINE commands never touch .env at all (`verify` is cryptographically
# offline and needs no credentials, yet the autoload coupled it to the directory's .env —
# and the help text's "every command talks to the hosted sandbox" was wrong for it).
# ...and HELP IS OFFLINE EXACTLY WHEN USAGE WILL BE PRINTED (first-run review, 0.3.4): only the
# FIRST argument used to decide, so `quickstart --help` loaded .env first and an unreadable .env
# blocked the help text that explains how to fix it. The first cut said "a help token ANYWHERE", and
# invariant-guard blocked it: main() prints usage only for a help token in the command or first-
# argument position, so a reason word `help` at position three skipped .env (and the F-011 fatal)
# for a command that then ACTED. ONE predicate, used here and by main().


def _wants_help(s) -> bool:
    return s in ("help", "--help", "-h")


def _help_flag_anywhere(argv) -> bool:
    """A help FLAG anywhere before `--` asks for help (first-run review of 0.4.1: `tokens revoke --help` exited 2 as
    an unknown option). Only the flags: the bare word `help` past the usage positions is a positional (0.3.4)."""
    scope = argv[:argv.index("--")] if "--" in argv else argv
    return any(s in ("--help", "-h") for s in scope)


_OFFLINE_CMD = (sys.argv[1] if len(sys.argv) > 1 else None) in (
    "verify", "--version", "-v", "-V", "version", None) or _wants_help(
    sys.argv[1] if len(sys.argv) > 1 else None) or _wants_help(sys.argv[2] if len(sys.argv) > 2 else None) or _help_flag_anywhere(sys.argv[1:])
# THE ENVIRONMENT AS THE SHELL GAVE IT (3A follow-up; closes a hole in the 2026-09-04 fix below). `python -m decidio`
# imports the `decidio` package first, and that import runs Guard.from_env() for the `guard` singleton, which fills
# os.environ from ./.env - so by the time this module ran, the project's .env was already "the process env": the
# snapshot below carried a hostile repo's PIP_INDEX_URL / DECIDIO_UPDATE_REGISTRY / DECIDIO_NO_UPDATE_CHECK, and the
# OFFLINE commands (verify) read the project's DECIDIO_API_URL, which the TypeScript CLI never does. Undo exactly what
# that import injected (a value something changed since is left alone); non-offline commands re-load .env below under
# this CLI's own rules (an unreadable .env is fatal there, the session token is refused).
from .guard import _DOTENV_INJECTED as _IMPORT_DOTENV  # noqa: E402 - must run before the snapshot below
for _k, _v in list(_IMPORT_DOTENV.items()):
    if os.environ.get(_k) == _v:
        del os.environ[_k]
_IMPORT_DOTENV.clear()
# THE SHELL'S OWN ENV, snapshotted BEFORE the project .env is promoted below (invariant-guard 2026-09-04; TS twin): the
# update gate reads its switches from here and runs pip with it, so a hostile repo's .env cannot point the check at a fake
# registry (PIP_INDEX_URL / DECIDIO_UPDATE_REGISTRY) and use our own "Upgrade now?" as consent.
_SHELL_ENV = dict(os.environ)
if not _OFFLINE_CMD:
    _load_env_file()
    # AN UNREADABLE .env IS FATAL FOR EVERY NON-OFFLINE COMMAND (F-011), not a warning. The warning
    # was fine for the target-host question that `_api()` already guards; it was wrong for
    # everything else that reads this file to DECIDE something. `_read_env()` returns {} on failure,
    # and {} is indistinguishable from "no agent configured here" - so an unreadable .env made
    # `quickstart` conclude the directory had no agent key and write straight to .env, clobbering a
    # real agent's private key, which this CLI treats as unrecoverable. A file that exists and
    # cannot be read is not an empty file, and no command that acts on its contents may pretend so.
    if _env_unreadable:
        print("✘ .env exists here but could not be read, so this command cannot know what is already configured in this directory.", file=sys.stderr)
        print("  Treating it as empty would risk overwriting an agent key that cannot be recovered. Fix the file's permissions (or move it aside) and run the command again. Nothing was changed.", file=sys.stderr)
        raise SystemExit(1)

# DEFAULT-FIRST: every command defaults to Decidio's hosted service,
# because that is the product people actually receive — the old localhost default was our own dev
# environment leaking into the package, and it broke the tour's own follow-up commands the moment
# cleanup removed .env. Explicit config (env or .env) always wins; the target host is announced on
# stderr so no command ever talks to a server silently.
# PRODUCTION BY DEFAULT (launch plan L9, founder F-1106-C2 (a); TS twin DEFAULT_API): released only after the cutover
# window, when mcp.decidioai.com is production's. The lab (staging) is https://mcp-staging.decidioai.com.
_DEFAULT_API = "https://mcp.decidioai.com"
_LAB_API = "https://mcp-staging.decidioai.com"
_LAB_ORIGINS = frozenset({_LAB_API, "https://decidio-api.onrender.com"})


def is_lab_api(url: str) -> bool:
    """Is this API origin Decidio's lab? Exact origins only (a look-alike is not the lab). PURE. TS twin isLabApi."""
    return url.rstrip("/").lower() in _LAB_ORIGINS

API = os.environ.get("DECIDIO_API_URL", _DEFAULT_API).rstrip("/")


def TOKEN() -> Optional[str]:
    """Read at CALL time, not import: init mints a fresh agent token mid-run and its closing
    doctor must probe with THAT (a stale capture would make init's own doctor
    report the just-minted token as rejected)."""
    return os.environ.get("DECIDIO_API_TOKEN")


_host_announced = False


def _plan_refused(what: str, body: Any) -> None:
    """A 402 is the workspace's PLAN (0.13.0, launch plan L4; TS twin): said in its own words - the server's sentence, which names
    what clears it and who can - and never as a sign-in problem (signing in again changes nothing)."""
    said = body.get("message") if isinstance(body, dict) and isinstance(body.get("message"), str) else "its plan doesn't cover this."
    _err(f"✘ {what} stopped at your workspace's plan: {said}")
    _err("  This isn't a sign-in problem - signing in again won't change it.")


def _api(path: str, method: str = "GET", body: Optional[dict] = None, bearer: Optional[str] = None, soft: bool = False) -> Tuple[int, Any]:
    global _host_announced
    if not _host_announced:
        _host_announced = True
        # Once per process, on stderr: WHICH server this command talks to (sandbox-first means a
        # missing config no longer fails loud, so the target must never be silent instead).
        _err(f"· decidio → {API}" + ("" if os.environ.get("DECIDIO_API_URL") else "  (default: Decidio — set DECIDIO_API_URL to point elsewhere)")
             + (f"  · links → {_APP_URL} (DECIDIO_APP_URL)" if _APP_URL_OVERRIDDEN else ""))
    headers = {"content-type": "application/json"}
    auth = TOKEN() if bearer is None else (bearer or None)
    # FAIL CLOSED on unreadable configuration (parity with the TS CLI): the .env we could not
    # read may name a self-hosted deployment, so guessing the public default WITH A CREDENTIAL in
    # hand is exactly the wrong move. Offline commands never reach here.
    if auth and _env_unreadable and not os.environ.get("DECIDIO_API_URL"):
        _err(f"✘ .env exists here but could not be read, so the target Decidio is unknown - refusing to send credentials to a guessed host ({API}).")
        _err("  Fix the file's permissions, or set DECIDIO_API_URL explicitly for this command. Nothing was sent.")
        raise SystemExit(1)
    # The wire rule, on the CLI door too — the ONE parsed chokepoint, not an inline regex
    # copy (A6, 0.1.12: the raw-string copies passed urllib-equivalent spellings the transport
    # then normalized to remote plaintext).
    if auth:
        from .signing import assert_safe_transport
        try:
            assert_safe_transport(API, True)
        except RuntimeError as e:
            _err(f"✘ {str(e).replace('[decidio] ', '', 1)}")
            raise SystemExit(1)
    if auth:
        headers["authorization"] = f"Bearer {auth}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read().decode()
            return r.status, (json.loads(text) if text else None)
    except urllib.error.HTTPError as e:
        text = e.read().decode()
        try:
            return e.code, json.loads(text)
        except Exception:
            return e.code, text
    except urllib.error.URLError as e:
        if soft:
            return 0, None   # an OPTIONAL call (the hand-off link): the caller degrades, the command goes on
        _err(f"✘ could not reach Decidio at {API} ({getattr(e, 'reason', e)}).")
        if "localhost" in API:
            # A dead localhost is almost always MISSING CONFIG (something overrode the sandbox
            # default), not a network problem — say the likely fix before generic advice.
            _err("  You're pointed at localhost — for Decidio's service run:")
            _err(f"    export DECIDIO_API_URL={_DEFAULT_API}")
            _err("  (or put that line in .env), then re-run this command.")
        else:
            _err("  Check your network, then re-run. If the URL is wrong, set DECIDIO_API_URL and retry.")
        raise SystemExit(1)


def _read_env() -> dict:
    out: dict = {}
    try:
        if not os.path.exists(ENV_PATH):
            return out
        text = open(ENV_PATH, encoding="utf-8").read()
    except Exception as e:  # noqa: BLE001 — warn-not-crash; see _warn_env_unreadable
        _warn_env_unreadable(e)
        return out
    for line in text.splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _write_secret_file(path: str, body: str) -> None:
    """Write a secrets file OWNER-ONLY (0600). Best-effort: Windows ignores POSIX modes (ACLs are
    inherited from the directory) and a chmod failure must never lose the write.
    TEMP + FSYNC + REPLACE (prodsec V033-02): a direct overwrite that fails half-way TRUNCATES the
    previous file - and for `.env.quickstart` the previous file is the only place the orphaned-token ids
    of earlier replacements live. The replace publishes the whole new file or nothing."""
    # THE TEMP FILE IS A SECRET FILE TOO (invariant-guard, 0.3.5): hardened BEFORE the replace (the ACL
    # travels with the file) and removed if the replace fails, so it can never be left behind.
    # `.env.*.tmp` is in the gitignore entries alongside the other secret-bearing names.
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, body.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    from .resume import harden_file as _harden_tmp
    _harden_tmp(tmp)
    try:
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:  # noqa: BLE001 - best effort; the error below is what matters
            pass
        raise
    try:
        os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001 — restricted FS: the write itself stands
        pass
    # ONE HARDENING PATH FOR EVERYTHING THIS SDK PROTECTS (F-009). This used to be a private,
    # weaker copy of the durable store's helper: it granted getpass.getuser() - who logged IN, not
    # who is writing - and it never checked whether the ACL it had just applied locked this process
    # out of its own credentials. harden_file resolves the effective token SID, keeps SYSTEM, reads
    # the file back to prove the restriction did not break access, and rolls the inheritance back
    # if it did. Best-effort by design: a failure never loses the write, but it is SAID.
    from .resume import harden_file as _harden_file
    _why = _harden_file(path)
    if _why:
        print(f"⚠ could not restrict {path} to owner-only on this Windows volume ({_why}) — it keeps the directory's inherited permissions. For production, move these values to a secret manager.", file=sys.stderr)


# THE TOKEN RECOVERY JOURNAL (prodsec V033-02, founder decision 2026-09-02: credential creation fails
# CLOSED if the journal cannot be made durable). Twin of cli.ts. Append-only JSON lines, owner-only,
# fsynced: `minted` BEFORE the credential file is written, `retired` AFTER a durable write or a proven
# revoke. `quickstart cleanup` sweeps outstanding entries and `doctor` names them. jtis only, never
# token values.
JOURNAL_PATH = ".decidio-token-journal"
# CORRUPTION IS UNCERTAINTY, NEVER ABSENCE (prodsec V035-01; see the TS twin): every non-blank row is
# parsed and schema-checked; anything else makes the journal UNTRUSTED - no mint, doctor red, cleanup
# non-zero, bytes preserved. Appends are framed (delimiter first if the file does not end with one; a
# schema version; a write loop until every byte is on disk before the fsync).
JOURNAL_SCHEMA = 1
_JOURNAL_EVENTS = ("probe", "minted", "retired")


class JournalCorruptError(Exception):
    def __init__(self, line: int, why: str):
        super().__init__(f"{JOURNAL_PATH} line {line}: {why}")
        self.line = line
        self.why = why


def _journal_row_problem(e) -> Optional[str]:
    if not isinstance(e, dict):
        return "not a JSON object"
    if "v" in e and (isinstance(e["v"], bool) or e["v"] != JOURNAL_SCHEMA):   # True == 1 in Python; TS refuses it
        return f"schema version {e.get('v')!r} is not {JOURNAL_SCHEMA}"
    if not isinstance(e.get("event"), str) or e["event"] not in _JOURNAL_EVENTS:
        return f"unknown event {e.get('event')!r}"
    if e["event"] != "probe" and (not isinstance(e.get("jti"), str) or not e["jti"].strip()):
        return f"{e['event']} row without a string jti"
    if e["event"] == "retired" and e.get("how") not in ("persisted", "revoked"):
        return f"retired row with how={e.get('how')!r}"
    return None


def _journal_rows() -> list:
    """Every non-blank row parsed and checked. Raises JournalCorruptError on the first row it cannot
    trust; every caller turns that into a refusal - never into "nothing owed"."""
    import json as _json
    if not os.path.exists(JOURNAL_PATH):
        return []
    rows = []
    with open(JOURNAL_PATH, encoding="utf-8") as fh:
        for i, line in enumerate(fh.read().split("\n"), start=1):
            if not line.strip():
                continue
            try:
                e = _json.loads(line)
            except Exception:  # noqa: BLE001
                raise JournalCorruptError(i, "not valid JSON (a torn or hand-edited row)") from None
            why = _journal_row_problem(e)
            if why:
                raise JournalCorruptError(i, why)
            rows.append(e)
    return rows


def _receipt_file_name(decision_id: str) -> str:
    """decidio-receipt-<id>.json with every character outside [A-Za-z0-9_-] escaped as `~` + hex code point, so two
    distinct ids can never share a file (first-run review of 0.4.1: dots were STRIPPED; TS twin receiptFileName)."""
    import re as _re_fn
    return "decidio-receipt-" + _re_fn.sub(r"[^A-Za-z0-9_-]", lambda m: "~" + format(ord(m.group(0)), "02x"), decision_id) + ".json"


def _write_receipt_file(name: str, data: str, say=print) -> str:
    """Writes a receipt unless one already exists: byte-identical is fine (receipts are immutable), DIFFERENT bytes
    are a refusal - never silently overwrite an audit artifact. Returns written / identical / conflict (TS twin)."""
    if os.path.exists(name):
        if open(name, encoding="utf-8").read() != data:
            _err(f"✘ {name} already exists with DIFFERENT bytes — refusing to overwrite an audit artifact. Move it aside or delete it, then re-run.")
            return "conflict"
        say(f"• {name} already exists (byte-identical — receipts are immutable); leaving it in place.")
        return "identical"
    with open(name, "w", encoding="utf-8") as fh:
        fh.write(data)
    return "written"


def _record_kind_of(credential) -> Optional[str]:
    """The record kind sealed into a receipt (approval / denial / decision), read from the canonical record the
    credential binds - the receipt's own bytes, never a second fetch (TS twin)."""
    import json as _json_rk
    try:
        rc = (credential or {}).get("credentialSubject", {}).get("recordCanonical")
        rec = _json_rk.loads(rc) if isinstance(rc, str) else rc
        kind = (rec or {}).get("recordKind")
        return kind if isinstance(kind, str) else None
    except Exception:  # noqa: BLE001 - a receipt without a readable canonical record simply has no kind to show
        return None


def _journal_append(entry: dict) -> None:
    import json as _json
    fresh = not os.path.exists(JOURNAL_PATH)
    row = (_json.dumps({"v": JOURNAL_SCHEMA, **entry, "at": _now_iso()}) + "\n").encode("utf-8")
    fd = os.open(JOURNAL_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        if not fresh:
            with open(JOURNAL_PATH, "rb") as _rb:
                _tail = _rb.read()
            if _tail and _tail[-1:] != b"\n":   # frame a torn previous row before appending
                _nl = b"\n"
                _w = 0
                while _w < len(_nl):
                    _w += os.write(fd, _nl[_w:])
        written = 0
        while written < len(row):
            written += os.write(fd, row[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    if fresh:
        try:
            os.chmod(JOURNAL_PATH, 0o600)
        except Exception:  # noqa: BLE001
            pass
        from .resume import harden_file as _hf
        _hf(JOURNAL_PATH)


def _now_iso() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _journal_probe() -> Optional[str]:
    """Prove the journal is READABLE and TRUSTED, then writable and durable, BEFORE minting. Returns the
    failure reason, or None."""
    try:
        _journal_rows()
    except Exception as e:  # noqa: BLE001
        return f"CORRUPT: {e}"
    try:
        _journal_append({"event": "probe"})
        return None
    except Exception as e:  # noqa: BLE001
        return str(e)


def _journal_minted(jti: str, agent_id: str, label: str) -> None:
    _journal_append({"event": "minted", "jti": jti, "agentId": agent_id, "label": label, "apiUrl": API})


def _journal_retire(jti: str, how: str) -> bool:
    """Records a hand-off (`persisted`) or a revocation (`revoked`). Returns False - and SAYS so - when the row could
    not be written: a silent failure here left a landed init token looking like a never-landed orphan (first-run
    review of 0.4.1; TS twin). The entry stays outstanding either way; cleanup re-tries revocations."""
    try:
        _journal_append({"event": "retired", "jti": jti, "how": how})
        return True
    except Exception as e:  # noqa: BLE001 - reported, never swallowed
        if how == "persisted":
            _err(f"  ⚠ could not note in {JOURNAL_PATH} that token {jti} was written to its credential file ({e}). The credential is safe in the file; doctor will list the token as live and held.")
        else:
            _err(f"  ⚠ could not note in {JOURNAL_PATH} that token {jti} was revoked ({e}). It IS revoked; a later cleanup will find the server already agrees and retire the row.")
        return False


def _journal_outstanding() -> list:
    """Minted jtis with no `retired` event - the tokens this directory still owes a revocation for.
    Raises JournalCorruptError (via _journal_rows) - callers refuse, never assume "nothing owed"."""
    minted: dict = {}
    for e in _journal_rows():
        if e["event"] == "minted":
            minted[e["jti"]] = e
        # ONLY A REVOCATION RETIRES A REVOCATION HANDLE (first-run review of 0.4.0; TS twin). A `persisted`
        # row retires nothing - it records that the token was HANDED to a credential file, which is what
        # separates a lost working credential from a never-landed orphan.
        if e["event"] == "retired" and e.get("how") == "persisted" and e["jti"] in minted:
            minted[e["jti"]] = {**minted[e["jti"]], "persisted": True}
        if e["event"] == "retired" and e.get("how") == "revoked":
            minted.pop(e["jti"], None)
    return list(minted.values())


def _credential_jtis_on_disk() -> set:
    """Token ids named in the credential files here: a live `init` token still HELD by its file is a
    developer's working credential, not something a tour cleanup may revoke (TS twin)."""
    import re as _re2
    out: set = set()
    for f in (".env", ".env.quickstart"):
        if not os.path.exists(f):
            continue
        try:
            text = open(f, encoding="utf-8").read()
        except Exception:  # noqa: BLE001
            continue
        for m in _re2.finditer(r"^\s*DECIDIO_(?:ORPHANED_)?TOKEN_JTI=(.+)$", text, _re2.M):
            for j in m.group(1).split(","):
                if j.strip():
                    out.add(j.strip())
    return out


def _journal_owed() -> list:
    """What `quickstart cleanup` REVOKES: the tour's own tokens (label "quickstart"), held by a file or not,
    and any token NEVER handed to a credential file (no `persisted` row: the write failed and so did the
    compensating revoke - the journal is its only handle). Never a developer's `init` credential that DID
    land. One predicate decides both "anything to clean?" and "what the sweep revokes" (TS twin)."""
    # A non-tour row without a `persisted` note is an orphan ONLY if no credential file here holds it: the file is the
    # proof it landed even when the note failed to write (first-run review of 0.4.1).
    held = _credential_jtis_on_disk()
    return [j for j in _journal_outstanding() if j.get("label") == "quickstart" or (not j.get("persisted") and j.get("jti") not in held)]


def _journal_unheld() -> list:
    """Live NON-tour tokens handed to a credential file that is no longer found here: cleanup NAMES them with
    the revoke command and never calls the journal clean over them, but does not kill a working credential it
    cannot see (TS twin)."""
    held = _credential_jtis_on_disk()
    return [j for j in _journal_outstanding() if j.get("label") != "quickstart" and j.get("jti") not in held and j.get("persisted")]


def _refuse_mint_no_journal(why: str) -> str:
    if why.startswith("CORRUPT: "):
        return f"✘ the token recovery journal cannot be trusted ({why[len('CORRUPT: '):]}) - it may hold the id of a token that is still live. Refusing to mint on top of uncertain history. Inspect the file, revoke anything it names (python -m decidio tokens list --mine), and repair or move it aside; every byte is left as found. Nothing was minted."
    return f"✘ could not write the token recovery journal ({JOURNAL_PATH}: {why}) - refusing to mint a credential this directory cannot record a revocation handle for. Fix the directory's permissions or free space and re-run. Nothing was minted."


def _upsert_env(updates: dict) -> None:
    # Update IN PLACE, never rewrite (the merge-and-rewrite dropped every
    # comment and blank line — "# Production database — do not touch" vanished unrecoverably,
    # since this file is gitignored). A user's line only changes when its KEY is being updated;
    # everything else survives byte-for-byte; new keys append.
    import re as _re

    remaining = dict(updates)
    updated_keys: set = set()
    lines: list = []
    try:
        if os.path.exists(ENV_PATH):
            for line in _re.split(r"\r?\n", open(ENV_PATH, encoding="utf-8").read()):
                m = _re.match(r"^\s*([A-Z_]+)=", line)
                # A hand-edited duplicate of an updated key is DROPPED, not kept (guard note:
                # last-wins on the next read would resurrect the stale value over the fresh one).
                if m and m.group(1) in updated_keys:
                    continue
                if m and m.group(1) in remaining:
                    updated_keys.add(m.group(1))
                    lines.append(f"{m.group(1)}={remaining.pop(m.group(1))}")
                else:
                    lines.append(line)
    except Exception:  # noqa: BLE001 — unreadable existing file: start fresh; the write still lands
        lines = []
    while lines and lines[-1] == "":
        lines.pop()
    for k, v in remaining.items():
        lines.append(f"{k}={v}")
    _write_secret_file(ENV_PATH, "\n".join(lines) + "\n")


# The tour's approval prompt is a QUESTION (first-run review of 0.4.0: the old Enter-to-approve prompt read the
# literal `no` as approval, and no suite ever drove the branch). One pure rule, shared with the TS twin
# through packages/conformance/vectors/consent-answers.json: an explicit yes approves, an explicit no
# rejects, anything else - a bare Enter included - asks again.
_APPROVE_WORDS = ("y", "yes", "approve", "approved")
_REJECT_WORDS = ("n", "no", "reject", "rejected", "deny", "denied")


def approval_answer(answer) -> str:
    a = str(answer if answer is not None else "").strip().lower()
    if a in _APPROVE_WORDS:
        return "approve"
    if a in _REJECT_WORDS:
        return "reject"
    return "again"


# ---- terminal presentation (0.4.2 layout pass; TS twin) --------------------------------------------------------------
_TTY_OUT = bool(getattr(sys.stdout, "isatty", lambda: False)()) and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"


def _paint(code: str, s: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m" if _TTY_OUT else s


def _bold(s: str) -> str:
    return _paint("1", s)


def _dim(s: str) -> str:
    return _paint("2", s)


def _link(url: str) -> str:
    """A clickable link on terminals that speak OSC 8; the plain URL elsewhere."""
    return f"\x1b]8;;{url}\x1b\\{url}\x1b]8;;\x1b\\" if _TTY_OUT else url


_FRAME_WIDTH = 84
# --explain (UAT round 2, 2026-09-04; TS twin): the tour prints one line per event and frames per step; the narration
# that explains each step is printed only when asked for.
_EXPLAIN = False


def _visible_length(s: str) -> int:
    import re as _re_v
    return len(_re_v.sub(r"\x1b\[[0-9;]*m|\x1b\]8;;[^\x1b]*\x1b\\", "", s))


def _frame_width(rows) -> int:
    """The frame width for THIS content: at least _FRAME_WIDTH, wide enough for the widest row, never past the terminal."""
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = 120
    if cols <= 20:
        cols = 120   # 0 / tiny = unknown (an unsized pty), not "wrap everything"
    widest = max((_visible_length(r) for r in rows), default=0)
    # NEVER wider than the terminal: the floor used to win over `cols - 1`, so an 80-column window got 84-wide frames and
    # wrapped every border (prodsec review of 0.4.3). The driver that gates the tours now also runs at 80 columns.
    return min(cols - 1, max(_FRAME_WIDTH, widest + 4))


def _block(n: str, title: str, rows, tone: Optional[str] = None) -> None:
    """One framed step block: a numbered heading, then rows (wrapped at word boundaries inside the frame). The tone paints
    the frame and its title only (UAT round 2): orange = the choice to make, green = the outcome went the run's way,
    red = a rejection. 256-colour orange, yellow on a 16-colour terminal; nothing under NO_COLOR or a pipe."""
    if tone == "choice":
        tint = "38;5;208" if ("256" in (os.environ.get("TERM") or "") or os.environ.get("COLORTERM") or os.environ.get("WT_SESSION")) else "33"
    else:
        tint = {"good": "32", "bad": "31"}.get(tone or "")

    def f(s: str) -> str:
        return _paint(tint, s) if tint else s
    width = _frame_width(rows)
    inner = width - 4
    head = f"┌ {n} {title} "
    print(f(head + "─" * max(1, width - _visible_length(head) - 1) + "┐"))
    for row in rows:
        pieces = []
        if _visible_length(row) <= inner:
            pieces.append(row)
        else:
            # escape-aware word wrap (a styled label is zero-width, never split); continuation lines hang under the label
            cur = ""
            for w in row.split(" "):
                if cur and _visible_length(cur) + 1 + _visible_length(w) > inner:
                    pieces.append(cur)
                    cur = " " * min(13, max(0, inner - 24)) + w
                else:
                    cur = f"{cur} {w}" if cur else w
            if cur:
                pieces.append(cur)
        for piece in pieces:
            print(f"{f('│')} {piece}{chr(27) + '[0m' if _TTY_OUT else ''}{' ' * max(0, inner - _visible_length(piece))} {f('│')}")
    print(f("└" + "─" * (width - 2) + "┘"))


_APP_URL_SHAPE = _re_did.compile(r"^https?://[\x21-\x7e]+$")


def _app_url_for(api, override=None):
    """The web app that goes with a Decidio API origin, for the links the CLI prints (launch plan L1c). DECIDIO_APP_URL
    wins when it is a plain http(s) address in printable ASCII (guard W1 on #743: a cloned repo's .env can set it, and an
    escape sequence in it would reach the terminal's hyperlinks); anything else is ignored, with one warning at load.
    Decidio's own hosts map to their own web app: the staging API (its onrender host, or mcp-staging) to
    staging.decidioai.com, production's (mcp.decidioai.com) to app.decidioai.com. Any other origin serves its web app
    itself. Twin: cli.ts appUrlFor."""
    if override is None:
        override = os.environ.get("DECIDIO_APP_URL")
    o = (override or "").strip(" \t\r\n")
    if _APP_URL_SHAPE.fullmatch(o):
        return o.rstrip("/")
    base = api.rstrip("/")
    return {
        "https://decidio-api.onrender.com": "https://staging.decidioai.com",
        "https://mcp-staging.decidioai.com": "https://staging.decidioai.com",
        "https://mcp.decidioai.com": "https://app.decidioai.com",
        "https://api.decidioai.com": "https://app.decidioai.com",   # production's REST address (the phone's), after the window
    }.get(base, base)


_APP_URL = _app_url_for(API)
# Links that DECIDIO_APP_URL sends elsewhere are named on the host line, as the API host is: a repo's .env can set it.
_APP_URL_OVERRIDDEN = _APP_URL != _app_url_for(API, "")


def _enter_lab() -> None:
    """THE HOSTED TOUR RUNS ON THE LAB (launch plan L9, founder F-1106-C4 (a); TS twin enterLab): `quickstart` with no
    DECIDIO_API_URL (shell or .env) points this run at the lab, so the tour's synthetic agent and its permanent sealed record
    never land in a production workspace. The tour's .env then names the lab, so its follow-up commands stay there."""
    global API, _APP_URL, _APP_URL_OVERRIDDEN
    API = _LAB_API
    os.environ["DECIDIO_API_URL"] = _LAB_API
    _APP_URL = _app_url_for(API)
    _APP_URL_OVERRIDDEN = _APP_URL != _app_url_for(API, "")


def _enter_lab_or_refuse() -> Optional[int]:
    """Move an unconfigured quickstart to the lab - unless a credential is configured that carries no host of its own (a
    DECIDIO_SESSION_TOKEN, or an agent token in the shell or .env): it was issued for the default, and the move would send it
    to the lab (invariant guard B1, cycle c-sdk-prod). Then refuse, nothing sent. TS twin enterLabOrRefuse."""
    if os.environ.get("DECIDIO_API_URL"):
        return None
    held = next((k for k in ("DECIDIO_SESSION_TOKEN", "DECIDIO_API_TOKEN") if (os.environ.get(k) or "").strip()), None)
    if held:
        _err(f"✘ {held} is set for the default Decidio ({_DEFAULT_API}), and the tour runs on the lab ({_LAB_API}) - so it isn't sent there. Nothing was sent.")
        _err(f"  Set DECIDIO_API_URL for the tour (the lab: DECIDIO_API_URL={_LAB_API}, then sign in there), or unset {held} - or run it on this machine: npx @decidio/sdk quickstart --demo")
        return 2
    _enter_lab()
    return None
_app_url_env = (os.environ.get("DECIDIO_APP_URL") or "").strip(" \t\r\n")
if _app_url_env and not _APP_URL_SHAPE.fullmatch(_app_url_env):
    print("⚠ ignoring DECIDIO_APP_URL: it must be a plain http(s) address (printable characters only)", file=sys.stderr)


# ---- the stored sign-in (0.4.2, UAT ruling 2026-09-03; TS twin) ------------------------------------------------------
# Sign in ONCE: the workspace session is kept in the user's profile, owner-only, bound to the terminal it was created in
# wherever the terminal identifies itself, and ends at the earliest of the server's 30 days, that terminal closing,
# `logout`, or `quickstart cleanup` - the lifetime the web app's sign-in has. Never in the project directory.
# FROM THE SHELL, NEVER THE PROJECT .env (3A follow-up; TS twin): which terminal bound the session, and WHERE the session
# and the trust store live, are the shell's and the OS's to say. Read from _SHELL_ENV (snapshotted before .env was
# promoted) so a cloned repo's .env cannot set XDG_CONFIG_HOME/LOCALAPPDATA/HOME to a path inside itself - which would put
# the session token and issuers.json in the repo AND let the repo plant a DID that `receipt`/`verify` then show as
# "remembered on this computer". (The .env autoload no longer promotes these, but reading _SHELL_ENV is the rule that
# holds even if a variable reaches os.environ another way.)
def _terminal_id() -> str:
    for k in ("WT_SESSION", "VSCODE_IPC_HOOK_CLI", "TERM_SESSION_ID", "ITERM_SESSION_ID", "TMUX_PANE", "KONSOLE_DBUS_SESSION", "GNOME_TERMINAL_SCREEN", "WINDOWID"):
        v = _SHELL_ENV.get(k)
        if v:
            return f"{k}={v}"
    return ""


def _session_dir() -> str:
    if os.name == "nt":
        home = _SHELL_ENV.get("USERPROFILE") or os.path.expanduser("~")
        base = _SHELL_ENV.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
    else:
        home = _SHELL_ENV.get("HOME") or os.path.expanduser("~")
        base = _SHELL_ENV.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    return os.path.join(base, "decidio")


def _session_file() -> str:
    return os.path.join(_session_dir(), "session.json")


def _jwt_expiry(token: str):
    import base64 as _b64
    import datetime as _dt
    import json as _json_e
    try:
        part = token.split(".")[1]
        payload = _json_e.loads(_b64.urlsafe_b64decode(part + "=" * (-len(part) % 4)).decode("utf-8"))
        exp = payload.get("exp")
        return _dt.datetime.fromtimestamp(exp, tz=_dt.timezone.utc) if isinstance(exp, (int, float)) else None
    except Exception:  # noqa: BLE001  lint-allow: not a ledger - a token whose payload is not JSON has no readable expiry; the 30-day default applies
        return None


def _save_session(token: str, email=None) -> dict:
    import datetime as _dt
    import json as _json_s
    os.makedirs(_session_dir(), exist_ok=True)
    exp = _jwt_expiry(token) or (_dt.datetime.now(tz=_dt.timezone.utc) + _dt.timedelta(days=30))
    s = {"v": 1, "api": API, "token": token, "email": email, "expiresAt": exp.isoformat(), "terminal": _terminal_id(),
         "createdAt": _dt.datetime.now(tz=_dt.timezone.utc).isoformat()}
    _write_secret_file(_session_file(), _json_s.dumps(s) + "\n")
    return s


def _load_session():
    """The stored session when it is for THIS Decidio, unexpired, and from this terminal (or unbound)."""
    import datetime as _dt
    import json as _json_l
    f = _session_file()
    if not os.path.exists(f):
        return None
    try:
        s = _json_l.loads(open(f, encoding="utf-8").read())
    except Exception as e:  # noqa: BLE001 - reported and removed, never silently "not signed in"
        _err(f"⚠ the stored sign-in ({f}) could not be read ({e}) - removing it; sign in again with: python -m decidio login")
        _end_session()
        return None
    if not isinstance(s, dict) or s.get("v") != 1 or not isinstance(s.get("token"), str) or s.get("api") != API:
        return None
    try:
        exp = _dt.datetime.fromisoformat(str(s.get("expiresAt")).replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001 - an unreadable expiry is an expired session
        exp = _dt.datetime.fromtimestamp(0, tz=_dt.timezone.utc)
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=_dt.timezone.utc)
    if exp <= _dt.datetime.now(tz=_dt.timezone.utc):
        _end_session()
        return None
    here = _terminal_id()
    if s.get("terminal") and s.get("terminal") != here:   # bound = valid only where it was bound (an id-less terminal gets nothing)
        return None
    return s


def _end_session() -> bool:
    f = _session_file()
    if not os.path.exists(f):
        return False
    try:
        os.remove(f)
        return True
    except OSError as e:
        _err(f"⚠ could not remove the stored sign-in ({f}: {e}) - remove it by hand.")
        return False


# ---- the host's issuer DID, remembered (3A, founder-approved 2026-09-24; TS twin) --------------------------------------
# A receipt names its own issuer, and pinning to that is circular: any key can sign a file that names itself. Signing in
# (or init) against a host is when this CLI first talks to that host on purpose, so it records the DID the host publishes
# at /api/did beside the host's address, next to the stored sign-in - and keeps it past logout and expiry, because an
# anchor re-learned every 30 days is not an anchor. A later sign-in that sees a DIFFERENT DID warns loudly and changes
# nothing. `verify` pins to the remembered DID by default. The TS CLI reads and writes the same file.
_DID_KEY_SHAPE = _re_did.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}\Z")


def _issuers_file() -> str:
    return os.path.join(_session_dir(), "issuers.json")


# A host we key literally, so two spellings never collapse into one trusted origin: ASCII letters/digits/hyphen in
# dot-separated labels. TS twin STORE_HOST_LABELS.
_STORE_HOST_LABELS = _re_did.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\Z")


def _issuer_store_key(url: str) -> str:
    """The issuer store's key for a Decidio address: its origin (scheme + lowercased host + non-default port), by a
    RESTRICTED parser that FAILS CLOSED, identically to the TS twin issuerStoreKey. It deliberately does NOT canonicalise
    the way a browser URL does: keying `https://%64ecidio-api.onrender.com` (or an IDN / numeric-shorthand / backslash
    spelling) by the real host would let a planted store entry under such a spelling be trusted AS the real host - and TS,
    on `new URL().origin`, DID canonicalise these, so the two SDKs also disagreed. Now both accept only a bare http(s)://,
    an ASCII-label host or a bracketed real IP literal as an origin; anything else keys as its trimmed lowercased self,
    which cannot equal a real origin and so is never mistaken for one. Both smokes run the same cases."""
    raw = url.strip()
    low = raw.rstrip("/").lower()
    m = _re_did.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]*)(?:[/?#]|\Z)", raw)   # require an explicit "://" authority
    if not m:
        return low
    scheme = m.group(1).lower()
    if scheme not in ("http", "https"):
        return low
    authority = m.group(2)
    at = authority.rfind("@")
    if at >= 0:
        authority = authority[at + 1:]   # userinfo is not part of the origin
    port_str = ""
    if authority.startswith("["):
        rb = authority.find("]")
        if rb < 0:
            return low
        inner = authority[1:rb].lower()
        rest = authority[rb + 1:]
        try:
            import ipaddress as _ip
            if not isinstance(_ip.ip_address(inner), _ip.IPv6Address):
                return low
        except ValueError:
            return low                    # a bracketed literal that is not a real IPv6: fail closed
        if rest != "":
            if not _re_did.match(r"^:[0-9]+\Z", rest):
                return low
            port_str = rest[1:]
        host = f"[{inner}]"
    else:
        c = authority.rfind(":")
        if c >= 0:
            p = authority[c + 1:]
            if not _re_did.match(r"^[0-9]+\Z", p):
                return low
            port_str = p
            host = authority[:c].lower()
        else:
            host = authority.lower()
        if not _STORE_HOST_LABELS.match(host):   # %-encoding, unicode/IDN, backslashes, empty: fail closed
            return low
    port = None if port_str == "" else int(port_str)
    dflt = 443 if scheme == "https" else 80
    return f"{scheme}://{host}:{port}" if port is not None and port != dflt else f"{scheme}://{host}"


def _read_issuer_store() -> dict:
    """Every remembered origin -> {did, firstSeen}. RAISES ValueError when the file exists but cannot be read, has the
    wrong shape (a version that is not the integer 1 - `true` is not 1), or spells one origin twice with different
    DIDs: an unreadable trust store is uncertainty, never "nothing remembered" (TS twin readIssuerStore)."""
    import json as _json_i
    f = _issuers_file()
    if not os.path.exists(f):
        return {}
    try:
        s = _json_i.loads(open(f, encoding="utf-8").read())
    except (OSError, ValueError) as e:
        raise ValueError(str(e)) from e
    v = s.get("v") if isinstance(s, dict) else None
    hosts = s.get("hosts") if type(v) is int and v == 1 else None
    if not isinstance(hosts, dict):
        raise ValueError("not a v1 issuer store")
    out: dict = {}
    for h, e in hosts.items():
        if not (isinstance(e, dict) and isinstance(e.get("did"), str) and _DID_KEY_SHAPE.match(e["did"]) and isinstance(e.get("firstSeen"), str)):
            raise ValueError(f"malformed entry for {h}")
        k = _issuer_store_key(h)
        if k in out and out[k]["did"] != e["did"]:
            raise ValueError(f"two entries for {k} name different DIDs")
        out.setdefault(k, {"did": e["did"], "firstSeen": e["firstSeen"]})
    return out


def _remembered_issuer(host: Optional[str] = None):
    """The {did, firstSeen} remembered for a Decidio address (default: the one this command talks to), or None. Raises
    like the store read."""
    return _read_issuer_store().get(_issuer_store_key(API if host is None else host))


def _verify_host() -> str:
    """The address `verify` resolves its remembered DID for: DECIDIO_API_URL from the SHELL, else the hosted service -
    verify reads no .env. ONE rule in both SDKs (TS twin verifyHost); `receipt` uses it to decide whether the flagless
    command it prints would land on the same trust anchor."""
    return _SHELL_ENV.get("DECIDIO_API_URL", _DEFAULT_API).rstrip("/")


def _warn_issuer_changed(known: dict, seen: str, via: str) -> None:
    """Said whenever a DID seen for a host differs from the one remembered for it - at sign-in, at init, and in a
    verify response: loud, and never adopted (TS twin warnIssuerChanged)."""
    key = _issuer_store_key(API)
    _err(f"⚠ THE ISSUER DID OF {key} HAS CHANGED — it was NOT adopted.")
    _err(f"    remembered (first seen {str(known.get('firstSeen'))[:10]}):  {known['did']}")
    _err(f"    {via} now says:  {seen}")
    _err("  Receipts from this host are still verified against the REMEMBERED DID. A new DID means a new signing key: a planned")
    _err("  rotation, another deployment behind the same address, or someone answering in its place. Confirm it with the host's")
    _err(f"  operator out of band before trusting it; to adopt it, remove the \"{key}\" entry from {_issuers_file()} and sign in again.")


def _remember_host_issuer() -> None:
    """At sign-in and init: fetch this host's published DID and remember it on first sight; a DIFFERENT DID later is
    shouted about and NOT adopted. Best-effort - a sign-in never fails over it - but every outcome is said."""
    import datetime as _dt
    import json as _json_w
    try:
        store = _read_issuer_store()
    except ValueError as e:
        _err(f"⚠ the issuer DIDs this computer remembers ({_issuers_file()}) could not be read ({e}) — left as found, nothing new remembered. Repair the file or move it aside.")
        return
    try:
        status, body = _api("/api/did", bearer="", soft=True)
    except Exception as e:  # noqa: BLE001 - a read timeout is not a URLError; remembering must never break a sign-in
        status, body = 0, None
        _err(f"  (could not fetch {API}/api/did: {e})")
    did = body.get("did") if isinstance(body, dict) and isinstance(body.get("did"), str) and _DID_KEY_SHAPE.match(body["did"]) else None
    if not did:
        print(_dim(f"  ({API}/api/did did not answer with a DID ({status or 'no response'}), so this host's issuer is not remembered yet — verify needs --issuer for its receipts until a later sign-in remembers it)"))
        return
    key = _issuer_store_key(API)
    known = store.get(key)
    if known and known.get("did") == did:
        return
    if known:
        _warn_issuer_changed(known, did, f"{API}/api/did")
        return
    store[key] = {"did": did, "firstSeen": _dt.datetime.now(tz=_dt.timezone.utc).isoformat()}
    try:
        os.makedirs(_session_dir(), exist_ok=True)
        _write_secret_file(_issuers_file(), _json_w.dumps({"v": 1, "hosts": store}, indent=2) + "\n")
    except OSError as e:
        _err(f"⚠ could not remember this host's issuer DID ({_issuers_file()}: {e}) — verify will need --issuer for its receipts.")
        return
    print(f"  ✔ remembered this host's issuer DID (from {API}/api/did) — verify pins its receipts to it, no --issuer needed: {did}")


def _host_anchor(body) -> Optional[str]:
    """The DID a receipt fetched from THIS host is pinned to. The DID remembered for this host wins: a server naming a
    DIFFERENT issuer (`expectedIssuer`) is warned about exactly like a changed /api/did and NOT followed. With nothing
    remembered: the server's CONFIGURED issuer (`expectedIssuer`), never the credential's own `issuer`, which is only
    what the file claims. None when neither exists, and when the store cannot be read (said): a server's DID that cannot
    be checked against the remembered one is no pin (TS twin hostAnchor)."""
    e = body.get("expectedIssuer") if isinstance(body, dict) else None
    named = e if isinstance(e, str) and _DID_KEY_SHAPE.match(e) else None
    try:
        mem = _remembered_issuer()
    except ValueError as x:
        _err(f"⚠ the issuer DIDs this computer remembers ({_issuers_file()}) could not be read ({x}) — no trust anchor until it is repaired or moved aside.")
        return None
    if mem and named and mem["did"] != named:
        _warn_issuer_changed(mem, named, "this server's verify response")
    return mem["did"] if mem else named


# Every sign-in this CLI completes says it is the command line's (cycle ai-cli-fence; founder F-1109-25 (a)): the server marks the
# session, and a browser or phone opened from it with a hand-off, so it can't show AI assistants more or confirm a name as anything
# but a person - that is done on the web or the phone. Nothing else changes; a server that predates it ignores the field.
_CLI_SIGN_IN = "cli"


def _login_flow(purpose: str, email_arg=None):
    """Sign in interactively and STORE the session: the CLI requests the sign-in email itself (first-run review of
    0.4.1: "request a link from the app" stalled the founder), you paste the link or its code."""
    import re as _re_l
    print("Sign in once — kept on this computer for 30 days, or until this terminal closes, logout, or cleanup." if purpose == "Signing in" else f"{purpose} needs your Decidio workspace sign-in — once: kept on this computer for 30 days, or until this terminal closes, logout, or cleanup.")
    email = email_arg if email_arg else _ask("  email: ")
    if not email:
        print("  ✘ no email given - re-run when you have it.")
        return None
    import getpass
    try:
        password = getpass.getpass("  password (Enter = emailed sign-in link): ")
    except EOFError:
        password = ""
    if password:
        status, body = _api("/demo/login", "POST", {"email": email, "password": password, "client": _CLI_SIGN_IN}, bearer="")
        if 200 <= status < 300 and isinstance(body, dict) and body.get("token"):
            s = _save_session(body["token"], email)
            print(f"  ✔ signed in as {email} until {s['expiresAt'][:10]}" + ("" if s.get("terminal") else _dim(" (no terminal id here: the sign-in ends on logout or cleanup, not on close)")))
            _remember_host_issuer()
            return body["token"]
        e0 = body.get("error") if isinstance(body, dict) else None
        print(f"  ✘ password sign-in failed ({status}){' — ' + e0 if e0 else ''}. No problem — the emailed link works for every account:")
    status, body = _api("/demo/login-link", "POST", {"email": email}, bearer="")
    if not (200 <= status < 300):
        e1 = body.get("error") if isinstance(body, dict) else None
        print(f"  ✘ could not request a sign-in email ({status}){' — ' + e1 if e1 else ''}. Check the address and re-run.")
        return None
    print(f"  ✔ sign-in email requested for {email} — check your inbox and spam; paste the link (or its login= code; single-use, 15 minutes)")
    if is_lab_api(API):
        print(_dim("    invite-only lab: a link arrives only for an invited address — not invited yet? request access: decidioai.com/#early-access"))
    else:
        print(_dim(f"    no email? the address needs a Decidio account first - ask your workspace owner for an invite, or sign up at {_APP_URL}"))
    pasted = _ask("  link or code: ")
    if not pasted:
        print("  ✘ nothing pasted — re-run when you have the email.")
        return None
    m = _re_l.search(r"[?&]login=([^&\s]+)", pasted)
    link_token = urllib.parse.unquote(m.group(1)) if m else pasted
    status, body = _api("/demo/login-consume", "POST", {"token": link_token, "client": _CLI_SIGN_IN}, bearer="")
    if 200 <= status < 300 and isinstance(body, dict) and body.get("token"):
        s = _save_session(body["token"], email)
        print(f"  ✔ signed in as {email} until {s['expiresAt'][:10]}" + ("" if s.get("terminal") else _dim(" (no terminal id here: the sign-in ends on logout or cleanup, not on close)")))
        _remember_host_issuer()
        return body["token"]
    e2 = body.get("error") if isinstance(body, dict) else None
    print(f"  ✘ that link didn't work ({status}){' — ' + e2 if e2 else ''}.")
    print("  Sign-in links are single-use and expire in 15 minutes — request a fresh one and re-run.")
    return None


def _cmd_login(email_arg=None) -> int:
    from .signing import assert_safe_transport as _ast
    try:
        _ast(API, True)
    except RuntimeError:
        _err(f"✘ refusing to send workspace credentials over plaintext http to {API}.")
        return 1
    s = _load_session()
    if s:
        who = f" as {s['email']}" if s.get("email") else ""
        print(f"• already signed in{who} on this terminal until {str(s.get('expiresAt'))[:10]} - run `python -m decidio logout` first to switch accounts.")
        return 0
    return 0 if _login_flow("Signing in", email_arg) else 1


def _cmd_logout() -> int:
    if _end_session():
        # SAY WHAT THIS DOES (prodsec second pass on 0.4.3, Low): it forgets the stored sign-in on this computer. The
        # session token itself is not invalidated - no server-side revocation exists yet - so the wording must not imply one.
        print("✔ signed out — the stored sign-in is removed from this computer.")
        print(f"  {_TRUTH_SESSION}; if you exported DECIDIO_SESSION_TOKEN or pasted the link anywhere else, those copies still work.")
    else:
        print("• no stored sign-in on this machine for this Decidio.")
    if os.environ.get("DECIDIO_SESSION_TOKEN"):
        print("  • DECIDIO_SESSION_TOKEN is still exported in this shell — unset it too (bash: unset DECIDIO_SESSION_TOKEN · PowerShell: Remove-Item Env:DECIDIO_SESSION_TOKEN).")
    return 0


def _stdin_is_console() -> bool:
    """Windows: isatty() is True for NUL and other character devices, which are not consoles - ask the console API."""
    if os.name != "nt":
        return sys.stdin.isatty()
    try:
        import ctypes
        import msvcrt
        handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        mode = ctypes.c_uint32()
        return bool(ctypes.windll.kernel32.GetConsoleMode(ctypes.c_void_p(handle), ctypes.byref(mode)))
    except Exception:  # noqa: BLE001 - no console API, no console
        return False


def _read_answer_nonblocking(prompt: str, is_settled) -> Optional[str]:
    """Print `prompt` and read ONE line without blocking the watch on the gated call: returns the line, or None the
    moment is_settled() turns true (the decision arrived from the web app or a phone). Raises EOFError when stdin ends.
    Three stdin shapes: a Windows console (the key buffer, echoed by hand - a console read left pending would block the
    process at exit), a Windows pipe or NUL (a daemon reader thread; select() does not take pipes there), and POSIX
    (select on stdin; the tty delivers whole lines)."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    import time as _time
    if os.name == "nt" and not _stdin_is_console():
        import threading as _threading
        slot: dict = {}

        def _reader() -> None:
            try:
                slot["line"] = sys.stdin.readline()
            except Exception as e:  # noqa: BLE001 - reported as end of input below
                slot["err"] = e
        _threading.Thread(target=_reader, daemon=True).start()
        while True:
            if is_settled():
                return None
            if "err" in slot or slot.get("line") == "":
                raise EOFError
            if "line" in slot:
                return str(slot["line"]).rstrip("\r\n")
            _time.sleep(0.05)
    if os.name == "nt":
        import msvcrt
        buf = ""
        while True:
            if is_settled():
                return None
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\r", "\n"):
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    return buf
                if ch == "\x08":
                    if buf:
                        buf = buf[:-1]
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                    continue
                if ch == "\x03":
                    raise KeyboardInterrupt
                if ch == "\x1a":
                    raise EOFError
                buf += ch
                sys.stdout.write(ch)
                sys.stdout.flush()
            else:
                _time.sleep(0.05)
    import select
    while True:
        if is_settled():
            return None
        ready, _, _ = select.select([sys.stdin], [], [], 0.2)
        if ready:
            line = sys.stdin.readline()
            if line == "":
                raise EOFError
            return line.rstrip("\r\n")


def _session_reminder() -> None:
    """Printed on EVERY end of the tour (approved, rejected, stopped): the exported workspace credential reaches child
    processes, and the reminder used to live only on the approval path (first-run review of 0.4.1; TS twin)."""
    print("  ⚠ agent code launched from THIS terminal inherits your sign-in — run logout first (it forgets the sign-in here; the token itself stays valid until it expires); if you")
    print("    exported DECIDIO_SESSION_TOKEN, unset it " + _dim("(bash/zsh: unset DECIDIO_SESSION_TOKEN · PowerShell: Remove-Item Env:DECIDIO_SESSION_TOKEN)"))


def _ask(prompt: str) -> Optional[str]:
    """input() that tolerates an abruptly-closed stdin (a devnull/closed stdin can
    slip past isatty() on some Windows hosts, and the raw EOFError traceback became the sign-in
    experience). None means "stdin ended" — the caller aborts down its existing no-credential
    path with the headless guidance, never a traceback."""
    try:
        # The prompt itself rides stderr - prompts are dialogue, not results, and a --json pipe
        # must stay pure even when a sign-in prompt fires first.
        print(prompt, end="", file=sys.stderr, flush=True)
        return input().strip()
    except EOFError:
        _err("✘ stdin ended at the sign-in prompt — this run is effectively headless.")
        _err("  Set DECIDIO_SESSION_TOKEN (a sign-in link's ?login= value is the token) and re-run.")
        return None


def _acquire_session() -> Optional[str]:
    """Owner SESSION token. Sources in order: DECIDIO_SESSION_TOKEN env, the stored sign-in, then an interactive
    sign-in that stores itself (TS twin acquireSession). Never written to the project directory."""
    from .signing import assert_safe_transport
    try:
        assert_safe_transport(API, True)
    except RuntimeError:
        _err(f"✘ refusing to send workspace credentials over plaintext http to {API} — use https (or localhost for local dev).")
        return None
    if os.environ.get("DECIDIO_SESSION_TOKEN"):
        return os.environ["DECIDIO_SESSION_TOKEN"]
    stored = _load_session()
    if stored:
        return stored["token"]
    # a real console, not isatty(): NUL and other character devices pass isatty() on Windows (the TS twin's isTTY does
    # not), and the Linux gate is where that difference showed as two vectors passing on one OS only.
    if not _stdin_is_console():
        _err("✘ This command needs your Decidio workspace sign-in, and this terminal can't prompt for one.")
        _err("  Fix: run `python -m decidio login` in an interactive terminal first (the sign-in is stored for this terminal),")
        _err("  or set DECIDIO_SESSION_TOKEN (exchange a sign-in link at POST /demo/login-consume with {\"token\": \"<login value>\", \"client\": \"cli\"}; the response's \"token\").")
        return None
    return _login_flow("This command")


# The take-away snippet init prints, in ONE constant printed VERBATIM: smoke.py runs ast.parse
# over this exact string, so a syntax error here fails CI instead of landing in the user's first
# copy-paste (the old closing line — "await guard resume controller
# .handle(...)" — was prose dressed as code, a SyntaxError the moment anyone pasted it).
INIT_SNIPPET = """\
from decidio import guard

@guard.approve(lambda o: {"action": "createOpportunity", "amount": o["amount"], "scope": "Opportunity"})
def create_opp(o):
    return {"id": "006X", "amount": o["amount"]}  # your real action - runs only after the gate says yes

stop_worker = guard.worker()  # durable resume with nothing to host: finishes any parked approval
"""


def _revoke_fresh_mint(jti: str, bearer: Optional[str], write_error: BaseException, target: str) -> bool:
    """A LIVE TOKEN WAS MINTED THIS RUN AND ITS ONLY LOCAL HOME JUST FAILED TO WRITE (retest V030-05).
    The mint happens before the secret is persisted, so a final write that fails - disk full, a
    permission flip, the path swapped underneath us - used to leave a live credential with nothing
    on disk naming it, and an unhandled traceback. Compensate: revoke it with the bearer that minted
    it, and say the jti out loud either way (revocation metadata, not a secret; the server's token
    list is the ledger of record). Twin of cli.ts revokeFreshMint. True when nothing live is left."""
    # The jti goes in the FIRST line: the DELETE below rides _api(), whose network-failure branch
    # exits the process, and a live token must never leave the terminal without its revocation id.
    _err(f"✘ could not write {target} ({write_error}). The token minted a moment ago (jti {jti}) is LIVE until revoked - revoking it now.")
    status, _body = _api(f"/api/workspace/agent-token/{jti}", "DELETE", bearer=bearer)
    if 200 <= status < 300:
        _journal_retire(jti, "revoked")
        _err(f"  ✔ the token minted a moment ago (jti {jti}) was REVOKED again, so nothing live was left behind. Fix the cause above and re-run - it will mint a fresh one.")
        return True
    try:
        _known = any(j.get("jti") == jti for j in _journal_outstanding())
    except Exception:  # noqa: BLE001 - an unreadable journal is reported as "not recorded" (the safe direction)
        _known = False
    if _known:
        _err(f"  Its id is kept in {JOURNAL_PATH} (owner-only, append-only) until it is revoked - `quickstart cleanup` retries it, and `doctor` names it.")
    else:
        _err("  Its id is NOT recorded anywhere but this terminal (the journal write is what failed) - write it down now and revoke it by hand.")
    _err(f"  ⚠ the token minted a moment ago (jti {jti}) is LIVE and could NOT be revoked ({status}). Revoke it by hand, or re-run init - the server keeps one active token per agent, so a fresh mint supersedes it:")
    _err(f"    python -m decidio tokens revoke {jti}")
    _err("    python -m decidio tokens list --mine")
    return False


def cmd_init(agent_id: str, force: bool = False, expires_days: Optional[int] = None) -> int:
    # BEFORE ANYTHING SERVER-SIDE: if git already tracks the file we would write the key into,
    # stop now. Refusing later would leave an orphaned registration and a live token behind for a
    # run that could never finish safely.
    if not _assert_not_tracked(ENV_PATH):
        return 1
    _err(f'Registering agent "{agent_id}" with Decidio at {API}…')
    # CLIENT-SIDE KEYGEN: generate the Ed25519 keypair LOCALLY and register only the PUBLIC
    # did:key. The private key NEVER crosses the wire — it goes straight to this host's env.
    existing_env = _read_env()
    existing_key = existing_env.get("DECIDIO_AGENT_KEY")
    source_system = os.environ.get("DECIDIO_SOURCE_SYSTEM") or existing_env.get("DECIDIO_SOURCE_SYSTEM")

    # NEVER silently orphan a different agent's key (parity with the TS CLI). Checked BEFORE
    # registering, so a refusal leaves nothing behind server-side either.
    existing_id = existing_env.get("DECIDIO_AGENT_ID")
    if existing_key and existing_id and existing_id != agent_id and not force:
        _err(f'✘ this directory\'s .env already holds the key for a DIFFERENT agent ("{existing_id}").')
        _err(f'  Registering "{agent_id}" here would overwrite that key — and a private key that is')
        _err("  overwritten is gone for good (it never left this machine). Nothing was written.")
        _err("  Pick one:")
        _err(f"    1. New directory (cleanest): mkdir {agent_id} && cd {agent_id} && python -m decidio init {agent_id}")
        _err(f"    2. Replace the old agent here, backing its .env up first: python -m decidio init {agent_id} --force")
        return 1
    try:
        from .signing import generate_keypair
        local = generate_keypair()
    except Exception as e:  # noqa: BLE001 — pre-base-dependency installs only (cryptography now ships with decidio)
        _err(f"✘ cannot generate a signing key ({e}) — the cryptography package ships with decidio now; upgrade or reinstall: pip install --upgrade decidio")
        return 1
    reg_body = {"agentId": agent_id, "did": local["did"]}
    # The agent's SOX answer ("Should another person approve this?"), passed through when DECIDIO_SOX_RELEVANT is yes/true or no/false;
    # anything else leaves it out - the server's default (connect-once slice 3): No on free; on Team and Enterprise unanswered, which bars
    # the agent's owner from approving its requests until its owner or the workspace admin answers.
    _sox = (os.environ.get("DECIDIO_SOX_RELEVANT") or "").strip().lower()
    if _sox in ("yes", "true", "no", "false"):
        reg_body["soxRelevant"] = _sox in ("yes", "true")
    if source_system:
        reg_body["sourceSystem"] = source_system
    # Everything that must be true BEFORE a secret lands in .env, run once and idempotently: the
    # ignore rule has to exist before the key is written, and --force must back the PREVIOUS
    # agent's file up before anything overwrites it. The key is now written earlier (see the
    # register branch), so the backup must never capture the partial file this init just wrote.
    _prepared = {"done": False}

    def _prepare_env_for_write() -> None:
        if _prepared["done"]:
            return
        _prepared["done"] = True
        _ensure_gitignore()
        if force and existing_key and existing_id and existing_id != agent_id:
            import re as _re2
            safe_id = _re2.sub(r"[^\w.-]", "_", existing_id)
            backup = f".env.{safe_id}.bak"
            _write_secret_file(backup, open(ENV_PATH, encoding="utf-8").read())
            print(f"✔ backed the previous agent's .env up to {backup} (its key would otherwise be unrecoverable)")

    session: Optional[str] = None
    status, body = _api("/api/agents/register", "POST", reg_body)
    if status in (401, 403):
        session = _acquire_session()
        if not session:
            _err("✘ unauthorized — sign in (or set DECIDIO_SESSION_TOKEN / DECIDIO_API_TOKEN) and retry.")
            return 1
        status, body = _api("/api/agents/register", "POST", reg_body, bearer=session)
    did = None
    private_key = None
    # Remove agent (0.13.0, call 9; TS twin): a removed agent's name stays taken - its own words, and a new name, never the reuse below.
    if status == 409 and isinstance(body, dict) and body.get("code") == "AGENT_REMOVED":
        _err(f"✘ {body.get('message') or f'{agent_id!r} was removed from this workspace.'}")
        _err(f"  Nothing was written. A new agent: python -m decidio init {agent_id}-{secrets.token_hex(2)}")
        return 1
    if status == 402:
        _plan_refused(f'Registering "{agent_id}"', body)
        _err("  Nothing was written.")
        return 1
    if status == 409:
        did = body.get("did")
        if not existing_key:
            # HARD STOP, not a degraded continue (a keyless config routes
            # everything unproven and silently caps evidence at agent_asserted).
            suggestion = f"{agent_id}-{secrets.token_hex(2)}"
            _err(f'✘ "{agent_id}" is already registered in this workspace, and its private key is not on this machine')
            print("  (keys never leave the machine that generated them — likely a previous run, or another directory).")
            print("  Nothing was written. Two ways forward:")
            print(f"    1. Fresh agent (most common): python -m decidio init {suggestion}")
            print(f'    2. Reuse "{agent_id}": restore its original DECIDIO_AGENT_KEY into .env here, then re-run init.')
            return 1
        print(f'• "{agent_id}" is already registered in this workspace (did {did}) — reusing it with the DECIDIO_AGENT_KEY already in .env.')
        if source_system:
            print(f'  Note: sourceSystem cannot change on an existing agent — the registered lane stands. To use the "{source_system}" lane, register a NEW name.')
    elif 200 <= status < 300:
        did = body.get("did")
        private_key = local["private_key_base64"]
        print(f"✔ registered (did {did}) — key generated locally, public did only sent to Decidio")
        # PERSIST THE KEY THE MOMENT IT HAS A COUNTERPART ON THE SERVER. Registration is
        # irreversible - a name stays taken, removed or not (0.13.0: Remove agent is final) - so until .env is written the
        # private half of a registered did exists ONLY in this local variable. Every exit in
        # between (a failed mint, an unreachable host, a raise) used to discard it while telling
        # the user to re-run, which was false: a re-run generates a NEW keypair, hits 409, and the
        # remedy it prints - restore the original DECIDIO_AGENT_KEY - is impossible for a key that
        # never touched disk. Writing the identity block here makes that guidance true.
        _prepare_env_for_write()
        _upsert_env({"DECIDIO_AGENT_ID": agent_id, "DECIDIO_AGENT_DID": did or local["did"], "DECIDIO_AGENT_KEY": local["private_key_base64"]})
    else:
        _err(f"✘ register failed ({status}): {body}")
        return 1

    # Mint the runtime credential: the floor-limited AGENT token (can call /agent/* only). The
    # session token stays in memory and dies with this process. On boxes without the tester-lab
    # fence (plain local dev) the mint refuses — local dev keeps its existing env auth.
    agent_token = None
    workspace_id = None
    token_jti = None
    mint_bearer = session or TOKEN()
    if mint_bearer:
        # FAIL CLOSED BEFORE THE MINT if this directory cannot record a revocation handle (V033-02).
        _ensure_gitignore()   # the journal may be created by the probe below - the ignore rule lands first
        _no_journal = _journal_probe()
        if _no_journal:
            _err(_refuse_mint_no_journal(_no_journal))
            return 1
        # Right-sized lifetime, not the server's year-long default (--expires-days to override).
        expires_in_days = expires_days if expires_days else 90
        status, body = _api("/api/workspace/agent-token", "POST", {"agentId": agent_id, "label": "sdk-cli", "expiresInDays": expires_in_days}, bearer=mint_bearer)
        if 200 <= status < 300 and isinstance(body, dict) and body.get("token"):
            agent_token = body["token"]
            workspace_id = body.get("workspaceId")
            token_jti = body.get("jti")
            # THE JTI IS DURABLE BEFORE ANYTHING ELSE CAN FAIL (see the TS twin).
            if token_jti:
                try:
                    _journal_minted(token_jti, agent_id, "sdk-cli")
                except Exception as _je:  # noqa: BLE001
                    _revoke_fresh_mint(token_jti, mint_bearer, _je, JOURNAL_PATH)
                    return 1
            print(f"✔ minted the agent API token — floor-limited: it can request authorization, poll status and report confirmation; it cannot administer the workspace or approve anything (expires {body.get('expiresAt') or f'in {expires_in_days} days'})")
            # The server keeps ONE active token per agent, so a re-mint REVOKES the previous one —
            # an authority event the person triggering it must see (a
            # still-valid token silently died with no mention).
            for superseded in (body.get("supersededJtis") or []):
                _journal_retire(superseded, "revoked")
                print(f"  • this replaces the agent's previous token (jti {superseded}) — now REVOKED: the server keeps one active token per agent. Anything still using it will 401.")
        elif status == 409 and isinstance(body, dict) and body.get("code") == "AGENT_REMOVED":
            # Removed between its registration and this mint (0.13.0; TS twin): no token, and re-running init for this name can't help.
            _err(f"✘ {body.get('message') or f'{agent_id!r} was removed from this workspace.'}")
            _err(f"  No token was minted. A new agent: python -m decidio init {agent_id}-{secrets.token_hex(2)}")
            return 1
        elif session:
            # Safe to re-run, and now TRUE: the agent's identity + private key were written the
            # moment registration succeeded, so a re-run reuses them and only re-mints.
            _err(f"✘ could not mint the agent token ({status}): {body} — the SDK has no runtime credential. "
                 f"The agent IS registered and its key is saved in {ENV_PATH}; fix the cause above and re-run "
                 f"init — it will reuse that key and mint again.")
            return 1
        else:
            print(f"• no agent token minted ({status}) — assuming local/operator auth via the existing DECIDIO_API_TOKEN.")

    secret = _read_env().get("DECIDIO_WEBHOOK_SECRET") or secrets.token_hex(32)
    env_out = {"DECIDIO_API_URL": API, "DECIDIO_AGENT_ID": agent_id, "DECIDIO_WEBHOOK_SECRET": secret}
    if source_system:
        env_out["DECIDIO_SOURCE_SYSTEM"] = source_system
    if did:
        env_out["DECIDIO_AGENT_DID"] = did
    if private_key:
        env_out["DECIDIO_AGENT_KEY"] = private_key  # written locally; never left this host
    if agent_token:
        env_out["DECIDIO_API_TOKEN"] = agent_token  # the FLOOR-LIMITED token — never the session
    if workspace_id:
        env_out["DECIDIO_WORKSPACE_ID"] = workspace_id
    # Revocation metadata, not a secret — parity with the quickstart env (the
    # two files disagreed, and `tokens revoke` is unusable without the jti in hand).
    if token_jti:
        env_out["DECIDIO_TOKEN_JTI"] = token_jti
    try:
        _prepare_env_for_write()
        _upsert_env(env_out)
        if token_jti:
            _journal_retire(token_jti, "persisted")
    except Exception as _we:  # noqa: BLE001 - the token minted above is live; compensate, then fail
        if agent_token and token_jti:
            _revoke_fresh_mint(token_jti, mint_bearer, _we, ENV_PATH)
        elif agent_token:
            _err(f"✘ could not write {ENV_PATH} ({_we}). The token minted a moment ago is LIVE and the server returned no revocation id - find and revoke it: python -m decidio tokens list --mine")
        else:
            _err(f"✘ could not write {ENV_PATH} ({_we}). No token was minted this run.")
        return 1
    # The closing doctor must see what init just wrote — overwrite the process env (a stale
    # doctor probed with the stale pre-init token).
    for k, v in env_out.items():
        os.environ[k] = v
    print(f"✔ wrote {ENV_PATH} (owner-only where the OS supports it) — every decidio command reads it from this directory (your script loads it into its own env)")
    if private_key:
        print(f"\n✔ signing key stored locally as DECIDIO_AGENT_KEY in {ENV_PATH} (keep it out of git; move it to your secret manager for production).\n")
    _remember_host_issuer()   # 3A: init is a deliberate first contact with this host - its receipts' trust anchor
    print("Add the gate to your agent — this snippet runs as-is (the wrap form guard.protect(fn, describe) works too):")
    print()
    print(INIT_SNIPPET)
    print("Then watch it route: python -m decidio approvals   (approve <id> and your function runs)")
    print()
    return cmd_doctor()


def cmd_doctor() -> int:
    env = _read_env()
    ok = True
    warned = 0

    def line(good: bool, label: str) -> None:
        nonlocal ok
        print(f"{'✔' if good else '✘'} {label}")
        ok = ok and good

    # Warnings COUNT in the summary ("all green" directly under a ⚠ line
    # contradicts itself — green with a caveat must say so).
    def warn(label: str) -> None:
        nonlocal warned
        warned += 1
        print(f"⚠ {label}")

    # THE TOKEN RECOVERY JOURNAL IS DOCTOR'S BUSINESS (0.3.5; TS twin): a minted token whose credential
    # file never landed and whose compensating revoke failed is LIVE, and this directory's journal is its
    # only handle.
    try:
        _journal_items = _journal_outstanding()
    except Exception as _jerr:  # noqa: BLE001
        _journal_items = []
        line(False, f"token recovery journal: {_jerr} — it may hold the id of a live token, and this directory cannot mint until it is repaired or moved aside (every byte is left as found).")
    _held_jti = _read_env().get("DECIDIO_TOKEN_JTI")
    for _j in _journal_items:
        if _j.get("jti") == _held_jti:
            line(True, f"token recovery journal: jti {_j['jti']} is live and held by {ENV_PATH} — it retires only when revoked (python -m decidio tokens revoke {_j['jti']}; a tour token: quickstart cleanup).")
            continue
        _where = f"DECIDIO_API_URL={_j['apiUrl']} " if _j.get("apiUrl") and _j.get("apiUrl") != API else ""
        warn(f"token recovery journal: jti {_j['jti']} ({_j.get('label') or 'token'}, agent {_j.get('agentId') or '?'}, minted {_j.get('at') or '?'} against {_j.get('apiUrl') or API}) has no recorded revocation in this directory's journal — it may still be live. Revoke it, or confirm it is gone: {_where}python -m decidio quickstart cleanup   (or: {_where}python -m decidio tokens revoke {_j['jti']})")

    # An unset URL is a WORKING default (Decidio's hosted service), not a failure — the default-first ruling.
    url_set = os.environ.get("DECIDIO_API_URL") or env.get("DECIDIO_API_URL")
    print(f"✔ API URL: {API}" + ("" if url_set else "  (default: Decidio — set DECIDIO_API_URL to point elsewhere)"))
    line(bool(os.environ.get("DECIDIO_AGENT_ID") or env.get("DECIDIO_AGENT_ID")), f"agent id: {os.environ.get('DECIDIO_AGENT_ID') or env.get('DECIDIO_AGENT_ID') or '(unset)'}")
    # The webhook secret is OPERATOR-ONLY transport config — a missing one must never fail doctor
    # (doctor exited 1 immediately after the product's own successful
    # quickstart, whose env rightly omits it). Informational either way.
    sec = os.environ.get("DECIDIO_WEBHOOK_SECRET") or env.get("DECIDIO_WEBHOOK_SECRET")
    print("✔ webhook secret: set — operator-only transport (inactive against Decidio's service; the poll worker guard.worker() is the self-serve resume path)" if sec
          else "• webhook secret: not set — only needed for the operator resume-webhook transport; the poll worker guard.worker() is the self-serve resume path (init generates one)")
    # Signing key — REQUIRED for auto-approve. Without it the SDK can't prove identity, so the
    # gate routes EVERY request to a human (safe, but surprising). Surface it loudly.
    signing = (os.environ.get("DECIDIO_AGENT_KEY") or env.get("DECIDIO_AGENT_KEY")) and (os.environ.get("DECIDIO_AGENT_DID") or env.get("DECIDIO_AGENT_DID"))
    if signing:
        print("✔ signing key: set — the agent can prove its identity, making it ELIGIBLE for policy auto-approve. Whether a rule matches is your workspace policy's decision; with no matching rule every request routes to a human (routing-by-default - a block is different: a named rule, or the universal backstop when no active policy governs agents at all).")
    else:
        warn("signing key: MISSING (DECIDIO_AGENT_KEY/DID) — without it the agent can't prove identity, so EVERY request routes to a human. Run `python -m decidio init` to generate one.")
    # Reachability and token role are SEPARATE checks (parity with the TS doctor — the old probe
    # called any <500 green, so a wrong-scope token looked healthy). /api/health is
    # unauthenticated truth about reachability; /api/records then classifies the token.
    try:
        status, _ = _api("/api/health", bearer="")
        line(200 <= status < 300, f"connectivity: API reachable ({status})")
        # EXPIRY BEFORE IT BITES (parity with the TS doctor): display-only read of the token's
        # own `exp`; the server stays the authority on validity.
        tok = os.environ.get("DECIDIO_API_TOKEN") or env.get("DECIDIO_API_TOKEN")
        # UNSET is its own diagnosis (a bare directory probed the server
        # with an EMPTY credential and called a never-existent token "invalid or expired").
        if not tok:
            line(False, "agent token: NOT CONFIGURED — no DECIDIO_API_TOKEN in this directory's .env or your environment. Run `python -m decidio init <agent-name>` to register an agent and mint one.")
        if tok:
            try:
                import base64 as _b64
                import time as _time
                part = tok.split(".")[1]
                payload = json.loads(_b64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
                if isinstance(payload.get("exp"), (int, float)):
                    secs_left = payload["exp"] - _time.time()
                    # A minute of grace absorbs mint-to-doctor latency so a fresh 90-day token
                    # reads "90", matching the Node doctor (89 vs 90).
                    days = int((secs_left + 60) // 86400)
                    # Under a day, days-precision reads as "0 day(s)" — which looks expired while
                    # ~23h remain. Switch units instead of rounding away the
                    # truth.
                    # The DISPLAYED number rounds; `days` (floored) still decides the threshold
                    # below. A seven-day quickstart token floors to 6 and read "expires in
                    # 6 day(s)" the second it was minted. Rounding a nearly-expired token UP
                    # would be the dangerous direction, so the threshold keeps the floor.
                    left = f"{max(1, int(secs_left // 3600))} hour(s)" if secs_left < 86400 else f"{round(secs_left / 86400)} day(s)"
                    agent_label = env.get("DECIDIO_AGENT_ID") or "<agent>"
                    if secs_left < 0:
                        line(False, f"agent token: EXPIRED {-days} day(s) ago - re-run `python -m decidio init {agent_label}` to mint a fresh one.")
                    elif days <= 14:
                        warn(f"agent token: expires in {left} - mint a fresh one before it does: python -m decidio init {agent_label}")
                    else:
                        # "Unexpired", never "valid" (TS parity): this reads the JWT's own exp and
                        # nothing else, so a REVOKED token would otherwise be reported as healthy
                        # for months. The scope probe below is what actually tests acceptance.
                        print(f"✔ agent token: unexpired for another {round(secs_left / 86400)} days (validity is decided by the server — see the token-scope check below)")
            except Exception:  # noqa: BLE001 — not a readable JWT; the scope probe is the real check
                pass
        # No token → nothing to probe: probing with an EMPTY credential is what produced the
        # "REJECTED — invalid or expired" misdiagnosis for a token that never existed.
        if tok:
            status, _ = _api("/api/records")
            if 200 <= status < 300:
                warn("token scope: SESSION/ADMIN-capable - this credential can approve and administer, and it does not belong in an agent's environment (the agent runtime needs only the floor-limited token init mints). Move it to your shell/CI secret store.")
            elif status == 401:
                probe_status, _ = _api("/agent/status/doctor-scope-probe")
                if probe_status == 404:
                    print("✔ token scope: agent floor — correct for the runtime SDK (approvals/receipt will ask you to sign in)")
                elif probe_status == 401:
                    line(False, "token: REJECTED on the agent floor too — it's invalid or expired. Re-run `python -m decidio init` to mint a fresh one.")
                else:
                    warn(f"token scope: agent-floor probe returned {probe_status} — inconclusive")
            else:
                warn(f"token scope: unexpected {status} from /api/records")
    except Exception as e:  # noqa: BLE001
        line(False, f"connectivity: cannot reach {API} — {e}")
    warn_note = f" ({warned} warning{'' if warned == 1 else 's'} above — working, worth a look)" if warned else ""
    print(f"\ndoctor: all green — durable resume ready.{warn_note}" if ok else "\ndoctor: fix the ✘ items above.")
    return 0 if ok else 1


AGENT_REQUEST_WINDOW = 1000


def list_agent_requests(bearer: Optional[str] = None) -> dict:
    """The approvals list's read (launch plan L7, the TS CLI's listAgentRequests): GET /api/queue/all?view=agent_requests, newest
    first, 100 a page, every page until the server's `total` is read (at most 10: the server scopes its 1,000 newest rows)."""
    items: list = []
    total = 0
    for page in range(1, AGENT_REQUEST_WINDOW // 100 + 1):
        status, body = _api(f"/api/queue/all?view=agent_requests&sort=created&dir=desc&pageSize=100&page={page}", bearer=bearer)
        if not (200 <= status < 300):
            return {"ok": False, "status": status, "body": body}
        got = body.get("items") if isinstance(body, dict) and isinstance(body.get("items"), list) else []
        t = body.get("total") if isinstance(body, dict) else None
        total = t if isinstance(t, int) and not isinstance(t, bool) else len(items) + len(got)
        items.extend(got)
        if not got or len(items) >= total:
            break
    return {"ok": True, "items": items, "total": total, "window_full": total >= AGENT_REQUEST_WINDOW}


def cmd_approvals(sub: Optional[str], rid: Optional[str], reason: Optional[str], json_mode: bool = False, mine_only: bool = False) -> int:
    if sub and sub.startswith("--"):
        sub = None
    # USAGE BEFORE AUTH: a malformed command fails on its shape, not the network.
    if sub in ("approve", "reject") and not rid:
        _err(f"usage: python -m decidio approvals {sub} <decisionId> [reason]")
        _err(f'       python -m decidio approvals {sub} <decisionId> --reason "text with -dashes"')
        return 2
    # A flag that cannot apply must be refused, not quietly ignored — the same rule this CLI states
    # for unknown flags. --json/--mine shape the LIST; they mean nothing for a single decision.
    if sub in ("approve", "reject") and (json_mode or mine_only):
        _err(f'✘ {"--json" if json_mode else "--mine"} applies to `approvals` (the list), not to '
             f"{sub} — refusing to ignore a flag you meant to matter.")
        return 2
    # --mine without an agent identity cannot mean anything — and quietly returning [] (exit 0)
    # would tell a script "no pending work" when the truth is "misconfigured" (observed:
    # it leaked "undefined" in human mode and lied with [] in JSON mode). Shape error, before auth.
    if mine_only and not os.environ.get("DECIDIO_AGENT_ID"):
        _err("✘ --mine needs an agent identity, and there is no DECIDIO_AGENT_ID in this directory's .env or your environment.")
        _err("  Run this from your agent's directory (where init wrote .env), or drop --mine for the workspace-wide list.")
        return 2
    # Approvals are a HUMAN act on the workspace — session scope, never the agent token. After
    # init writes the floor-limited agent token to .env, a 401 here is the NORMAL state, and it
    # must read as "sign in", never as an empty queue (parity with the TS CLI — an auth refusal
    # rendered as zero pending approvals hides requests that are waiting on a human).
    bearer: Optional[str] = None
    status, body = _api("/api/decisions/cards")
    if status in (401, 403):
        bearer = _acquire_session()
        if not bearer:
            _err("✘ approvals need a workspace sign-in.")
            return 1
        status, body = _api("/api/decisions/cards", bearer=bearer)
    if sub in ("approve", "reject"):
        if not rid:
            _err(f"usage: python -m decidio approvals {sub} <decisionId> [reason]")
            return 2
        status, body = _api(f"/api/decisions/{rid}/{'approve' if sub == 'approve' else 'reject'}", "POST", {"reason": reason}, bearer=bearer)
        if 200 <= status < 300:
            # HONESTY over green checkmarks (parity with the TS CLI): a replay is a NO-OP and
            # must read as one, never as a fresh approval. Non-zero exit for scripts.
            if isinstance(body, dict) and body.get("alreadyResolved"):
                print(f"• {rid} was already resolved — nothing changed.")
                print(f"  Decisions are single-use: a second {sub} can never re-execute the action (that's the replay protection working).")
                print(f"  See its sealed record: python -m decidio receipt {rid}")
                return 1
            sig = body.get("resumeSignal") if isinstance(body, dict) else None
            # Spelled out, not "{sub}d" — that template would print "rejectd".
            print(f"✔ {'approved' if sub == 'approve' else 'rejected'} {rid}" + (f" — agent signalled ({'ok' if sig.get('ok') else sig.get('error')})" if sig else ""))
            # WHAT WAS SENT, not "what was recorded" (parity with the TS CLI). The reason seals
            # immutably, but the record stores it TOKENIZED - a name or figure reads back as
            # [PARTY_3] / [METRIC_5] - so printing the typed text under "recorded" asserted
            # something the artifact does not contain.
            if reason:
                print(f"  reason sent verbatim: {json.dumps(reason)}")
                print("  (it seals immutably; personal or sensitive values are tokenized at rest, so the")
                print(f"   stored text can differ - see exactly what was kept: python -m decidio receipt {rid})")
            if sub == "approve":
                print("  The agent's function runs next — a blocking call resumes now; a durable one when its worker or resume route picks this up.")
            else:
                print("  The agent's action will NOT run; the rejection seals as a verifiable record.")
            print(f"  Download the receipt: python -m decidio receipt {rid}")
            return 0
        if status == 404:
            _err(f'✘ no decision "{rid}" in this workspace — check the id (python -m decidio approvals lists pending ones).')
            return 1
        _err(f"✘ {sub} failed ({status}): {body}")
        return 1
    if not (200 <= status < 300):
        _err(f"✘ could not list approvals ({status}): {body}")
        return 1
    # EVERY agent request, page by page (launch plan L7; parity with the TS CLI): the Queue's own paged feed, filtered to agent
    # requests on the server, newest first, 100 a page until `total` is read. The old read was the cards view's first 50, so
    # `--mine --json` could print [] and exit 0 while an older request of this agent waited.
    listed = list_agent_requests(bearer)
    if not listed["ok"]:
        _err(f"✘ could not list approvals ({listed['status']}): {listed['body']}")
        return 1
    cards = listed["items"]
    # The server scopes a window of its 1,000 newest rows: a total that fills it may leave older ones unread. --json refuses.
    if listed["window_full"]:
        _err(f"⚠ this workspace has {listed['total']} or more agent requests in view, the most the server reads at once — older pending approvals may exist beyond them.")
        if json_mode:
            return 1
    pending = [c for c in cards if c.get("isAgentRequest") and c.get("status") != "sealed"]
    my_agent = os.environ.get("DECIDIO_AGENT_ID")

    def _is_mine(c: dict) -> bool:
        return bool(my_agent) and str(c.get("title", "")).startswith(f"{my_agent}:")

    shown = [c for c in pending if _is_mine(c)] if mine_only else pending
    if json_mode:
        # Stable machine output: agents scripting the queue parse this, not prose.
        print(json.dumps([{"decisionId": c.get("id"), "action": (c.get("agentRequest") or {}).get("action"), "amount": (c.get("agentRequest") or {}).get("amount"), "title": c.get("title")} for c in shown], indent=2))
        return 0
    if mine_only and not shown:
        print(f'No pending approvals for "{my_agent}" ({len(pending)} pending elsewhere in this workspace - drop --mine to see them).')
        return 0
    if not pending:
        print("No pending agent approvals.")
        return 0
    scope_note = f" - workspace-wide; '<-' marks this directory's agent ({my_agent}). Use --mine to list only those." if my_agent and not mine_only else ""
    print(f"Pending agent approvals ({len(shown)}{f' for {my_agent}' if mine_only else ''}){scope_note}:")
    for c in shown:
        ar = c.get("agentRequest") or {}
        amt = f"  ${ar['amount']:,}" if ar.get("amount") is not None else ""
        mine = "  <-" if not mine_only and _is_mine(c) else ""
        print(f"  {c['id']}  {ar.get('action','?')}{amt}  — {c.get('title','')}{mine}")
    print("\nApprove:  python -m decidio approvals approve <id> [reason]   ·   Reject:  ... reject <id> [reason]")
    return 0


def _is_tracked_by_git(path: str) -> bool:
    """Is this path ALREADY TRACKED by git? A .gitignore entry has no effect on a tracked file,
    so writing a private key into one is how the key reaches permanent history — in the very
    commit that adds the ignore rule. False when git is absent or this is not a repository."""
    import subprocess

    try:
        return subprocess.run(["git", "ls-files", "--error-unmatch", path],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except Exception:  # noqa: BLE001 - no git on PATH is an honest "not tracked"
        return False


def _assert_not_tracked(path: str) -> bool:
    """REFUSE to write secrets into a file git is already tracking (parity with the TS CLI).
    This is the check behind the claim: without it the CLI asserted that keys stay out of git
    while doing nothing to make it so. True when it is safe to proceed."""
    if not _is_tracked_by_git(path):
        return True
    _err(f"✘ {path} is ALREADY TRACKED by git — refusing to write the agent's private key into it.")
    _err("  A .gitignore entry does not untrack a file: the next `git add -A` would commit")
    _err("  DECIDIO_AGENT_KEY and DECIDIO_API_TOKEN into permanent history. Nothing was written.")
    _err("  Fix it, then re-run:")
    _err(f"    git rm --cached {path}        # stop tracking it (keeps your local copy)")
    _err(f'    git commit -m "stop tracking {path}"')
    _err("  If it has ALREADY been committed with secrets in it, rotate them — history rewriting")
    _err("  alone does not un-leak a key that was pushed.")
    return False


def _ensure_gitignore() -> None:
    """Keep secrets out of git without nagging (parity with the TS CLI)."""
    # Every file this CLI may write that can hold a private key — including the --force backup
    # (.env.<agent>.bak), which git's plain `.env` pattern does NOT match, and the tour-scoped
    # .env.quickstart (parity gap with the TS CLI, closed here).
    entries = [".env", ".env.quickstart", ".env.*.bak", ".env.*.tmp", ".decidio-pending/", ".decidio-token-journal"]
    creating = not os.path.exists(".gitignore")
    # A file WE create is this project's first .gitignore, and node_modules/ belongs in it (prodsec review of 0.4.3); an
    # existing file gets only the secret entries - the developer's own ignore list is theirs.
    if creating:
        entries.append("node_modules/")
    existing = "" if creating else open(".gitignore", encoding="utf-8").read()
    lines = [l.strip() for l in existing.splitlines()]
    missing = [e for e in entries if e not in lines and e.rstrip("/") not in lines]
    if not missing:
        return
    with open(".gitignore", "a", encoding="utf-8") as f:
        if existing and not existing.endswith("\n"):
            f.write("\n")
        f.write("\n".join(missing) + "\n")
    print(f"✔ {'wrote' if creating else 'added'} {' + '.join(missing)} to .gitignore (secret files here will not be committed)")


def _valued_opt(args, flag: str) -> Optional[str]:
    """The value of a valued option, `--flag value` or `--flag=value`; None when absent."""
    if flag in args:
        i = args.index(flag)
        return args[i + 1] if i + 1 < len(args) else None
    for a in args:
        if a.startswith(flag + "="):
            return a[len(flag) + 1:]
    return None


def cmd_quickstart(auto_approve_demo: bool = False, keep_agent: bool = False, explain: bool = False, phone: Optional[str] = None) -> int:
    """The guided two-minute tour, parity with `npx @decidio/sdk quickstart`: fresh agent, one
    gated demo action, human approval (interactive or headless), execution, receipt, offline
    verify. Zero-config: with no DECIDIO_API_URL it targets the lab (announced; F-1106-C4 (a))."""
    import json as _json
    import re as _re
    import threading
    import time as _time

    global _EXPLAIN, _host_announced
    _EXPLAIN = bool(explain)
    if phone is not None and phone not in ("app", "web"):
        _err("✘ --phone takes app (default: the QR opens the installed app when there is one) or web (the QR opens the phone web rendering, always).")
        return 2
    t0 = _time.time()
    print(_bold("Decidio quickstart") + " — gate an action, route it to a human, execute on approval, hold the proof.")
    if is_lab_api(API):
        print(f"  Target: {API}" + _dim("  (Decidio's lab: invite-only, synthetic data — no lab invite? npx @decidio/sdk quickstart --demo runs the same tour on this machine)"))
    else:
        print(f"  Target: {API}" + _dim("  (your workspace — the tour adds one agent and one permanent sealed record)"))
    _host_announced = True   # the Target line IS the announcement here - no second "decidio →" line on stderr
    # SIDE EFFECTS UP FRONT: say what the tour creates before creating any of it — in one line, with the long form
    # behind --explain (UAT round 2: the tour must read as signal, not prose).
    if _EXPLAIN:
        print("  This tour will: register one synthetic agent · mint a 7-DAY floor-limited token ·")
        print("  write .env (or .env.quickstart), .decidio-token-journal (revocation ids, no secrets) and .gitignore")
        print("  entries (incl. .decidio-pending/, the durable store your real agent will use) · save the receipt")
        print("  as decidio-receipt-<id>.json here (shareable: action, amount, policy, the human's reason - no secrets; it stays)")
        print("  · create one synthetic decision and its sealed record (records are permanent by design) · wait up to")
        print("  5 minutes for your y (approve) or n (reject) at the human step. Cleanup offer at the end.")
    else:
        print(_dim("  Creates here: a synthetic agent + 7-day token (.env), .decidio-token-journal (revocation ids, no secrets), .gitignore entries incl."))
        print(_dim("  .decidio-pending/ (the durable store), the receipt as decidio-receipt-<id>.json, one sealed record (permanent). --explain for the long form."))
    print()
    session = _acquire_session()
    if not session:
        return 1

    # COLLISION IS OURS TO ABSORB (parity with the TS CLI): 2 bytes is 65k names on a workspace
    # this product calls SHARED, so evaluators collided in the low hundreds of runs and the first
    # thing they saw was our own 409 contradicting our own "no collisions" claim.
    # SAFETY CHECKS BEFORE ANY SERVER-SIDE WORK. These ran AFTER register and mint, which
    # inverted init's own stated rule — "refusing later would leave an orphaned registration and
    # a live token behind" — and the refusal they print says "Nothing was written" while a live
    # token existed server-side. Which file the tour will write is knowable up front.
    # ANY agent identity in .env sends the tour to its own file - not only a signing key (prodsec review of 0.4.3: the SDK's
    # agent_key is optional, so a key-less agent .env had its agent fields overwritten by the tour and stripped by cleanup).
    _prior = _read_env()
    env_file = ".env.quickstart" if any((_prior.get(k) or "").strip() for k in ("DECIDIO_AGENT_KEY", "DECIDIO_AGENT_ID", "DECIDIO_AGENT_DID", "DECIDIO_API_TOKEN")) else ENV_PATH
    if not _assert_not_tracked(env_file):
        return 1
    # CONNECTIVITY BEFORE ANY DISK WRITE (first-run audit of 0.4.4: a network failure had already written .gitignore). A
    # dead host leaves the directory exactly as it was, and says so.
    _reach, _ = _api("/api/health", bearer="", soft=True)
    if not (200 <= _reach < 300):
        _err(f"✘ cannot reach {API}" + (f" (HTTP {_reach})" if _reach else " (no response)") + " — check the network (or DECIDIO_API_URL) and re-run. Nothing was written.")
        return 1
    _ensure_gitignore()

    agent_id = f"quickstart-{secrets.token_hex(5)}"
    if _EXPLAIN:
        print(f'  Registering agent "{agent_id}"…')
    try:
        from .signing import generate_keypair
        local = generate_keypair()
    except Exception as e:  # noqa: BLE001 — pre-base-dependency installs only (cryptography now ships with decidio)
        _err(f"✘ cannot generate a signing key ({e}) — the cryptography package ships with decidio now; upgrade or reinstall: pip install --upgrade decidio")
        return 1
    status, body = _api("/api/agents/register", "POST", {"agentId": agent_id, "did": local["did"]}, bearer=session)
    # A 409 on a name WE generated is our problem to absorb, not the reader's to diagnose (parity
    # with the TS CLI). Retry silently with a fresh name rather than failing the very first command.
    _tries = 0
    while status == 409 and _tries < 3:
        _tries += 1
        agent_id = f"quickstart-{secrets.token_hex(5)}"
        status, body = _api("/api/agents/register", "POST", {"agentId": agent_id, "did": local["did"]}, bearer=session)
        if 200 <= status < 300:
            print(f'  (that name was taken — using "{agent_id}" instead)')
    if not (200 <= status < 300):
        # Every failure names the next command (parity with the TS CLI) - this branch used to end
        # the very first thing a new user runs with no way forward.
        if status == 402:
            _plan_refused("The tour's agent", body)
        else:
            _err(f"✘ could not register the tour's agent ({status}): {body}")
        if status == 402:
            _err("  The tour registers one agent of its own. Remove one you no longer use on the Agents page, or see your plan there.")
        elif status == 409:
            _err("  Every generated name collided, which should be almost impossible - something is")
            _err("  likely wrong with this workspace's agent list rather than with your setup.")
            _err("  See what is registered: python -m decidio tokens list")
        else:
            _err("  Check the target and your sign-in, then re-run: python -m decidio doctor")
        _err("  No credential was written to this directory (the only write so far is the .gitignore entries above, which are safe to keep).")
        return 1
    # INSPECT THE REPLACEMENT TARGET BEFORE THE MINT (prodsec V033-02; see the TS twin): nothing
    # server-side may happen until every local precondition of persisting the result holds.
    prev_tour_file = None
    if env_file != ENV_PATH and os.path.exists(env_file):
        try:
            prev_tour_file = open(env_file, encoding="utf-8").read()
        except Exception as _re_err:  # noqa: BLE001
            _err(f"✘ {env_file} exists but could not be read ({_re_err}) - a previous tour's credentials may be in it, and this tour would have to replace it. Refusing to mint a new token on top of a file this command cannot read: fix its permissions or move it aside, then re-run. Nothing was minted.")
            return 1
    _no_journal = _journal_probe()
    if _no_journal:
        _err(_refuse_mint_no_journal(_no_journal))
        return 1
    # A tour credential should outlive the tour and not much else.
    status, mint = _api("/api/workspace/agent-token", "POST", {"agentId": agent_id, "label": "quickstart", "expiresInDays": 7}, bearer=session)
    if not (200 <= status < 300) or not (isinstance(mint, dict) and mint.get("token")):
        _err(f"✘ token mint failed ({status}): {mint}")
        return 1
    # No webhook secret (the tour never uses that transport, and inheriting the
    # .env's secret duplicated one agent's secret into another's file). DECIDIO_TOKEN_JTI is
    # revocation METADATA — what `quickstart cleanup` and `tokens revoke` need later.
    env_out = {
        "DECIDIO_API_URL": API, "DECIDIO_AGENT_ID": agent_id,
        "DECIDIO_AGENT_DID": (body or {}).get("did") or local["did"], "DECIDIO_AGENT_KEY": local["private_key_base64"],
        "DECIDIO_API_TOKEN": mint["token"], "DECIDIO_WORKSPACE_ID": mint.get("workspaceId") or "",
    }
    if mint.get("jti"):
        env_out["DECIDIO_TOKEN_JTI"] = mint["jti"]
        try:
            _journal_minted(mint["jti"], agent_id, "quickstart")
        except Exception as _je:  # noqa: BLE001
            _revoke_fresh_mint(mint["jti"], session, _je, JOURNAL_PATH)
            return 1
    # NEVER clobber a real agent's key (keys never leave this machine — overwriting
    # .env's DECIDIO_AGENT_KEY orphans that agent irrecoverably). A directory that already holds
    # one gets a TOUR-SCOPED env file instead.
    if env_file != ENV_PATH:
        # A PREVIOUS tour in this directory is REVOKED AND REPLACED, never backed up. Backing it
        # up stranded a live credential: the .bak held that tour's private key AND an unrevoked
        # 7-day token, `quickstart cleanup` only ever touched the current file, and `.env.*.bak`
        # is gitignored — so N tours left N-1 live tokens on disk, invisible, until they expired.
        # The "its key would otherwise be unrecoverable" argument that justifies init's backup
        # does not apply here: a tour agent is synthetic and disposable, which is its whole point.
        if prev_tour_file is not None:
            prev = prev_tour_file
            prev_m = _re.search(r"^DECIDIO_AGENT_ID=(.+)$", prev, _re.MULTILINE)
            prev_id = prev_m.group(1) if prev_m else None
            jti_m = _re.search(r"^DECIDIO_TOKEN_JTI=(.+)$", prev, _re.MULTILINE)
            prev_jti = jti_m.group(1) if jti_m else None
            # ORPHANS SURVIVE EVERY OUTCOME OF THIS REPLACEMENT (F-010, completed after the 0.3.0
            # retest; see the TS twin). The first fix carried them forward only in the
            # revoke-FAILED branch below, so a replacement whose CURRENT revoke succeeded rebuilt
            # the file fresh and silently dropped the ids of tokens an EARLIER replace had failed
            # to kill - their only cleanup handles. Seed from the old file unconditionally, append
            # this tour's jti only on its own failure, write the key whenever anything remains.
            _orph_m = _re.search(r"^DECIDIO_ORPHANED_TOKEN_JTI=(.+)$", prev, _re.MULTILINE)
            _carried = [j.strip() for j in ((_orph_m.group(1) if _orph_m else "").split(",")) if j.strip()]
            if prev_id and prev_id != agent_id:
                if prev_jti:
                    rv_status, _rv = _api(f"/api/workspace/agent-token/{prev_jti}", "DELETE", bearer=session)
                    if 200 <= rv_status < 300:
                        _journal_retire(prev_jti, "revoked")
                        print(f"  ✔ the previous tour agent ({prev_id}) had its token REVOKED before this tour replaced it — no live credential is left behind")
                    else:
                        # RETAIN THE ID OF A CREDENTIAL WE FAILED TO KILL (F-010). The warning named
                        # the jti and the very next line overwrote the only file that held it, so
                        # the one identifier needed to revoke a LIVE token survived just as long as
                        # the terminal scrollback.
                        _carried.append(prev_jti)
                        print(f"  ⚠ could not revoke the previous tour's token (jti {prev_jti}, {rv_status}) — it is still LIVE. Its id is kept in {env_file} as DECIDIO_ORPHANED_TOKEN_JTI, and `quickstart cleanup` will retry it; or revoke it by hand: python -m decidio tokens revoke {prev_jti}", file=sys.stderr)
                else:
                    print("  ⚠ the previous tour file carried no revocation id, so its token (if any) must be revoked from your Decidio app.")
            if _carried:
                env_out["DECIDIO_ORPHANED_TOKEN_JTI"] = ",".join(dict.fromkeys(_carried))
                print(f"  • {len(dict.fromkeys(_carried))} orphaned token id(s) from earlier replacements carried forward — `quickstart cleanup` will retry them.")
        try:
            _write_secret_file(env_file, "\n".join(f"{k}={v}" for k, v in env_out.items()) + "\n")
            if mint.get("jti"):
                _journal_retire(mint["jti"], "persisted")
        except Exception as _we:  # noqa: BLE001 - V030-05: the tour token is live; compensate, then fail
            if mint.get("jti"):
                _revoke_fresh_mint(mint["jti"], session, _we, env_file)
            else:
                _err(f"✘ could not write {env_file} ({_we}). The tour token minted a moment ago is LIVE and the server returned no revocation id - find and revoke it: python -m decidio tokens list --mine")
            return 1
        print(f"  ✔ .env already holds your agent — this tour uses {env_file}")
    else:
        try:
            _upsert_env(env_out)
            if mint.get("jti"):
                _journal_retire(mint["jti"], "persisted")
        except Exception as _we:  # noqa: BLE001
            if mint.get("jti"):
                _revoke_fresh_mint(mint["jti"], session, _we, env_file)
            else:
                _err(f"✘ could not write {env_file} ({_we}). The tour token minted a moment ago is LIVE and the server returned no revocation id - find and revoke it: python -m decidio tokens list --mine")
            return 1

    # FROM HERE THE TOKEN IS LIVE AND ON DISK. No failure path may return without revoking it:
    # nine of them used to, each leaving a 7-day token, a private key and a registered agent
    # behind, because the cleanup was reachable from exactly one place — the happy end.
    def _fail_tour(code: int) -> int:
        print()
        print("  The tour did not complete — cleaning up the credentials it created:")
        try:
            _quickstart_cleanup(session, env_file)
        except Exception:  # noqa: BLE001 - best-effort; the revoke line above says what happened
            pass
        return code
    expires_note = f" · expires {str(mint.get('expiresAt'))[:10]}" if mint.get("expiresAt") else ""
    _block("①", "Register a synthetic agent", [
        f"{_bold('agent')}    {agent_id}",
        f"{_bold('key')}      generated locally · only the public half was registered",
        f"{_bold('token')}    7-day, floor-limited{expires_note} · written to {env_file}",
    ])
    if _EXPLAIN:
        print("  The tour runs exactly this (blocking mode, so you can watch it live; your real agent omits mode=")
        print("  and gets durable-by-default, resumed by a worker — the README shows both):")
        print()
        print('     pay_invoice = guard.protect(pay_invoice_raw,')
        print('         lambda inv: {"action": "payInvoice", "amount": inv["amount"], "scope": "Invoice"},')
        print('         mode="blocking")')
        print()
    from .guard import DecidioRateLimitError, Guard, GuardConfig
    state: dict = {"decision_id": None, "result": None, "error": None}
    cfg = GuardConfig(
        api_url=API, agent_id=agent_id, api_token=mint["token"],
        agent_key=local["private_key_base64"], agent_did=(body or {}).get("did") or local["did"],
        workspace_id=mint.get("workspaceId"), poll_interval=1.5, poll_timeout=300.0,
        on_pending=lambda p: state.__setitem__("decision_id", p.get("decisionId")),
    )
    g = Guard(cfg)
    pay_invoice = g.protect(lambda inv: {"paid": True, "id": inv["id"]},
                            lambda inv: {"action": "payInvoice", "amount": inv["amount"], "scope": "Invoice"},
                            mode="blocking")

    def _run() -> None:
        try:
            state["result"] = pay_invoice({"id": "INV-2026-001", "amount": 86000})
        except Exception as e:  # noqa: BLE001
            state["error"] = e

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    waited = 0.0
    while state["decision_id"] is None and state["error"] is None and waited < 30:
        _time.sleep(0.25)
        waited += 0.25
    # An EARLY rejection (before routing) must be diagnosed as ITSELF, not as a routing timeout
    # (the sandbox's per-hour action cap surfaced here as "check
    # connectivity", and doctor then corroborated the wrong suspect with "all green").
    if state["decision_id"] is None and isinstance(state["error"], DecidioRateLimitError):
        e = state["error"]
        cap = f" ({e.limit} actions/hour on lab workspaces)" if e.limit is not None else ""
        resets = f". It resets {e.reset_at}" if e.reset_at else ""
        _err(f"✘ this workspace's governed-action allowance is used up{cap}.")
        _err(f"  Nothing was routed or executed — the cap is the sandbox protecting itself, not a fault{resets}.")
        _err("  Re-run the tour after the reset (or talk to us about a production workspace).")
        return _fail_tour(1)
    if state["decision_id"] is None and state["error"] is not None:
        _err(f"✘ the gate refused before routing: {state['error']}")
        return _fail_tour(1)
    decision_id = state["decision_id"]
    if not decision_id:
        _err("✘ the gate did not route within 30s — check connectivity (python -m decidio doctor) and re-run.")
        return _fail_tour(1)
    _block("②", "Gate a demo action", [
        f"{_bold('call')}     guard.protect(pay_invoice_raw, lambda inv: {{\"action\": \"payInvoice\", \"amount\": inv[\"amount\"], \"scope\": \"Invoice\"}}, mode=\"blocking\")   " + _dim("# blocking here; without mode= it is durable"),
        f"{_bold('routed')}   $86,000 payInvoice ROUTED to a human (decision {decision_id}) — nothing executes until someone decides " + _dim("(routed, not a BLOCK: a human can still say yes; a block no one can override)"),
    ])
    if _EXPLAIN:
        print("  This agent has no auto-approve rule, so the policy ROUTES it to a person (routing-by-default). That is")
        print("  distinct from a BLOCK, which no human can override: a block is a named rule, or the universal backstop")
        print("  when no active policy governs agents at all.")
        print()

    # The human moment — and it must BE one (a headless tour that approves its
    # own request has no discrete human yes). Headless STOPS here unless --auto-approve-demo was
    # passed, and that path is labeled AUTOMATED authority. isatty() lies on some Windows stdin
    # redirections, so EOF on the prompt also counts as headless.
    interactive = False
    verdict = "approve"   # the automated path below is an explicit, LABELED yes
    decided_outside = None   # "approved"/"rejected" when the web app or a phone decided and this terminal followed
    denial_verified = False   # set only when ④ verified the denial's sealed record PINNED
    if _stdin_is_console():
        # THE THREE DOORS (UAT 2026-09-03; TS twin): here, the web app, or a phone - all signed in - and whichever answers
        # first wins. The gated call is already polling in its thread, so a click in the app shows up here in seconds.
        _hs, _hand = _api("/demo/session-link", "POST", {"decisionId": decision_id, **({"phone": "web"} if phone == "web" else {})}, bearer=session, soft=True)
        door_link = _hand.get("link") if (200 <= _hs < 300 and isinstance(_hand, dict) and isinstance(_hand.get("link"), str)) else None
        qr = _hand.get("qr") if (door_link and isinstance(_hand, dict) and isinstance(_hand.get("qr"), str)) else None
        plain_link = f"{_APP_URL}/queue?focus={urllib.parse.quote(decision_id)}"   # the desktop app's deep link to one decision
        rows = [
            f"{_bold('here')}         Type y to approve or n to reject, then Enter   {_dim('(waits up to 5 minutes)')}",
            f"{_bold('web app')}      {_link(door_link or plain_link)}   " + _dim("(one-time sign-in · 5 minutes)" if door_link else "(sign in there if it asks)"),
        ]
        if qr:
            rows.append(f"{_bold('your phone')}   scan — the same one-time sign-in" + (", in the phone browser (--phone web)" if phone == "web" else ": the Decidio app if it is installed, the browser if not"))
            rows.extend("             " + l for l in qr.split("\n") if l.strip())
        elif door_link:
            rows.append(f"{_bold('your phone')}   " + _dim("the link above works on a phone too (no QR came back this time)"))
        rows.append(_dim("whichever answers first wins — the terminal follows the web app or your phone."))
        _block("③", "Your call", rows, tone="choice")
        interactive = True
        verdict = "again"
        _eof = False

        def _settled() -> bool:
            return state["result"] is not None or state["error"] is not None
        for _attempt in range(3):
            try:
                _a = _read_answer_nonblocking("  › " if _attempt == 0 else "   Please answer y (approve) or n (reject): ", _settled)
            except EOFError:
                _eof = True
                break
            if _a is None:
                print()
                break   # decided elsewhere while the prompt was open
            verdict = approval_answer(_a)
            if verdict != "again":
                break
        if _eof and verdict == "again" and not _settled():
            interactive = False
            verdict = "approve"
        elif verdict == "again" and state["result"] is not None:
            decided_outside = "approved"
            verdict = "approve"
        elif verdict == "again" and state["error"] is not None:
            from .errors import DecidioRejected as _RejOut
            if isinstance(state["error"], _RejOut):
                decided_outside = "rejected"
                verdict = "reject"
    from .errors import DecidioTimeout as _Timeout
    if interactive and verdict == "again" and not isinstance(state["error"], _Timeout):
        print("③ No decision was made (no y or n answer), so the tour stops here rather than guess.")
        print("   The request is still ROUTED and waiting in your queue - approve or reject it there, or re-run the tour.")
        print(f"   NOTE: this tour's credentials are still live in {env_file} (a 7-day token + the agent's key). Once you")
        print("   have decided - or if you abandon the tour - remove them: python -m decidio quickstart cleanup")
        print()
        _session_reminder()
        raise SystemExit(3)
    # F5 (first-run review of 0.4.1): the prompt has no timer, the blocking call does. An answer that arrives after the
    # call expired must not seal a decision the tour has already abandoned (TS twin).
    if interactive and isinstance(state["error"], _Timeout):
        print("③ the tour's blocking call gave up after 5 minutes while waiting for your answer, so your answer is NOT posted:")
        if getattr(state["error"], "withdrawn", False):
            # 0.6.4: the SDK's last act on a timeout is to WITHDRAW the request, so it no longer waits in
            # the queue and a later answer there does nothing - say that, not "decide it there" (TS twin).
            print("   the request was WITHDRAWN from your queue (it no longer waits for an answer; deciding it there does nothing). Re-run the tour and answer within 5 minutes.")
        else:
            print("   the request is still ROUTED in your queue (the withdraw call did not land) - decide it there, or re-run the tour and answer within 5 minutes.")
        print(f"   NOTE: this tour's credentials are still live in {env_file} - remove them: python -m decidio quickstart cleanup")
        print()
        _session_reminder()
        raise SystemExit(3)
    if not interactive and not auto_approve_demo:
        print("③ This terminal can't put a human in the loop, and an approval IS a human act — the tour")
        print("   stops here rather than approve its own request. The decision is routed and waiting:")
        print("")
        print(f"     python -m decidio approvals approve {decision_id}     (or approve it in your Decidio app)")
        print("")
        print("   Re-run interactively to watch the whole loop — or, for CI, re-run with")
        print("   --auto-approve-demo to let the tour approve itself under that explicit label.")
        print("   Tidy this tour up any time: python -m decidio quickstart cleanup")
        print("")
        print("   (exit 3 = the tour stopped at the human moment. Nothing executed and no receipt")
        print("    was written, so this run is deliberately not reported as a completed tour.)")
        # EXIT NON-ZERO (parity with the TS CLI). The tour did all it could, but the thing it
        # exists to demonstrate - a human approving and the function then running - did not
        # happen. Exiting 0 told `quickstart && next-step` the loop had been shown when it had not.
        #
        # DELIBERATELY NOT cleaned up: the decision is ROUTED and waiting for a human, and
        # revoking the agent behind a pending approval would destroy the very thing the reader
        # was just told to go and approve. But a live 7-day token IS on disk, and saying so is
        # the difference between a considered choice and an oversight.
        print()
        print(f"   NOTE: this tour's credentials are still live in {env_file} (a 7-day token + the")
        print("   agent's key), because the decision above is still waiting for you. Once you have")
        print("   approved it — or if you abandon the tour — remove them:")
        print("     python -m decidio quickstart cleanup")
        print()
        _session_reminder()
        raise SystemExit(3)
    if not interactive:
        print("③ --auto-approve-demo: approving with your session credential. This is AUTOMATED authority")
        print("   (a flag you passed, not a human decision in the moment) — fine for CI, not the real story.")
    rejected = verdict == "reject"
    if rejected:
        # THE OTHER HALF OF THE PRODUCT, rehearsed: a human says no and nothing happens.
        if decided_outside:
            status, rj = 200, {"alreadyResolved": True, "sealed": True}
        else:
            status, rj = _api(f"/api/decisions/{decision_id}/reject", "POST", {"reason": "quickstart: rejected by the approver"}, bearer=session)
        if not (200 <= status < 300):
            _err(f"✘ reject failed ({status}): {rj}")
            return _fail_tour(1)
        if decided_outside:
            print("  ✔ rejected in the web app (or on your phone) — this terminal saw it and followed")
        # The server answers 200 + alreadyResolved when the decision was decided EITHER way before this call
        # (e.g. approved in the app first). The tour follows that decision rather than calling it a defect.
        from .errors import DecidioRejected as _Rejected
        decided_in_app = isinstance(rj, dict) and rj.get("alreadyResolved") is True
        if not decided_outside:
            print("  • this decision was already decided from your app — the tour follows that decision" if decided_in_app else "  ✔ rejected")
        th.join(timeout=60)
        if th.is_alive():
            _err("✘ the gated call did not settle within 60s of the rejection — the tour did not complete.")
            return _fail_tour(1)
        if state["error"] is None and not decided_in_app:
            # The gated function RETURNED after a rejection. That is the failure this product exists to
            # prevent, and no narration may soften it.
            _ret = state["result"].value if state["result"] is not None else None
            _err(f"✘ the gated function RAN after the rejection (it returned {_json.dumps(_ret)}) — this is a defect, not a tour. Please report it: decidioai.com/#early-access")
            return _fail_tour(1)
        ran_on_app_approval = state["error"] is None
        if ran_on_app_approval:
            _ret = state["result"].value if state["result"] is not None else None
            print(f"  ✔ your app APPROVED it first, so that decision stood and your function ran: {_json.dumps(_ret)}. Re-run the tour to watch a rejection.")
        elif isinstance(state["error"], _Rejected):
            print(f"  ✔ your function did NOT run — the wrapper refused: {state['error']}" + ("" if _EXPLAIN else _dim("  (a human said no, and nothing happened)")))
            if _EXPLAIN:
                print("    That is the product: a human said no, and nothing happened.")
                # THE DENIAL IS A RECORD TOO (first-run review of 0.4.1; TS twin): same download, same pinned offline
                # verification, and the record kind named.
                print("  Downloading the sealed record of the DENIAL and verifying it OFFLINE…")
            _rs, _rec = _api(f"/api/records/{decision_id}/verify", bearer=session)
            if 200 <= _rs < 300 and isinstance(_rec, dict) and _rec.get("credential"):
                _fname = _receipt_file_name(decision_id)
                if _write_receipt_file(_fname, _json.dumps(_rec["credential"], indent=2) + "\n") == "conflict":
                    return _fail_tour(1)
                from . import verify as _verify_d
                # PINNED to the server's configured issuer (else the DID remembered for this host) - never the credential's
                # own `issuer`, which the old code read back out of the response it was checking (3A; TS twin) - and the
                # server's own verdict is honoured: a record its check failed is never shown as VALID.
                _issuer = _host_anchor(_rec)
                _v = _verify_d.verify_receipt(_rec["credential"], _issuer) if _issuer else _verify_d.verify_receipt(_rec["credential"])
                _srv_invalid = _rec.get("valid") is False
                _pin = ", PINNED to your workspace issuer" if _issuer else ""
                _kind_line = f"{'✔ VALID' if _v.get('valid') and not _srv_invalid else '✘ INVALID'} — {_fname} (signature + content binding, offline{_pin}) · record kind: {_record_kind_of(_rec['credential']) or '?'}"
                if not _v.get("valid") or not _issuer or _srv_invalid:
                    print(f"  {_kind_line}")
                    _why = ("no trust anchor: the server named no issuer and none is remembered for this host" if not _issuer
                            else (_v.get("reason") or "no reason given") if not _v.get("valid")
                            else f"the server's own check says it does NOT verify: {_rec.get('reason') or 'no reason given'}")
                    _err(f"  ✘ the denial's receipt did not verify PINNED ({_why}) — the tour did not complete.")
                    return _fail_tour(1)
                _block("④", "The record", [
                    f"✔ VALID — {_fname} " + _dim("(signature + content binding, offline, PINNED to your workspace issuer)"),
                    f"{_bold('decision')} payInvoice $86,000 · REJECTED · routed to a human by policy (no auto-approve rule for this agent)",
                    f"{_bold('record')}   record kind: {_record_kind_of(_rec['credential']) or '?'} " + _dim("— the denial is sealed too"),
                    f"{_bold('issuer')}   {_issuer} " + _dim(f"· your trust anchor — named by this server over the signed-in connection, never read from the receipt; cross-check {API}/api/did"),
                ], tone="bad")
                denial_verified = True
            else:
                print(f"  • no sealed record was issued for this rejection ({_rs}) — the denial is on the decision in your queue.")
        else:
            _err(f"✘ the gated call ended with an error rather than a clean refusal: {state['error']} — nothing ran, but the tour did not complete.")
            return _fail_tour(1)
        print()
        secs = round(_time.time() - t0)
        if ran_on_app_approval:
            print(f"Done in {secs}s: gated → routed to a human → decided in your app (approved) → your function ran once.")
        else:
            _block("✔", f"Done in {secs}s", [
                f"{_bold('gated')}        payInvoice $86,000 — ROUTED to a human as {decision_id}",
                f"{_bold('decided')}      REJECTED {'in the web app (or on your phone)' if decided_outside else 'by you, here'}",
                f"{_bold('executed')}     nothing — your function never ran",
                f"{_bold('record')}       " + ("the DENIAL is sealed too — VALID, verified offline (④ above)" if denial_verified else "none was issued for this rejection (④ above)"),
                _dim("gated → routed to a human → REJECTED → your function never ran"),
            ], tone="bad")
            print("Re-run the tour and answer y to watch the approval half, with its offline-verifiable receipt.")
        print()
        _session_reminder()
        print(f"{_bold('Where next')}  your queue {_link(_APP_URL)} · README \"Durable resume\" " + _dim("· built by OmniTwin - decidioai.com/#early-access"))
    else:
        reason = "quickstart --auto-approve-demo (automated)" if not interactive else "quickstart"
        if decided_outside:
            status, ap = 200, {"alreadyResolved": True}
        else:
            status, ap = _api(f"/api/decisions/{decision_id}/approve", "POST", {"reason": reason}, bearer=session)
        if not (200 <= status < 300):
            _err(f"✘ approve failed ({status}): {ap}")
            return _fail_tour(1)
        already = isinstance(ap, dict) and ap.get("alreadyResolved")
        if decided_outside:
            print("  ✔ approved in the web app (or on your phone) — this terminal saw it and followed")
        else:
            print(f"  ✔ approved{' (already decided from your app — the tour follows that decision)' if already else ''}")

        th.join(timeout=60)
        if state["error"] is not None:
            from .errors import DecidioRejected as _RejectedA
            if isinstance(state["error"], _RejectedA):
                _err("✘ it was REJECTED from your app before this tour's approval landed — your function did NOT run (that is the product). Re-run the tour to watch the approval half.")
                return _fail_tour(1)
            _err(f"✘ the gated call did not complete: {state['error']}")
            return _fail_tour(1)
        # 0.2.0 returns ProtectedExecution: the value AND what Decidio recorded. The tour shows both,
        # because "your function ran" and "Decidio has proof it ran" are the two halves of the pitch.
        _done = state["result"]
        _tier = (_done.confirmation or {}).get("evidence_tier")
        print(f"  ✔ your function executed AFTER approval: {_json.dumps(_done.value)}" + (f" · confirmation.evidence_tier = {_tier}" if _tier else ""))
        if _EXPLAIN and _tier:
            print("    (the call itself told you what was recorded — the wrapper's signed report)")

        if _EXPLAIN:
            print("  Downloading the sealed Authority Receipt and verifying it OFFLINE…")
        status, rec = _api(f"/api/records/{decision_id}/verify", bearer=session)
        if not (200 <= status < 300) or not (isinstance(rec, dict) and rec.get("credential")):
            _err(f"✘ receipt fetch failed ({status})")
            return _fail_tour(1)
        fname = _receipt_file_name(decision_id)
        if _write_receipt_file(fname, _json.dumps(rec["credential"], indent=2) + "\n") == "conflict":
            return _fail_tour(1)
        from . import verify as _verify
        # Verify PINNED to the server's CONFIGURED issuer (`expectedIssuer`), else the DID remembered for this host - never
        # the credential's own `issuer`, which the server echoes back and the old code pinned to (3A; TS twin: circular - a
        # receipt signed by anyone verified "pinned" against itself). An unpinned VALID only proves self-consistency.
        issuer = _host_anchor(rec)
        v = _verify.verify_receipt(rec["credential"], issuer)
        # THE SERVER'S OWN VERDICT IS HONOURED: /verify also binds the credential to the stored record, which an offline
        # check cannot see. A record the server's check failed is never presented as verified.
        server_invalid = rec.get("valid") is False
        pin_note = ", PINNED to your workspace issuer" if issuer else "; issuer unpinned"
        kind_line = f"{'✔ VALID' if v.get('valid') and not server_invalid else '✘ INVALID'} — {fname} (signature + content binding, offline{pin_note}) · record kind: {_record_kind_of(rec['credential']) or '?'}"
        if not v.get("valid") or not issuer or server_invalid:
            print(f"  {kind_line}")
        if not v.get("valid"):
            # Every other failure in this tour cleans up after itself (TS twin): same rule, same exit.
            _err(f"  ✘ the receipt did not verify ({v.get('reason') or 'no reason given'}) — the tour did not complete.")
            return _fail_tour(1)
        if server_invalid:
            _err(f"  ✘ the server's own check says this record does NOT verify ({rec.get('reason') or 'no reason given'}) — the tour did not complete.")
            return _fail_tour(1)
        if not issuer:
            # NOT A PASSED TOUR (first-run review of 0.3.5; TS twin): an unpinned VALID proves the receipt
            # is self-consistent, not who issued it - a self-signed forgery passes the same check.
            _err("  ⚠ the server named no issuer (expectedIssuer) and no DID is remembered for this host, so this check ran UNPINNED —")
            _err("    it proves the receipt is internally consistent, NOT who issued it (a self-signed forgery also passes).")
            _err(f"    Take your Decidio's issuer DID from {API}/api/did (public, no sign-in) — never from the receipt — then re-check:")
            _err(f"      python -m decidio verify --issuer <did:key:...> {fname}")
            _err("  ✘ the tour does not count an UNPINNED check as success.")
            return _fail_tour(1)
        status, detail = _api(f"/api/records/{decision_id}", bearer=session)
        tier = ((detail or {}).get("record", {}).get("confirmation") or {}).get("status") if isinstance(detail, dict) else None
        _block("④", "The receipt", [
            f"✔ VALID — {fname} " + _dim("(signature + content binding, offline, PINNED to your workspace issuer)"),
            f"{_bold('decision')} payInvoice $86,000 · APPROVED · routed to a human by policy (no auto-approve rule for this agent)",
            f"{_bold('record')}   record kind: {_record_kind_of(rec['credential']) or '?'}" + (f" · evidence: {tier}" if tier else "") + " " + _dim("— the receipt seals the DECISION; execution evidence lives on the record"),
            f"{_bold('issuer')}   {issuer} " + _dim(f"· your trust anchor — named by this server over the signed-in connection, never read from the receipt; cross-check {API}/api/did"),
        ], tone="good")

        secs = round(_time.time() - t0)
        _block("✔", f"Done in {secs}s", [
            f"{_bold('gated')}        payInvoice $86,000 — ROUTED to a human as {decision_id}",
            f"{_bold('decided')}      " + ("approved in the web app (or on your phone)" if decided_outside else "approved by --auto-approve-demo (automated, and labeled so on the record)" if not interactive else "approved by you, here"),
            f"{_bold('executed')}     your function ran once, AFTER approval",
            f"{_bold('receipt')}      VALID — verified offline, pinned to your workspace issuer (④ above)",
            _dim("gated → routed to a human → approved → executed once → a receipt you can verify offline"),
        ], tone="good")
        print()
        print(_bold("Take it to your real agent — the .env here already works:"))
        print("  from decidio import guard")
        print('  do_it = guard.protect(do_it_raw, lambda a: {"action": "yourAction", "amount": a["amount"], "scope": "YourScope"})' + _dim("   # durable by default"))
        print()
        if _EXPLAIN:
            print("  The README Setup flow is this same blocking tour in your own code; if you keep this agent, its .env")
            print("  already works here, so skip its init.")
        _session_reminder()
        # The tour is the only place someone has EXPERIENCED the product rather than read about it - they
        # just watched a receipt verify offline. Saying who built it, and offering a conversation, belongs
        # here rather than only in a document they may never scroll to. (Twin of the TS tour close.)
        print(f"{_bold('Where next')}  your queue {_link(_APP_URL)} · README \"Durable resume\" " + _dim("· built by OmniTwin - decidioai.com/#early-access"))
    # Leave nothing behind unless asked to. Interactive: offer, default KEEP.
    # Automated: default CLEANUP unless --keep-agent.
    do_cleanup = False
    if interactive:
        try:
            answer = input("\nKeep this agent for development? [Enter = keep - c + Enter = clean up now]: ").strip().lower()
            do_cleanup = answer == "c"
        except EOFError:
            do_cleanup = False
        if not do_cleanup:
            print("  Kept. Tidy up any time: python -m decidio quickstart cleanup")
    elif auto_approve_demo and not keep_agent:
        do_cleanup = True
        print("\nAutomated run: cleaning the tour up (pass --keep-agent to keep the agent + token).")
    # The cleanup's exit code is part of THIS command's answer. Discarding it let a tour that
    # failed to revoke its token exit 0 - a CI job would go green while a live credential stayed
    # valid, which is the one outcome cleanup exists to prevent. The standalone
    # `quickstart cleanup` subcommand always propagated; the embedded call now matches it.
    cleanup_code = _quickstart_cleanup(session, env_file) if do_cleanup else 0
    # An INVALID receipt already failed the tour closed above (0.4.0), and a rejected tour has no receipt at
    # all: by here the tour completed, and the cleanup's exit code is the only thing left to report (TS twin).
    return cleanup_code or 0


def _quickstart_cleanup(session: str, env_file: str) -> int:
    """Revoke the tour's token, delete its local credential file and remove the tour's agent on the server (0.13.0). Honest about
    what remains: sealed records are PERMANENT by design; the agent's registration row stays, marked removed (its name stays
    taken)."""
    env: dict = {}
    # An unreadable credential file must not stop the sweep: the JOURNAL below is the durable record
    # of what this directory still owes, and it is exactly the case the journal exists for.
    try:
        if os.path.exists(env_file):
            for line in open(env_file, encoding="utf-8"):
                if "=" in line and not line.startswith("#"):
                    k, val = line.split("=", 1)
                    env[k.strip()] = val.strip()
    except Exception as _ee:  # noqa: BLE001
        _err(f"  ⚠ {env_file} could not be read ({_ee}) - sweeping the token recovery journal instead.")
    # SWEEP THE JOURNAL (V033-02): every minted token this directory never recorded as persisted or
    # revoked - live until it is revoked here, by hand, or by expiry.
    _journal_revoked = 0
    _journal_stuck = []
    _journal_reconciled = 0
    _unheld: list = []
    try:
        # The credential file's OWN ids are revoked (and retired) by their branches below; the sweep covers
        # what no file here can reach, so its sentence stays true (TS twin).
        import re as _re_own
        _own_ids: set = set()
        if os.path.exists(env_file):
            try:
                for _m in _re_own.finditer(r"^\s*DECIDIO_(?:ORPHANED_)?TOKEN_JTI=(.+)$", open(env_file, encoding="utf-8").read(), _re_own.M):
                    for _j0 in _m.group(1).split(","):
                        if _j0.strip():
                            _own_ids.add(_j0.strip())
            except Exception:  # noqa: BLE001 - an unreadable file is handled below
                pass
        _outstanding = [j for j in _journal_owed() if j.get("jti") not in _own_ids]
        _unheld = _journal_unheld()
        _owed_ids = {j.get("jti") for j in _outstanding}
        _unheld_ids = {j.get("jti") for j in _unheld}
        _held_elsewhere = [j for j in _journal_outstanding() if j.get("jti") not in _owed_ids and j.get("jti") not in _unheld_ids and j.get("jti") not in _own_ids]
    except Exception as _jc:  # noqa: BLE001 - UNCERTAINTY IS NOT ABSENCE (TS twin)
        _err(f"✘ the token recovery journal cannot be trusted ({_jc}). It may hold the id of a live token, so this cleanup cannot claim nothing is owed. Every byte is left as found: inspect {JOURNAL_PATH}, revoke anything it names (python -m decidio tokens list --mine), then repair or move it aside and re-run.")
        return 1
    for _j in _held_elsewhere:
        print(f"  • journalled token {_j['jti']} ({_j.get('label') or 'token'}) is live and still held by a credential file here — not a tour token, left alone (revoke it yourself: python -m decidio tokens revoke {_j['jti']})")
    for _j in _unheld:
        _err(f"  ⚠ journalled token {_j['jti']} ({_j.get('label') or 'token'}) is live: it was written to a credential file that is no longer here — not a tour token, so this cleanup will not revoke it. If it is yours and lost, revoke it: python -m decidio tokens revoke {_j['jti']}")
    for _j in _outstanding:
        # A jti minted against ANOTHER Decidio cannot be revoked here (the server answers 404 for a
        # token it does not hold), so the sweep says which API owns it instead of failing forever.
        if _j.get("apiUrl") and _j.get("apiUrl") != API:
            _journal_stuck.append(_j["jti"])
            _err(f"  ⚠ journalled token {_j['jti']} was minted against {_j['apiUrl']}, not {API} — revoke it there: DECIDIO_API_URL={_j['apiUrl']} python -m decidio tokens revoke {_j['jti']}")
            continue
        _js, _jb = _api(f"/api/workspace/agent-token/{_j['jti']}", "DELETE", bearer=session)
        if 200 <= _js < 300:
            _journal_retire(_j["jti"], "revoked")

            if isinstance(_jb, dict) and _jb.get("changed") is False:
                _journal_reconciled += 1
                print(f"  • journalled token {_j['jti']} was already revoked — retiring its journal entry.")
            else:
                _journal_revoked += 1
                print(f"  ✔ journalled token revoked (jti {_j['jti']}{', ' + _j['label'] if _j.get('label') else ''}) — from the journal: {'its credential file is gone' if _j.get('persisted') else 'its credential file never landed'}, so the journal was the handle")
        else:
            _journal_stuck.append(_j["jti"])
            _err(f"  ⚠ journalled token {_j['jti']} could NOT be revoked ({_js}) — it is still live; its id stays in {JOURNAL_PATH}.")
    if _journal_stuck:
        _err(f"✘ {len(_journal_stuck)} journalled token(s) are STILL LIVE and could not be revoked. Nothing was deleted; retry, or revoke by hand:")
        for _sj in _journal_stuck:
            _err(f"    python -m decidio tokens revoke {_sj}")
        return 1
    # SWEEP THE ORPHANS FIRST (F-010). These are tokens a previous replace could not revoke:
    # still live, and no longer the CURRENT credential, so nothing else will ever come back for
    # them. One that still refuses to die keeps its id on disk and fails the command, exactly like
    # the current token below - a cleanup must never report success over a credential it could not
    # kill.
    _orphans = [j.strip() for j in (env.get("DECIDIO_ORPHANED_TOKEN_JTI") or "").split(",") if j.strip()]
    _still = []
    for _oj in _orphans:
        _os_status, _ = _api(f"/api/workspace/agent-token/{_oj}", "DELETE", bearer=session)
        if 200 <= _os_status < 300:
            _journal_retire(_oj, "revoked")
            print(f"  ✔ orphaned token revoked (jti {_oj}) — it had survived an earlier replace")
        else:
            _still.append(_oj)
            print(f"  ⚠ orphaned token {_oj} could NOT be revoked ({_os_status}) — it is still live.", file=sys.stderr)
    if _still:
        print(f"✘ {len(_still)} orphaned token(s) are STILL LIVE and could not be revoked. Nothing was deleted; {env_file} keeps their ids so you can retry:", file=sys.stderr)
        for _oj in _still:
            print(f"    python -m decidio tokens revoke {_oj}", file=sys.stderr)
        return 1
    jti = env.get("DECIDIO_TOKEN_JTI")
    if not jti and _journal_revoked > 0 and (not os.path.exists(env_file) or not env):
        # The credential file never landed (or cannot be read) and the journal sweep revoked what it
        # owed: there is no current token to revoke and nothing of the tour's on disk to remove.
        print(f"  • no credential file to clean: the journal sweep revoked {_journal_revoked} token(s) this directory owed.")
        jti = None
        _skip_missing_jti = True
    else:
        _skip_missing_jti = False
    if jti:
        status, _body = _api(f"/api/workspace/agent-token/{jti}", "DELETE", bearer=session)
        if 200 <= status < 300:
            _journal_retire(jti, "revoked")   # the journal learns of the revocation too (TS twin)
        if 200 <= status < 300 and isinstance(_body, dict) and _body.get("changed") is False:
            print(f"  • token was already revoked (jti {jti}) — nothing to do.")
        elif 200 <= status < 300:
            print(f"  ✔ token revoked (jti {jti})")
        else:
            # DO NOT DELETE WHAT WE STILL NEED TO REVOKE (TS parity — cli.ts already refuses this).
            # Deleting the credential file after a FAILED revoke destroys the only local handle to
            # a token that is still live: the jti goes with it, and the operator is left with a
            # working credential they can no longer name. Keep the file and say so.
            # STDERR, not stdout (F-014 / TS parity). These lines report a FAILURE that leaves a
            # live credential behind; on stdout they are indistinguishable from the command's
            # ordinary progress output, and a log that captures only stderr drops them entirely.
            print(f"  ⚠ token revoke returned {status} — the token is STILL LIVE (it expires on its own within 7 days).", file=sys.stderr)
            print(f"  {env_file} has been KEPT so its jti is not lost: revoke it with `python -m decidio tokens revoke {jti}`, then delete the file.", file=sys.stderr)
            return 1
    elif not _skip_missing_jti and not os.path.exists(env_file):
        # No credential file and the journal owed nothing this sweep could act on. (A corrupt journal never
        # reaches here - it refused above.) Unheld non-tour tokens were named above and are not "nothing".
        if _unheld:
            _err(f"  • no credential file here ({env_file} is already gone); the journal names {len(_unheld)} live token(s) this cleanup will not revoke (above).")
        else:
            print(f"  • no credential file here ({env_file} is already gone) and the token recovery journal owes nothing further" + (f" ({_journal_reconciled} already-revoked row(s) reconciled)" if _journal_reconciled else "") + ".")
    elif not _skip_missing_jti:
        print(f"  ⚠ no DECIDIO_TOKEN_JTI in {env_file} (older tour) — revoke by hand: python -m decidio tokens list, then tokens revoke <jti>. It expires on its own within 7 days.", file=sys.stderr)
        print(f"  {env_file} has been KEPT (deleting it would remove the credential without revoking it).", file=sys.stderr)
        return 1
    # Remove ONLY what the tour wrote (in a project directory the tour MERGES into an
    # existing .env, so deleting the whole file would destroy the project's own variables — a
    # cleanup must never remove anything it didn't create). The file itself goes only when nothing
    # else lives in it.
    # An unreadable credential file after the revocations above is reported, not raised (TS twin).
    _env_raw = None
    if os.path.exists(env_file):
        try:
            _env_raw = open(env_file, encoding="utf-8").read()
        except Exception as _ee:  # noqa: BLE001
            _err(f"  ⚠ {env_file} could not be read ({_ee}) — left as it is; remove it by hand once it is readable.")
    if _env_raw is not None:
        import re as _re
        tour_keys = {"DECIDIO_API_URL", "DECIDIO_AGENT_ID", "DECIDIO_AGENT_DID", "DECIDIO_AGENT_KEY", "DECIDIO_API_TOKEN", "DECIDIO_WORKSPACE_ID", "DECIDIO_TOKEN_JTI", "DECIDIO_ORPHANED_TOKEN_JTI"}
        kept = []
        for line in _env_raw.splitlines():
            m = _re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=", line)
            if m:
                if m.group(1) not in tour_keys:
                    kept.append(line)
            elif line.strip():
                kept.append(line)
        if not kept:
            os.remove(env_file)
            print(f"  ✔ {env_file} deleted (the agent's local key is gone — the registered agent is now inert)")
        else:
            _write_secret_file(env_file, "\n".join(kept) + "\n")
            plural = "" if len(kept) == 1 else "s"
            print(f"  ✔ tour credentials removed from {env_file} — its {len(kept)} other line{plural} untouched (the agent's local key is gone — the registered agent is now inert)")
    # HONEST ACCOUNTING includes the queue (a headless-stopped tour leaves its
    # routed decision pending in the SHARED workspace queue, and cleanup said nothing about it).
    # Listing is a read; clearing it stays a human act — we print the command, we don't run it.
    tour_agent = env.get("DECIDIO_AGENT_ID")
    if tour_agent:
        _cards_status, cards_body = _api("/api/decisions/cards", bearer=session)
        cards = (cards_body or {}).get("cards", []) if isinstance(cards_body, dict) else []
        stranded = [c for c in cards
                    if c.get("isAgentRequest") and c.get("status") != "sealed"
                    and isinstance(c.get("title"), str) and c["title"].startswith(f"{tour_agent}:")]
        for c in stranded:
            print(f"  ⚠ this tour's decision {c.get('id')} is still PENDING in your workspace queue — clear it with:")
            print(f'      python -m decidio approvals reject {c.get("id")} "quickstart cleanup"')
    # REMOVE THE TOUR'S AGENT (0.13.0, launch plan L4 Remove agent; TS twin): on the server too - its new requests stop, its name stays
    # taken and the records it made stay. Only the TOUR's own agent (a quickstart- name from the tour's file). A Decidio without the
    # remove door (an older server: a 404 with no code) leaves it registered, inert without its key and token, and says so.
    agent_stuck = False
    if tour_agent and tour_agent.startswith("quickstart-"):
        rm_status, rm_body = _api("/api/agents/remove", "POST", {"agentId": tour_agent}, bearer=session)
        rm_code = rm_body.get("code") if isinstance(rm_body, dict) else None
        if 200 <= rm_status < 300:
            if isinstance(rm_body, dict) and rm_body.get("changed") is False:
                print(f'  • the tour\'s agent "{tour_agent}" was already removed')
            else:
                print(f'  ✔ the tour\'s agent "{tour_agent}" removed — it can\'t make new requests (its name stays taken; the records it made stay)')
        elif rm_status == 404 and rm_code == "NOT_FOUND":
            print(f'  • the tour\'s agent "{tour_agent}" is not registered here — nothing to remove')
        elif rm_status == 404:
            print(f'  • this Decidio can\'t remove agents yet — the tour\'s agent "{tour_agent}" stays registered, inert without its key and token')
        else:
            agent_stuck = True
            _err(f'  ⚠ the tour\'s agent "{tour_agent}" could NOT be removed ({rm_status}) — it is inert without its key and token; remove it on the Agents page.')
    print("  • What remains, by design: the sealed decision record (records are permanent — that is the product)")
    print("    and the agent's registration row, marked removed (its name stays taken, so its records keep pointing at one agent).")
    # The durable store is the agent's OWN execution ledger, so cleanup does not delete it - but a
    # first-run review found it undisclosed beside a message that listed "what remains". Say it.
    if os.path.isdir(".decidio-pending"):
        print("  • Also kept: .decidio-pending/ — this agent's own execution ledger: whatever this agent parked (call arguments,")
        print("    execution evidence; never credentials, by design). Gitignored; owner-only where the OS supports it. If nothing is")
        print("    pending and you do not want the history, remove it:")
        print("      " + ("Remove-Item -Recurse .decidio-pending" if os.name == "nt" else "rm -r .decidio-pending"))
    # The tour's sign-in ends with the tour (UAT ruling 2026-09-03; TS twin).
    if _end_session():
        print("  ✔ signed out — the stored sign-in is removed from this computer (the token itself stays valid until it expires; python -m decidio login to sign in again).")
    elif os.environ.get("DECIDIO_SESSION_TOKEN"):
        print("  • DECIDIO_SESSION_TOKEN is still exported in this shell — unset it when you are done.")
    return 1 if agent_stuck else 0


def cmd_tokens(sub: Optional[str], jti: Optional[str], mine_only: bool = False) -> int:
    """tokens list [--mine] / tokens revoke <jti> — agent-token lifecycle from the terminal."""
    if sub not in ("list", "revoke"):
        _err("usage: python -m decidio tokens list [--mine]")
        _err("       python -m decidio tokens revoke <jti>")
        _err("  Agent tokens are shown by jti (their revocation id) — the token VALUE is never shown again after minting.")
        return 2
    if sub == "revoke" and not jti:
        _err("usage: python -m decidio tokens revoke <jti>   (find the jti with: python -m decidio tokens list)")
        return 2
    # Same grammar and same shape-error as approvals --mine (a first run in the
    # SHARED sandbox listed 138 workspace-wide rows — accurate, documented, and still terrible
    # isolation optics with no way to narrow).
    # --mine AFTER CLEANUP: .env is gone, but this directory's token recovery journal still names its agents (first-run
    # audit of 0.4.4; TS twin). The journal is the identity source then; an empty one keeps the shape error below.
    try:
        journal_agents = list(dict.fromkeys(r.get("agentId") for r in _journal_rows() if isinstance(r, dict) and isinstance(r.get("agentId"), str) and r.get("agentId")))
    except Exception:  # noqa: BLE001  lint-allow: a corrupt journal is refused by mint and cleanup; here it only widens --mine's identity source
        journal_agents = []
    my_agents = [os.environ["DECIDIO_AGENT_ID"]] if os.environ.get("DECIDIO_AGENT_ID") else journal_agents
    if mine_only and not my_agents:
        _err("✘ --mine needs an agent identity, and there is no DECIDIO_AGENT_ID in this directory's .env or your environment.")
        _err("  Run this from your agent's directory (where init wrote .env), or drop --mine for the workspace-wide list.")
        return 2
    bearer: Optional[str] = None
    status, body = _api("/api/workspace/agent-token")
    if status in (401, 403):
        bearer = _acquire_session()
        if not bearer:
            return 1
        if sub == "list":
            status, body = _api("/api/workspace/agent-token", bearer=bearer)
    if sub == "revoke":
        status, rbody = _api(f"/api/workspace/agent-token/{jti}", "DELETE", bearer=bearer)
        if 200 <= status < 300:
            # Replay honesty (the SDK's own contract): revoking an
            # already-revoked token changes nothing and must read as a no-op, not a fresh kill.
            # The server says which via `changed`.
            if isinstance(rbody, dict) and rbody.get("changed") is False:
                _journal_retire(jti, "revoked")
                print(f"• {jti} was already revoked — nothing changed.")
                print("  Revocation is permanent; there is no re-revoke. See it: python -m decidio tokens list")
                return 1
            _journal_retire(jti, "revoked")
            print(f"✔ revoked {jti} — the token is dead now (its agent stays registered; mint a new one with init).")
            return 0
        if status == 404:
            _err(f'✘ no token with jti "{jti}" — list them: python -m decidio tokens list')
            return 1
        _err(f"✘ revoke failed ({status}): {rbody}")
        return 1
    if not (200 <= status < 300):
        _err(f"✘ could not list tokens ({status}): {body}")
        return 1
    all_tokens = (body or {}).get("tokens") if isinstance(body, dict) else body
    all_tokens = all_tokens if isinstance(all_tokens, list) else []
    my_agent = os.environ.get("DECIDIO_AGENT_ID") or (f"{', '.join(journal_agents)} (from the token recovery journal)" if journal_agents else None)
    # FILTER FIRST, FORMAT SECOND (parity with approvals --mine): the human view and any future
    # machine view must be the same set.
    tokens = [t for t in all_tokens if isinstance(t, dict) and t.get("agentId") in my_agents] if mine_only else all_tokens
    if not tokens:
        if mine_only:
            elsewhere = f" ({len(all_tokens)} elsewhere in this workspace — drop --mine to see them)" if all_tokens else ""
            print(f'No agent tokens for "{my_agent}"{elsewhere}.')
        else:
            print("No agent tokens in this workspace.")
        return 0

    # Status is derived per row, revoked first — a list that showed revoked tokens as "Active"
    # would make the revocation audit surface unable to confirm its own revocations.
    def _status(t: dict) -> str:
        if t.get("revokedAt"):
            return f"REVOKED {str(t['revokedAt'])[:10]}"
        exp = t.get("expiresAt")
        if isinstance(exp, str):
            try:
                from datetime import datetime, timezone
                if datetime.fromisoformat(exp.replace("Z", "+00:00")) < datetime.now(timezone.utc):
                    return "expired"
            except Exception:  # noqa: BLE001 — an unparseable expiry reads as active, like JS's NaN compare
                pass
        return "active"

    mine_note = f' for "{my_agent}"' if mine_only else ""
    scope_note = f" — workspace-wide (a shared workspace shows every member's agents; --mine narrows to this directory's agent, {my_agent})" if my_agent and not mine_only else ""
    print(f"Agent tokens ({len(tokens)}{mine_note}){scope_note}:")
    for t in tokens:
        print(f"  {t.get('jti')}  {_status(t)}  agent={t.get('agentId') or '?'}  label={t.get('label') or ''}  expires={t.get('expiresAt') or '?'}")
    # The governed-action allowance rides the same response — showing it here is what keeps the
    # per-hour cap from ever being a surprise 429 (the cap was undocumented
    # and its refusal untyped).
    al = body.get("allowance") if isinstance(body, dict) else None
    # 0.13.0: by kind (the server's agent limits by kind) - requests that need a person, and requests the rules decide; an older
    # server sends the one allowance.
    pa = al.get("person") if isinstance(al, dict) else None
    ra = al.get("rules") if isinstance(al, dict) else None
    if isinstance(pa, dict) and isinstance(ra, dict) and pa.get("limit") is not None and ra.get("limit") is not None:
        resets = f" (resets {pa['resetAt']})" if pa.get("resetAt") else ""
        print(f"\nAgent requests this hour: {pa.get('remaining')} of {pa['limit']} left that need a person, {ra.get('remaining')} of {ra['limit']} left that the rules decide{resets}.")
    elif isinstance(al, dict) and al.get("limit") is not None:
        resets = f" (resets {al['resetAt']})" if al.get("resetAt") else ""
        print(f"\nGoverned-action allowance: {al.get('remaining')}/{al['limit']} remaining this hour{resets}.")
    print("\nRevoke one:  python -m decidio tokens revoke <jti>")
    return 0


def cmd_verify(args: list) -> int:
    """Delegates to decidio.verify.run — the SAME conformance-locked implementation that
    `python -m decidio.verify` runs (equivalent-path rule: a second verifier door must be the
    same code). run(), not main(): the standalone door's --version/--help handling must not
    swallow a file that happens to be named "version" on this door (parity with the TS sdk
    door, which treats every positional as a file). Fully offline."""
    from . import verify as _verify
    if not args:
        _err("usage: python -m decidio verify [--issuer <did:key>] <receipt.json> [more.json ...]   (or --allow-unpinned)")
        _err("  Verifies Authority Receipts OFFLINE — signature, content binding, chain order.")
        return 2

    # THE TRUST ANCHOR, in order (3A; TS twin): an explicit --issuer; else the DID this computer remembered for the
    # configured host (DECIDIO_API_URL from the shell, or the hosted service - verify reads no .env) when it signed in or
    # ran init; else a built-in Decidio issuer (the standalone door's rule); else the refusal. NEVER the receipt's own
    # issuer field. Read lazily - an explicit --issuer never touches the store.
    def _remembered():
        try:
            m = _remembered_issuer(_verify_host())
        except ValueError as e:
            raise ValueError(f"the issuer DIDs this computer remembers ({_issuers_file()}) could not be read ({e}) — refusing to fall back to another trust anchor.\n"
                             "  Pass --issuer <did:key> for this run, or repair the file (or move it aside and sign in again). Nothing was verified.") from e
        return (m["did"], f"remembered for {_issuer_store_key(_verify_host())} since {str(m.get('firstSeen'))[:10]}") if m else None
    return _verify.run(args, command="python -m decidio verify", remembered=_remembered,
                       no_anchor_hint=f"  Nothing is remembered for {_issuer_store_key(_verify_host())} on this computer: signing in once (python -m decidio login) remembers its DID, and then no --issuer is needed.")


def cmd_receipt(rid: Optional[str], json_mode: bool = False) -> int:
    if not rid:
        _err("usage: python -m decidio receipt <decisionId>")
        _err("  Downloads the decision's sealed Authority Receipt (a W3C Verifiable Credential) to a .json file.")
        _err("  Find decision ids via `python -m decidio approvals` or in your Decidio app.")
        return 2
    # Receipts are workspace data — session scope, like approvals. (The record-detail /verify
    # route carries the credential; the plain record route does not.)
    bearer: Optional[str] = None
    status, body = _api(f"/api/records/{rid}/verify")
    if status in (401, 403):
        bearer = _acquire_session()
        if not bearer:
            _err("✘ downloading a receipt needs a workspace sign-in.")
            return 1
        status, body = _api(f"/api/records/{rid}/verify", bearer=bearer)
    if status == 404:
        _err(f'✘ no sealed record for "{rid}" in this workspace.')
        _err("  Receipts exist once a decision is SEALED (approved or rejected). Still pending? python -m decidio approvals")
        return 1
    if not (200 <= status < 300) or not (isinstance(body, dict) and body.get("credential")):
        _err(f"✘ could not fetch the receipt ({status}): {str(body)[:300]}")
        return 1
    import json as _json
    name = _receipt_file_name(rid)
    next_bytes = _json.dumps(body["credential"], indent=2) + "\n"
    # THE TRUST ANCHOR (3A; TS twin): the DID remembered for this host, else the server's CONFIGURED issuer (a server
    # naming a different one than the remembered DID is warned about and not followed). Never body["issuer"]: the server
    # echoes the credential's own issuer there - what the file CLAIMS - so pinning to it was circular.
    issuer = _host_anchor(body)
    # THE FILE IS CHECKED AGAINST THE ANCHOR IT IS HANDED OVER WITH, offline, before anything is said about it (a server
    # can name one DID and serve a credential signed by another key), and THE SERVER'S OWN VERDICT IS HONOURED (/verify
    # also binds the credential to the stored record, which an offline check cannot see). Either failure: the file is
    # still written - it is the evidence of the problem - and says so; the command exits 1.
    from . import verify as _verify_r
    local = _verify_r.verify_receipt(body["credential"], issuer) if issuer else None
    server_invalid = body.get("valid") is False
    local_invalid = local is not None and not local.get("valid")
    bad = server_invalid or local_invalid
    say = _err if json_mode else print   # --json: stdout is the JSON result ONLY
    _wrote = _write_receipt_file(name, next_bytes, say=say)
    if _wrote == "conflict":
        return 1
    if _wrote == "written":
        say(f"• wrote {name} — kept for inspection only: it does NOT verify (below)" if bad else f"✔ wrote {name}")
    detail_status, detail = _api(f"/api/records/{rid}", bearer=bearer)
    conf = (detail or {}).get("record", {}).get("confirmation") if isinstance(detail, dict) else None
    # WHAT THE TOKENS MEAN, for you. The receipt is sealed over the TOKENIZED payload - that is
    # what makes it verifiable offline by someone who cannot reach Decidio, and what stops a
    # downloaded copy leaking names to whoever it is forwarded to. So the file keeps its tokens
    # and the server resolves them per viewer, over the authenticated channel, for exactly the
    # fields this access covers. Absent when entitled to nothing, or for a service token with no
    # per-user identity.
    resolved = body.get("resolved") if isinstance(body, dict) else None
    if not isinstance(resolved, dict):
        resolved = None

    def _bad_said() -> None:
        if server_invalid:
            _err(f"✘ the server's own check says this record does NOT verify: {body.get('reason') or 'no reason given'}")
            _err(f"  (signature {'INVALID' if body.get('signatureValid') is False else 'valid'} · content bound {'NO' if body.get('contentBound') is False else 'yes'}"
                 f" · matches the stored record {'NO' if body.get('matchesRecord') is False else 'yes'} · stored payload {'ALTERED' if body.get('payloadMatches') is False else 'intact'})")
        if local_invalid:
            _err(f"✘ this receipt does NOT verify against this Decidio's issuer DID ({issuer}): {local.get('reason') or 'no reason given'}")
        _err(f"  Do not rely on {name}. Report it to the operator of {API} — a sealed record is immutable, so this is tampering, a defect, or an unannounced key change (see any warning above), never a normal state.")
    if json_mode:
        # `issuer` is the TRUST ANCHOR this file was checked against (None when there is none - an older server, or a
        # store that could not be read). `valid` reports the OFFLINE verdict against that anchor: False when either check
        # failed, True only when the offline check actually ran and passed, and None when NO offline check ran (no
        # anchor) - the server's own "valid" is not enough to call a receipt verified, since the whole point is the
        # offline pin (3A follow-up: an unreadable store used to yield valid:true, issuer:null - the server's word alone).
        valid = False if bad else (True if (local is not None and local.get("valid")) else None)
        _out = {"file": name, "decisionId": rid, "evidenceTier": (conf or {}).get("status") if isinstance(conf, dict) else None, "confirmed": bool((conf or {}).get("confirmed")) if isinstance(conf, dict) else False,
                "issuer": issuer, "valid": valid}
        if bad:
            _out["reason"] = body.get("reason") if server_invalid else local.get("reason")
        if resolved:
            _out["resolved"] = resolved
        print(_json.dumps(_out, indent=2))
        if bad:
            _bad_said()
            return 1
        return 0
    if bad:
        _bad_said()
        return 1
    if isinstance(conf, dict) and conf.get("status"):
        confirmed = " (confirmed)" if conf.get("confirmed") else ""
        print(f'  Sealed credential: the authority decision (its confirmation field reads "pending" forever — immutable). Current record evidence tier: {conf["status"]}{confirmed}.')
    if resolved and not sys.stdout.isatty():
        # A pipe or a log is not a terminal: resolved identities (a full name among them) stay off it (first-run audit
        # of 0.4.4); --json hands them over explicitly.
        print(f"  {len(resolved)} identity field(s) your access covers are shown only on a terminal (this is a pipe or a log) — use --json to receive them explicitly.")
    elif resolved:
        _n = len(resolved)
        print(f'  Resolved for you ({_n} field{"" if _n == 1 else "s"} your access covers — the FILE keeps the tokens, so it stays verifiable and safe to hand on):')
        for _tok, _val in resolved.items():
            print(f"    {_tok}  →  {_val}")
    print("  Verify it offline — no Decidio account or network needed (the verifier is built in):")
    if issuer:
        # NOBODY PASTES A DID WHEN THIS COMPUTER ALREADY KNOWS IT (3A; TS twin). The flagless command resolves the DID
        # remembered for VERIFY'S host - DECIDIO_API_URL from the shell, never .env (_verify_host) - then the built-in
        # list by the receipt's own issuer; the plain form is printed only when that lands on this same anchor. An
        # unreadable store makes a flagless verify refuse, so only the explicit form is true then.
        v_host = _verify_host()
        plain, via = False, ""
        try:
            mem = _remembered_issuer(v_host)
            claimed = str((body.get("credential") or {}).get("issuer") or "")
            flagless = mem["did"] if mem else next((k["did"] for k in _verify_r.KNOWN_ISSUERS if k["did"] == claimed), None)
            plain = flagless == issuer
            via = "remembered on this computer" if mem else "built into the verifier"
        except ValueError:
            plain = False
        if plain:
            print(f"    python -m decidio verify {name}")
            print(f"  No --issuer needed here: it pins to this Decidio's issuer ({via}), which the server also named:")
        else:
            print("  Record your workspace's issuer DID — copy this line, and pin it forever:")
        print()
        print(issuer)
        print()
        print(f"  Cross-check it out of band — the same DID is published by this Decidio host at {API}/api/did (public, no sign-in).")
        print("  Anywhere else, pin it explicitly (copy the DID from the line above — this one may wrap):" if plain else "  Then verify, pinned to it (the same DID, inline — copy from the line above, not this one, which your terminal may wrap):")
        print(f"    python -m decidio verify --issuer {issuer} {name}")
        if not plain and _issuer_store_key(v_host) != _issuer_store_key(API):
            print(f"  (verify reads no .env, so a flagless run pins to the DID for {v_host}, not {API} - export DECIDIO_API_URL={API} in your shell to verify this host's receipts without --issuer.)")
        elif not plain:
            print("  Or sign in once (python -m decidio login): this computer then remembers the DID, and verify needs no --issuer.")
    else:
        print(f"  To also prove WHO issued it, pin your Decidio's issuer DID — published at {API}/api/did (public, no sign-in), never read off the receipt:")
        print(f"    python -m decidio verify --issuer <did:key:...> {name}")
    return 0


USAGE = """decidio — the Decidio SDK command line (Python)

  The wrapper IS the SDK: guard.protect(fn, describe) ships in this package (from decidio import guard).
  This command line is the tour, the sign-in, and the token admin around it.

  New here? See the whole thing work in about two minutes:

      python -m decidio quickstart

  It gates a demo action, routes it to YOU for approval, executes on your yes, and hands you a
  cryptographically verifiable receipt of the DECISION (execution evidence then accrues on the
  hosted record — the receipt seals who authorized what, not what ran afterward). Guided and
  explicit — this CLI never acts, signs you in, or writes files unless you ask it to.

THE TOUR
  python -m decidio quickstart          the guided two-minute tour: gate -> approve -> execute -> proof
                                       (interactive: y approves, n rejects - Enter is not an answer. Headless it stops
                                       at the routed decision; --auto-approve-demo for CI, labeled
                                       automated; ends with a keep-or-cleanup choice; --explain prints
                                       the long narration of each step; --phone web makes the QR open
                                       the phone web rendering even when the Decidio app is installed)
  python -m decidio quickstart cleanup  revoke the tour's token + delete its local credentials (the inert
                                       registration row and the permanent sealed record stay)
                                       (and end the stored sign-in)
  python -m decidio quickstart --auto-approve-demo  headless tour; cleans up after itself
                                       (add --keep-agent to KEEP the tour agent + token)

SIGN IN (once)
  python -m decidio login [email]      sign in ONCE: the CLI emails you a link, you paste it; the sign-in
                                       is kept on this computer 30 days, or until this terminal closes, logout, or cleanup
  python -m decidio logout             forget the stored sign-in on this computer (the token itself stays valid
                                       until it expires — there is no server-side revocation yet)

YOUR AGENT AND ITS TOKENS
  python -m decidio init [agentId]      sign in, register the agent, mint its API token, write .env
                                       --unique / --force / --expires-days N (default 90)
  python -m decidio doctor              check config, connectivity, and what your token can do
  python -m decidio tokens list [--mine]  agent tokens with status (active/expired/REVOKED) by
                                       jti — token values are never re-shown; the list is
                                       workspace-wide, --mine narrows to this directory's agent
  python -m decidio tokens revoke <jti> kill a token now instead of waiting out its lifetime

APPROVALS AND RECEIPTS
  python -m decidio approvals [--json] [--mine]   list pending agent approvals
  python -m decidio approvals approve <id> [reason]
  python -m decidio approvals reject <id> [reason]
                                       the reason is FREE TEXT, sent exactly as typed. It seals
                                       immutably; personal or sensitive values are tokenized at
                                       rest, so the STORED text can differ (see `receipt <id>`).
                                       If it starts with a dash, put it after -- or use --reason:
                                         ... approve <id> -- "-50% cut, per the board"
                                         ... approve <id> --reason "-50% cut, per the board"
  python -m decidio receipt <id> [--json]   download a sealed decision's Authority Receipt (.json)
  python -m decidio verify [--issuer <did>] <receipt.json> [more...]   verify receipts OFFLINE, pinned to a trust
                                       anchor it prints first: --issuer if given, else the DID this computer remembered
                                       for your Decidio when you signed in, else the built-in hosted-service issuer
                                       (never the receipt's own issuer field; --allow-unpinned: structural check only)

CODING AGENTS (Claude Code)
  python -m decidio hook ...            not in the Python CLI: the hooks run under npx — npx @decidio/sdk hook install

DEVELOPMENT
  python -m decidio --version           print the CLI version

NOTES
  Every NETWORK command talks to Decidio (https://mcp.decidioai.com) unless DECIDIO_API_URL says
  otherwise (the invite-only lab: https://mcp-staging.decidioai.com); the target host is announced on stderr each run. "verify" is
  fully offline — it touches no network and reads no .env (only the issuer DIDs remembered at sign-in).
  Update check: network commands ask the public PyPI registry once a day whether a newer version exists. If so,
  an interactive run asks "Upgrade now? [y/n]" first (y upgrades and re-runs your command; n exits); a headless
  run prints the notice and continues (DECIDIO_REQUIRE_LATEST=1 makes it exit). DECIDIO_NO_UPDATE_CHECK=1 skips
  the check. Nothing is sent to Decidio; verify never checks.
  Help: --help (or -h) after any command prints this page - one page for every command.
  Exit codes: 0 success / 1 failure or honest no-op (e.g. replay refused) / 2 usage error /
  3 quickstart stopped at the human moment (headless: routed, but nothing executed and no
  receipt written - pass --auto-approve-demo for a run that completes unattended).
  Errors and usage go to stderr; stdout carries results only (safe to pipe).
  Docs: the README that shipped with this package (quickstart, durable resume, adapters)."""


# ---- the update gate (founder ruling 2026-09-04; TS twin) ----------------------------------------------------------
# Network commands ask the PUBLIC registry (PyPI) once a day whether a newer version exists - never our servers, cached
# in the user's profile, silent when offline. Interactive + newer: ask first; y upgrades through pip and re-runs the
# command, n exits 1. Headless + newer: the notice prints and the command runs (DECIDIO_REQUIRE_LATEST=1 exits instead).
# DECIDIO_NO_UPDATE_CHECK=1 skips the check. verify never checks.
_GATED_CMDS = {"quickstart", "init", "login", "doctor", "approvals", "receipt", "tokens"}


def _semver_newer(a: str, b: str) -> bool:
    # STRICT, EXACTLY THREE ALL-DIGIT COMPONENTS (3A follow-up; TS twin). The old parse did `int(x) for x in split(".")[:3]`,
    # which silently dropped a fourth component and let " 3 " through (int() strips); require the whole string to be
    # `\d+\.\d+\.\d+` so no trailing bytes ever reach the compare or the notice.
    import re as _r
    def _p(s: str):
        return [int(x) for x in s.split(".")] if _r.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", s) else None
    pa, pb = _p(a), _p(b)
    if pa is None or pb is None:
        return False
    return pa > pb


def _latest_published() -> Optional[str]:
    import time as _t
    cache = os.path.join(_session_dir(), "update-check.json")
    try:
        import re as _re_c
        with open(cache, encoding="utf-8") as fh:
            c = json.load(fh)
        # The CACHED value gets the SAME full-match the network answer does (3A follow-up; TS twin): a planted
        # update-check.json could otherwise carry a "latest" with terminal escape codes or trailing bytes into the notice.
        if isinstance(c.get("latest"), str) and _re_c.fullmatch(r"\d+\.\d+\.\d+", c["latest"]) and _t.time() - float(c.get("checkedAt", 0)) < 86400:
            return c["latest"]
    except Exception:  # noqa: BLE001 - no usable cache: ask the registry
        pass
    reg = (_SHELL_ENV.get("DECIDIO_UPDATE_REGISTRY") or "https://pypi.org").rstrip("/")
    try:
        with urllib.request.urlopen(urllib.request.Request(f"{reg}/pypi/decidio/json"), timeout=2) as r:
            body = json.loads(r.read().decode())
        latest = (body.get("info") or {}).get("version") if isinstance(body, dict) else None
        # Only a plain x.y.z is a usable answer (never printed or compared otherwise: a hostile registry could smuggle
        # terminal control sequences into a "version").
        import re as _re_v
        if not isinstance(latest, str) or not _re_v.fullmatch(r"\d+\.\d+\.\d+", latest):
            return None
        try:
            os.makedirs(_session_dir(), exist_ok=True)
            with open(cache, "w", encoding="utf-8") as fh:
                json.dump({"checkedAt": _t.time(), "latest": latest}, fh)
        except Exception:  # noqa: BLE001 - the cache is optional
            pass
        return latest
    except Exception:  # noqa: BLE001 - offline or a registry hiccup: never block a working tool
        return None


_TRUTH_SESSION = "The session token itself stays valid until it expires (up to 30 days) — there is no server-side revocation yet"


def _update_gate(cmd: Optional[str], args: list) -> Optional[int]:
    """An exit code to stop with, or None to run the command."""
    from . import __version__
    # DECIDIO_UPDATE_REEXEC marks the re-run this gate itself spawns after an upgrade: it never checks again, so a version
    # that did not move (pip installed into another site) cannot loop the prompt.
    if not cmd or cmd not in _GATED_CMDS or _SHELL_ENV.get("DECIDIO_NO_UPDATE_CHECK") or _SHELL_ENV.get("DECIDIO_UPDATE_REEXEC") or "-" in __version__ or "+" in __version__:
        return None
    latest = _latest_published()
    if not latest or not _semver_newer(latest, __version__):
        return None
    import subprocess as _sp
    upgrade_cmd = "pip install -U decidio"
    notice = f"{latest} is available (you have {__version__})."
    if not (_stdin_is_console() and sys.stdout.isatty()):
        _err(f"⚠ {notice} Upgrade: {upgrade_cmd}")
        if _SHELL_ENV.get("DECIDIO_REQUIRE_LATEST"):
            _err("✘ DECIDIO_REQUIRE_LATEST is set — not running a stale version.")
            return 1
        return None
    a = (_ask(f"{notice} Upgrade now? [y/n]: ") or "").strip().lower()
    if a not in ("y", "yes"):
        _err(f"✘ not upgraded — run this when ready: {upgrade_cmd}")
        return 1
    argv_up = [sys.executable, "-m", "pip", "install", "-U", "decidio"]
    if _SHELL_ENV.get("DECIDIO_UPDATE_DRY_RUN"):   # the smokes: prove the path without touching the machine
        print(f"  would run: {' '.join(argv_up)}")
        return None
    print(f"  upgrading: {' '.join(argv_up)}")
    if _sp.call(argv_up, env=_SHELL_ENV) != 0:
        _err(f"✘ the upgrade did not complete — run it by hand: {upgrade_cmd}")
        return 1
    print(f"  ✔ upgraded — re-running: python -m decidio {' '.join(args)}")
    return _sp.call([sys.executable, "-m", "decidio", *args], env={**_SHELL_ENV, "DECIDIO_UPDATE_REEXEC": "1"})


def main(argv: Optional[list] = None) -> int:
    # UTF-8 streams at EVERY entry to this door — the console-script (decidio.exe) calls main()
    # directly and bypasses __main__.py — reconfigure here or the console-script door mojibakes.
    for _stream in (sys.stdout, sys.stderr):
        if hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001 — an exotic stream must not kill the CLI
                pass
    args = argv if argv is not None else sys.argv[1:]
    cmd = args[0] if args else None
    if cmd in ("--version", "-v", "-V", "version"):
        from . import __version__
        print(__version__)
        return 0
    if cmd is None or _wants_help(cmd):   # the SAME predicate _OFFLINE_CMD used
        print(USAGE)
        return 0
    if len(args) > 1 and _wants_help(args[1]):
        print(USAGE)
        return 0
    if _help_flag_anywhere(args):   # `<command> [sub] --help` - one page for every command
        print(USAGE)
        return 0
    # STRICT FLAGS (unknown options were silently ignored — a security CLI fails
    # closed on options it doesn't understand, BEFORE any auth or network).
    known = {
        "quickstart": ({"--explain", "--auto-approve-demo", "--keep-agent"}, {"--phone"}),
        "login": (set(), set()),
        "logout": (set(), set()),
        "init": ({"--unique", "--force"}, {"--expires-days"}),
        "doctor": (set(), set()),
        # --reason carries free text that may itself start with "-" (a sealed reason is verbatim),
        # so it is VALUED: its value is consumed, never parsed as a flag.
        "approvals": ({"--json", "--mine"}, {"--reason"}),
        "receipt": ({"--json"}, set()),
        "verify": ({"--allow-unpinned"}, {"--issuer"}),
        "tokens": ({"--mine"}, set()),
        "dev": (set(), {"--target", "--port"}),
        "hook": ({"--project"}, {"--timeout", "--approver", "--cli"}),
    }
    if cmd in known:
        plain, valued = known[cmd]
        rest = args[1:]
        positionals: list = []
        i = 0
        while i < len(rest):
            a = rest[i]
            # `--` is the POSIX end-of-options marker. Everything after it is literal text — that
            # is the escape hatch a sealed free-text reason needs, and refusing it here (as
            # "unknown option --") would have made the verbatim-reason path unreachable.
            if a == "--":
                positionals.extend(rest[i + 1:])
                break
            # ANY leading dash is an option, not a positional (parity with the TS CLI). Checking
            # only "--" let single-dash tokens fall through as positionals: harmless where arity
            # catches them, SILENT where it does not (`verify -q file.json` dropped the flag and
            # exited as though it had applied). A lone "-" stays positional for the stdin
            # convention; everything after "--" is already literal.
            # ...but ONLY while we are still reading OPTIONS. `approvals approve <id> ...` takes a
            # sealed REASON as its tail, where "-50%" is a word, not a flag; refusing it there
            # would re-break the verbatim-reason guarantee. `verify` takes file positionals, which
            # never start with a dash, so its whole line stays under the rule.
            _in_free_text_tail = (cmd == "approvals"
                                  and positionals[:1] in (["approve"], ["reject"])
                                  and len(positionals) >= 2)
            if not _in_free_text_tail and a.startswith("-") and not a.startswith("--"):
                _err(f'✘ unknown option "{a}" for `{cmd}` — refusing to guess (a flag you meant to '
                     f'matter must never be silently ignored). Short flags are not supported; use the long form.')
                _err()
                _err(USAGE)
                return 2
            if a.startswith("--"):
                if a in valued:
                    i += 2
                    continue
                if any(a.startswith(v + "=") for v in valued):  # --flag=value form
                    i += 1
                    continue
                if a not in plain:
                    _err(f'✘ unknown option "{a}" for `{cmd}` — refusing to guess (a flag you meant to matter must never be silently ignored).')
                    _err()
                    _err(USAGE)
                    return 2
            else:
                positionals.append(a)
            i += 1
        # POSITIONAL arity is part of the same contract (`tokens revoke jti1
        # jti2` revoked only the first and reported unqualified success — silent false success on
        # a security control). Anything beyond what the command reads is refused, not dropped.
        # approvals approve/reject take a free-text reason, so their tail is exempt; verify takes
        # any number of files.
        max_pos = {"quickstart": 1, "init": 1, "doctor": 0, "receipt": 1, "tokens": 2, "dev": 0, "login": 1, "logout": 0, "hook": 2}
        exempt_tail = (cmd == "approvals" and positionals and positionals[0] in ("approve", "reject")) or cmd == "verify"
        if not exempt_tail and cmd == "approvals" and positionals:
            _err(f'✘ unknown approvals subcommand "{positionals[0]}" — use approve or reject (or no subcommand to list).')
            return 2
        if not exempt_tail and cmd in max_pos and len(positionals) > max_pos[cmd]:
            _err(f'✘ unexpected argument "{positionals[max_pos[cmd]]}" for `{cmd}` — refusing to guess (an argument you meant to matter must never be silently ignored).')
            _err()
            _err(USAGE)
            return 2
        if cmd == "quickstart" and len(positionals) == 1 and positionals[0] != "cleanup":
            _err(f'✘ unknown quickstart subcommand "{positionals[0]}" — the only one is: python -m decidio quickstart cleanup')
            return 2
        if cmd == "tokens" and len(positionals) > 1 and positionals[0] == "list":
            _err(f'✘ unexpected argument "{positionals[1]}" for `tokens list` — it takes none (an argument you meant to matter must never be silently ignored).')
            return 2
    gated = _update_gate(cmd, args)   # a stale install: ask to upgrade, or say so (see _update_gate)
    if gated is not None:
        return gated
    if cmd == "quickstart":
        # F-1106-C4 (a): with no DECIDIO_API_URL the whole command - the tour and its cleanup - is the lab's.
        _refused = _enter_lab_or_refuse()
        if _refused is not None:
            return _refused
        rest_args = args[1:]
        if "cleanup" in rest_args:
            # ...or, with no tour file at all, a token recovery journal that still owes revocations
            # (the double-fault shape: the credential file never landed; the journal is the only handle).
            def _journal_owes() -> bool:
                try:
                    return bool(_journal_owed()) or bool(_journal_unheld())
                except Exception:  # noqa: BLE001 - a corrupt journal must reach the sweep's refusal
                    return True
            env_file = ".env.quickstart" if os.path.exists(".env.quickstart") else (ENV_PATH if _read_env().get("DECIDIO_AGENT_ID", "").startswith("quickstart-") else (".env.quickstart" if _journal_owes() else None))
            if not env_file:
                # Nothing this command may act on. Outstanding rows that remain are HELD tokens (owed/unheld came back
                # empty) - name them rather than say the journal owes nothing (prodsec V041-02; TS twin).
                try:
                    _held_rows = _journal_outstanding()
                except Exception:  # noqa: BLE001  lint-allow: a corrupt journal was refused by the sweep dispatch above; here it only decides the wording
                    _held_rows = []
                if _held_rows:
                    print(f"Nothing to clean up here: no tour credentials. The token recovery journal names {len(_held_rows)} live token(s) held by a credential file here ({', '.join(j['jti'] for j in _held_rows)}) — not tour tokens, left alone; doctor lists them.")
                else:
                    print("Nothing to clean up here: no .env.quickstart, .env doesn't belong to a quickstart agent, and the token recovery journal has no live token to act on.")
                # The documented promise - cleanup ENDS the stored sign-in - holds even with nothing else to clean
                # (prodsec retest of 0.4.4: this early return skipped it and exited 0).
                if _end_session():
                    print("  ✔ signed out — the stored sign-in is removed from this computer (the token itself stays valid until it expires).")
                return 0
            session = _acquire_session()
            if not session:
                return 1
            return _quickstart_cleanup(session, env_file)
        return cmd_quickstart(auto_approve_demo="--auto-approve-demo" in rest_args, keep_agent="--keep-agent" in rest_args, explain="--explain" in rest_args, phone=_valued_opt(rest_args, "--phone"))
    if cmd == "tokens":
        positional = [x for x in args[1:] if not x.startswith("-")]
        return cmd_tokens(positional[0] if positional else None, positional[1] if len(positional) > 1 else None,
                          mine_only="--mine" in args[1:])
    if cmd == "init":
        rest_args = args[1:]
        unique = "--unique" in rest_args
        exp_days: Optional[int] = None
        # BOTH forms (the strict table's generic `=` allowance let --expires-days=30
        # pass the gate while this parser read only the space form — a silently-ignored
        # credential-LIFETIME flag, the exact class the verifier doors just fixed).
        eq_form = next((x for x in rest_args if x.startswith("--expires-days=")), None)
        if "--expires-days" in rest_args or eq_form:
            if eq_form:
                raw: Optional[str] = eq_form[len("--expires-days="):]
                rest_args = [x for x in rest_args if x != eq_form]
            else:
                i = rest_args.index("--expires-days")
                raw = rest_args[i + 1] if i + 1 < len(rest_args) else None
                rest_args = [x for j, x in enumerate(rest_args) if j not in (i, i + 1)]
            if not raw or not raw.isdigit() or int(raw) < 1:
                _err("✘ --expires-days needs a positive whole number of days (e.g. --expires-days 30).")
                return 2
            exp_days = int(raw)
        # After `--` the next token is the name VERBATIM (TS twin): the strict table lets it through,
        # and the old "first non-dash token" rule dropped it and registered a substituted id.
        agent_arg = (rest_args[rest_args.index("--") + 1] if "--" in rest_args and rest_args.index("--") + 1 < len(rest_args)
                     else next((x for x in rest_args if not x.startswith("-")), None))
        name = agent_arg or os.environ.get("DECIDIO_AGENT_ID", "my-agent")
        if unique:
            name = f"{name}-{secrets.token_hex(2)}"
        return cmd_init(name, force="--force" in args, expires_days=exp_days)
    if cmd == "login":
        return _cmd_login(next((x for x in args[1:] if not x.startswith("-")), None))
    if cmd == "logout":
        return _cmd_logout()
    if cmd == "doctor":
        return cmd_doctor()
    if cmd == "approvals":
        # A REASON IS FREE TEXT AND IS SEALED INTO AN IMMUTABLE RECORD. Filtering "anything that
        # starts with -" silently deleted words like "-50%" and the receipt then attested text the
        # human never typed. Everything after `--` is literal; `--reason <text>` is explicit; and
        # otherwise the reason is the remainder AS TYPED, dashes included. (Parity with the TS CLI.)
        rest_args = args[1:]
        dashdash = rest_args.index("--") if "--" in rest_args else -1
        head = rest_args[:dashdash] if dashdash >= 0 else rest_args
        literal = rest_args[dashdash + 1:] if dashdash >= 0 else []
        r_idx = head.index("--reason") if "--reason" in head else -1
        r_eq = next((x for x in head if x.startswith("--reason=")), None)
        flagless = [x for i, x in enumerate(head)
                    if not x.startswith("-") and not (r_idx >= 0 and i == r_idx + 1)]
        sub = flagless[0] if flagless else None
        rid = flagless[1] if len(flagless) > 1 else None
        # Reason precedence: --reason wins (space form, then `=` form); then anything after
        # `--`; then the literal remainder after the id.
        reason: Optional[str] = None
        if r_idx >= 0:
            reason = head[r_idx + 1] if len(head) > r_idx + 1 else None
        elif r_eq is not None:
            reason = r_eq[len("--reason="):]
        elif literal:
            reason = " ".join(literal)
        elif sub and rid:
            rest = [x for x in head[head.index(rid) + 1:] if x not in ("--json", "--mine")]
            reason = " ".join(rest) if rest else None
        # Only a MISSING value is an error; a single-dash value is the documented hatch (A8,
        # 0.1.12: startswith("-") also caught "-50% cut" — the exact text the hatch exists
        # for). The "--" narrowing is load-bearing: it admits "-50% cut" while still refusing
        # a double-dash typo'd flag as a value (`--reason --nope` must not seal "--nope").
        if (r_idx >= 0 or r_eq is not None) and (reason is None or reason == "" or (r_idx >= 0 and reason.startswith("--"))):
            _err(f'✘ --reason needs the text to record (quote it if it contains spaces): '
                 f'python -m decidio approvals {sub or "approve"} <id> --reason "over budget -50% cut required"')
            return 2
        # A reason with nothing to attach to is a flag that cannot apply — refusing beats
        # silently ignoring text the operator believed was recorded.
        if reason is not None and sub not in ("approve", "reject"):
            _err('✘ --reason only applies to approve/reject (a sealed reason needs a decision to seal onto): '
                 'python -m decidio approvals approve <id> --reason "..."')
            return 2
        # Flags are read from HEAD ONLY. Scanning the whole line would find "--json" inside a
        # reason typed after `--` and refuse the command — the escape hatch has to hold both sides.
        return cmd_approvals(sub, rid, reason,
                             json_mode="--json" in head, mine_only="--mine" in head)
    if cmd == "receipt":
        rest_args = args[1:]
        rid_arg = next((x for x in rest_args if not x.startswith("-")), None)
        return cmd_receipt(rid_arg, "--json" in rest_args)
    if cmd == "verify":
        return cmd_verify(args[1:])
    if cmd == "quickstart":
        return cmd_quickstart()
    if cmd == "dev":
        # Honesty over a green exit (`dev` exited 0 having done nothing,
        # which reads as a relay that started). The Node CLI carries the actual relay.
        _err("✘ the dev relay is not implemented in the Python CLI yet — use the Node one: npx @decidio/sdk dev (same relay, same webhook).")
        return 1
    if cmd == "hook":
        # The Claude Code hooks (0.8.0) live in the Node CLI: Claude Code runs `npx @decidio/sdk hook pretool` with the
        # tool call on stdin, so a Python twin would be a second runtime to install for the same hook. Said plainly,
        # exit 1 - never a green exit that reads as an installed hook.
        _err("✘ the Claude Code hooks are not implemented in the Python CLI — use the Node one: npx @decidio/sdk hook install (the same gate, the same approvals).")
        return 1
    # Exit 2, not 1: an unknown command is a USAGE error (the help text promises that contract).
    # A flag in command position gets a NAMED fix, not just a refusal.
    if cmd.startswith("-"):
        _err(f'✘ unknown command "{cmd}" — flags go AFTER the command (e.g. python -m decidio approvals {cmd}).\n\n{USAGE}')
    else:
        _err(f'✘ unknown command "{cmd}"\n\n{USAGE}')
    return 2


if __name__ == "__main__":
    # UTF-8 out on this door too (`python -m decidio.cli`); the packaged doors — __main__.py for
    # `python -m decidio`, verify.py's guard for `python -m decidio.verify` — carry their own.
    for _stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(_stream, "reconfigure"):
                _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — a non-reconfigurable stream keeps its encoding
            pass
    raise SystemExit(main())
