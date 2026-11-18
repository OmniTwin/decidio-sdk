"""Decidio Guard error types — the SEMANTIC mirror of @decidio/guard (TS).

Naming: the short forms (DecidioBlocked, ...) are the original Python names; the
TS-suffixed forms (DecidioBlockedError, ...) are aliases so a developer can catch
the SAME name in both languages (the suffix was dropped in
Python for four errors and kept for DecidioRateLimitError — inconsistent with
Node, the README, and itself). Both names are exported and permanent."""
from __future__ import annotations


class DecidioError(Exception):
    """Base for all Decidio Guard errors."""


class DecidioBlocked(DecidioError):
    """Policy blocked the action (incl. the universal deny-by-default backstop). fn never runs."""

    def __init__(self, reason: str, decision_id: str):
        super().__init__(f"Decidio blocked the action: {reason}")
        self.reason = reason
        self.decision_id = decision_id


class DecidioRejected(DecidioError):
    """A human rejected the routed action."""

    def __init__(self, reason: str, decision_id: str):
        super().__init__(f"A human rejected the action: {reason}")
        self.reason = reason
        self.decision_id = decision_id


class DecidioRequestChanged(DecidioBlocked):
    """THE REQUEST CHANGED AFTER APPROVAL (0.7.0). Decidio records an approval for `decision_id`, but it is
    bound (by a keyed commitment) to a DIFFERENT request than the one about to run - the arguments, the
    amount or the described context changed after a human approved, or this agent's key material changed
    since it asked. Nothing was executed. A new request needs a new approval. Subclasses DecidioBlocked,
    so code that already treats a block as "did not run" keeps doing so. Mirrors the TS
    DecidioRequestChangedError."""

    code = "request_changed"

    def __init__(self, decision_id: str, detail: "str | None" = None):
        super().__init__(detail or f"the request changed after approval (decision {decision_id})", decision_id)
        extra = f"({detail}) " if detail and not detail.startswith("the request changed after approval") else ""
        self.args = (f"[decidio] the request changed after approval: decision {decision_id} was approved for a "
                     f"different request than the one about to run. Nothing was executed. {extra}A changed request "
                     f"needs its own approval - reject {decision_id} and run the action again.",)


class DecidioApprovalUnverified(DecidioBlocked):
    """An approval that cannot be TIED to this request (0.7.0): Decidio answered without the request
    commitment this SDK sent (code "commitment_missing" - the gate predates request binding), or holds one
    this process cannot recompute (code "unverifiable" - no or unreadable key material, or a malformed
    answer). Fail closed: nothing was executed. Subclasses DecidioBlocked. Mirrors the TS
    DecidioApprovalUnverifiedError."""

    def __init__(self, decision_id: str, code: str, detail: str):
        super().__init__(detail, decision_id)
        self.code = code
        self.args = (f"[decidio] cannot confirm that decision {decision_id} approved THIS request: {detail}. "
                     f"Nothing was executed.",)


class DecidioSuspended(DecidioError):
    """(durable mode) The action was routed and is now parked for async approval; the
    process may exit and resume later. NOT a failure — catch it and return/stop."""

    def __init__(self, decision_id: str, action: str):
        super().__init__(
            f'Decidio suspended "{action}" for async approval (decision {decision_id}). '
            "It will resume when a human approves."
        )
        self.decision_id = decision_id
        self.action = action


class DecidioTimeout(DecidioError):
    """(blocking mode only) No human decided within the poll timeout.

    ``withdrawn`` (0.6.4+): True when the SDK told Decidio it gave up and the request was closed as
    WITHDRAWN (it leaves the queue; a later approval does nothing); False when that best-effort call
    failed, so the request may still be open in Decidio. Nothing was executed locally either way.

    ``shared`` (0.12.0; TS twin): True when the request was left open on purpose because it may be shared - the
    authorize answered an earlier request (``idempotentReplay``) or joined one another caller is waiting on
    (``openTwin``), or the withdraw was refused because another caller joined it (409 SHARED_REQUEST). A person
    still decides it."""

    def __init__(self, decision_id: str, withdrawn: bool = False, shared: bool = False):
        super().__init__(f"Timed out waiting for human approval ({decision_id})")
        self.decision_id = decision_id
        self.withdrawn = withdrawn
        self.shared = shared


class DecidioUnsafeArguments(DecidioError, ValueError):
    """A value that cannot survive JSON with its meaning intact was refused before routing.
    Subclasses ValueError too, so pre-0.1.10 `except ValueError` handlers keep working.
    `decision_id` is set only on defense-in-depth refusals after a decision already exists."""

    def __init__(self, message: str, decision_id=None):
        super().__init__(message)
        self.decision_id = decision_id


def _side_effect_note(endpoint: str, code=None) -> str:
    """What this failure means for SIDE EFFECTS, by endpoint. Every non-2xx used to end with
    "Nothing was routed or executed", which is TRUE for authorize and for a status read, and FALSE
    for confirm - a confirm fails AFTER the agent's action has already run, so telling that caller
    nothing executed invites them to run the action a second time to "make it happen". This
    sentence is the one an operator acts on; it has to match reality per door."""
    if endpoint.startswith("/agent/confirm"):
        # THE TWO REFUSALS THAT ARE NOT ABOUT THE REPORT. A 409 here does not mean "your report
        # failed"; it means the gate refuses to attach execution evidence to this decision at all -
        # because a human denied it, or because authority was never granted. Saying "only its report
        # failed" would bury the alarming half: something executed against a decision that was not
        # approved. TWIN PARITY: this branch shipped on the TypeScript door only, so a Python agent
        # that ran an action against a DENIED decision was told the one sentence the TS twin
        # explicitly rejects as false. The shared corpus could not see it either - confirm.json had
        # no HTTP-code dimension - which is how the gate that exists to stop the twins diverging
        # stayed green through it.
        if code == "TERMINALLY_DENIED":
            return (" A human DENIED this decision, and your action appears to have run anyway. Decidio "
                    "recorded the refusal and will NOT attach execution evidence to a denied decision. "
                    "Do NOT re-run it - investigate why the action executed without an approval.")
        if code == "NOT_AUTHORIZED":
            return (" This decision is not an approved, sealed decision, so no execution evidence can "
                    "attach to it yet. If your action already ran, it ran WITHOUT authority - do NOT "
                    "re-run it; investigate. If you are confirming early, wait for the approval and "
                    "confirm then.")
        # States the invariant and stops. Whether the report can be re-sent depends on whether the
        # evidence reached the ledger - which this layer cannot see, and the caller's own
        # diagnostic already answers correctly.
        return " Your action ALREADY RAN - only its report failed. Do NOT re-run it."
    if endpoint.startswith("/agent/status"):
        return " This call is a read, so it changed nothing; the decision itself is unaffected."
    return " Nothing was routed or executed."


def _server_said(body) -> "str | None":
    """The server's own sentence on a refusal (its `message`, else `error`), bounded - or None (TS twin: serverSaid)."""
    if not isinstance(body, dict):
        return None
    said = body.get("message") if isinstance(body.get("message"), str) else body.get("error") if isinstance(body.get("error"), str) else None
    return said[:400] if said else None


class DecidioHttpError(DecidioError):
    """A gate response this SDK could not accept. Subclasses DecidioError so the DOCUMENTED
    `except DecidioError:` actually catches it — a bare RuntimeError escaped that contract and
    hard-crashed production agents on the day their token expired.

    `status` is the HTTP status; `retryable` is decided by the status, not by "anything that is
    not a credential problem" - 401/403 were the only terminal ones, so a 400, a 404, a 409 or a
    422 all advertised themselves as safe to retry, and a caller branching on `retryable` would
    loop forever on a request the server will never accept."""

    def __init__(self, status: int, endpoint: str, body=None):
        credential = status in (401, 403)
        retryable = (not credential) and (status in (408, 429) or (status >= 500 and status != 501))
        _code = body.get("code") if isinstance(body, dict) else None
        if credential:
            head = (" - the credential was rejected. The agent token may have expired or been revoked "
                    "(re-running init for the same agent revokes the previous one). Mint a fresh one: "
                    "python -m decidio init <agent-name>, then restart this process.")
        elif status == 402:
            # 0.13.0 (launch plan L4; TS twin): a 402 is the workspace's PLAN, in its own words - not a credential, not the
            # request, and no retry changes it; the server's sentence says what clears it and who can.
            said = _server_said(body)
            head = (" - your workspace's plan doesn't cover this. It isn't a sign-in problem: signing in again won't change it."
                    + (f" Decidio says: {said}" if said else ""))
        elif _code == "AGENT_REMOVED":
            # 0.13.0 (Remove agent, call 9; TS twin): this agent was removed - final; a new agent under a new name is the way on.
            head = (" - this agent was removed from its workspace, so it can't make new requests (the requests it made before "
                    "stay as they are). Register a new agent under a new name: python -m decidio init <new-name>, then restart "
                    "this process.")
        elif retryable:
            head = ((" - this looks transient. Your action ALREADY RAN; do NOT re-run it - only its report failed to land, and the door's own note says whether a report was kept to re-send.")
                    if "/agent/confirm" in str(endpoint) else
                    (" - this looks transient; polling again is safe (a status read changes nothing).")
                    if "/agent/status" in str(endpoint) else
                    # 0.12.0 (11f; TS twin): the SDK retries the authorize itself, with the SAME body - the same request
                    # key - so its retries were the same request. "A retry creates a NEW request" stopped being true.
                    (" - this looks transient. This SDK already retried it with the same request key (a request still "
                     "waiting is answered with the one already waiting); retrying is safe and can never double-execute.")
                    if "/agent/authorize" in str(endpoint) else
                    " - this looks transient; retrying is safe and can never double-execute.")
        else:
            head = (" - the server refused the request itself, so retrying it unchanged will fail the "
                    "same way. Fix the request (or the decision it names) first.")
        # The CODE decides which confirm advice is true, so it has to be read before the message is
        # built (above). `body` was already stored and never consulted.
        super().__init__(f"[decidio] {endpoint} refused this call (HTTP {status})" + head + _side_effect_note(endpoint, _code))
        self.status = status
        self.endpoint = endpoint
        self.body = body
        self.retryable = retryable


# TS-name aliases — same classes, catchable under the Node names (see module docstring).
DecidioBlockedError = DecidioBlocked
DecidioRejectedError = DecidioRejected
DecidioRequestChangedError = DecidioRequestChanged
DecidioApprovalUnverifiedError = DecidioApprovalUnverified
DecidioSuspendedError = DecidioSuspended
DecidioTimeoutError = DecidioTimeout
DecidioUnsafeArgumentsError = DecidioUnsafeArguments
# DecidioHttpError needs no alias — it carries the same name in both SDKs.


import re as _re


def decision_id_problem(raw) -> "str | None":
    """ONE rule for what counts as a usable decision id, returning a REASON rather than raising, so
    every door can apply the same check and raise its own error type.

    All four copies (core inline, adapters, resume, confirm) tested truthiness only, so `"   "`
    passed every one of them: the blocking path would poll `/agent/status/%20%20%20`, the durable
    path would park under a whitespace key, and the confirmation would attest a decision nobody
    can look up. Control characters are refused for the same reason a reason-string is sanitised -
    an id goes into a URL path, a filename and an audit line. Nothing is silently trimmed: an id
    that needs trimming is not the id the server sent, and quietly rewriting an identifier is how
    two systems end up disagreeing about which decision they mean."""
    if not isinstance(raw, str):
        return f"it is {type(raw).__name__}, not a string"
    if len(raw) == 0:
        return "it is empty"
    if len(raw.strip()) == 0:
        return "it is only whitespace"
    if raw != raw.strip():
        return ("it has leading or trailing whitespace (ids are used verbatim in URLs, filenames "
                "and audit lines - this SDK will not silently trim one)")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        return "it contains control characters"
    # THE SERVER'S GRAMMAR, MIRRORED (class G). The prodsec report asked the SDK to "mirror the
    # server's actual issued ID grammar" - there wasn't one, every server schema was
    # z.string().min(1), so the SDK was the STRICTER of the two and the fix had to start there.
    # apps/api/src/authority/decision-id.ts now defines it and every server door applies it; this
    # is the mirror. Keeping the two in step matters in BOTH directions: looser here and the SDK
    # parks, polls and signs an id the server will reject at the next door; stricter here and the
    # SDK refuses an id the server legitimately issued. The shared corpus
    # (vectors/decision-id.json) holds all three implementations to the same answers.
    if len(raw) > 128:
        return f"it is {len(raw)} characters long (limit 128)"
    # `fullmatch`, NOT `match` with `$`: in Python `$` also matches just before a TRAILING
    # NEWLINE, so `^...$` accepts an id ending in one while JavaScript and the server reject it.
    # Unreachable
    # today only because the control-character loop above fires first - and the server has no
    # separate control-char check, so the next person who "simplifies this to match the server"
    # would silently reopen it. The corpus case "a newline (the copy-paste case)" is the backstop.
    if not _re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", raw):
        return ("it is not letters, digits, dot, dash or underscore starting with a letter or "
                "digit (an opaque id needs nothing else, and every other character is a way to "
                "make two different strings look like the same decision)")
    return None
