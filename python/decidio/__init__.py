"""@decidio/guard (Python) — the one-line approval gate for AI-agent actions.

    from decidio import guard
    @guard.approve(lambda o: {"action": "createOpportunity", "amount": o["amount"]})
    async def create_opp(o): ...        # no rename, no call-site change

    # or the wrap form, when you cannot decorate the definition:
    create_opp = guard.protect(create_opp_raw,
        lambda o: {"action": "createOpportunity", "amount": o["Amount"], "scope": "Opportunity"})

Decidio gates (proceed | route | block) + records a portable, verifiable Authority
Receipt the customer owns; the AGENT executes its own action on resume. Decidio never
executes and holds no downstream credentials.
"""
from .guard import Guard, GuardConfig, ProtectedExecution, guard, protect, protect_best_effort, approve, ApprovalContext
from .signing import (
    assert_json_safe,
    sign_execution_report,
    verify_execution_report,
    result_digest,
)
from .canonical import canonicalize, canonicalize_args, canonical_json, JsonValue
from .evidence import (
    EVIDENCE_TIERS,
    build_confirm_body,
    describe_tier_gap,
    read_confirm_response,
)
from .resume import (
    ResumeController,
    PendingAction,
    PendingStore,
    DecidioDenied,
    DecidioRecoveryUnavailable,
    MemoryPendingStore,
    FilePendingStore,
    harden_dir,
    sign_body,
    verify_signature,
    check_approval,
    approval_refusal,
    claim_approval,
    claim_refusal,
    new_claim_key,
)
from .signing import binding_material, request_commitment, idempotency_key, invocation_request_key, own_request_key, committed_request_json
from .errors import (
    DecidioError,
    DecidioBlocked,
    DecidioRejected,
    DecidioSuspended,
    DecidioTimeout,
    DecidioBlockedError,
    DecidioRejectedError,
    DecidioSuspendedError,
    DecidioTimeoutError,
    DecidioUnsafeArguments,
    DecidioUnsafeArgumentsError,
    DecidioHttpError,
    DecidioRequestChanged,
    DecidioRequestChangedError,
    DecidioApprovalUnverified,
    DecidioApprovalUnverifiedError,
)
# Lives in guard.py beside the authorize transport it types (the HTTP 429 branch), but is one of
# the Decidio error classes and exported with them.
from .guard import DecidioRateLimitError

__all__ = [
    "guard", "protect", "protect_best_effort", "ProtectedExecution",
    "approve", "Guard", "GuardConfig", "ApprovalContext",
    "ResumeController", "PendingAction", "PendingStore", "MemoryPendingStore", "FilePendingStore",
    "DecidioDenied", "DecidioRecoveryUnavailable",
    "harden_dir", "sign_body", "verify_signature", "assert_json_safe",
    "canonicalize", "canonicalize_args", "canonical_json", "JsonValue",
    "EVIDENCE_TIERS", "read_confirm_response", "build_confirm_body", "describe_tier_gap",
    "sign_execution_report", "verify_execution_report", "result_digest",
    "DecidioError", "DecidioBlocked", "DecidioRejected", "DecidioSuspended", "DecidioTimeout",
    "DecidioBlockedError", "DecidioRejectedError", "DecidioSuspendedError", "DecidioTimeoutError",
    "DecidioRateLimitError", "DecidioUnsafeArguments", "DecidioUnsafeArgumentsError",
    "DecidioHttpError",
    "DecidioRequestChanged", "DecidioRequestChangedError", "DecidioApprovalUnverified", "DecidioApprovalUnverifiedError",
    "check_approval", "approval_refusal", "claim_approval", "claim_refusal", "new_claim_key",
    "binding_material", "request_commitment", "idempotency_key", "invocation_request_key", "own_request_key", "committed_request_json",
]
__version__ = "0.20.0"
