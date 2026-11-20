# Changelog — decidio (Python)

Release notes for the Python client SDK. `@decidio/sdk` (npm) ships the same changes under the same
version (the two are conformance-locked twins). Each entry names what changed, what a reader must do on
upgrade, and what proved it.

## Unreleased

## 0.21.0 - managed approvals and source-available SDKs (2026-11-20)

- **A new licence: the Functional Source License (FSL-1.1-ALv2)**. From this release the `decidio` package is licensed under
  FSL-1.1-ALv2 instead of Apache-2.0: any use except a product or service that competes with Decidio, and each version also
  becomes available under Apache-2.0 two years after its release. 0.20.1 and earlier stay Apache-2.0. Nothing to change in
  your code.
- **Requests nobody answers: a typed `unanswered` outcome**. An agent's request a person must approve
  now closes seven days after it was asked if nobody decides it, and no authority is granted. `/agent/status` still answers `state:
  "rejected"` and adds the typed `closedBy: {"reason": "unanswered", "deadline": ...}`. The blocking wait, `check_approval` (new
  code `unanswered`, with `deadline`) and `approval_refusal` raise the new **`DecidioUnanswered`** (alias `DecidioUnansweredError`;
  `code`, `decision_id`, `deadline`) - NOT `DecidioRejected`, and not `expired`. The durable resume discards the parked action as
  final with the outcome status `unanswered`; a refused `/agent/confirm` for such a request names it. New exports:
  `DecidioUnanswered`, `DecidioUnansweredError`, `unanswered_of`, `UNANSWERED_WORDS`. Proved by `smoke.py` (three checks, mirrored
  in `smoke.ts`).

## 0.20.1 - published with attestations (2026-11-18)

- **The first Python release from the public repository** (`OmniTwin/decidio-sdk`, PyPI trusted publishing, PEP 740
  attestations). 0.20.0 never reached PyPI: the upload action's older twine refused its metadata.
  Unchanged from 0.19.0 otherwise; it moves in lockstep with `@decidio/sdk` (0.20.0 was npm only).

## Earlier releases

Notes for releases before 0.20.0 are not carried in this file.
