/** Every tier the gate can record, weakest to strongest. Mirrors the server's enum exactly; an
 *  answer outside this list means this SDK version does not understand the record, and an answer
 *  we do not understand is never treated as evidence. */
export const EVIDENCE_TIERS = [
  "pending",
  "execution_unconfirmed",
  "agent_asserted",
  "sensor_observed",
  "application_confirmed",
  "independently_reconciled",
] as const;
export type EvidenceTier = (typeof EVIDENCE_TIERS)[number];

const CONFIRMING: readonly string[] = ["sensor_observed", "application_confirmed", "independently_reconciled"];
/** Whether a recorded tier attests a COMMITTED execution - the same set the live reader uses, so a
 *  tombstone that kept only the tier can still answer the question honestly (retest V030-07). */
export function tierConfirms(tier: string | undefined | null): boolean { return typeof tier === "string" && CONFIRMING.includes(tier); }
/** The tier a `reported` tombstone records. The server caps a confirming tier whose proof failed to
 *  `execution_unconfirmed` (apps/api agent-confirm.ts, lint-locked CONFIRM-TRUTH), so a body that
 *  says otherwise is one the current server cannot emit; the tombstone applies the same rule, so
 *  reconfirm() - which derives from the tier - can never answer "confirmed" where resolve() answered
 *  "not confirmed" over the same record. Every other tier is stored verbatim. */
export function tombstoneTier(ev: EvidenceOutcome): string {
  return ev.executionReportVerified === false && tierConfirms(ev.evidenceTier) ? "execution_unconfirmed" : (ev.evidenceTier ?? "recorded");
}

export interface EvidenceOutcome {
  /** Decidio accepted the report and named the tier it recorded. */
  reportRecorded: boolean;
  /** The tier Decidio recorded, verbatim. */
  evidenceTier?: EvidenceTier;
  /** The recorded tier attests a committed execution. */
  executionConfirmed: boolean;
  /** Present when the outcome is worth explaining (why a signed report did not confirm, or why
   *  a report was not recorded at all) — always actionable, never a shrug. */
  diagnostic?: string;
  /** Present when the gate reported on the SIGNED execution report: whether the attestation
   *  proof VERIFIED (C3, 0.1.12 — this field used to be read off the wire and discarded, so a
   *  failed attestation was invisible to every client door). */
  executionReportVerified?: boolean;
  /** WHY the attestation did not verify, verbatim from the gate (unknown did, expired proof,
   *  burnt nonce, payload mismatch). It was folded into `diagnostic` prose and nowhere else, so a
   *  caller who wanted to BRANCH on the reason — retry vs re-register vs alert — had to regex an
   *  English sentence. Same rule as the typed HTTP errors: give callers the fact, not a string to
   *  parse. */
  executionReportReason?: string;
  /** Whether re-sending this report could succeed. False for a refusal the server will repeat
   *  (an unrecognised tier, a denied success flag); true for a transport or availability failure.
   *  Undefined when the report WAS recorded and there is nothing to retry. */
  confirmationRetryable?: boolean;
  /** Whether the reported value reached durable storage, so `reconfirm()` can re-send it. On the
   *  inline path this is false by construction — nothing is parked — which is exactly why an
   *  inline caller needs to see the outcome at the call site rather than in a log line. */
  reportJournalled?: boolean;
  /** Set when the caller's `evidence` mapper (or the canonical model) rejected the return value,
   *  so an EMPTY captured response was reported. The execution is recorded; its evidence is not.
   *  This was previously a console.warn and nothing else — invisible to the code that could
   *  actually fix it. */
  evidenceError?: string;
}

/** The SERVER's rule for `application_confirmed`, restated here exactly as implemented so this
 *  explanation can never drift from it: the captured response must carry a RECORD ID
 *  (`id` / `recordId` / `Id`), and must not explicitly deny success (`success: false` /
 *  `ok: false`). An id with no success field is treated as a commit; a response with neither is
 *  honestly `execution_unconfirmed`. */
export function describeTierGap(capturedResponse: unknown): string {
  const r = (capturedResponse ?? {}) as Record<string, unknown>;
  const id = r.id ?? r.recordId ?? r.Id ?? null;
  const denied = r.success === false || r.ok === false;
  if (denied) {
    return "your protected function reported success: false (or ok: false), so Decidio recorded the execution as UNCONFIRMED — that is the response saying the downstream write did not commit. If it did commit, return a truthy success flag.";
  }
  if (id == null) {
    return "your protected function's return value carried no record id (`id`, `recordId` or `Id`), so Decidio has no evidence that the downstream write committed and honestly recorded the execution as UNCONFIRMED. Return the source system's identifiers (e.g. `{ id, success }` or `{ recordId, ok }`), or map them with the `evidence` option, to earn application_confirmed.";
  }
  return "the report was accepted but the gate recorded a weaker tier — check that this agent's registration and signing key still match (`npx @decidio/sdk doctor`).";
}

/** Read the gate's confirm response and say precisely what happened. Fail-closed: an unknown or
 *  missing tier is NOT a recorded report. */
export function readConfirmResponse(body: unknown, opts: { signed: boolean; capturedResponse?: unknown; journalled?: boolean }): EvidenceOutcome {
  const journalled = opts.journalled ?? false;
  const retry = journalled
    ? "re-send the report with `guard.resume.reconfirm(decisionId)` once connectivity or the service is healthy."
    : "this path journalled no report, so there is nothing to re-send from here — record the outcome from your own system, or run the action through `guard.protect`'s durable mode, where reports ARE journalled and `reconfirm` can replay them.";
  const b = body as { ok?: unknown; confirmation?: unknown } | null;
  if (!b || b.ok !== true || typeof b.confirmation !== "string") {
    return { reportRecorded: false, executionConfirmed: false, confirmationRetryable: true, reportJournalled: journalled, diagnostic: `the gate answered 2xx but named no evidence tier — the execution report is NOT recorded. Your action DID run; ${retry}` };
  }
  const tier = b.confirmation as string;
  if (!(EVIDENCE_TIERS as readonly string[]).includes(tier)) {
    return { reportRecorded: false, executionConfirmed: false, confirmationRetryable: false, reportJournalled: journalled, diagnostic: `the gate reported an evidence tier this SDK does not recognise (${JSON.stringify(tier)}) — refusing to treat it as evidence. Upgrade @decidio/sdk; your action DID run, and ${retry}` };
  }
  const rpt = (body as { executionReport?: unknown } | null)?.executionReport as { verified?: unknown; reason?: unknown } | undefined;
  const hasVerdict = !!rpt && typeof rpt === "object" && typeof rpt.verified === "boolean";
  const proofExplicitlyFailed = hasVerdict && rpt!.verified === false;

  const executionConfirmed = CONFIRMING.includes(tier) && !proofExplicitlyFailed;
  const outcome: EvidenceOutcome = { reportRecorded: true, evidenceTier: tier as EvidenceTier, executionConfirmed, reportJournalled: journalled };
  if (!executionConfirmed && !proofExplicitlyFailed && opts.signed) outcome.diagnostic = describeTierGap(opts.capturedResponse);
  else if (!executionConfirmed && !proofExplicitlyFailed) outcome.diagnostic = "no signing key is configured, so the gate capped this report at an unproven agent assertion. Run `npx @decidio/sdk init` to generate the agent's key and earn a confirming tier.";
  if (hasVerdict) {
    outcome.executionReportVerified = rpt!.verified as boolean;
    if (typeof rpt!.reason === "string" && rpt!.reason) outcome.executionReportReason = rpt!.reason;
    if (proofExplicitlyFailed) {
      const why = typeof rpt!.reason === "string" && rpt!.reason ? ` (${rpt!.reason})` : "";
      outcome.diagnostic = `the signed execution report did NOT verify${why}, so this is NOT a confirmed execution — the gate reported tier "${tier}", and this SDK refuses to read an unproven attestation as confirmation. Your action DID run and the report IS recorded at that tier - there is nothing to re-send, and re-sending would not change the verdict; the record stands as unverified. Check the agent's key/DID/registration (npx @decidio/sdk doctor) so the NEXT execution verifies.`;
    }
  }
  return outcome;
}

import { signExecutionReport, resultDigest, type RequesterIdentity } from "./signing.js";

/** Minimal identity a confirm body needs. */
export interface ReportIdentity { agentId: string; agentKey?: string; agentDid?: string; workspaceId?: string }

/** The ONE confirm request shape, shared by every door (inline, durable resume, adapters).
 *  Carries the identity proof (who is reporting) AND — when a key is configured — a signed,
 *  decision-bound ExecutionReport over the canonical response digest (what was reported). */
export function buildConfirmBody(cfg: ReportIdentity, decisionId: string, canonicalResult: unknown, requesterIdentity?: RequesterIdentity, source = "wrapper"): Record<string, unknown> {
  const executionReport = (cfg.agentKey && cfg.agentDid)
    ? signExecutionReport(cfg.agentKey, {
        decisionId, agentId: cfg.agentId, did: cfg.agentDid, workspaceId: cfg.workspaceId,
        source, resultDigest: resultDigest(canonicalResult ?? null),
      })
    : undefined;
  return {
    decisionId,
    capturedResponse: canonicalResult ?? null,
    source,
    ...(requesterIdentity ? { requesterIdentity } : {}),
    ...(executionReport ? { executionReport } : {}),
  };
}
