import { createHmac, timingSafeEqual, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, randomUUID, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, rmSync, renameSync, openSync, closeSync, fsyncSync, linkSync } from "node:fs";
import { join } from "node:path";
import { userInfo } from "node:os";
import { execFileSync } from "node:child_process";
import type { IncomingMessage, ServerResponse, RequestListener } from "node:http";
import { signConfirm, canonicalize as jcs, assertSafeTransport, carriesCredential, bindingMaterial, requestCommitment, type BindingMaterial, type CommittedRequest } from "./signing.js";
import { canonicalizeArgs, canonicalize as toCanonical, DecidioUnsafeArgumentsError } from "./canonical.js";
import { readConfirmResponse, buildConfirmBody, tierConfirms, tombstoneTier, type EvidenceOutcome, type EvidenceTier } from "./evidence.js";
import { DecidioHttpError, decisionIdProblem } from "./errors.js";

type ArgsBinding = { decisionId: string; action: string; amount: number; scope?: string; args: unknown[]; requestCommitment?: string; claimKey?: string };
const argsBindingBytes = (p: ArgsBinding) =>
  Buffer.from(jcs({ decisionId: p.decisionId, action: p.action, amount: p.amount, ...(p.scope !== undefined ? { scope: p.scope } : {}), args: p.args, ...(p.requestCommitment !== undefined ? { requestCommitment: p.requestCommitment } : {}), ...(p.claimKey !== undefined ? { claimKey: p.claimKey } : {}) }), "utf8");

function signArgs(p: ArgsBinding, agentKey?: string, webhookSecret?: string): PendingAction["argsSig"] {
  const bytes = argsBindingBytes(p);
  if (agentKey) {
    try {
      const key = createPrivateKey({ key: Buffer.from(agentKey, "base64"), format: "der", type: "pkcs8" });
      return { kind: "ed25519", sig: Buffer.from(edSign(null, bytes, key)).toString("base64url") };
    } catch { }
  }
  if (webhookSecret) return { kind: "hmac", sig: createHmac("sha256", webhookSecret).update(bytes).digest("hex") };
  return undefined;
}

function verifyArgs(p: PendingAction, agentKey?: string, webhookSecret?: string): "ok" | "mismatch" | "unbound" | "unverifiable" {
  if (!p.argsSig) return "unbound";
  const bytes = argsBindingBytes(p);
  try {
    if (p.argsSig.kind === "ed25519") {
      if (!agentKey) return "unverifiable";
      const pub = createPublicKey(createPrivateKey({ key: Buffer.from(agentKey, "base64"), format: "der", type: "pkcs8" }));
      return edVerify(null, bytes, pub, Buffer.from(p.argsSig.sig, "base64url")) ? "ok" : "mismatch";
    }
    if (!webhookSecret) return "unverifiable";
    const expected = createHmac("sha256", webhookSecret).update(bytes).digest("hex");
    const a = Buffer.from(expected), b = Buffer.from(p.argsSig.sig);
    return a.length === b.length && timingSafeEqual(a, b) ? "ok" : "mismatch";
  } catch { return "mismatch"; }
}

const evidenceBindingBytes = (decisionId: string, attemptId: string | null, evidence: unknown) =>
  Buffer.from(jcs({ decisionId, attemptId: attemptId ?? null, evidence: evidence ?? null }), "utf8");

export function signEvidence(decisionId: string, attemptId: string | null, evidence: unknown, agentKey?: string, webhookSecret?: string): { kind: "ed25519" | "hmac"; sig: string } | undefined {
  const bytes = evidenceBindingBytes(decisionId, attemptId, evidence);
  if (agentKey) {
    try {
      const key = createPrivateKey({ key: Buffer.from(agentKey, "base64"), format: "der", type: "pkcs8" });
      return { kind: "ed25519", sig: Buffer.from(edSign(null, bytes, key)).toString("base64url") };
    } catch { }
  }
  if (webhookSecret) return { kind: "hmac", sig: createHmac("sha256", webhookSecret).update(bytes).digest("hex") };
  return undefined;
}

export function verifyEvidence(rec: ExecutionRecord, agentKey?: string, webhookSecret?: string): "ok" | "mismatch" | "unbound" | "unverifiable" {
  if (!rec.evidenceSig) return "unbound";
  const bytes = evidenceBindingBytes(rec.decisionId, rec.attemptId, rec.evidence ?? null);
  try {
    if (rec.evidenceSig.kind === "ed25519") {
      if (!agentKey) return "unverifiable";
      const pub = createPublicKey(createPrivateKey({ key: Buffer.from(agentKey, "base64"), format: "der", type: "pkcs8" }));
      return edVerify(null, bytes, pub, Buffer.from(rec.evidenceSig.sig, "base64url")) ? "ok" : "mismatch";
    }
    if (!webhookSecret) return "unverifiable";
    const expected = createHmac("sha256", webhookSecret).update(bytes).digest("hex");
    const x = Buffer.from(expected), y = Buffer.from(rec.evidenceSig.sig);
    return x.length === y.length && timingSafeEqual(x, y) ? "ok" : "mismatch";
  } catch { return "mismatch"; }
}

/** A routed action parked on the agent side, awaiting human approval. The `args`
 *  are the original call arguments, replayed verbatim when the action resumes. */
export interface PendingAction {
  decisionId: string;
  receiptId?: string;
  action: string;
  amount: number;
  scope?: string;
  args: unknown[];
  createdAt: string;
  /** Integrity binding over {decisionId, action, amount, scope, args} — without it the parked
   *  payload would be mutable between routing and execution. ed25519 = detached
   *  signature by the agent's key; hmac = keyed by the webhook secret. Verified before ANY
   *  re-execution; a mismatch REFUSES and leaves the file for inspection. When the controller
   *  holds an agent key, a MISSING signature is also refused (a stripped signature is
   *  indistinguishable from tampering) — including entries parked by pre-0.1.6 versions:
   *  drain pending approvals before upgrading, or delete + re-run them. Only a keyless
   *  controller executes unbound entries (with a loud warning). Honest scope: this defends
   *  against modification by anything lacking the agent's key material — a fully compromised
   *  agent host can bypass the guard entirely and is out of client-side scope (server-sealed
   *  args binding is the receipt-v2 design). */
  argsSig?: { kind: "ed25519" | "hmac"; sig: string };
  /** The request commitment this SDK SENT with /agent/authorize (0.7.0) — see `requestCommitment`
   *  in signing.ts. Recorded so `resolve()` can apply the one fail-closed rule that needs to know
   *  what was sent: a gate that answers with no commitment for a request this SDK bound is refused.
   *  The value that decides execution is always a FRESH recompute over these parked arguments,
   *  compared with the commitment Decidio returns. Absent on entries parked before 0.7.0 (and by
   *  an agent with no key material), which are checked on Decidio's state alone. */
  requestCommitment?: string;
  /** THE RUN'S CLAIM KEY: made at random when the action is parked, and the key this parked
   *  action collects a person's approval with (POST /agent/claim) right before it runs. It lives HERE, with the parked
   *  action, so every resume of it - a worker that restarts, a signal after a lost answer, a claim an operator released -
   *  is the same run to Decidio (`again: true`), while another process that parked its own copy of the request holds its
   *  own key and is told the approval was used. Covered by the payload signature. Absent on entries parked before 0.12.0:
   *  those claim with a fresh key each time (a lost answer then costs a new approval, never a second run). */
  claimKey?: string;
}

/** Where suspended actions live between request and approval. The default is a
 *  file store; swap in Redis/Postgres/your queue for production. AGENT-SIDE only —
 *  Decidio never sees this. */
/** The durable execution state machine (v2).
 *
 *  parked → claimed_preinvoke → invoking → (executed_unreported | indeterminate) → reported
 *  plus the terminal `discarded` (a human or policy said NO: written from parked/claimed_preinvoke, never invoked).
 *
 *  THE ONE RULE: nothing transitions BACK to parked once `invoking` has been written. Deletion
 *  is cleanup, never the single-use guarantee — that was the 0.1.x model, and a store whose
 *  delete() failed (or silently kept the row) let a fresh process execute an already-committed
 *  action a second time. The state IS the guarantee now; a failed delete is a tidiness problem.
 *
 *  `indeterminate` is the honest answer to the case an SDK cannot decide: the handler was
 *  invoked and then threw. Whether the downstream write committed is not knowable from here, so
 *  the action is never automatically retried — it waits for `reconcile()`. */
export type ExecutionState =
  | "parked"
  | "claimed_preinvoke"
  /** A human or policy said NO. Terminal: the handler must never run for this decision. */
  | "discarded"
  | "invoking"
  | "executed_unreported"
  | "indeterminate"
  | "reported";

/** Ordered weakest→strongest. Resolution ALWAYS takes the strongest state present for a
 *  decision, which is what makes a partially-failed transition safe: if a crash leaves both the
 *  old and new markers on disk, the stronger one wins and an executed action can never read
 *  back as parked. */
/** `discarded` sits ABOVE the pre-invocation states and BELOW the execution ones, and the position
 *  is load-bearing in both directions:
 *
 *  - above `parked`/`claimed_preinvoke`, so a denial beats a payload whose deletion FAILED. That is
 *    the whole F-001 fix: the old code deleted the payload and wrote no state, the shipped file
 *    store swallows unlink errors, and the ledger therefore still read `parked` — so a later,
 *    out-of-order `approved` signal executed an action a human had explicitly refused.
 *  - below `invoking`…`reported` — but rank is NOT how the two are reconciled, and relying on it
 *    was wrong in both directions. A stronger marker written beside a tombstone outranked the
 *    denial AND was then deleted by setState's weaker-marker sweep, so a refused decision read back
 *    as runnable. `resolve()` therefore prefers the DENIAL whenever its marker is present, at any
 *    rank. That decides authority, not truth: if an execution marker is there too, something DID
 *    run, and swallowing that is the opposite failure — so resolve() flags the conflict on the
 *    record (`executionDespiteDenial`), recover() reports it, and reconfirm() says so instead of
 *    "this process never executed it". A denial governs the decision; it never edits history. */
export const EXECUTION_STATES: readonly ExecutionState[] = [
  "parked", "claimed_preinvoke", "discarded", "invoking", "executed_unreported", "indeterminate", "reported",
];
/** States from which the handler must NEVER be invoked again automatically. `discarded` is here
 *  FOREVER — `claim()` gates on this list, so a denied decision can never be claimed again, by this
 *  process or any future one. */
export const NON_REPLAYABLE: readonly ExecutionState[] = ["discarded", "invoking", "executed_unreported", "indeterminate", "reported"];

export interface ExecutionRecord {
  decisionId: string;
  state: ExecutionState;
  /** The attempt that owns (or last owned) this decision. A fencing token: a write from a
   *  stale attempt is refused. */
  attemptId: string | null;
  action?: string;
  /** The canonical reported value — present from `executed_unreported` onward. This is what
   *  `reconfirm()` re-sends; it carries no handler binding, so replaying it can only ever
   *  re-send a report, never re-run the action. */
  evidence?: unknown;
  /** Whether `evidence` was actually recorded. Separate from `evidence` because `null` is a
   *  legitimate reported value (an action whose return could not be mapped still reports a null
   *  captured response), so presence cannot be inferred from the value. Python has carried this
   *  flag from the start; TypeScript inferring presence from `!== undefined` was a twin
   *  divergence waiting to disagree about a null-evidence decision. */
  hasEvidence?: boolean;
  /** Set when the evidence MAPPER failed, so `evidence` is null because nothing could be captured
   *  — not because the action returned null. The ledger could not previously tell those apart, and
   *  the difference decides whether an operator may fill the value: a null the SDK OBSERVED is a
   *  measurement, a null it failed to produce is a gap. */
  evidenceError?: string;
  /** Integrity binding over {decisionId, attemptId, evidence}, written when the evidence is
   *  recorded. `reconfirm()` verifies it before re-signing, so a record altered in a shared store
   *  is refused rather than attested. Absent when the agent has no key material — the same
   *  "unbound" state the parked args can be in, reported the same way. */
  evidenceSig?: { kind: "ed25519" | "hmac"; sig: string };
  /** WHY this decision is `discarded` — the verdict a human or policy returned, and any reason
   *  text. Recorded on the tombstone so recovery can say "a human rejected this" rather than
   *  reporting a bare terminal state an operator would have to go and look up. */
  verdict?: "rejected" | "blocked";
  discardReason?: string;
  /** Set when this row was reconstructed by an upgrade rather than written by a live execution —
   *  currently only `"0.1.x report journal"`. Such a row predates evidence binding and can never
   *  carry a valid signature, so the strict check exempts it EXPLICITLY. The exemption must be a
   *  positive flag: exempting "anything with no signature" would hand an attacker the bypass. */
  migratedFrom?: string;
  /** Why the outcome is unknown — present on `indeterminate`. */
  error?: string;
  /** The tier Decidio recorded — present on `reported`. */
  confirmation?: string;
  /** Set when an OPERATOR settled this decision rather than the SDK observing it. Kept so an
   *  audit of the agent-side ledger can tell an observed execution from an asserted one. */
  /** `workerStopped` records that a HUMAN asserted the claiming worker was stopped before this
   *  decision was released — the assertion that made the release legal. It is stamped here because
   *  the whole point of requiring it is to put a name against that judgement: without it the ledger
   *  showed a decision released from `invoking` with no trace that anyone had claimed to check. */
  reconciled?: { outcome: SettleOutcome; reason?: string; at: string; workerStopped?: boolean };
  /** Set when a DENIED decision also carries an execution record. That pair is the single most
   *  alarming state the machine can hold — a human refused it and something ran anyway — so it must
   *  never resolve to silence. The revision chain cannot produce it (no transition publishes over
   *  a denial); it is DERIVED by the legacy-marker reader, and PERSISTED only when a 0.2/0.3
   *  directory that held a denial marker beside an execution marker is migrated onto the chain —
   *  there it is the record of what that layout held. */
  executionDespiteDenial?: { state: ExecutionState; at: string; hasEvidence: boolean };
  at: string;
}

export type SettleOutcome = "committed" | "not_committed";

/** Refuse a reconciliation that would be a fabrication. Shared by every store so the rule cannot
 *  drift between implementations — a store that allowed `committed` from `parked` would let an
 *  operator mint an execution report for an action nothing ever invoked. */
/** A decision an operator SETTLED as committed is finished: its report is recorded and sent. A
 *  late write from the attempt that was still running would produce a second authority report for
 *  one decision, so it is refused here rather than in each store. `not_committed` settlements are
 *  deliberately not covered — that outcome exists so a new attempt can run and record. */
/** The ledger row is owned by a NEWER attempt. Typed for the same reason `DecidioAlreadySettled`
 *  is: `reportAfterExecution` must keep going when the ledger fails, so a bare Error here read as
 *  "the disk write failed" and the stale attempt went on to POST — a second authority report for
 *  one decision. Reachable through the SDK's own documented flow: `reconcile(id, not_committed)`
 *  releases a decision whose original attempt is still alive (recover() invites exactly that, since
 *  it says the process "died" when it may not have), the release is legitimate and the new attempt
 *  SHOULD run — but the old attempt's report must not be sent. */
export class DecidioStaleAttemptError extends Error {
  constructor(public decisionId: string, public owner: string | null, public state: ExecutionState) {
    super(`[decidio] ${decisionId}: this attempt no longer owns the decision — attempt ${owner ?? "(unknown)"} holds it in state ${state}. Refusing a state write from a superseded attempt.`);
    this.name = "DecidioStaleAttemptError";
  }
}

export class DecidioAlreadySettledError extends Error {
  constructor(public decisionId: string) {
    super(`[decidio] ${decisionId}: an operator already settled this decision as committed and its report is recorded — refusing a second execution report. Nothing was re-run; this write is the duplicate, not the execution.`);
    this.name = "DecidioAlreadySettledError";
  }
}

/** A DENIAL IS TERMINAL, and that has to be enforced where the state is WRITTEN — not only where
 *  it is reconciled. Refusing `settle` from `discarded` closed the operator's door and left three
 *  others open, each of which walked a refused action all the way to execution:
 *    - `discarded` sits mid-rank in EXECUTION_STATES, so the advance-only rule happily accepted
 *      `discarded → invoking → executed_unreported`;
 *    - `markDiscarded` leaves the record UNOWNED (`attemptId: ""`) when nothing had claimed it, so
 *      the ownership fence — which skips when there is no owner — did not stop that walk either;
 *    - reachable through the shipped controller, not just the store API: an `approved` signal
 *      claims, a `rejected` signal writes the tombstone, and the first call then invokes anyway.
 *  Typed, for the same reason DecidioAlreadySettledError is: the reporting stage deliberately keeps
 *  going when the ledger fails, so a generic error here would read as "the disk write failed" and
 *  send an authority report for an action a human refused. */
/** `recover()` could not enumerate the ledger. It is a THROW, not an empty list, because those two
 *  are the same value to a caller and mean opposite things: `[]` is "you owe nothing", and this is
 *  "I cannot tell you what you owe". The old code logged to stderr and returned `[]`, so a script
 *  reading `if (!(await recover()).length) allClear()` treated an unreadable store — a permissions
 *  change, a mounted volume gone, a corrupt directory — as proof that no action was left
 *  outstanding. A crash is the correct failure here; silence is not. */
export class DecidioRecoveryUnavailableError extends Error {
  constructor(public cause: unknown) {
    super(`[decidio] recover(): the execution ledger could not be read (${(cause as any)?.message ?? cause}). Refusing to return an empty recovery list, which would read as "nothing is outstanding" — inspect the store; some actions may be awaiting a report.`);
    this.name = "DecidioRecoveryUnavailableError";
  }
}

export class DecidioDeniedError extends Error {
  constructor(public decisionId: string, public verdict: string) {
    super(`[decidio] ${decisionId}: this decision was DENIED (${verdict}) and a denial is terminal — refusing a state write that would move it back toward execution. Nothing may advance out of a denial; if this action should now proceed it needs a NEW request and a new approval.`);
    this.name = "DecidioDeniedError";
  }
}

/** UNANSWERED: nobody decided this request by its deadline, so no authority was granted. Decidio
 *  still answers state `rejected` - so an older SDK stops rather than waits - and says why in the typed `closedBy` field
 *  (`{ reason: "unanswered", deadline }`), never in `reason`. It is NOT a person's no, so it is NOT DecidioRejectedError: nothing
 *  ran, and the agent may ask again (the same request asked again is a NEW request) if it is still needed - and tell the user.
 *  Not `expired` either: that is an approval that lapsed before it ran. */
export class DecidioUnansweredError extends Error {
  readonly code = "unanswered" as const;
  constructor(public decisionId: string, public deadline: string | null = null) {
    super(`[decidio] ${UNANSWERED_WORDS} (decision ${decisionId}${deadline ? `, deadline ${deadline}` : ""}). Nothing was executed.`);
    this.name = "DecidioUnansweredError";
  }
}
/** Decidio's own words for it (the server's CLOSURE_WORDS.unanswered), so every door of this SDK says the same thing. */
export const UNANSWERED_WORDS = "UNANSWERED: nobody decided this by its deadline; no authority was granted. Do not perform it; ask again if it is still needed, and tell the user.";
/** Is this status answer (or a 409 body that carries one) an UNANSWERED request? Reads the typed field only - never `reason`. */
export function unansweredOf(st: unknown): { deadline: string | null } | null {
  const c = (st as { closedBy?: { reason?: unknown; deadline?: unknown } | null } | null | undefined)?.closedBy;
  return c && typeof c === "object" && c.reason === "unanswered" ? { deadline: typeof c.deadline === "string" ? c.deadline : null } : null;
}

function assertNotDenied(id: string, cur: ExecutionRecord, next: ExecutionState): void {
  if (cur.state === "discarded" && next !== "discarded") throw new DecidioDeniedError(id, cur.verdict ?? "rejected");
}

function assertClaimedBy(id: string, cur: ExecutionRecord, attemptId: string): void {
  if (cur.state !== "claimed_preinvoke" || cur.attemptId !== attemptId) {
    throw new Error(`[decidio] ${id}: refusing to cross the invocation boundary — attempt ${attemptId} does not hold a claim on this decision (state ${cur.state}, held by ${cur.attemptId || "nobody"}). A claim is the only way to acquire ownership; call claim() and act on its result.`);
  }
}

function assertNotSettled(id: string, cur: ExecutionRecord, next: ExecutionState): void {
  if (cur.reconciled?.outcome === "committed" && (next === "executed_unreported" || next === "indeterminate")) {
    throw new DecidioAlreadySettledError(id);
  }
}

export const SETTLE_OUTCOMES: readonly SettleOutcome[] = ["committed", "not_committed"];

export function assertSettlable(id: string, state: ExecutionState, outcome: SettleOutcome, opts: { hasObservedEvidence?: boolean; workerStopped?: boolean } = {}): void {
  const hasObservedEvidence = opts.hasObservedEvidence ?? true;
  if (!SETTLE_OUTCOMES.includes(outcome)) {
    throw new Error(`[decidio] ${id}: outcome must be "committed" or "not_committed", not ${JSON.stringify(outcome)}.`);
  }
  if (state === "discarded") {
    throw new Error(`[decidio] ${id}: this decision was DENIED by a human or a policy, and a denial is final — it cannot be reconciled, released or retried. Nothing ran, so there is no outcome to record. If this action should now proceed it needs a NEW request and a new approval.`);
  }
  if (outcome === "committed") {
    if (state === "reported") throw new Error(`[decidio] ${id}: already reported — there is nothing left to reconcile.`);
    if (state === "executed_unreported" && hasObservedEvidence) throw new Error(`[decidio] ${id}: this decision already holds evidence this SDK OBSERVED — an operator assertion must not replace a captured result. If the report simply has not reached Decidio, re-send the real one: reconfirm("${id}").`);
    if (rank(state) < rank("invoking")) throw new Error(`[decidio] ${id}: refusing to record a COMMITTED outcome from state ${state} — the handler was never invoked, so no downstream write can have happened. If you mean "run it", let it resume normally.`);
  } else {
    if (state === "reported") throw new Error(`[decidio] ${id}: already reported — releasing it would re-run an execution Decidio has already recorded.`);
    if (state === "executed_unreported") throw new Error(`[decidio] ${id}: this decision holds CAPTURED EVIDENCE of an execution — releasing it would re-run a proven write. Re-send the evidence with reconfirm("${id}") instead.`);
    if (state === "parked") throw new Error(`[decidio] ${id}: already parked — nothing to release.`);
    if (state === "invoking" && opts.workerStopped !== true) {
      throw new Error(`[decidio] ${id}: this decision is still INVOKING — the worker that claimed it may be running the action right now, and releasing it would let a second worker run the same approved action. Stop or confirm the death of that worker first, then say so explicitly: reconcile("${id}", { outcome: "not_committed", reason: …, workerStopped: true }). If you cannot confirm it stopped, treat the decision as possibly executed and reconcile it as "committed" once you have checked the downstream system.`);
    }
  }
}

export interface ClaimResult {
  /** True only when THIS attempt may proceed to invoke. */
  ok: boolean;
  /** The state that refused the claim, when ok is false — so a caller can tell "another worker
   *  has it" from "this already executed and must be reconciled". */
  state?: ExecutionState;
  reason?: string;
}

/** Agent-side durable state. The shipped stores are file- and memory-backed; swap in
 *  Redis/Postgres/your queue for production. AGENT-SIDE only — Decidio never sees this.
 *
 *  v2 (0.2.0) makes the state machine MANDATORY. The 0.1.x contract left `claim()` optional and
 *  fell back to a process-local set, which cannot survive a restart and therefore could not
 *  carry a single-execution guarantee across processes at all. Every method below must be
 *  atomic against concurrent callers — compare-and-swap, a transaction, or an equivalent
 *  fencing token. */
export interface PendingStore {
  put(p: PendingAction): Promise<void>;
  get(decisionId: string): Promise<PendingAction | null>;
  /** CLEANUP ONLY. Removing a row must never be what prevents a second execution.
   *
   *  `attemptId` scopes the cleanup to its OWNER. A superseded attempt tidies up on its way out
   *  (see the stale-attempt branch of the reporting stage), and without this it deleted the payload
   *  of the attempt that had legitimately taken over — the live worker's own recovery data, removed
   *  by the dead one. Omit it for genuine housekeeping that is not attributable to an attempt. */
  delete(decisionId: string, attemptId?: string): Promise<void>;
  /** Parked entries only — anything claimed or beyond is excluded. */
  list(): Promise<PendingAction[]>;

  /** Atomically take ownership for THIS attempt. Must refuse when the decision is already
   *  claimed by a live attempt, or is in any NON_REPLAYABLE state. */
  claim(decisionId: string, attemptId: string): Promise<ClaimResult>;
  /** The handler is about to be called. After this point the store must never report the
   *  decision as executable again, whatever else fails. */
  markInvoking(decisionId: string, attemptId: string): Promise<void>;
  /** The handler returned. `evidence` is the canonical reported value. */
  recordExecuted(decisionId: string, attemptId: string, evidence: unknown, evidenceSig?: ExecutionRecord["evidenceSig"], evidenceError?: string): Promise<void>;
  /** The handler was invoked and threw: the downstream outcome is unknown. */
  markIndeterminate(decisionId: string, attemptId: string, error: string): Promise<void>;
  /** Decidio accepted the execution report. */
  markReported(decisionId: string, attemptId: string, confirmation: string): Promise<void>;
  /** A human or policy DENIED this decision. Writes the terminal tombstone that makes the decision
   *  permanently unclaimable — and it must be written BEFORE any payload cleanup, because cleanup
   *  is best-effort and a store that swallows its failure would otherwise leave the row readable as
   *  `parked`. A conforming store persists this durably; returning without persisting reintroduces
   *  F-001. Safe to call more than once (a denial is idempotent). */
  markDiscarded(decisionId: string, verdict: "rejected" | "blocked", reason?: string): Promise<void>;
  /** The authoritative state for one decision, or null if this store has never seen it. */
  getExecution(decisionId: string): Promise<ExecutionRecord | null>;
  /** Every execution record the store holds — the basis for honest recovery reporting. */
  listExecutions(): Promise<ExecutionRecord[]>;
  /** Operator reconciliation — the only legal backwards transition, and the only exit from
   *  `indeterminate`. Never called by any automatic path.
   *
   *  A CUSTOM STORE MUST RAISE THE TYPED ERRORS at its own fences: `DecidioStaleAttemptError` when
   *  a superseded attempt writes, and `DecidioAlreadySettledError` when a second execution report
   *  lands on a decision an operator settled as committed. The reporting stage deliberately keeps
   *  going when the ledger fails — that is what stops an evidence gap from costing an execution —
   *  so a store that raises a generic error for either case sends a duplicate authority report
   *  instead of stopping. */
  settle(decisionId: string, outcome: SettleOutcome, opts?: { evidence?: unknown; reason?: string; evidenceSig?: ExecutionRecord["evidenceSig"]; workerStopped?: boolean }): Promise<void>;
  /** Release a claim taken BEFORE invocation, so a pre-invoke failure stays retryable. It is a
   *  contract error to call this once `markInvoking` has been written, and a conforming store
   *  must refuse it. */
  releasePreinvoke(decisionId: string, attemptId: string): Promise<void>;
}

const rank = (s: ExecutionState): number => EXECUTION_STATES.indexOf(s);

/** In-memory store. Single-process only BY CONSTRUCTION — it is the right choice for tests and
 *  for a worker that owns its queue, and the wrong one for two processes sharing work, which is
 *  exactly what `FilePendingStore` (atomic renames on one volume) or a real database is for. */
export class MemoryPendingStore implements PendingStore {
  private m = new Map<string, PendingAction>();
  private x = new Map<string, ExecutionRecord>();
  private rec(id: string): ExecutionRecord {
    return this.x.get(id) ?? { decisionId: id, state: "parked", attemptId: null, at: new Date().toISOString() };
  }
  /** Advance only. A write from a stale attempt, or one that would move the state BACKWARDS,
   *  is refused — the in-memory expression of the same rule the file store gets from
   *  strongest-wins resolution. */
  private advance(id: string, attemptId: string, state: ExecutionState, patch: Partial<ExecutionRecord> = {}, takeover = false): void {
    const cur = this.rec(id);
    if (!takeover && cur.attemptId && cur.attemptId !== attemptId) {
      throw new DecidioStaleAttemptError(id, cur.attemptId, cur.state);
    }
    assertNotDenied(id, cur, state);
    assertNotSettled(id, cur, state);
    if (rank(state) < rank(cur.state)) {
      throw new Error(`[decidio] ${id}: refusing to move ${cur.state} → ${state}; execution state only ever advances.`);
    }
    this.x.set(id, { ...cur, ...patch, decisionId: id, attemptId, state, at: new Date().toISOString() });
  }
  async put(p: PendingAction) {
    this.m.set(p.decisionId, p);
    if (!this.x.has(p.decisionId)) this.x.set(p.decisionId, { decisionId: p.decisionId, state: "parked", attemptId: null, action: p.action, at: new Date().toISOString() });
  }
  async get(id: string) { return this.m.get(id) ?? null; }
  /** Cleanup only — the execution record STAYS. Scoped to the owning attempt: see PendingStore. */
  async delete(id: string, attemptId?: string) {
    if (attemptId && !this.ownsPayload(id, attemptId)) return;
    this.m.delete(id);
  }
  private ownsPayload(id: string, attemptId: string): boolean {
    const owner = this.x.get(id)?.attemptId;
    return !owner || owner === attemptId;
  }
  async list() { return [...this.m.values()].filter((p) => this.rec(p.decisionId).state === "parked"); }
  async claim(id: string, attemptId: string): Promise<ClaimResult> {
    if (!this.m.has(id)) return { ok: false, reason: "no parked entry" };
    const cur = this.rec(id);
    if (NON_REPLAYABLE.includes(cur.state)) return { ok: false, state: cur.state, reason: `already ${cur.state}` };
    if (cur.state === "claimed_preinvoke") return { ok: false, state: cur.state, reason: "claimed by another attempt" };
    this.advance(id, attemptId, "claimed_preinvoke", { action: this.m.get(id)?.action }, true);
    return { ok: true };
  }
  async markInvoking(id: string, attemptId: string) {
    const cur = this.rec(id);
    assertNotDenied(id, cur, "invoking");
    assertClaimedBy(id, cur, attemptId);
    this.advance(id, attemptId, "invoking");
  }
  async recordExecuted(id: string, attemptId: string, evidence: unknown, evidenceSig?: ExecutionRecord["evidenceSig"], evidenceError?: string) { this.advance(id, attemptId, "executed_unreported", { evidence, hasEvidence: true, evidenceSig, evidenceError }); }
  async markIndeterminate(id: string, attemptId: string, error: string) { this.advance(id, attemptId, "indeterminate", { error }); }
  async markReported(id: string, attemptId: string, confirmation: string) { this.advance(id, attemptId, "reported", { confirmation }); }
  async markDiscarded(id: string, verdict: "rejected" | "blocked", reason?: string) { this.advance(id, this.x.get(id)?.attemptId ?? "", "discarded", { verdict, ...(reason ? { discardReason: reason } : {}) }); }
  async getExecution(id: string) { return this.x.get(id) ?? null; }
  async listExecutions() { return [...this.x.values()]; }
  /** OPERATOR RECONCILIATION — the ONE legal backwards transition, and the only exit from
   *  `indeterminate` or a stalled claim. It is legal only because a human asserted the downstream
   *  truth this machine cannot observe, so no automatic path may call it.
   *
   *  `committed`     → `executed_unreported` carrying the operator's evidence, so the ordinary
   *                    reporting path can send it. The handler is NEVER invoked.
   *  `not_committed` → back to `parked`, permitting exactly one more ordinary attempt. */
  async settle(id: string, outcome: SettleOutcome, opts: { evidence?: unknown; reason?: string; evidenceSig?: ExecutionRecord["evidenceSig"]; workerStopped?: boolean } = {}): Promise<void> {
    const cur = this.rec(id);
    assertSettlable(id, cur.state, outcome, { hasObservedEvidence: !cur.evidenceError, workerStopped: opts.workerStopped });
    const at = new Date().toISOString();
    const reconciled = { outcome, reason: opts.reason, at, ...(opts.workerStopped ? { workerStopped: true } : {}) };
    this.x.set(id, outcome === "committed"
      ? { ...cur, state: "executed_unreported", evidence: opts.evidence ?? null, hasEvidence: true, evidenceSig: opts.evidenceSig, evidenceError: undefined, reconciled, at }
      : { ...cur, state: "parked", attemptId: null, error: undefined, reconciled, at });
  }

  async releasePreinvoke(id: string, attemptId: string) {
    const cur = this.rec(id);
    if (NON_REPLAYABLE.includes(cur.state)) throw new Error(`[decidio] ${id}: refusing to release this decision — its durable state is ${cur.state}, which is terminal or past the invocation boundary. releasePreinvoke only ever releases a claim nothing has acted on.`);
    if (cur.attemptId && cur.attemptId !== attemptId) return;
    this.x.set(id, { ...cur, state: "parked", attemptId: null, at: new Date().toISOString() });
  }
}

/** The ACL principal for THIS process, resolved from the token SID rather than the login name.
 *
 *  Shared by every hardening site (F-009): the durable pending directory AND the `.env` the CLI
 *  writes. `writeSecretFile` had its own weaker copy that granted `userInfo().username` — who
 *  logged IN, which is not always who is writing. A Windows service, a scheduled task or an
 *  impersonated thread has a different effective identity, and granting the wrong name while
 *  `/inheritance:r` strips every other ACE is how a hardening step locks the writer out of its own
 *  secrets. A SID also needs no localisation or escaping, where a name can carry spaces, a domain
 *  prefix, or be renamed out from under the ACE. */
export function windowsPrincipal(): string {
  const sysRoot = process.env.SystemRoot ?? process.env.windir ?? "C:\\Windows";
  for (const exe of [join(sysRoot, "System32", "whoami.exe"), "whoami"]) {
    try {
      const out = execFileSync(exe, ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" });
      const m = out.match(/S-1-[0-9-]+/);
      if (m) return `*${m[0]}`;
    } catch { }
  }
  try { return userInfo().username; } catch { return process.env.USERNAME ?? process.env.USER ?? ""; }
}

/** Restrict a FILE to its owner on Windows, with the same verify-then-roll-back discipline as
 *  `hardenDir`. Returns null on success, or the reason it could not be done.
 *
 *  The verification is the point, and it is what the CLI's own version lacked: a SUCCESSFUL
 *  `icacls` that locks this process out of the file it just wrote is more dangerous than a failed
 *  one, and it printed nothing at all. Here the file is read back, and if that fails the
 *  inheritance goes back rather than leaving credentials the SDK can no longer read. */
export function hardenFile(file: string): string | null {
  if (process.platform !== "win32") return null;
  try {
    const principal = windowsPrincipal();
    if (!principal) return "could not determine the current user";
    execFileSync("icacls", [file, "/inheritance:r", "/grant:r", `${principal}:F`, "/grant:r", "*S-1-5-18:F"], { stdio: "ignore" });
    try { readFileSync(file, "utf8"); }
    catch (verifyError: any) {
      try { execFileSync("icacls", [file, "/inheritance:e"], { stdio: "ignore" }); } catch { }
      return `the restriction applied but this process could no longer read the file (${verifyError?.message ?? verifyError}), so it was rolled back`;
    }
    return null;
  } catch (e: any) {
    return String(e?.message ?? e);
  }
}

/** Restrict a directory to its owner. On Windows POSIX modes are a no-op, so strip inheritance
 *  and grant only the effective user. A FAILURE IS SAID, never swallowed: these files hold the
 *  arguments of actions awaiting approval, and "silently kept the directory's inherited
 *  permissions" is exactly the outcome an operator must not discover from an auditor. */
export function hardenDir(dir: string): void {
  if (process.platform !== "win32") return;
  const warn = (why: string) =>
    console.warn(`[decidio] WARNING: could not restrict ${dir} to owner-only (${why}). It keeps the directory's inherited permissions, so other accounts on this machine may be able to read parked action arguments. Move the pending store to a protected location, or set DECIDIO_PENDING_DIR to one.`);
  try {
    const principal = windowsPrincipal();
    if (!principal) throw new Error("could not determine the current user");
    execFileSync("icacls", [dir, "/inheritance:r", "/grant:r", `${principal}:(OI)(CI)F`, "/grant:r", "*S-1-5-18:(OI)(CI)F"], { stdio: "ignore" });

    const probe = join(dir, `.decidio-acl-probe-${process.pid}`);
    try {
      writeFileSync(probe, "probe", { mode: 0o600 });
      readFileSync(probe, "utf8");
      rmSync(probe, { force: true });
    } catch (verifyError: any) {
      try { execFileSync("icacls", [dir, "/inheritance:e"], { stdio: "ignore" }); } catch { }
      try { rmSync(probe, { force: true }); } catch { }
      warn(`the restriction applied but this process could no longer write there (${verifyError?.message ?? verifyError}), so it was rolled back`);
    }
  } catch (e: any) {
    warn(String(e?.message ?? e));
  }
}

/** File-backed store so a COLD process (the original requester long gone) can still resume — the
 *  proof that nothing is "kept alive". One JSON file per decision holds the parked payload, and
 *  one marker file per execution state holds the ledger.
 *
 *  A claim is `link()`, not `rename()`: link fails when the target exists, so two processes racing
 *  for the same decision produce one winner and one clean refusal, while rename would silently
 *  overwrite and let both proceed. (0.1.x renamed `<id>.json` → `<id>.claimed`, and a stale
 *  `.claimed` from a crash then needed a TTL nobody had written — that gap is closed by the
 *  `claimed_stalled` state and `reconcile()`, which release it explicitly rather than on a timer.
 *  A timer would have to guess whether the handler ran.) */
export class FilePendingStore implements PendingStore {
  constructor(private dir: string) {
    mkdirSync(dir, { recursive: true });
    hardenDir(dir);
    try { this.migrateLegacy(); }
    catch (e: any) { console.error(`[decidio] could not upgrade the older pending layout in ${dir} (${e?.message ?? e}). Entries written by an older SDK may not appear in recover() — inspect the directory before assuming it is empty.`); }
  }
  private key(id: string) { return id.replace(/[^\w.-]/g, "_"); }
  private path(id: string) { return join(this.dir, `${this.key(id)}.json`); }

  private revPath(key: string, n: number) { return join(this.dir, `${key}.rev.${n}`); }
  /** Legacy (0.2/0.3) marker path, read for migration and never written. */
  private markerPath(key: string, s: ExecutionState) { return join(this.dir, `${key}.${s}`); }

  private listRevs(key: string, names?: string[]): number[] {
    const prefix = `${key}.rev.`;
    const out: number[] = [];
    if (!names) { try { names = readdirSync(this.dir); } catch (e: any) { if (e?.code === "ENOENT") return out; throw new DecidioStateCorruptError(key, [`${this.dir}: ${e?.message ?? e}`]); } }
    for (const name of names) {
      if (!name.startsWith(prefix)) continue;
      const tail = name.slice(prefix.length);
      if (tail.length && /^\d+$/.test(tail)) out.push(Number(tail));
    }
    return out;
  }
  private legacyMarkers(key: string, names?: string[]): ExecutionState[] {
    if (names) return EXECUTION_STATES.filter((s) => names.includes(`${key}.${s}`));
    return EXECUTION_STATES.filter((s) => existsSync(this.markerPath(key, s)));
  }

  /** Write `text` to a fresh temp file beside `target`, fsynced. Returns the temp path. */
  private writeTemp(target: string, text: string): string {
    const tmp = `${target}.${process.pid}.${randomUUID()}.tmp`;
    const fd = openSync(tmp, "w", 0o600);
    try { writeFileSync(fd, text); fsyncSync(fd); } finally { closeSync(fd); }
    return tmp;
  }
  /** Durable write for the PAYLOAD file (not the chain): temp → fsync → atomic rename. */
  private writeAtomic(file: string, text: string): void {
    const tmp = this.writeTemp(file, text);
    renameSync(tmp, file);
  }

  /** The head of the chain, or the migrated reading of a legacy layout that has not been
   *  upgraded. Corruption is REPORTED, never treated as absent: an unreadable record is the one
   *  that proves an action already ran. */
  private readHead(id: string, names?: string[]): { rec: ExecutionRecord | null; rev: number; corrupt: string[] } {
    const key = this.key(id);
    for (let tries = 0; tries < 4; tries++) {
      const revs = this.listRevs(key, names);
      const markers = this.legacyMarkers(key, names);
      names = undefined;
      if (revs.length === 0) {
        if (markers.length === 0) return { rec: null, rev: 0, corrupt: [] };
        const legacy = this.resolveLegacyMarkers(key);
        return { rec: legacy.rec, rev: 0, corrupt: legacy.corrupt };
      }
      if (markers.length) {
        return { rec: null, rev: Math.max(...revs), corrupt: markers.map((s) => `${this.markerPath(key, s)}: a legacy state marker beside the revision chain — written by an older SDK after this directory was upgraded, or left by an interrupted upgrade; the two cannot be reconciled automatically`) };
      }
      const top = Math.max(...revs);
      const f = this.revPath(key, top);
      try {
        const r = JSON.parse(readFileSync(f, "utf8")) as ExecutionRecord;
        if (!r || typeof r !== "object" || !(EXECUTION_STATES as readonly string[]).includes((r as { state?: unknown }).state as string)) {
          return { rec: null, rev: top, corrupt: [`${f}: the record carries no recognised state (${JSON.stringify((r as { state?: unknown })?.state ?? null)})`] };
        }
        return { rec: r, rev: top, corrupt: [] };
      } catch (e: any) {
        if (e?.code === "ENOENT") continue;
        return { rec: null, rev: top, corrupt: [`${f}: ${e?.message ?? e}`] };
      }
    }
    return { rec: null, rev: 0, corrupt: [`${key}: the revision chain changed under every read attempt`] };
  }

  /** TEST SEAM, a no-op in production. Called with the operation name and the state about to be
   *  published, AFTER validation and BEFORE the publish — the exact window a concurrent writer
   *  can land in. The deterministic two-process suites subclass the store and block here so the
   *  race the retest found is reproduced on purpose, every run, rather than by luck. */
  protected _barrier(_op: string, _id: string, _next: ExecutionState): void { }

  /** ONE TRANSITION = read head → compute successor → publish with link(). `compute` receives the
   *  current record (null if none) and returns the successor, or null for "nothing to write" (a
   *  refusal that is a return value, like a lost claim, rather than an error). Every rule runs
   *  INSIDE `compute`, against the revision that is about to be superseded; if a rival publishes
   *  first, `compute` runs again against the rival's record. */
  private transition(id: string, op: string, compute: (cur: ExecutionRecord | null, rev: number) => ExecutionRecord | null): ExecutionRecord | null {
    const key = this.key(id);
    for (let attempt = 0; attempt < 16; attempt++) {
      const { rec, rev, corrupt } = this.readHead(id);
      if (corrupt.length) throw new DecidioStateCorruptError(id, corrupt);
      const next = compute(rec, rev);
      if (next === null) return null;
      this._barrier(op, id, next.state);
      const target = this.revPath(key, rev + 1);
      const tmp = this.writeTemp(target, JSON.stringify(next, null, 2));
      try { linkSync(tmp, target); }
      catch (e: any) {
        try { rmSync(tmp); } catch { }
        if (e?.code === "EEXIST") continue;
        throw e;
      }
      try { rmSync(tmp); } catch { }
      return next;
    }
    throw new Error(`[decidio] ${id}: could not publish a state transition after 16 attempts — another writer kept winning the next revision. Retry, or look for a process writing this decision in a loop.`);
  }

  /** The 0.2/0.3 reading of a marker layout — strongest marker wins, a denial marker wins at any
   *  rank, and a denial beside an execution marker is reported as both. Used ONLY to migrate an
   *  older directory and to report one that could not be migrated; nothing writes markers. */
  private resolveLegacyMarkers(key: string): { rec: ExecutionRecord | null; corrupt: string[] } {
    const corrupt: string[] = [];
    let best: ExecutionRecord | null = null;
    let denial: ExecutionRecord | null = null;
    for (const s of EXECUTION_STATES) {
      const f = this.markerPath(key, s);
      if (!existsSync(f)) continue;
      try {
        const r = JSON.parse(readFileSync(f, "utf8")) as ExecutionRecord;
        if (!best || rank(s) >= rank(best.state)) best = { ...r, state: s };
        if (s === "discarded") denial = { ...r, state: "discarded" };
      } catch (e) { corrupt.push(`${f}: ${(e as Error).message}`); }
    }
    if (!denial) return { rec: best, corrupt };
    const ran = best && rank(best.state) >= rank("invoking") ? best : null;
    return { rec: ran ? { ...denial, executionDespiteDenial: { state: ran.state, at: ran.at, hasEvidence: !!ran.hasEvidence } } : denial, corrupt };
  }

  /** The generic ADVANCE, with every fence evaluated against the head the publish will supersede.
   *  `pre` is a per-method check (markInvoking's claim requirement) that must ALSO run inside the
   *  transition — a check that runs before it is a check against a snapshot. */
  private setState(id: string, attemptId: string, state: ExecutionState, patch: Partial<ExecutionRecord> = {}, pre?: (cur: ExecutionRecord) => void): void {
    this.transition(id, "advance", (rec) => {
      const cur: ExecutionRecord = rec ?? { decisionId: id, state: "parked", attemptId: null, at: new Date().toISOString() };
      pre?.(cur);
      if (cur.attemptId && cur.attemptId !== attemptId) throw new DecidioStaleAttemptError(id, cur.attemptId, cur.state);
      assertNotDenied(id, cur, state);
      assertNotSettled(id, cur, state);
      if (rank(state) < rank(cur.state)) throw new Error(`[decidio] ${id}: refusing to move ${cur.state} → ${state}; execution state only ever advances.`);
      return { ...cur, ...patch, decisionId: id, attemptId, state, at: new Date().toISOString() };
    });
  }

  async put(p: PendingAction) {
    this.writeAtomic(this.path(p.decisionId), JSON.stringify(p, null, 2));
    this.transition(p.decisionId, "put", (cur) => cur ? null
      : { decisionId: p.decisionId, state: "parked", attemptId: null, action: p.action, at: new Date().toISOString() });
  }
  async get(id: string) {
    const f = this.path(id);
    return existsSync(f) ? (JSON.parse(readFileSync(f, "utf8")) as PendingAction) : null;
  }
  /** CLEANUP ONLY — the payload goes, the execution record STAYS. That is the whole point of
   *  the v2 model: a failed or skipped delete can no longer make an executed action runnable. */
  async delete(id: string, attemptId?: string) {
    if (attemptId) {
      const owner = this.readHead(id).rec?.attemptId;
      if (owner && owner !== attemptId) return;
    }
    try { if (existsSync(this.path(id))) rmSync(this.path(id)); } catch { }
  }
  async list() {
    if (!existsSync(this.dir)) return [];
    const out: PendingAction[] = [];
    const names = readdirSync(this.dir);
    for (const f of names.filter((f) => f.endsWith(".json"))) {
      let p: PendingAction;
      try { p = JSON.parse(readFileSync(join(this.dir, f), "utf8")) as PendingAction; }
      catch (e) { console.error(`[decidio] skipping unreadable parked entry ${f} (${(e as Error).message}) — the other parked actions still resume; inspect or delete this file.`); continue; }
      const { rec } = this.readHead(p.decisionId, names);
      if (!rec || rec.state === "parked") out.push(p);
    }
    return out;
  }
  async claim(id: string, attemptId: string): Promise<ClaimResult> {
    if (!existsSync(this.path(id))) return { ok: false, reason: "no parked entry" };
    let refusal: ClaimResult | null = null;
    this.transition(id, "claim", (cur) => {
      const state = cur?.state ?? "parked";
      if (NON_REPLAYABLE.includes(state)) { refusal = { ok: false, state, reason: `already ${state}` }; return null; }
      if (state === "claimed_preinvoke") { refusal = { ok: false, state, reason: "claimed by another attempt" }; return null; }
      return { ...(cur ?? {}), decisionId: id, state: "claimed_preinvoke", attemptId, action: cur?.action, at: new Date().toISOString() };
    });
    return refusal ?? { ok: true };
  }
  async markInvoking(id: string, attemptId: string) {
    this.setState(id, attemptId, "invoking", {}, (cur) => {
      assertNotDenied(id, cur, "invoking");
      assertClaimedBy(id, cur, attemptId);
    });
  }
  async recordExecuted(id: string, attemptId: string, evidence: unknown, evidenceSig?: ExecutionRecord["evidenceSig"], evidenceError?: string) { this.setState(id, attemptId, "executed_unreported", { evidence, hasEvidence: true, evidenceSig, evidenceError }); }
  async markIndeterminate(id: string, attemptId: string, error: string) { this.setState(id, attemptId, "indeterminate", { error }); }
  async markReported(id: string, attemptId: string, confirmation: string) { this.setState(id, attemptId, "reported", { confirmation }); }
  async markDiscarded(id: string, verdict: "rejected" | "blocked", reason?: string) {
    this.transition(id, "discard", (rec) => {
      const cur: ExecutionRecord = rec ?? { decisionId: id, state: "parked", attemptId: null, at: new Date().toISOString() };
      assertNotSettled(id, cur, "discarded");
      if (rank("discarded") < rank(cur.state)) throw new Error(`[decidio] ${id}: refusing to move ${cur.state} → discarded; execution state only ever advances.`);
      return { ...cur, decisionId: id, attemptId: cur.attemptId ?? "", state: "discarded", verdict, ...(reason ? { discardReason: reason } : {}), at: new Date().toISOString() };
    });
  }
  async getExecution(id: string) {
    const { rec, corrupt } = this.readHead(id);
    if (corrupt.length) throw new DecidioStateCorruptError(id, corrupt);
    return rec;
  }
  async listExecutions() {
    if (!existsSync(this.dir)) return [];
    const keys = new Set<string>();
    const names = readdirSync(this.dir);
    for (const name of names) {
      const m = /^(.*)\.rev\.\d+$/.exec(name);
      if (m) { keys.add(m[1]!); continue; }
      const dot = name.lastIndexOf(".");
      if (dot < 0) continue;
      const suffix = name.slice(dot + 1) as ExecutionState;
      if ((EXECUTION_STATES as readonly string[]).includes(suffix)) keys.add(name.slice(0, dot));
    }
    const out: ExecutionRecord[] = [];
    for (const key of keys) {
      const { rec, corrupt } = this.readHead(key, names);
      if (corrupt.length) { out.push({ decisionId: rec?.decisionId ?? key, state: "indeterminate", attemptId: null, error: `state files unreadable — ${corrupt.join("; ")}`, at: new Date().toISOString() }); continue; }
      if (rec) out.push(rec);
    }
    return out;
  }
  /** OPERATOR RECONCILIATION — see MemoryPendingStore.settle. The one legal backwards move, and
   *  now a transition like any other: two conflicting settlements both validate, both try to
   *  publish the next revision, exactly one wins, and the loser re-validates against the winner's
   *  record — where `assertSettlable` refuses it (captured evidence protects a `committed`; a
   *  `parked` record refuses `committed`). Before this, both won and the second erased the first. */
  async settle(id: string, outcome: SettleOutcome, opts: { evidence?: unknown; reason?: string; evidenceSig?: ExecutionRecord["evidenceSig"]; workerStopped?: boolean } = {}): Promise<void> {
    this.transition(id, "settle", (rec) => {
      const cur: ExecutionRecord = rec ?? { decisionId: id, state: "parked", attemptId: null, at: new Date().toISOString() };
      assertSettlable(id, cur.state, outcome, { hasObservedEvidence: !cur.evidenceError, workerStopped: opts.workerStopped });
      const at = new Date().toISOString();
      const reconciled = { outcome, reason: opts.reason, at, ...(opts.workerStopped ? { workerStopped: true } : {}) };
      return outcome === "committed"
        ? { ...cur, state: "executed_unreported", evidence: opts.evidence ?? null, hasEvidence: true, evidenceSig: opts.evidenceSig, evidenceError: undefined, reconciled, at }
        : { ...cur, state: "parked", attemptId: null, error: undefined, reconciled, at };
    });
  }

  async releasePreinvoke(id: string, attemptId: string) {
    this.transition(id, "release", (rec) => {
      const state = rec?.state ?? "parked";
      if (NON_REPLAYABLE.includes(state)) throw new Error(`[decidio] ${id}: refusing to release this decision — its durable state is ${state}, which is terminal or past the invocation boundary. releasePreinvoke only ever releases a claim nothing has acted on.`);
      if (rec?.attemptId && rec.attemptId !== attemptId) return null;
      if (state === "parked") return null;
      return { ...(rec ?? {}), decisionId: id, state: "parked", attemptId: null, action: rec?.action, at: new Date().toISOString() };
    });
  }

  /** ONE-WAY MIGRATION of older layouts, run at construction.
   *    0.2/0.3 one-marker-per-state  → the head of a fresh revision chain (markers removed)
   *    0.1.x `<id>.json` with no state → parked
   *    0.1.x `<id>.claimed`           → INDETERMINATE, never parked: a claimed 0.1.x entry may have
   *                                     been mid-flight when the process died, and assuming it did
   *                                     not run is the assumption that duplicates a payment
   *    0.1.x `reports/<id>.json`      → executed_unreported (the report can be re-sent)
   *  Nothing ambiguous is made executable by an upgrade, and nothing unreadable is silently
   *  dropped: a key whose markers cannot be parsed is left exactly as found and reads as corrupt. */
  migrateLegacy(): { migrated: number; indeterminate: number; reports: number; chained: number } {
    if (!existsSync(this.dir)) return { migrated: 0, indeterminate: 0, reports: 0, chained: 0 };
    let migrated = 0, indeterminate = 0, chained = 0;

    const markerKeys = new Set<string>();
    for (const name of readdirSync(this.dir)) {
      const dot = name.lastIndexOf(".");
      if (dot < 0) continue;
      if ((EXECUTION_STATES as readonly string[]).includes(name.slice(dot + 1))) markerKeys.add(name.slice(0, dot));
    }
    for (const key of markerKeys) {
      if (this.listRevs(key).length) continue;
      const present = this.legacyMarkers(key);
      const { rec, corrupt } = this.resolveLegacyMarkers(key);
      if (corrupt.length || !rec) {
        console.error(`[decidio] ${key}: the older state marker(s) for this decision could not be read (${corrupt.join("; ") || "no readable marker"}) — left in place; the decision reads as unreadable until a person inspects it.`);
        continue;
      }
      const target = this.revPath(key, 1);
      const tmp = this.writeTemp(target, JSON.stringify(rec, null, 2));
      try { linkSync(tmp, target); chained++; } catch (e: any) { if (e?.code !== "EEXIST") { try { rmSync(tmp); } catch { } throw e; } }
      try { rmSync(tmp); } catch { }
      for (const s of present) { try { rmSync(this.markerPath(key, s)); } catch { } }
    }
    if (chained) console.error(`[decidio] upgraded ${chained} decision${chained === 1 ? "" : "s"} from the one-marker-per-state layout to the revision chain. Do not run an older SDK against this directory again: it would write markers this layout refuses to read.`);

    for (const name of readdirSync(this.dir)) {
      if (name.endsWith(".claimed")) {
        const key = name.slice(0, -".claimed".length);
        try {
          const p = JSON.parse(readFileSync(join(this.dir, name), "utf8")) as PendingAction;
          const published = this.transition(p.decisionId, "migrate", (cur) => cur && NON_REPLAYABLE.includes(cur.state) ? null : ({
            ...(cur ?? {}), decisionId: p.decisionId, state: "indeterminate", attemptId: null, action: p.action,
            error: "upgraded from 0.1.x while claimed — whether it ran is not knowable; reconcile it", at: new Date().toISOString(),
          }));
          if (published === null) {
            renameSync(join(this.dir, name), join(this.dir, `${name}.migrated`));
            continue;
          }
          this.writeAtomic(this.path(p.decisionId), JSON.stringify(p, null, 2));
          renameSync(join(this.dir, name), join(this.dir, `${name}.migrated`));
          indeterminate++;
        } catch { console.error(`[decidio] could not migrate legacy claimed entry ${key} — inspect it by hand.`); }
        continue;
      }
      if (!name.endsWith(".json")) continue;
      try {
        const p = JSON.parse(readFileSync(join(this.dir, name), "utf8")) as PendingAction;
        if (!p?.decisionId) continue;
        if (this.readHead(p.decisionId).rec) continue;
        this.transition(p.decisionId, "migrate", (cur) => cur ? null
          : { decisionId: p.decisionId, state: "parked", attemptId: null, action: p.action, at: new Date().toISOString() });
        migrated++;
      } catch { }
    }
    if (indeterminate) console.error(`[decidio] upgraded ${indeterminate} in-flight 0.1.x entr${indeterminate === 1 ? "y" : "ies"} to INDETERMINATE — they will not auto-run; review them with guard.resume.recover().`);
    const reports = this.migrateLegacyReports();
    return { migrated, indeterminate, reports, chained };
  }

  /** 0.1.x wrote execution reports to `<pendingDir>/reports/<id>.json` — evidence that an action
   *  ALREADY RAN and still owes Decidio a report. 0.2.0 keeps that in the ledger, so without this
   *  those files become invisible: `recover()` returns nothing and `reconfirm()` answers "nothing
   *  is recorded for X … or this process never executed it" about an action that demonstrably
   *  did. That is the SDK losing a durable authority fact on upgrade, so the reports are pulled
   *  into `executed_unreported` rows where reconfirm() can actually re-send them.
   *
   *  The file is CONSUMED (renamed to `.migrated`) rather than deleted: if anything here is
   *  wrong, the original bytes are still on disk to inspect. */
  private migrateLegacyReports(): number {
    const reportsDir = join(this.dir, "reports");
    if (!existsSync(reportsDir)) return 0;
    let moved = 0;
    for (const name of readdirSync(reportsDir)) {
      if (!name.endsWith(".json")) continue;
      const file = join(reportsDir, name);
      try {
        const e = JSON.parse(readFileSync(file, "utf8")) as { decisionId?: string; action?: string; reported?: unknown; at?: string };
        if (!e?.decisionId) continue;
        const published = this.transition(e.decisionId, "migrate", (cur) =>
          cur && (cur.state === "discarded" || rank(cur.state) >= rank("executed_unreported")) ? null : ({
            ...(cur ?? {}), decisionId: e.decisionId!, state: "executed_unreported", attemptId: null, action: e.action,
            evidence: e.reported, hasEvidence: true, migratedFrom: "0.1.x report journal",
            at: e.at ?? new Date().toISOString(),
          }));
        renameSync(file, `${file}.migrated`);
        if (published === null) {
          const head = this.readHead(e.decisionId).rec;
          if (head?.state === "discarded") console.error(`[decidio] ${e.decisionId}: a 0.1.x execution report was found for a decision that was DENIED (${head.verdict ?? "rejected"}). It has NOT been added to the ledger — a denial is terminal and this report will not be sent. The file is kept as ${file}.migrated: if that action really ran, check the downstream system and correct it there.`);
          continue;
        }
        moved++;
      } catch { console.error(`[decidio] could not migrate the 0.1.x execution report ${file} — it records an action that RAN. Inspect it by hand before deleting it.`); }
    }
    if (moved) console.error(`[decidio] recovered ${moved} execution report${moved === 1 ? "" : "s"} written by 0.1.x into the execution ledger — re-send them with guard.resume.recover() / reconfirm(). The original files are kept alongside as .migrated.`);
    return moved;
  }
}

/** The state on disk could not be read. Never silently treated as "nothing here": an
 *  unreadable record is the one that proves an action already ran. */
export class DecidioStateCorruptError extends Error {
  constructor(public decisionId: string, public details: string[]) {
    super(`[decidio] ${decisionId}: durable execution state is unreadable (${details.join("; ")}). Refusing to guess whether this action ran — inspect these files; reconcile() once you know.`);
    this.name = "DecidioStateCorruptError";
  }
}

/** Thrown by a `withApproval`-wrapped call when the action is routed and configured
 *  for async resume: the action is now SUSPENDED (parked in the store), not failed.
 *  The caller can stop here — the process may even exit; the resume transport will
 *  complete it later. */
export class DecidioSuspendedError extends Error {
  constructor(public decisionId: string, public action: string) {
    super(`Decidio suspended "${action}" for async approval (decision ${decisionId}). It will resume when a human approves.`);
    this.name = "DecidioSuspendedError";
  }
}

/** `indeterminate` (0.2.0): the handler was INVOKED and then threw. Whether the downstream
 *  effect committed is not knowable from here, so the action is never retried automatically —
 *  it waits for reconcile(). Callers that switch exhaustively on this union must handle it. */
/** `already_resolved` (0.3.5): this resume signal LOST the transition race to an earlier, FINAL answer
 *  (a denial, an execution that already ran, or a report already recorded) — `reason` names which. It used
 *  to read `unknown`, the word for "not ours" (prodsec V033-06). An `invoking` row is NOT final and answers
 *  `indeterminate` (prodsec V035-02). Both members are additive: an exhaustive switch over this union
 *  gains a case per release, which the changelog announces. */
/** `lost_race` (0.4.1): this signal lost the pre-invocation claim to ANOTHER ATTEMPT that is still in flight, or
 *  the invocation boundary could not be recorded at all (a store fault) - and it did NOTHING. (A boundary lost to
 *  an attempt already in flight reads `indeterminate`: that attempt may be running.) Nothing ran on this signal; the winner reports, or the entry stays
 *  parked for a later signal. It used to read `unknown` (the word for "not ours") for the claim loser and
 *  `no_handler` for the boundary loser although a handler was registered (prodsec V040-01). A loss to a FINAL
 *  answer (a denial, an execution) stays `already_resolved`. Additive, like the two above. */
/** `not_approved` (0.7.0): the signal said "approved" but DECIDIO does not record an approval for this
 *  decision (it is still pending, or answered a state this SDK does not recognise). Every resume signal
 *  is a wake-up now, never the authority: the approval is confirmed with GET /agent/status right before
 *  the action runs. Nothing ran; the entry stays parked and a later signal resolves it. Not a resolution,
 *  so `onResolved` does not fire (like `unknown`).
 *  `request_unverified` (0.7.0): Decidio records an approval, but it cannot be tied to THIS parked
 *  request — the request changed after approval (the commitment Decidio holds does not match a fresh
 *  recompute over the parked arguments), the gate kept no commitment for a request this SDK bound, or
 *  this process lacks the key material to recompute it. `reason` says which. Nothing ran; the entry
 *  stays parked for inspection. Both members are additive, announced in the changelog. */
export type ResumeStatus = "executed" | "rejected" | "blocked" | "unanswered" | "no_handler" | "unknown" | "indeterminate" | "already_resolved" | "lost_race" | "not_approved" | "request_unverified";

function outcomeFromHead(head: ExecutionRecord | null | undefined, decisionId: string, action?: string): ResumeOutcome | undefined {
  if (!head) return undefined;
  const base = action ? { decisionId, action } : { decisionId };
  switch (head.state) {
    case "discarded": return { status: "already_resolved", ...base, reason: `this decision was DENIED (${head.verdict ?? "rejected"}); that answer is final and this signal did nothing` };
    case "executed_unreported": case "reported": return { status: "already_resolved", ...base, reason: `this decision already ran (durable state ${head.state}); this signal arrived after it and did nothing` };
    case "invoking": case "indeterminate": return { status: "indeterminate", ...base, reason: `this decision is in durable state ${head.state}: its action may still be running or may have finished without reporting - it may or may not have run. Nothing will retry it; check the worker and the downstream system, then settle it with reconcile("${decisionId}", …).` };
    case "claimed_preinvoke": return { status: "lost_race", ...base, reason: `another attempt holds the pre-invocation claim on this decision; this signal did nothing. If that attempt is alive it will report; if it died, recover() lists the decision and reconcile() can settle it` };
    default: return undefined;
  }
}
/** The states a durable action can actually be in — every one of them nameable, including the
 *  one nobody likes. */
export type RecoveryState =
  /** Parked, waiting on a human. Nothing has executed. */
  | "parked"
  /** Claimed by an attempt that never reached the invocation boundary, so the handler PROVABLY
   *  did not run — but the row is not parked either: `list()` excludes it and every ordinary
   *  signal answers `lost_race`, so nothing will pick it up on its own. It is stalled until an
   *  operator releases it. Reporting this as "parked" (as 0.2.0's first draft did) told a UI an
   *  approved action was still queued to resume when in fact it had been silently dropped. */
  | "claimed_stalled"
  /** DENIED, and an execution marker exists anyway. Nothing here will run it and nothing will
   *  report it — the decision is closed — but an effect may exist downstream, so this is the one
   *  recovery row that asks a human to go and look. It cannot be reconciled or retried; a denial is
   *  terminal. Callers switching exhaustively on this union must handle it. */
  | "denied_with_evidence"
  /** Claimed for execution and NOT journalled: the process died somewhere between claiming and
   *  recording the result. The action MAY OR MAY NOT have run — this cannot be resolved locally
   *  and must never be retried automatically. */
  | "indeterminate"
  /** Executed, result captured, report not yet accepted by Decidio. Safe to `reconfirm`. */
  | "executed_unreported"
  /** a parked row whose payload is gone: cannot execute, not awaiting anyone (0.3.5) */
  | "orphaned_state";

export interface RecoveryItem {
  decisionId: string;
  action?: string;
  state: RecoveryState;
  /** What a human should do about it, in words. */
  guidance: string;
}

/** What the SDK knows about THIS execution, handed to a handler that opts in with
 *  `withContext: true`.
 *
 *  The point is `idempotencyKey`. This SDK can guarantee it will not invoke your handler twice;
 *  it cannot guarantee your downstream API only commits once, because that is the vendor's
 *  property, not ours. Passing this key to Stripe/Salesforce/your own service is what closes the
 *  remaining window — and until now the handler had no way to reach the decision id at all, so
 *  the one thing that could close it was the one thing a caller could not get.
 *
 *  Opt-in, never inferred from arity. A signature check would have to guess whether a bound
 *  method, a *args function or a decorated tool wanted the context, and guessing wrong means
 *  passing a context object as someone's first business argument — in a library whose whole job
 *  is not doing surprising things to a payment call. */
export interface ExecutionContext {
  decisionId: string;
  /** The attempt that owns this execution. Null on the inline path, where there is no durable
   *  attempt — the value is honest about which door you came through. */
  attemptId: string | null;
  /** Defaults to `decisionId`. Stable across every attempt at the same decision, which is exactly
   *  what a downstream idempotency key must be. */
  idempotencyKey: string;
}

export interface ResumeOutcome {
  status: ResumeStatus; decisionId: string; action?: string; result?: unknown; reason?: string;
  /** executed only: Decidio ACCEPTED the execution report and named the tier it recorded.
   *  `status: "executed"` describes the LOCAL run; this describes the record. */
  reportRecorded?: boolean;
  /** executed only: the recorded tier attests a COMMITTED execution. Deliberately a different
   *  question — and a different name — from `reportRecorded`. */
  executionConfirmed?: boolean;
  /** executed only: the evidence tier Decidio recorded, verbatim. */
  evidenceTier?: EvidenceTier;
  /** executed only, when the gate reported on the SIGNED execution report: whether the
   *  attestation proof VERIFIED (C3, 0.1.12). */
  executionReportVerified?: boolean;
  /** executed only: why the evidence landed where it did, when that is worth explaining. */
  diagnostic?: string;
  /** The four fields the INLINE door returns. The durable door computed the same outcome and kept
   *  three of them for its own prose, so the same question got a field on one path and a sentence
   *  on the other — and `reportJournalled` was worst, because the durable path is the one where
   *  `reconfirm()` genuinely CAN help and it never said so. */
  executionReportReason?: string;
  confirmationRetryable?: boolean;
  reportJournalled?: boolean;
  evidenceError?: string;
}

/** Minimal config the controller needs to confirm outcomes + poll status. Shared
 *  with GuardConfig (apiUrl/apiToken). */
export interface ResumeConfig {
  apiUrl: string;
  apiToken?: string;
  /** Agent identity for SIGNING the confirm call on resume (so the durable path can earn the
   *  application_confirmed tier, not just the inline path). Default from DECIDIO_AGENT_ID/
   *  _KEY/_DID env when unset — a cold resume process that has the env signs automatically. */
  agentId?: string;
  agentKey?: string;
  agentDid?: string;
  /** The workspace the agent acts in (DECIDIO_WORKSPACE_ID) — bound into the cold-resume confirm
   *  proof (D-B3.6) so it's tenant-scoped too. Default from env when unset. */
  workspaceId?: string;
  /** Shared secret Decidio signs the resume webhook with (HMAC-SHA256) — DECIDIO_WEBHOOK_SECRET, the
   *  dedicated secret your Decidio deployment signs resume webhooks with (never its API_AUTH_TOKEN, the
   *  admin bearer). NO FALLBACK since 0.7.0: it used to default to
   *  the API token, so anyone holding a leaked agent token could sign an "approved" callback. With
   *  no secret (and no `allowUnsigned`) the webhook handlers refuse every call. The poll worker
   *  (`worker()`) needs no inbound secret. The webhook is only a WAKE-UP either way: the approval
   *  is confirmed with Decidio (GET /agent/status + the request commitment) before anything runs.
   *  (The parked-payload integrity HMAC still falls back to the API token when this is unset — that
   *  key never authenticates a signal.) */
  webhookSecret?: string;
  /** @deprecated Ignored since 0.2.0 and accepted only so existing callers keep compiling.
   *  Execution evidence now lives in the PendingStore's own execution record, beside the state
   *  that makes a decision non-replayable. 0.1.x kept it in a separate local directory, so two
   *  workers sharing one Redis/Postgres store still held two disjoint journals and neither could
   *  reconfirm the other's work — and a store-recorded execution could read back as "nothing has
   *  executed" if the local file was lost. One store, one truth. */
  reportDir?: string;
  /** Map the action's natural return value to the evidence Decidio records — same option, same
   *  meaning as `protect`'s, so a durable resume reports exactly what the inline path would. */
  evidence?: (result: any) => unknown;
  /** Escape hatch to accept UNSIGNED resume webhooks (no secret). Off by default:
   *  with no secret and this unset, the webhook handler rejects every call (fail
   *  closed) so a misconfigured agent can't be driven by forged callbacks. Setting it
   *  true REMOVES webhook authenticity — anyone who can reach the endpoint can signal
   *  work — and the controller says so loudly at startup (an absolute fail-closed
   *  guarantee must disclose its opt-out). Only behind a trusted network boundary
   *  (e.g. mTLS / private mesh), never on an internet-reachable endpoint. */
  allowUnsigned?: boolean;
  /** The callback URL Decidio should POST the verdict to (webhook transport). Sent
   *  on /agent/authorize so the decision carries it; omit when using the poll worker. */
  resumeUrl?: string;
  /** Fired for every outcome except `unknown` (executed / indeterminate / rejected / blocked /
   *  no_handler / already_resolved / lost_race), via either transport. Use it to log, close a
   *  listener, or exit a CLI.
   *  `indeterminate` is new in 0.2.0 and DOES fire here: a handler that ran and then threw is a
   *  terminal outcome for automation — nothing will retry it — so a listener that only handled
   *  the old four would silently miss the one case that needs a human. */
  onResolved?: (o: ResumeOutcome) => void;
  fetchImpl?: typeof fetch;
}

/** Re-execute the agent's own fn on approval, confirm the captured outcome to
 *  Decidio, and clear the parked entry. Bound to a store + a registry of raw fns. */
export interface ResumeController extends ResumeConfig {
  store: PendingStore;
  /** Register a RAW fn under its action name so a (possibly cold) resume can replay
   *  it. `withApproval` auto-registers on the hot path; a cold worker/service should
   *  register at startup so it can resume actions it never originated. */
  register(action: string, fn: (...args: any[]) => Promise<any>, evidence?: (result: any) => unknown, withContext?: boolean): void;
  /** Park a routed action WITH its integrity binding (prefer this over store.put — the
   *  binding is what lets resolve() refuse a tampered payload). */
  park(p: Omit<PendingAction, "createdAt" | "argsSig">): Promise<void>;
  /** Drive a parked decision to completion once a verdict is known. Idempotent: a second call
   *  after success answers `already_resolved` (no double-write); an id this SDK never parked
   *  answers `unknown`; a call that loses the pre-invocation claim answers `lost_race`.
   *
   *  `verdict: "approved"` is a REQUEST to execute, never the authority (0.7.0): right before the
   *  action runs, resolve() confirms with Decidio that THIS parked request was approved (GET
   *  /agent/status + the request commitment — `checkApproval`). Decidio still pending → `not_approved`;
   *  Decidio says rejected/blocked → recorded as that denial; an approval that cannot be tied to these
   *  arguments → `request_unverified`. A transport failure during that check throws (nothing ran). A
   *  `rejected`/`blocked` verdict is applied as given — it can only ever prevent execution.
   *
   *  A PERSON'S approval is then COLLECTED ONCE (0.12.0, `claimApproval`) with the claim key parked with the action:
   *  another run already used it, or it expired → `blocked` with the reason (recorded like a block; nothing ran); a 404
   *  or a claim that could not be sent → throws (nothing ran, the entry stays parked for the next signal). */
  resolve(input: { decisionId: string; verdict: "approved" | "rejected" | "blocked"; reason?: string }): Promise<ResumeOutcome>;
  /** node:http listener for Decidio's signed approval webhook (Express/Fastify/node). The webhook is a
   *  WAKE-UP (0.7.0): after its signature is verified — with `webhookSecret` only, never the API token —
   *  only its decision id is read; the outcome follows Decidio's own state for that decision. */
  webhookHandler(): RequestListener;
  /** Web-Fetch handler (Request → Response) for Next.js route handlers, Hono,
   *  Cloudflare Workers, Bun, Deno. Same fail-closed signature check. */
  fetchHandler(): (req: Request) => Promise<Response>;
  /** Poll-based resume for hosts with no inbound URL (CLI/laptop). A long-lived
   *  watcher — this is a durable WORKER, not the request path blocking. */
  worker(opts?: { intervalMs?: number; timeoutMs?: number; onResolved?: (o: ResumeOutcome) => void }): { stop: () => void };
  /** Re-send a recorded execution report, IDEMPOTENTLY. Re-signs at send time over the value in
   *  the store's execution ledger — it can never re-run the business action, because the ledger
   *  holds no handler binding. Returns the evidence outcome; a decision with nothing recorded returns
   *  `reportRecorded: false` with guidance rather than pretending. */
  /** `acceptUnbound` is an OPERATOR override for a record whose integrity binding is missing or
   *  unverifiable — the case a 0.1.x upgrade legitimately produces. It is a call-site argument on
   *  purpose: any flag stored in the record itself would be writable by whoever planted the
   *  record. */
  reconfirm(decisionId: string, opts?: { acceptUnbound?: boolean }): Promise<EvidenceOutcome>;
  /** Settle a decision an operator has checked downstream — the ONLY exit from `indeterminate`
   *  and from a claim that stalled before invocation, and the only backwards transition in the
   *  machine. `committed` records and reports the evidence you supply WITHOUT invoking the
   *  handler; `not_committed` parks the decision so exactly one more ordinary attempt can run.
   *  Never called automatically: the whole point is that a human looked. */
  reconcile(decisionId: string, opts: { outcome: SettleOutcome; evidence?: unknown; reason?: string; workerStopped?: boolean }): Promise<EvidenceOutcome>;
  /** Every durable item that needs a human's attention, with its state named — including the one
   *  state that CANNOT be resolved automatically: `indeterminate`, where a process died between
   *  claiming an action and journalling its result, so whether the action ran is unknown locally.
   *  This never executes or retries anything; it reports. */
  recover(): Promise<RecoveryItem[]>;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function sign(secret: string, body: string): string {
  return "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
}
/** Verify Decidio's `x-decidio-signature` over the raw webhook body (HMAC-SHA256).
 *  Exported so engine adapters (e.g. the Inngest bridge) reuse the exact check. */
export function verifyResumeSignature(secret: string, body: string, header: string | undefined): boolean {
  if (!header) return false;
  const expected = sign(secret, body);
  const a = Buffer.from(expected), b = Buffer.from(header);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Throwing wrapper over the ONE confirm-body rule, for a caller building their own confirm door.
 *  Returns the recorded tier or throws.
 *
 *  It now DELEGATES to `readConfirmResponse` rather than re-implementing the check, because the
 *  two had drifted into opposite answers: this function accepted `confirmation: "anything"` and
 *  handed it back as a recorded tier, while the parser every real door uses treats an
 *  unrecognised tier as NOT evidence (closed enum, fail-closed — an answer we do not understand
 *  is never evidence). Its own comment claimed it was "shared by every confirm door", and no door
 *  called it: the claim was what kept anyone from noticing the disagreement. */
export function assertConfirmRecorded(body: any, decisionId: string, signed: boolean): string {
  const ev = readConfirmResponse(body, { signed, journalled: false });
  if (!ev.reportRecorded || !ev.evidenceTier) {
    throw new Error(`[decidio] ${decisionId}: ${ev.diagnostic ?? "confirm answered 2xx but reported no recorded evidence tier — treating the confirmation as NOT recorded"}`);
  }
  if (signed && ev.evidenceTier !== "application_confirmed") {
    console.warn(`[decidio] execution evidence for ${decisionId} was recorded as "${ev.evidenceTier}", not application_confirmed, despite a signed report — the server did not accept the identity proof (key/DID/registration mismatch?). Run \`npx @decidio/sdk doctor\` and re-init if this persists.`);
  }
  return ev.evidenceTier;
}

function buildResumeConfirmRequest(cfg: ResumeConfig, decisionId: string, canonicalResult: unknown): Record<string, unknown> {
  const requesterIdentity = signConfirm(decisionId, cfg);
  if (!requesterIdentity) console.warn(`[decidio] execution evidence for ${decisionId} will be recorded as an unproven agent assertion — no signing key configured. Set DECIDIO_AGENT_KEY/DID to earn a confirming tier.`);
  return buildConfirmBody({ agentId: cfg.agentId ?? "agent", agentKey: cfg.agentKey, agentDid: cfg.agentDid, workspaceId: cfg.workspaceId }, decisionId, canonicalResult, requesterIdentity);
}

async function postConfirm(cfg: ResumeConfig, decisionId: string, body: Record<string, unknown>, journalled = true): Promise<EvidenceOutcome> {
  const f = cfg.fetchImpl ?? fetch;
  assertSafeTransport(cfg.apiUrl, carriesCredential(cfg));
  const r = await f(cfg.apiUrl.replace(/\/$/, "") + "/agent/confirm", {
    method: "POST",
    headers: { "content-type": "application/json", ...(cfg.apiToken ? { authorization: `Bearer ${cfg.apiToken}` } : {}) },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const raw = await r.text().catch(() => "");
    let parsed: unknown = raw; try { parsed = raw ? JSON.parse(raw) : undefined; } catch { }
    throw new DecidioHttpError(r.status, "/agent/confirm", parsed);
  }
  const parsed: any = await r.json().catch(() => null);
  return readConfirmResponse(parsed, { signed: !!body.requesterIdentity, capturedResponse: body.capturedResponse, journalled });
}

/** What GET /agent/status answers. `requestCommitment` (0.7.0) is the commitment the decision was
 *  authorized with, or null for a decision whose request was never bound. `spent` and `grantExpiresAt` (0.8.0,
 *  mini-approvals): the grant is ONE-TIME - `spent` once an execution was recorded on it, `grantExpiresAt` when
 *  it lapses (the seal's time plus the gate's TTL) for a granted decision, null otherwise. A gate that predates
 *  them answers neither. `handedBackAt` (when a replay handed the grant to a retry) and `claimed` (0.12.0: whether a
 *  run has collected a person's approval - never by whom) are informational: reading the status claims NOTHING, and
 *  this SDK decides a claim only by claiming (claimApproval). */
export interface DecisionStatus { state: string; decisionId?: string; receiptId?: string | null; reason?: string | null; requestCommitment?: string | null; spent?: boolean; grantExpiresAt?: string | null; handedBackAt?: string | null; claimed?: boolean;
  /** 0.21.0: set when nobody decided the request by its deadline (state `rejected`): see DecidioUnansweredError. */
  closedBy?: { reason: "unanswered"; deadline: string | null } | null }

type StatusConfig = { apiUrl: string; apiToken?: string; agentKey?: string; agentDid?: string; fetchImpl?: typeof fetch };

async function statusOf(cfg: StatusConfig, decisionId: string): Promise<DecisionStatus> {
  const f = cfg.fetchImpl ?? fetch;
  assertSafeTransport(cfg.apiUrl, carriesCredential(cfg));
  const r = await f(cfg.apiUrl.replace(/\/$/, "") + "/agent/status/" + encodeURIComponent(decisionId), {
    headers: { ...(cfg.apiToken ? { authorization: `Bearer ${cfg.apiToken}` } : {}) },
  });
  if (!r.ok) throw new DecidioHttpError(r.status, `/agent/status/${decisionId}`);
  return r.json() as any;
}

/** Why an approval check did not pass.
 *  pending / unrecognized_state — Decidio records no approval (yet): nothing may run.
 *  rejected / blocked           — Decidio's final answer is no.
 *  spent                        — the approval was already used: an execution is recorded on it (one approval
 *                                 covers one action, once) - ask again.
 *  expired                      — the approval lapsed (its grant's time passed) before anything ran - ask again.
 *  request_changed              — the approval is for a DIFFERENT request than the one about to run.
 *  commitment_missing           — this SDK bound the request, the gate answered without a commitment.
 *  unverifiable                 — Decidio holds a commitment this process cannot recompute (no or
 *                                 unreadable key material), or answered a malformed one. */
export type ApprovalCheckCode = "pending" | "unrecognized_state" | "rejected" | "blocked" | "unanswered" | "spent" | "expired" | "request_changed" | "commitment_missing" | "unverifiable";

/** The outcome of the one check. Plain JSON on purpose: an engine that runs it as an activity or a
 *  step (Temporal, Inngest) memoizes it across its serialization boundary. */
export interface ApprovalCheck {
  ok: boolean;
  decisionId: string;
  /** Decidio's derived state, verbatim ("" when it answered none). */
  state: string;
  code?: ApprovalCheckCode;
  /** The server's (tokenized) reason for a rejection, or this SDK's explanation of a refusal. */
  reason?: string;
  /** 0.21.0, code `unanswered`: the deadline nobody decided it by (ISO), when Decidio named one. */
  deadline?: string | null;
}

/** CONFIRM WITH DECIDIO THAT *THIS* REQUEST WAS APPROVED — the check every door runs right before it
 *  executes a routed approval: the inline blocking wait, the durable resume (webhook AND worker), and
 *  each engine adapter (LangGraph, Temporal, Inngest, OpenAI Agents). A resume signal is a wake-up; it
 *  is never the authority.
 *
 *  Approved means: GET /agent/status/:decisionId answers approved/auto_approved AND the commitment it
 *  returns equals a FRESH recompute over `request` — the exact request about to run. The fail-closed
 *  rules:
 *   - Decidio holds a commitment → it must match; no key material to recompute it → refused.
 *   - Decidio holds none, but this SDK bound the request (`sent`, default: this config has key
 *     material, so it would have sent one) → refused: the gate predates request binding.
 *   - Decidio holds none and nothing was bound (a keyless agent, or an entry parked before 0.7.0) →
 *     the state alone decides — nothing on either side could say more.
 *  A transport failure THROWS (it is not an answer); every other outcome is a value.
 *
 *  `status` lets a caller that has just read the status (the blocking poll, the worker) pass it in
 *  instead of reading it twice. */
export async function checkApproval(
  cfg: StatusConfig,
  decisionId: string,
  request: CommittedRequest,
  opts: { sent?: boolean; status?: DecisionStatus } = {},
): Promise<ApprovalCheck> {
  const st: any = opts.status ?? await statusOf(cfg, decisionId);
  const state = typeof st?.state === "string" ? st.state : "";
  const serverReason = typeof st?.reason === "string" && st.reason ? st.reason : undefined;
  const no = (code: ApprovalCheckCode, reason?: string): ApprovalCheck => ({ ok: false, decisionId, state, code, ...(reason ? { reason } : {}) });
  const unanswered = state === "rejected" ? unansweredOf(st) : null;
  if (unanswered) return { ok: false, decisionId, state, code: "unanswered", reason: UNANSWERED_WORDS, deadline: unanswered.deadline };
  if (state === "rejected") return no("rejected", serverReason);
  if (state === "blocked") return no("blocked", serverReason);
  if (state === "pending") return no("pending", `Decidio records decision ${decisionId} as pending - no human has approved it`);
  if (state !== "approved" && state !== "auto_approved") return no("unrecognized_state", `Decidio answered state ${JSON.stringify(st?.state ?? null)} for decision ${decisionId}, which is not an approval this SDK recognises (an answer it does not understand is never permission)`);
  if (st?.spent === true) return no("spent", `decision ${decisionId} was approved once and that approval is already spent (an execution is recorded on it) - ask again for a fresh approval; nothing was executed`);
  if (typeof st?.grantExpiresAt === "string") {
    const until = Date.parse(st.grantExpiresAt);
    if (!Number.isFinite(until)) return no("unverifiable", `Decidio answered a malformed grant expiry for decision ${decisionId} (${JSON.stringify(st.grantExpiresAt)}), so the approval cannot be known to be in force`);
    if (until <= Date.now()) return no("expired", `decision ${decisionId}'s approval expired at ${st.grantExpiresAt} before anything ran - ask again for a fresh approval; nothing was executed`);
  } else if (typeof st?.spent === "boolean" && st?.grantExpiresAt === null) {
    return no("expired", `decision ${decisionId} is approved but Decidio names no expiry for its grant (its age is unknown) - ask again for a fresh approval; nothing was executed`);
  }
  const server = st?.requestCommitment;
  if (server !== undefined && server !== null) {
    if (typeof server !== "string" || !/^[0-9a-f]{64}$/.test(server)) return no("unverifiable", `Decidio answered a malformed request commitment for decision ${decisionId}, so the approval cannot be tied to this request`);
    let material: BindingMaterial | undefined;
    try { material = bindingMaterial(cfg); }
    catch (e: any) { return no("unverifiable", String(e?.message ?? e)); }
    if (!material) return no("unverifiable", `Decidio bound decision ${decisionId} to a request commitment, but this process has no key material to recompute it (DECIDIO_AGENT_KEY + DECIDIO_AGENT_DID, or DECIDIO_API_TOKEN) - restore the agent's environment`);
    let fresh: string;
    try { fresh = requestCommitment(material, request); }
    catch (e: any) { return no("unverifiable", `the request about to run could not be canonicalized for the commitment check (${e?.message ?? e})`); }
    const a = Buffer.from(fresh), b = Buffer.from(server);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return no("request_changed", `the request changed after approval: decision ${decisionId} was approved for a different request than the one about to run (or this agent's key material changed since it asked)`);
    }
    return { ok: true, decisionId, state };
  }
  if (opts.sent ?? !!((cfg.agentKey && cfg.agentDid) || cfg.apiToken)) {
    return no("commitment_missing", `Decidio answered for decision ${decisionId} without the request commitment this SDK sent, so it cannot confirm the approval covers THIS request - the gate predates request binding (upgrade the Decidio gate; nothing was executed)`);
  }
  return { ok: true, decisionId, state };
}

/** How long the SDK waits before each retry of a call it may safely repeat (11f): the authorize POST (with the same
 *  body, so the same request key) and the claim (with the same claim key). Bounded: two retries, then the failure is the
 *  caller's to see. Python twin: RETRY_DELAYS. */
export const RETRY_DELAYS_MS: readonly number[] = [300, 1_000];
/** The grammar the gate takes for a request key and a claim key alike. */
export const REQUEST_KEY_RE = /^[A-Za-z0-9._:-]{16,128}$/;

/** A claim key: RANDOM PER RUN (two workers with one key would be one run to Decidio, and both would run). The durable
 *  path makes one when it parks an action and keeps it there; the blocking wait and the OpenAI resume make one per call. */
export function newClaimKey(): string {
  return `run_${randomBytes(18).toString("base64url")}`;
}

/** Why a claim did not let this run go ahead. already_used / expired / not_claimable are Decidio's FINAL answers (409):
 *  this approval will never run here. not_found (404: no such decision for this credential, or a gate that predates
 *  claims), refused (any other 4xx), unreachable (a network failure or a 5xx after the retries) and unrecognized (an
 *  answer this SDK does not understand) may change - nothing ran, and a later try may succeed. */
export type ClaimCode = "already_used" | "expired" | "not_claimable" | "not_found" | "refused" | "unreachable" | "unrecognized";
/** The outcome of one claim. Plain JSON on purpose, like ApprovalCheck: an engine that must run HTTP in an activity
 *  (Temporal) returns it across its serialization boundary. */
export type ClaimOutcome =
  | { ok: true; decisionId: string; again: boolean; /** Decidio's signature over this claim, for the coding-agent hook (cli.ts verifyGateAnswer) */ gateAnswer?: unknown }
  | { ok: false; decisionId: string; code: ClaimCode; final: boolean; reason: string; status?: number };

/** COLLECT A PERSON'S APPROVAL FOR THIS RUN, ONCE (POST /agent/claim/:decisionId) - the step every door that RUNS on a
 *  person's approval takes right before it runs: the blocking wait, the durable resume, Temporal and the OpenAI resume. The
 *  first claim wins; the same key claiming again is the same run retrying (`again: true`); any other key is told the
 *  approval was already used. Reading the status claims nothing, so nothing that only watches ever calls this. An
 *  auto-approval is never claimed (it is never shared). Retried with the SAME key on a network failure or a 5xx; every
 *  answer other than a 200 that says `claimed: true` means DO NOT RUN. Never throws for an answer - a refusal is a value. */
export async function claimApproval(cfg: StatusConfig, decisionId: string, claimKey: string, guard?: { guardSession: string; guardChallenge: string }): Promise<ClaimOutcome> {
  const no = (code: ClaimCode, reason: string, status?: number): ClaimOutcome => ({ ok: false, decisionId, code, final: code === "already_used" || code === "expired" || code === "not_claimable", reason, ...(status !== undefined ? { status } : {}) });
  if (typeof claimKey !== "string" || !REQUEST_KEY_RE.test(claimKey)) return no("refused", "this run's claim key is not one Decidio accepts (16-128 letters, digits, dot, colon, underscore or dash). Nothing ran.");
  const f = cfg.fetchImpl ?? fetch;
  assertSafeTransport(cfg.apiUrl, carriesCredential(cfg));
  const url = cfg.apiUrl.replace(/\/$/, "") + "/agent/claim/" + encodeURIComponent(decisionId);
  let last = "";
  for (let attempt = 0; ; attempt++) {
    let res: Response | undefined;
    try {
      res = await f(url, { method: "POST", headers: { "content-type": "application/json", ...(cfg.apiToken ? { authorization: `Bearer ${cfg.apiToken}` } : {}) }, body: JSON.stringify({ claimKey, ...(guard ?? {}) }) });
    } catch (e: any) { last = `could not reach Decidio: ${e?.cause?.code ?? e?.code ?? e?.message ?? e}`; }
    if (res) {
      const body: any = await res.json().catch(() => null);
      if (res.status === 200) {
        if (body && body.ok === true && body.claimed === true) return { ok: true, decisionId, again: body.again === true, ...(guard && body.gateAnswer !== undefined ? { gateAnswer: body.gateAnswer } : {}) };
        return no("unrecognized", "Decidio answered the claim with HTTP 200 but did not say this run collected the approval, and an answer this SDK does not understand is never permission. Nothing ran.", 200);
      }
      if (res.status === 409) {
        const code = body?.code;
        if (code === "ALREADY_USED") return no("already_used", "this approval was already used by another run. Ask again for a new approval. Nothing ran.", 409);
        if (code === "EXPIRED") return no("expired", "this approval has expired. Ask again for a new approval. Nothing ran.", 409);
        if (code === "NOT_CLAIMABLE") return no("not_claimable", "Decidio says this approval can't be collected by a run (only a person's approval is, and a deploy approval belongs to its deploy job). Nothing ran.", 409);
        return no("unrecognized", `Decidio refused the claim with a code this SDK does not know (${JSON.stringify(code ?? null)}). Nothing ran.`, 409);
      }
      if (res.status === 404) return no("not_found", "Decidio did not let this agent collect the approval (HTTP 404: it does not know this decision for this credential, or it predates approval claims). Nothing ran.", 404);
      if (!(res.status === 429 || (res.status >= 500 && res.status !== 501))) return no("refused", `Decidio refused to let this run collect the approval (HTTP ${res.status}). Nothing ran.`, res.status);
      last = `HTTP ${res.status}`;
    }
    if (attempt >= RETRY_DELAYS_MS.length) return no("unreachable", `could not collect the approval from Decidio after ${attempt + 1} tries (${last}). Nothing ran.`);
    await sleep(RETRY_DELAYS_MS[attempt]!);
  }
}

const V2_STORE_METHODS = [
  "put", "get", "delete", "list",
  "claim", "markInvoking", "recordExecuted", "markIndeterminate", "markReported",
  "markDiscarded",
  "getExecution", "listExecutions", "releasePreinvoke", "settle",
] as const;

function assertStoreV2(store: PendingStore): void {
  const missing = V2_STORE_METHODS.filter((m) => typeof (store as any)[m] !== "function");
  if (!missing.length) return;
  throw new Error(
    `[decidio] this PendingStore is missing ${missing.length} required method${missing.length === 1 ? "" : "s"}: ${missing.join(", ")}.\n` +
    `  The durable execution state machine is MANDATORY (parked → claimed_preinvoke → invoking → executed_unreported | indeterminate → reported, plus the terminal "discarded" that a denial writes).\n` +
    `  The 0.1.x contract left claim() optional and fell back to a process-local guard, which cannot survive a restart — so it never carried the single-execution guarantee it appeared to. A store that cannot record that invocation BEGAN cannot prevent a committed action from running twice.\n` +
    `  Fix: implement the missing methods (see the PendingStore docs), or use the shipped FilePendingStore / MemoryPendingStore. Nothing was started.`,
  );
}

let reportDirWarned = false;

/** The webhook handlers' refusal when no webhook secret is configured - with the remedy. */
/** The one remedy every webhook-secret refusal names (#4B review W3): the dedicated webhook secret - NEVER the
 *  server's API_AUTH_TOKEN, the admin bearer, which a refusal that said "the value your deployment signs
 *  with" used to steer operators into copying onto agent hosts. */
export const WEBHOOK_SECRET_REMEDY = "Set webhookSecret (DECIDIO_WEBHOOK_SECRET) to the dedicated secret your Decidio deployment signs resume webhooks with - never the server's API_AUTH_TOKEN (its admin bearer, which must not be copied onto an agent host) - or use the poll worker (guard.worker()), which needs no inbound secret.";
const NO_WEBHOOK_SECRET = `resume webhook refused: no webhookSecret is configured (and allowUnsigned is off). Since 0.7.0 the API token is no longer accepted as the webhook key. ${WEBHOOK_SECRET_REMEDY}`;

function webhookBody(o: ResumeOutcome) {
  return {
    ok: true,
    outcome: {
      status: o.status, decisionId: o.decisionId,
      ...(o.reason ? { reason: o.reason } : {}),
      ...(o.reportRecorded !== undefined ? { reportRecorded: o.reportRecorded } : {}),
      ...(o.executionConfirmed !== undefined ? { executionConfirmed: o.executionConfirmed } : {}),
      ...(o.evidenceTier ? { evidenceTier: o.evidenceTier } : {}),
      ...(o.executionReportVerified !== undefined ? { executionReportVerified: o.executionReportVerified } : {}),
      ...(o.executionReportReason ? { executionReportReason: o.executionReportReason } : {}),
      ...(o.confirmationRetryable !== undefined ? { confirmationRetryable: o.confirmationRetryable } : {}),
      ...(o.reportJournalled !== undefined ? { reportJournalled: o.reportJournalled } : {}),
      ...(o.evidenceError ? { evidenceError: o.evidenceError } : {}),
      ...(o.diagnostic ? { diagnostic: o.diagnostic } : {}),
    },
  };
}

export function createDecidioResume(opts: ResumeConfig & { store: PendingStore }): ResumeController {
  assertStoreV2(opts.store);
  const registry = new Map<string, { fn: (...args: any[]) => Promise<any>; evidence?: (result: any) => unknown; withContext?: boolean }>();
  const secret = opts.webhookSecret ?? "";
  const integrityKey = (): string => ctrl.webhookSecret ?? ctrl.apiToken ?? "";
  let unsignedHandlerWarned = false;
  const warnIfNoWebhookKey = () => {
    if (secret || opts.allowUnsigned || unsignedHandlerWarned) return;
    unsignedHandlerWarned = true;
    console.warn(`[decidio] this resume webhook handler has no webhookSecret, so it will REFUSE every webhook (401).${opts.apiToken ? " Since 0.7.0 the API token is no longer accepted as the webhook key — a leaked agent token must not be able to sign an approval signal." : ""} ${WEBHOOK_SECRET_REMEDY}`);
  };
  if (opts.reportDir && !reportDirWarned) {
    reportDirWarned = true;
    console.warn(`[decidio] reportDir is ignored since 0.2.0 — execution evidence now lives in the PendingStore's own execution ledger, beside the state that makes a decision non-replayable. Reports written by 0.1.x under <pendingDir>/reports are migrated into that ledger on first use of a FilePendingStore, so nothing is lost; remove the option when convenient.`);
  }
  if (opts.allowUnsigned) console.warn("[decidio] WARNING: allowUnsigned is ON — this controller will accept UNSIGNED resume webhooks. Anyone who can reach the endpoint can signal work (parked-payload integrity still gates execution). Use this only behind a trusted network boundary, never on an internet-reachable endpoint.");
  async function reportAfterExecution(pending: PendingAction, decisionId: string, result: unknown, attemptId: string): Promise<ResumeOutcome> {
    const base = { status: "executed" as const, decisionId, action: pending.action, result };
    let reported: unknown;
    let haveReported = false;
    let buildProblem: string | undefined;
    const evidenceMapper = registry.get(pending.action)?.evidence ?? ctrl.evidence;
    try {
      reported = toCanonical((evidenceMapper ? evidenceMapper(result) : result) ?? null, "evidence(result)");
      haveReported = true;
    } catch (e: any) {
      buildProblem = `${e?.message ?? e}`;
      reported = null;
      haveReported = true;
    }
    let journalled = false;
    if (haveReported) {
      try { await ctrl.store.recordExecuted(decisionId, attemptId, reported, signEvidence(decisionId, attemptId, reported, ctrl.agentKey, integrityKey()), buildProblem); journalled = true; }
      catch (e: any) {
        if (e instanceof DecidioStaleAttemptError) {
          console.warn(`[decidio] ${decisionId}: this action finished, but the decision is now owned by a newer attempt — it was released for retry while this one was still running. This attempt's report is NOT being sent; the owning attempt reports. Your action DID run: if that means it ran twice, the release was premature.`);
          try { await ctrl.store.delete(decisionId, attemptId); } catch { }
          return { ...base, reportRecorded: false, executionConfirmed: false, confirmationRetryable: false, reportJournalled: false, diagnostic: `${decisionId} was released to a newer attempt while this one was running; this attempt's report was not sent. If your action is not idempotent, note that it has now run more than once.` };
        }
        if (e instanceof DecidioAlreadySettledError) {
          console.warn(`[decidio] ${decisionId}: this action finished, but an operator had already reconciled the decision as committed and Decidio has that report. This attempt's own report is NOT being sent — one decision, one report. If your result differs from what was reconciled, correct it in Decidio; do NOT re-run the action.`);
          try { await ctrl.store.delete(decisionId, attemptId); } catch { }
          return { ...base, reportRecorded: true, executionConfirmed: false, reportJournalled: true, diagnostic: `an operator settled ${decisionId} as committed while this attempt was running; their report stands and this one was not sent.` };
        }
        if (e instanceof DecidioDeniedError) {
          console.error(`[decidio] ${decisionId}: this decision is DENIED, so no execution report will be sent. If your action nevertheless ran, your store let a refused decision reach the handler — treat that as a defect in the store, and correct the downstream effect by hand.`);
          return { ...base, reportRecorded: false, executionConfirmed: false, confirmationRetryable: false, reportJournalled: false, diagnostic: `${decisionId} is denied; no report was sent.` };
        }
        console.error(`[decidio] ${decisionId}: the action RAN but its execution report could NOT be recorded (${e?.message ?? e}). If the report also fails to send, this execution is NOT locally recoverable — record the outcome from your own system.`);
      }
    }
    let confirmRequest: Record<string, unknown> | undefined;
    try { confirmRequest = buildResumeConfirmRequest(ctrl, decisionId, reported); } catch { confirmRequest = undefined; }
    const deletePending = async () => {
      try { await ctrl.store.delete(decisionId, attemptId); }
      catch (e: any) { console.warn(`[decidio] ${decisionId}: the parked payload could not be removed (${e?.message ?? e}). This is cleanup only — the execution ledger already records this decision as executed, so no process can run it again; remove the row at your convenience.`); }
    };
    if (!confirmRequest) {
      await deletePending();
      const diagnostic = `"${pending.action}" EXECUTED, but no execution report could be built (${buildProblem ?? "unknown"}). Nothing will re-run it. ` + (journalled
        ? `The reported value IS recorded, so fix the agent's signing config (DECIDIO_AGENT_KEY/DID) and re-send it with reconfirm("${decisionId}").`
        : `The reported value could not be recorded either, so nothing here can re-send it — record the outcome from your own system.`);
      console.warn(`[decidio] ${decisionId}: ${diagnostic}`);
      return { ...base, reportRecorded: false, executionConfirmed: false, confirmationRetryable: false, reportJournalled: journalled, ...(buildProblem ? { evidenceError: buildProblem } : {}), diagnostic };
    }
    await deletePending();
    let ev: EvidenceOutcome;
    try { ev = await postConfirm(ctrl, decisionId, confirmRequest, journalled); }
    catch (e: any) {
      ev = {
        reportRecorded: false, executionConfirmed: false,
        diagnostic: journalled
          ? `the execution report did not reach Decidio (${e?.message ?? e}). Your action DID run and the report is journalled - re-send it with reconfirm("${decisionId}").`
          : `the execution report did not reach Decidio (${e?.message ?? e}) AND could not be journalled locally, so nothing here can re-send it. Your action DID run - record the outcome from your own system.`,
      };
    }
    if (ev.reportRecorded) await ctrl.store.markReported(decisionId, attemptId, tombstoneTier(ev)).catch(() => { });
    const diagnostic = buildProblem
      ? `${ev.diagnostic ? ev.diagnostic + " " : ""}Also: the action's return value was not reportable (${buildProblem}), so an empty response was reported - map it with the \`evidence\` option to earn a confirming tier.`
      : ev.diagnostic;
    if (!ev.reportRecorded) console.warn(`[decidio] ${decisionId}: ${diagnostic}`);
    else if (!ev.executionConfirmed || ev.executionReportVerified === false) console.warn(`[decidio] execution evidence for ${decisionId} recorded as ${ev.evidenceTier} - ${diagnostic}`);
    return { ...base, reportRecorded: ev.reportRecorded, executionConfirmed: ev.executionConfirmed, ...(ev.evidenceTier ? { evidenceTier: ev.evidenceTier } : {}), ...(ev.executionReportVerified !== undefined ? { executionReportVerified: ev.executionReportVerified } : {}), ...(ev.executionReportReason ? { executionReportReason: ev.executionReportReason } : {}), ...(ev.confirmationRetryable !== undefined ? { confirmationRetryable: ev.confirmationRetryable } : {}), reportJournalled: journalled, ...(buildProblem ? { evidenceError: buildProblem } : {}), ...(diagnostic ? { diagnostic } : {}) };
  }

  const refusalWarned = new Set<string>();
  const refuseOnce = (decisionId: string, msg: string, tail?: string) => {
    if (refusalWarned.has(decisionId)) return;
    refusalWarned.add(decisionId);
    console.error(msg + (tail ?? " (This prints once per worker process — the entry stays parked until you act.)"));
  };

  async function resolveCore({ decisionId, verdict, reason }: { decisionId: string; verdict: string; reason?: string }, prefetched?: DecisionStatus): Promise<ResumeOutcome> {
    const finish = (o: ResumeOutcome): ResumeOutcome => { if (o.status !== "unknown") opts.onResolved?.(o); return o; };
    const idProblem = decisionIdProblem(decisionId);
    if (idProblem) return { status: "unknown", decisionId: String(decisionId ?? ""), reason: `not a decision id this SDK will act on (${idProblem})` };
    const pending = await ctrl.store.get(decisionId);
    if (!pending) {
      const mapped = outcomeFromHead(await ctrl.store.getExecution(decisionId), decisionId);
      if (mapped) return finish(mapped);
      return { status: "unknown", decisionId };
    }
    if (verdict === "rejected" && unansweredOf(prefetched)) {
      await ctrl.store.markDiscarded(decisionId, "rejected", UNANSWERED_WORDS);
      await ctrl.store.delete(decisionId);
      return finish({ status: "unanswered", decisionId, action: pending.action, reason: UNANSWERED_WORDS });
    }
    if (verdict === "rejected" || verdict === "blocked") {
      await ctrl.store.markDiscarded(decisionId, verdict, reason);
      await ctrl.store.delete(decisionId);
      return finish({ status: verdict, decisionId, action: pending.action, reason });
    }
    if (verdict !== "approved" && verdict !== "auto_approved") return { status: "unknown", decisionId };
    if (pending.decisionId !== decisionId) {
      refuseOnce(decisionId, `[decidio] REFUSING to execute ${decisionId}: the parked entry in this slot belongs to a DIFFERENT decision (${pending.decisionId}) — the pending file was moved or swapped. Delete it and re-run the action.`);
      return finish({ status: "no_handler", decisionId, action: pending.action, reason: "parked payload decision-id mismatch" });
    }
    const strictBinding = !!ctrl.agentKey;
    const integrity = verifyArgs(pending, ctrl.agentKey, integrityKey());
    if (integrity === "mismatch") {
      refuseOnce(decisionId, `[decidio] REFUSING to execute ${decisionId}: the parked payload FAILED its integrity check — the arguments on disk are not the arguments that were routed for approval. The pending file is untouched for inspection; delete it and re-run the action to request a fresh approval.`);
      return finish({ status: "no_handler", decisionId, action: pending.action, reason: "parked payload integrity check failed" });
    }
    if (integrity === "unverifiable") {
      refuseOnce(decisionId, `[decidio] REFUSING to execute ${decisionId}: the parked payload is signed but this process lacks the key material to verify it (DECIDIO_AGENT_KEY / DECIDIO_WEBHOOK_SECRET). Restore the agent's env and retry.`);
      return finish({ status: "no_handler", decisionId, action: pending.action, reason: "parked payload unverifiable" });
    }
    if (integrity === "unbound" && strictBinding) {
      refuseOnce(decisionId, `[decidio] REFUSING to execute ${decisionId}: the parked payload has NO integrity signature, but this agent has keys and would have signed it — a missing signature means the file was tampered with. Delete it and re-run the action.`);
      return finish({ status: "no_handler", decisionId, action: pending.action, reason: "parked payload unsigned (expected a signature)" });
    }
    if (integrity === "unbound") console.warn(`[decidio] executing ${decisionId} from an UNBOUND parked entry (this agent has no key material to bind or verify payloads) — its arguments cannot be integrity-checked. Run \`npx @decidio/sdk init\` to enable binding.`);
    const fn = registry.get(pending.action)?.fn;
    if (!fn) {
      console.error(`[decidio] cannot resume ${decisionId}: no function is registered for action "${pending.action}" in THIS process.`);
      console.error(`  A worker only re-executes actions registered where it runs. At startup, either declare the action on the wrapper:`);
      console.error(`      const doIt = guard.protect(doItRaw, describe, { action: "${pending.action}" });`);
      console.error(`  or register the raw function directly:`);
      console.error(`      guard.register("${pending.action}", doItRaw);`);
      console.error(`  then start the worker. The approved action stays parked until then — nothing is lost.`);
      return finish({ status: "no_handler", decisionId, action: pending.action, reason: `no fn registered for action "${pending.action}" in this process — declare { action } on protect(), or call guard.register("${pending.action}", fn) at startup` });
    }
    const attemptId = randomUUID();
    const claim = await ctrl.store.claim(decisionId, attemptId);
    if (!claim.ok) {
      if (claim.state && NON_REPLAYABLE.includes(claim.state)) {
        refuseOnce(decisionId, claim.state === "discarded"
          ? `[decidio] REFUSING to execute ${decisionId}: it was DENIED (${(await ctrl.store.getExecution(decisionId))?.verdict ?? "rejected"}) and that answer is final. Nothing ran. A denial cannot be reconciled or retried — if this action should now proceed, it needs a NEW request and a new approval.`
          : `[decidio] REFUSING to execute ${decisionId}: its durable state is ${claim.state} — invocation already began, so re-running it could duplicate a committed effect. Inspect it with guard.resume.recover(); settle it with guard.resume.reconcile("${decisionId}", …).`,
          claim.state === "discarded" ? " (This prints once per worker process. The decision is closed — no action is needed.)" : undefined);
        if (claim.state === "invoking" || claim.state === "indeterminate") {
          return finish({ status: "indeterminate", decisionId, action: pending.action, reason: claim.state === "invoking"
            ? `this decision is in durable state invoking: its action may still be running, may have crashed before any effect, or may have finished without reporting - it may or may not have run. Nothing will retry it; check the worker and the downstream system, then settle it with reconcile("${decisionId}", …).`
            : claim.reason });
        }
        return finish({ status: "already_resolved", decisionId, action: pending.action, reason: claim.state === "discarded" ? `this decision was already DENIED (${(await ctrl.store.getExecution(decisionId))?.verdict ?? "rejected"}); that answer is final and this signal lost the race to it` : `this decision already ran (durable state ${claim.state}); this signal lost the race to it` });
      }
      const mapped = outcomeFromHead(await ctrl.store.getExecution(decisionId), decisionId, pending.action);
      if (mapped) return finish(mapped);
      return finish({ status: "lost_race", decisionId, action: pending.action, reason: `another attempt holds the pre-invocation claim on this decision${claim.state ? ` (durable state ${claim.state})` : ""}; this signal lost the race and did nothing. If that attempt is alive it will report; if it died, recover() lists the decision and reconcile() can settle it` });
    }

    let check: ApprovalCheck;
    try {
      check = await checkApproval(ctrl, decisionId,
        { action: pending.action, amount: pending.amount, ...(pending.scope !== undefined ? { scope: pending.scope } : {}), args: pending.args },
        { sent: !!pending.requestCommitment, ...(prefetched ? { status: prefetched } : {}) });
    } catch (e) {
      await ctrl.store.releasePreinvoke(decisionId, attemptId).catch(() => {});
      throw e;
    }
    if (!check.ok) {
      if (check.code === "unanswered") {
        await ctrl.store.markDiscarded(decisionId, "rejected", UNANSWERED_WORDS);
        await ctrl.store.delete(decisionId);
        return finish({ status: "unanswered", decisionId, action: pending.action, reason: UNANSWERED_WORDS });
      }
      if (check.code === "rejected" || check.code === "blocked") {
        await ctrl.store.markDiscarded(decisionId, check.code, check.reason);
        await ctrl.store.delete(decisionId);
        return finish({ status: check.code, decisionId, action: pending.action, ...(check.reason ? { reason: check.reason } : {}) });
      }
      await ctrl.store.releasePreinvoke(decisionId, attemptId).catch(() => {});
      if (check.code === "pending" || check.code === "unrecognized_state") {
        return { status: "not_approved", decisionId, action: pending.action, reason: `${check.reason}. This signal was a wake-up, not an approval: nothing ran, and the entry stays parked for the real answer.` };
      }
      refuseOnce(decisionId, `[decidio] REFUSING to execute ${decisionId}: ${check.reason}. Nothing ran; the parked entry is untouched for inspection. If the request really changed, reject this decision and re-run the action to request a fresh approval.`);
      return finish({ status: "request_unverified", decisionId, action: pending.action, reason: check.reason });
    }

    if (check.state === "approved") {
      let claimed: ClaimOutcome;
      try { claimed = await claimApproval(ctrl, decisionId, pending.claimKey ?? newClaimKey()); }
      catch (e) { await ctrl.store.releasePreinvoke(decisionId, attemptId).catch(() => {}); throw e; }
      if (!claimed.ok) {
        if (claimed.final) {
          await ctrl.store.markDiscarded(decisionId, "blocked", claimed.reason);
          await ctrl.store.delete(decisionId);
          return finish({ status: "blocked", decisionId, action: pending.action, reason: claimed.reason });
        }
        await ctrl.store.releasePreinvoke(decisionId, attemptId).catch(() => {});
        throw new Error(`[decidio] ${decisionId}: ${claimed.reason} The entry stays parked; the next signal tries again with the same claim key.`);
      }
    }

    try { await ctrl.store.markInvoking(decisionId, attemptId); }
    catch (e: any) {
      await ctrl.store.releasePreinvoke(decisionId, attemptId).catch(() => {});
      console.error(`[decidio] ${decisionId}: could not record the invocation boundary (${e?.message ?? e}) — refusing to run the action rather than run it unrecorded.`);
      const mapped = outcomeFromHead(await ctrl.store.getExecution(decisionId), decisionId, pending.action);
      if (mapped) return finish(mapped);
      return finish({ status: "lost_race", decisionId, action: pending.action, reason: `could not durably record the invocation boundary (${e?.message ?? e}); nothing ran, the entry stays parked, and a later signal may retry` });
    }

    let result: unknown;
    try {
      const entry = registry.get(pending.action);
      result = entry?.withContext
        ? await fn({ decisionId, attemptId, idempotencyKey: decisionId } satisfies ExecutionContext, ...(pending.args as any[]))
        : await fn(...(pending.args as any[]));
    } catch (e: any) {
      const why = String(e?.message ?? e);
      await ctrl.store.markIndeterminate(decisionId, attemptId, why).catch((se: any) =>
        console.error(`[decidio] ${decisionId}: could not record INDETERMINATE (${se?.message ?? se}) — treat this decision as possibly executed.`));
      console.error(`[decidio] ${decisionId}: "${pending.action}" was INVOKED and then threw (${why}). Whether the downstream effect committed is not knowable from here, so it will NOT be retried automatically. Check the downstream system, then: guard.resume.reconcile("${decisionId}", { outcome: "committed", evidence: … }) or { outcome: "not_committed", reason: … }.`);
      return finish({ status: "indeterminate", decisionId, action: pending.action, reason: why });
    }
    return finish(await reportAfterExecution(pending, decisionId, result, attemptId));
  }

  async function wake(decisionId: unknown): Promise<ResumeOutcome> {
    const idProblem = decisionIdProblem(decisionId);
    if (idProblem) return { status: "unknown", decisionId: String(decisionId ?? ""), reason: `not a decision id this SDK will act on (${idProblem})` };
    const id = decisionId as string;
    const pending = await ctrl.store.get(id);
    if (!pending) return resolveCore({ decisionId: id, verdict: "approved" });
    const st = await statusOf(ctrl, id);
    const state = typeof st?.state === "string" ? st.state : "";
    const reason = typeof st?.reason === "string" && st.reason ? st.reason : undefined;
    if (state === "approved" || state === "auto_approved") return resolveCore({ decisionId: id, verdict: "approved" }, st);
    if (state === "rejected" || state === "blocked") return resolveCore({ decisionId: id, verdict: state, ...(reason ? { reason } : {}) }, st);
    return { status: "not_approved", decisionId: id, action: pending.action, reason: `Decidio records decision ${id} as ${JSON.stringify(state || null)}; a webhook is a wake-up, not an approval, so nothing ran and the entry stays parked` };
  }

  const ctrl: ResumeController = {
    ...opts,
    agentId: opts.agentId ?? process.env.DECIDIO_AGENT_ID,
    agentKey: opts.agentKey ?? process.env.DECIDIO_AGENT_KEY,
    agentDid: opts.agentDid ?? process.env.DECIDIO_AGENT_DID,
    workspaceId: opts.workspaceId ?? process.env.DECIDIO_WORKSPACE_ID,
    webhookSecret: opts.webhookSecret,
    store: opts.store,

    register(action, fn, evidence, withContext) {
      const prev = registry.get(action);
      if (prev && prev.fn !== fn) console.warn(`[decidio] action "${action}" is being registered again with a DIFFERENT function — the latest one wins, and a resumed decision would run IT. Give each protected function its own action name.`);
      if (prev && prev.evidence && evidence && prev.evidence !== evidence) console.warn(`[decidio] action "${action}" is being registered again with a DIFFERENT evidence mapper — the latest one wins, and a resumed decision's record would carry ITS output. Give each protected function its own action name.`);
      registry.set(action, { fn, evidence: evidence ?? prev?.evidence, withContext: withContext ?? prev?.withContext });
    },

    async park(p) {
      const idProblem = decisionIdProblem(p.decisionId);
      if (idProblem) throw new DecidioUnsafeArgumentsError(`[decidio] refusing to park ${JSON.stringify(p.decisionId ?? null)}: it is not a decision id this SDK will act on (${idProblem}). Nothing was parked and nothing will execute - a decision id comes from the gate's answer, verbatim.`, typeof p.decisionId === "string" ? p.decisionId : "");
      try { toCanonical(p.args, "args"); }
      catch (e: any) {
        throw new DecidioUnsafeArgumentsError(`${e?.message ?? e} NOT parked and NOT executable — but decision ${p.decisionId} may already be routed; reject it in your queue: npx @decidio/sdk approvals reject ${p.decisionId}`, p.decisionId);
      }
      const parked = { ...p, claimKey: p.claimKey ?? newClaimKey() };
      const argsSig = signArgs(parked, ctrl.agentKey, integrityKey());
      if (!argsSig) console.warn(`[decidio] parking ${p.decisionId} UNBOUND — no agent key or webhook secret to sign the payload with, so a modified pending file could not be detected. Run \`npx @decidio/sdk init\` to configure keys.`);
      await ctrl.store.put({ ...parked, createdAt: new Date().toISOString(), ...(argsSig ? { argsSig } : {}) });
    },

    async resolve(input) { return resolveCore(input); },

    webhookHandler(): RequestListener {
      warnIfNoWebhookKey();
      return (req: IncomingMessage, res: ServerResponse) => {
        if (req.method !== "POST") { res.statusCode = 405; return res.end("method not allowed"); }
        let raw = "";
        req.on("data", (c) => (raw += c));
        req.on("end", async () => {
          try {
            if (!secret) {
              if (!opts.allowUnsigned) { res.statusCode = 401; return res.end(JSON.stringify({ error: NO_WEBHOOK_SECRET })); }
            } else if (!verifyResumeSignature(secret, raw, req.headers["x-decidio-signature"] as string | undefined)) {
              res.statusCode = 401; return res.end(JSON.stringify({ error: "bad signature" }));
            }
            const body = JSON.parse(raw || "{}");
            const outcome = await wake(body.decisionId);
            res.statusCode = 200; res.setHeader("content-type", "application/json");
            res.end(JSON.stringify(webhookBody(outcome)));
          } catch (e: any) {
            res.statusCode = 500; res.end(JSON.stringify({ error: e instanceof DecidioStateCorruptError ? "DecidioStateCorruptError" : "resume failed", message: e?.message ?? String(e) }));
          }
        });
      };
    },

    fetchHandler() {
      warnIfNoWebhookKey();
      return async (req: Request): Promise<Response> => {
        if (req.method !== "POST") return new Response("method not allowed", { status: 405 });
        const raw = await req.text();
        if (!secret) {
          if (!opts.allowUnsigned) return new Response(JSON.stringify({ error: NO_WEBHOOK_SECRET }), { status: 401 });
        } else if (!verifyResumeSignature(secret, raw, req.headers.get("x-decidio-signature") ?? undefined)) {
          return new Response(JSON.stringify({ error: "bad signature" }), { status: 401 });
        }
        try {
          const body = JSON.parse(raw || "{}");
          const outcome = await wake(body.decisionId);
          return new Response(JSON.stringify(webhookBody(outcome)), { status: 200, headers: { "content-type": "application/json" } });
        } catch (e: any) {
          return new Response(JSON.stringify({ error: e instanceof DecidioStateCorruptError ? "DecidioStateCorruptError" : "resume failed", message: e?.message ?? String(e) }), { status: 500 });
        }
      };
    },

    async reconcile(decisionId, opts) {
      const idProblem = decisionIdProblem(decisionId);
      if (idProblem) return { reportRecorded: false, executionConfirmed: false, diagnostic: `${JSON.stringify(decisionId ?? null)} is not a decision id this SDK will act on (${idProblem}). Nothing was settled.` };
      let entry: ExecutionRecord | null;
      try { entry = await ctrl.store.getExecution(decisionId); }
      catch (e: any) {
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `the durable state for ${decisionId} could not be read (${e?.message ?? e}). Refusing to settle a decision whose state is unknown — inspect the store first.` };
      }
      if (!entry) {
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `nothing is recorded for ${decisionId} in this store, so there is nothing to reconcile. Check the decision id, or the store this worker is configured with.` };
      }
      let settleEvidence: unknown;
      try { settleEvidence = opts.outcome === "committed" ? toCanonical(opts.evidence ?? null, "reconcile(evidence)") : null; }
      catch (e: any) {
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `the evidence you passed to reconcile("${decisionId}") is not reportable as-is (${e?.message ?? e}). Nothing was settled. Pass plain JSON — the same rule your action's return value follows.` };
      }
      const settleSig = opts.outcome === "committed"
        ? signEvidence(decisionId, entry.attemptId ?? null, settleEvidence, ctrl.agentKey, integrityKey())
        : undefined;
      try { await ctrl.store.settle(decisionId, opts.outcome, { evidence: settleEvidence, reason: opts.reason, evidenceSig: settleSig, workerStopped: opts.workerStopped }); }
      catch (e: any) {
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `${e?.message ?? e}` };
      }
      if (opts.outcome !== "committed") {
        console.warn(`[decidio] ${decisionId}: released for one more attempt on your assertion that nothing committed${opts.reason ? ` (${opts.reason})` : ""}. The next resume signal will run it.`);
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `${decisionId} is parked again and may run once more. Nothing was reported, because on your account nothing executed.` };
      }
      let request: Record<string, unknown>;
      try { request = buildResumeConfirmRequest(ctrl, decisionId, settleEvidence); }
      catch (e: any) {
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `the reconciled report for ${decisionId} could not be signed (${e?.message ?? e}). The evidence IS recorded locally — fix the agent's signing config (DECIDIO_AGENT_KEY/DID) and re-send it with reconfirm("${decisionId}").` };
      }
      let ev: EvidenceOutcome;
      try { ev = await postConfirm(ctrl, decisionId, request); }
      catch (e: any) {
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `the reconciled report for ${decisionId} did not reach Decidio (${e?.message ?? e}). The evidence IS recorded locally — call reconfirm("${decisionId}") when the service is healthy. Do NOT re-run the action.` };
      }
      if (ev.reportRecorded) await ctrl.store.markReported(decisionId, entry.attemptId ?? "reconcile", tombstoneTier(ev)).catch(() => { });
      return {
        ...ev,
        diagnostic: `${ev.diagnostic ? `${ev.diagnostic} ` : ""}This report was RECONCILED BY AN OPERATOR${opts.reason ? ` (${opts.reason})` : ""}, not observed by the SDK: its tier reflects the evidence you supplied, not a return value this process saw.`,
      };
    },

    async reconfirm(decisionId, opts) {
      const idProblem = decisionIdProblem(decisionId);
      if (idProblem) return { reportRecorded: false, executionConfirmed: false, diagnostic: `${JSON.stringify(decisionId ?? null)} is not a decision id this SDK will act on (${idProblem}). Nothing was sent.` };
      let entry: ExecutionRecord | null;
      try { entry = await ctrl.store.getExecution(decisionId); }
      catch (e: any) {
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `the durable state for ${decisionId} could not be read (${e?.message ?? e}). Refusing to guess whether it executed — inspect the store; do NOT re-run the action to find out.` };
      }
      if (entry?.state === "reported") {
        const confirmed = tierConfirms(entry.confirmation);
        return { reportRecorded: true, executionConfirmed: confirmed, evidenceTier: entry.confirmation as EvidenceTier | undefined, diagnostic: `${decisionId} was already reported (${entry.confirmation ?? "recorded"}${confirmed ? ", a confirming tier" : ", not a confirming tier"}) — nothing to re-send.` };
      }
      if (entry?.state === "indeterminate") {
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `${decisionId} is INDETERMINATE: it was invoked and its outcome is unknown, so there is no captured result to re-send. Settle it with reconcile("${decisionId}", …) once you have checked the downstream system.` };
      }
      if (entry?.state === "discarded") {
        return {
          reportRecorded: false, executionConfirmed: false,
          diagnostic: entry.executionDespiteDenial
            ? `${decisionId} was DENIED (${entry.verdict ?? "rejected"}), and this store ALSO holds an execution marker for it (${entry.executionDespiteDenial.state} at ${entry.executionDespiteDenial.at}). A denial is terminal, so no report will be sent for it — but something may have run. Check the downstream system and correct it there; do NOT re-run the action.`
            : `${decisionId} was DENIED (${entry.verdict ?? "rejected"}) and nothing ran, so there is no execution report to send. A denial cannot be reconciled or retried.`,
        };
      }
      if (!entry || !entry.hasEvidence) {
        return {
          reportRecorded: false, executionConfirmed: false,
          diagnostic: `nothing is recorded for ${decisionId}: either its report was already recorded (nothing to do) or this process never executed it. Check the record in Decidio — do NOT re-run the action to find out.`,
        };
      }
      const evStrict = !!ctrl.agentKey;
      const evStatus = verifyEvidence(entry, ctrl.agentKey, integrityKey());
      if (evStatus === "mismatch") {
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `the recorded evidence for ${decisionId} does not match its integrity binding — it was altered after this agent wrote it. REFUSING to attest it. Inspect the pending store; if you know the true outcome, settle it with reconcile("${decisionId}", …).` };
      }
      if (evStatus !== "ok" && evStrict && !opts?.acceptUnbound) {
        const why = entry.migratedFrom
          ? `it was migrated from ${entry.migratedFrom}, which predates evidence binding — that is expected, and it is why this call has an override`
          : `this agent signs its evidence, so a record without a usable binding did not come from this agent`;
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `the recorded evidence for ${decisionId} carries ${evStatus === "unbound" ? "NO integrity binding" : "a binding this agent's key cannot verify"} (${why}). REFUSING to attest it by default. If you have checked what this row claims and want it sent anyway: reconfirm("${decisionId}", { acceptUnbound: true }). If you do not trust it, settle the decision instead: reconcile("${decisionId}", …).` };
      }
      if (evStatus !== "ok" && evStrict) console.warn(`[decidio] ${decisionId}: attesting evidence with ${evStatus === "unbound" ? "NO integrity binding" : "an unverifiable binding"} because acceptUnbound was passed${entry.migratedFrom ? ` (row migrated from ${entry.migratedFrom})` : ""}. You are vouching for this row; the agent's signature will say it came from here.`);
      if (evStatus !== "ok") console.warn(`[decidio] ${decisionId}: re-sending an execution report whose evidence is ${evStatus === "unbound" ? "UNBOUND (written without agent key material, so it cannot be integrity-checked)" : "UNVERIFIABLE with this agent's current key material"}${entry.migratedFrom ? ` — it was migrated from ${entry.migratedFrom}, which predates evidence binding` : ""}. Run \`npx @decidio/sdk init\` to enable binding.`);
      let request: Record<string, unknown>;
      try { request = buildResumeConfirmRequest(ctrl, decisionId, entry.evidence); }
      catch (e: any) {
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `the journalled report for ${decisionId} could not be re-signed (${e?.message ?? e}). The entry is kept; fix the agent's signing config (DECIDIO_AGENT_KEY/DID) and retry.` };
      }
      let ev: EvidenceOutcome;
      try { ev = await postConfirm(ctrl, decisionId, request); }
      catch (e: any) {
        return { reportRecorded: false, executionConfirmed: false, diagnostic: `the execution report for ${decisionId} still did not reach Decidio (${e?.message ?? e}). The recorded evidence is KEPT — call reconfirm("${decisionId}") again when the service is healthy. Your action already ran; do NOT re-run it.` };
      }
      if (ev.reportRecorded) await ctrl.store.markReported(decisionId, entry.attemptId ?? "reconfirm", tombstoneTier(ev)).catch(() => { });
      return ev;
    },

    async recover() {
      const items: RecoveryItem[] = [];
      let execs: ExecutionRecord[];
      try { execs = await ctrl.store.listExecutions(); }
      catch (e: any) { throw new DecidioRecoveryUnavailableError(e); }
      for (const r of execs) {
        const a = r.action ?? "(unknown action)";
        switch (r.state) {
          case "executed_unreported":
            items.push({ decisionId: r.decisionId, action: r.action, state: "executed_unreported",
              guidance: `"${a}" executed at ${r.at} and its execution report has not been recorded. Re-send it safely: guard.resume.reconfirm("${r.decisionId}") — this replays the saved report and cannot re-run the action.` });
            break;
          case "indeterminate":
            items.push({ decisionId: r.decisionId, action: r.action, state: "indeterminate",
              guidance: `"${a}" was INVOKED and its outcome is unknown${r.error ? ` (${r.error})` : ""}. It will NOT be retried automatically. Check the downstream system, then settle it: guard.resume.reconcile("${r.decisionId}", { outcome: "committed", evidence: … }) or { outcome: "not_committed", reason: … }.` });
            break;
          case "invoking":
            items.push({ decisionId: r.decisionId, action: r.action, state: "indeterminate",
              guidance: `"${a}" was invoked at ${r.at} by attempt ${r.attemptId ?? "(unknown)"} and no outcome has been recorded since. That does NOT mean the worker died — it may still be running this action. It will not be retried automatically. Check that worker first: if it is gone, settle it with { outcome: "committed", evidence: … } once you have checked the downstream system, or release it with { outcome: "not_committed", reason: …, workerStopped: true }.` });
            break;
          case "claimed_preinvoke":
            items.push({ decisionId: r.decisionId, action: r.action, state: "claimed_stalled",
              guidance: `"${a}" was claimed at ${r.at} by attempt ${r.attemptId ?? "(unknown)"} which never reached the invocation boundary — the handler provably did not run, and nothing will retry it on its own. Release it: guard.resume.reconcile("${r.decisionId}", { outcome: "not_committed", reason: "claimed but never invoked" }).` });
            break;
          case "parked":
            if (!(await ctrl.store.get(r.decisionId))) {
              items.push({ decisionId: r.decisionId, action: r.action, state: "orphaned_state", guidance: `"${a}" is recorded as parked but its payload is gone, so nothing can execute it — an orphaned row (usually a legacy denial whose state was never written), not work awaiting a human. Nothing will run. It needs no action; remove its revision files if you want the listing clean.` });
            } else {
              items.push({ decisionId: r.decisionId, action: r.action, state: "parked", guidance: `"${a}" is parked awaiting a human decision. Nothing has executed.` });
            }
            break;
          case "discarded":
            if (r.executionDespiteDenial) {
              items.push({ decisionId: r.decisionId, action: r.action, state: "denied_with_evidence",
                guidance: `"${a}" was DENIED (${r.verdict ?? "rejected"})${r.discardReason ? ` — ${r.discardReason}` : ""}, but this store also holds an execution marker for it (${r.executionDespiteDenial.state} at ${r.executionDespiteDenial.at}${r.executionDespiteDenial.hasEvidence ? ", with a captured result" : ""}). Nothing will run it and nothing will report it — a denial is terminal and cannot be reconciled. CHECK THE DOWNSTREAM SYSTEM: if the action really ran, correct it there.` });
            }
            break;
          case "reported":
            break;
        }
      }
      return items;
    },

    worker(workerOpts) {
      const corruptWarned = new Set<string>();
      let listWarned = false;
      const interval = workerOpts?.intervalMs ?? 2_500;
      const deadline = workerOpts?.timeoutMs ? Date.now() + workerOpts.timeoutMs : Infinity;
      let stopped = false;
      (async () => {
        while (!stopped) {
          let pendings: PendingAction[] = [];
          try { pendings = await ctrl.store.list(); }
          catch (e: any) {
            if (!listWarned) { listWarned = true; console.error(`[decidio] the durable store could not be listed (${e?.message ?? e}) — this worker resumes nothing until it can be read again.`); }
          }
          for (const p of pendings) {
            let st: DecisionStatus;
            try { st = await statusOf(ctrl, p.decisionId); } catch { continue; }
            const verdict =
              st.state === "approved" || st.state === "auto_approved" ? "approved" :
              st.state === "rejected" ? "rejected" :
              st.state === "blocked" ? "blocked" : null;
            if (!verdict) continue;
            try {
              let outcome: ResumeOutcome;
              try { outcome = await resolveCore({ decisionId: p.decisionId, verdict, ...(typeof st.reason === "string" && st.reason ? { reason: st.reason } : {}) }, st); }
              catch (e) {
                if (e instanceof DecidioStateCorruptError) {
                  if (!corruptWarned.has(p.decisionId)) { corruptWarned.add(p.decisionId); console.error(`[decidio] LEDGER CORRUPT for ${p.decisionId}: ${e.message} — this worker will not touch it until the ledger is repaired; the other parked actions still resume.`); }
                  continue;
                }
                throw e;
              }
              if (outcome.status === "executed" && outcome.reportRecorded) console.error(`[decidio] resumed ${p.decisionId}: approved → "${p.action}" executed; evidence recorded as ${outcome.evidenceTier}${outcome.executionConfirmed ? "" : " (execution NOT confirmed — see the warning above)"}.`);
              else if (outcome.status === "executed") console.error(`[decidio] resumed ${p.decisionId}: approved → "${p.action}" executed, but its execution report did NOT reach Decidio — recover with: guard.resume.reconfirm("${p.decisionId}")`);
              else if (outcome.status === "rejected") console.error(`[decidio] resumed ${p.decisionId}: REJECTED — the parked "${p.action}" was discarded, nothing executed.`);
              else if (outcome.status === "unanswered") console.error(`[decidio] resumed ${p.decisionId}: UNANSWERED — nobody decided it by its deadline, so no authority was granted; the parked "${p.action}" was discarded, nothing executed. Ask again if it is still needed.`);
              else if (outcome.status === "blocked") console.error(`[decidio] resumed ${p.decisionId}: BLOCKED ${outcome.reason ? `(${outcome.reason})` : "by policy"} — the parked "${p.action}" was discarded, nothing executed.`);
              workerOpts?.onResolved?.(outcome);
            } catch (e) {
              console.warn(`[decidio] resume failed for ${p.decisionId}, will retry: ${(e as Error).message}`);
            }
          }
          if (Date.now() > deadline) break;
          await sleep(interval);
        }
      })();
      return { stop: () => { stopped = true; } };
    },
  };
  return ctrl;
}

export { sign as _signResumeBody };
