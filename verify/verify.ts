import { createPublicKey, verify as edVerify, createHash, createHmac } from "node:crypto";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(s: string): Buffer {
  const bytes = [0];
  for (const ch of s) {
    const val = B58.indexOf(ch);
    if (val < 0) throw new Error("invalid base58");
    let carry = val;
    for (let i = 0; i < bytes.length; i++) { carry += bytes[i]! * 58; bytes[i] = carry & 0xff; carry >>= 8; }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (const ch of s) { if (ch === B58[0]) bytes.push(0); else break; }
  return Buffer.from(bytes.reverse());
}

function assertNoLoneSurrogate(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("JCS: unpaired high surrogate");
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new Error("JCS: unpaired low surrogate");
    }
  }
}
export function jcsCanonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JCS: non-finite numbers are not valid JSON");
    return JSON.stringify(value);
  }
  if (typeof value === "string") { assertNoLoneSurrogate(value); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map(jcsCanonicalize).join(",")}]`;
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    for (const k of keys) assertNoLoneSurrogate(k);
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcsCanonicalize(obj[k])}`).join(",")}}`;
  }
  throw new Error(`JCS: cannot canonicalise type ${typeof value}`);
}
const jcsBytes = (v: unknown) => Buffer.from(jcsCanonicalize(v), "utf8");

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const deriveHash = (canonical: string, prevHash: string | null) => sha256((prevHash ?? "") + canonical);
const CRYPTOSUITE = "eddsa-jcs-2022";
const XSD_DATE_TIME_STAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
/** XSD dateTimeStamp, CALENDRICALLY (prodsec V033-04): the regex holds the shape, this holds the
 *  fields - month 1-12, a real day for that month and year, hour 0-23, minute 0-59, second 0-59, an
 *  offset within -14:00..+14:00. "2026-13-45T25:61:61Z" was VALID before, because digits are digits.
 *  Spelled the same way in all three verifiers; no Date construction (engine-defined leniency). */
export function isCalendricalDateTimeStamp(s: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|([+-])(\d{2}):(\d{2}))$/.exec(s);
  if (!m) return false;
  const y = +m[1]!, mo = +m[2]!, d = +m[3]!, h = +m[4]!, mi = +m[5]!, se = +m[6]!;
  if (y < 1 || mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59) return false;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]!;
  if (d > dim) return false;
  if (m[8] !== "Z") { const oh = +m[10]!, om = +m[11]!; if (oh > 14 || om > 59 || (oh === 14 && om !== 0)) return false; }
  return true;
}


function hashData(unsecuredDocument: Record<string, unknown>, proofConfig: Record<string, unknown>): Buffer {
  return Buffer.concat([
    createHash("sha256").update(jcsBytes(proofConfig)).digest(),
    createHash("sha256").update(jcsBytes(unsecuredDocument)).digest(),
  ]);
}

/** What the SEALED payload says about its own decision — read back out of `recordCanonical`.
 *
 *  Purely informational, and deliberately named for what it is: a snapshot taken AT SEAL TIME.
 *  A receipt for an approved, executed action can still read `result: routed_to_human` with
 *  `confirmation: pending`, because confirmation arrives AFTER the seal and a sealed record is
 *  immutable, so it is never written back. That is correct behaviour, not staleness — but "VALID"
 *  reads as "approved and executed" unless the boundary is stated, so these fields are surfaced
 *  rather than left in the JSON for the reader to infer. */
export interface SealedState {
  /** `authority.result` — the GATE's disposition (e.g. `routed_to_human`), NOT the human's verdict. */
  result?: string | null;
  /** `confirmation.status` as of the seal — NOT current execution status. */
  confirmation?: string | null;
  /** Whether the payload names a ratifier. */
  ratified?: boolean;
  /** How many deciders the payload names IN ADVANCE (`nominatedDeciders`; `deciders` in payloads sealed before 0.5.0). */
  nominatedDeciders?: number;
}

export interface VerifyResult {
  valid: boolean;
  issuer: string;
  contentBound: boolean;
  /** The kind of record the receipt seals - `approval`, `denial` or `decision` - read from the canonical record the
   *  credential binds (present only when content-bound). A denial's receipt is a receipt too (0.4.2). */
  recordKind?: string;
  recordId?: string;
  dNumber?: string | null;
  prevHash?: string | null;
  reason?: string;
  /** Present when `recordCanonical` parsed and carried recognisable authority fields. Absent is
   *  not an error — receipts of other kinds legitimately lack them. */
  sealedState?: SealedState;
}

/** Read the decision-state fields back out of the sealed canonical payload.
 *
 *  FAILS SOFT BY DESIGN. This is a reporting aid, never a verification input: `recordCanonical` is
 *  content-bound against `contentHash` before this is called, so nothing here can change a verdict.
 *  A payload that cannot be parsed, or one of a kind carrying no authority block, reports nothing
 *  rather than degrading a VALID receipt over a display concern. */
/** The record kind sealed into the canonical record (`approval` / `denial` / `decision`), or undefined when the
 *  canonical record does not carry one. Read from the receipt's own bytes, never fetched. */
export function readRecordKind(recordCanonical: string): string | undefined {
  let p: any;
  try { p = JSON.parse(recordCanonical); } catch { return undefined; }
  return p && typeof p === "object" && !Array.isArray(p) && typeof p.recordKind === "string" ? p.recordKind : undefined;
}
export function readSealedState(recordCanonical: string): SealedState | undefined {
  let p: any;
  try { p = JSON.parse(recordCanonical); } catch { return undefined; }
  if (!p || typeof p !== "object" || Array.isArray(p)) return undefined;
  const authority = p.authority && typeof p.authority === "object" && !Array.isArray(p.authority) ? p.authority : null;
  const confirmation = p.confirmation && typeof p.confirmation === "object" && !Array.isArray(p.confirmation) ? p.confirmation : null;
  const s: SealedState = {};
  if (authority && (typeof authority.result === "string" || authority.result === null)) s.result = authority.result;
  if (confirmation && (typeof confirmation.status === "string" || confirmation.status === null)) s.confirmation = confirmation.status;
  if ("ratifiedBy" in p) s.ratified = p.ratifiedBy !== null && p.ratifiedBy !== undefined;
  const nominated = p.nominatedDeciders ?? p.deciders;
  if (Array.isArray(nominated)) s.nominatedDeciders = nominated.length;
  return Object.keys(s).length ? s : undefined;
}

/** Verify a Decidio Authority Receipt (W3C VC, DataIntegrityProof / eddsa-jcs-2022) offline.
 *  Pass `expectedIssuer` (Decidio's published did:key) to assert the receipt was issued by
 *  Decidio — a valid signature by *some* key is not proof of *who* issued it. */
export function verifyReceipt(vc: any, expectedIssuer?: string): VerifyResult {
  try {
    if (expectedIssuer !== undefined && expectedIssuer.trim() === "") {
      return { valid: false, issuer: String(vc?.issuer ?? ""), contentBound: false, reason: "an empty --issuer/expectedIssuer was supplied — that is not an unpinned check, it is a missing pin (an unset environment variable interpolates to \"\"). Omit the argument entirely to verify unpinned on purpose." };
    }
    const did = String(vc?.issuer ?? "");
    if (!did.startsWith("did:key:z")) return { valid: false, issuer: did, contentBound: false, reason: "unsupported issuer DID (expected did:key Ed25519)" };
    if (expectedIssuer && did !== expectedIssuer) {
      const cs0 = vc?.credentialSubject ?? {};
      const bound = typeof cs0.recordCanonical === "string" && typeof cs0.contentHash === "string"
        && deriveHash(cs0.recordCanonical, typeof cs0.prevHash === "string" ? cs0.prevHash : null) === cs0.contentHash;
      return { valid: false, issuer: did, contentBound: bound, recordId: typeof cs0.recordId === "string" ? cs0.recordId : undefined, reason: "issuer DID is not the expected issuer (the receipt itself may be internally consistent — it was just not issued by who you pinned)" };
    }
    const mc = b58decode(did.slice("did:key:z".length));
    if (mc[0] !== 0xed || mc[1] !== 0x01) return { valid: false, issuer: did, contentBound: false, reason: "issuer DID is not Ed25519" };
    const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: mc.subarray(2).toString("base64url") } as any, format: "jwk" });

    const cs = vc?.credentialSubject ?? {};
    if (cs.prevHash !== null && cs.prevHash !== undefined && typeof cs.prevHash !== "string")
      return { valid: false, issuer: did, contentBound: false, recordId: cs.recordId, reason: "prevHash must be a string or null (an array/object cannot be hashed unambiguously)" };
    if (typeof cs.contentHash !== "string" || typeof cs.recordId !== "string")
      return { valid: false, issuer: did, contentBound: false, reason: "recordId and contentHash must be strings" };
    const contentBound = typeof cs.recordCanonical === "string" && deriveHash(cs.recordCanonical, cs.prevHash ?? null) === cs.contentHash;
    if (!contentBound) return { valid: false, issuer: did, contentBound: false, recordId: cs.recordId, reason: "contentHash does not match recordCanonical (content tampered)" };

    const proof = vc?.proof ?? {};
    if (proof.type !== "DataIntegrityProof") return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: "unsupported proof (expected DataIntegrityProof)" };
    if (proof.cryptosuite === "eddsa-2022") return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: "receipt uses Decidio's pre-standard format (eddsa-2022); not verifiable under the published spec — ask for a re-sealed receipt" };
    if (proof.cryptosuite !== CRYPTOSUITE) return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: `unsupported cryptosuite (expected ${CRYPTOSUITE})` };
    if (proof.proofPurpose !== "assertionMethod") {
      return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: `proofPurpose is ${JSON.stringify(proof.proofPurpose ?? null)}, not "assertionMethod" — this proof was made for a different purpose, so it is not an issuance of this credential` };
    }
    if (typeof proof.verificationMethod !== "string" || !proof.verificationMethod.startsWith(`${did}#`)) {
      return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: `verificationMethod ${JSON.stringify(proof.verificationMethod ?? null)} does not identify a key of the issuer (${did}) — the signature was checked against the issuer's key, but the proof names a different one` };
    }
    if (proof.verificationMethod !== `${did}#${did.slice("did:key:".length)}`) {
      return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: `verificationMethod ${JSON.stringify(proof.verificationMethod)} is not the issuer's did:key method identifier (expected ${did}#${did.slice("did:key:".length)}) — did:key has exactly one verification method, and this proof names a fragment that does not exist` };
    }
    if (typeof proof.created !== "string" || !XSD_DATE_TIME_STAMP.test(proof.created)) {
      return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: `proof has no usable "created" timestamp (${JSON.stringify(proof.created ?? null)}) — a sealed assertion must say when it was made` };
    }
    if (!isCalendricalDateTimeStamp(proof.created)) {
      return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: `proof "created" timestamp ${JSON.stringify(proof.created)} is not a real date-time (a field is out of range) — a sealed assertion cannot have been made at a time that does not exist` };
    }
    if (typeof proof.proofValue !== "string") return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: "proofValue must be a string (base58-btc multibase)" };
    const proofValue = proof.proofValue;
    if (!proofValue.startsWith("z")) return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: "missing/invalid proofValue (expected base58-btc multibase)" };
    const unsafeNumber = (v: unknown): boolean =>
      typeof v === "number" ? Number.isInteger(v) && !Number.isSafeInteger(v)
        : Array.isArray(v) ? v.some(unsafeNumber)
          : v !== null && typeof v === "object" ? Object.values(v as Record<string, unknown>).some(unsafeNumber)
            : false;
    if (unsafeNumber(vc)) return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: "receipt contains an integer beyond 2^53 — its exact signed value cannot be reproduced, so it is not verifiable" };

    const { proof: _omit, ...unsecuredDocument } = vc as Record<string, unknown>;
    const { proofValue: _pv, ...proofConfig } = proof as Record<string, unknown>;
    if (proofConfig["@context"] !== undefined) {
      const pc = ([] as unknown[]).concat(proofConfig["@context"] as unknown);
      const dc = ([] as unknown[]).concat(unsecuredDocument["@context"] as unknown);
      if (dc.length !== pc.length) return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: "@context does not match between document and proof (one carries entries the other does not cover)" };
      for (let i = 0; i < pc.length; i++) {
        if (pc[i] !== dc[i]) return { valid: false, issuer: did, contentBound, recordId: cs.recordId, reason: "proof @context does not match the document @context" };
      }
      unsecuredDocument["@context"] = proofConfig["@context"];
    }
    const valid = edVerify(null, hashData(unsecuredDocument, proofConfig), pub, b58decode(proofValue.slice(1)));
    return { valid, issuer: did, contentBound, recordId: cs.recordId, dNumber: cs.dNumber ?? null, prevHash: cs.prevHash ?? null, reason: valid ? undefined : "signature does not verify against issuer DID", sealedState: valid && contentBound ? readSealedState(cs.recordCanonical) : undefined, recordKind: valid && contentBound ? readRecordKind(cs.recordCanonical) : undefined };
  } catch (e: any) {
    return { valid: false, issuer: String(vc?.issuer ?? ""), contentBound: false, reason: String(e?.message ?? e) };
  }
}

/** Verify an ordered chain: each receipt's prevHash must equal the prior contentHash,
 *  and every receipt must independently verify. Proves tamper-evident ordering. */
export function verifyChain(vcs: any[], expectedIssuer?: string): { valid: boolean; length: number; reason?: string; anchor?: "genesis" | "segment" } {
  if (!vcs.length) return { valid: false, length: 0, reason: "no receipts supplied" };
  const issuers = [...new Set(vcs.map((v) => String((v as any)?.issuer ?? "")))];
  if (issuers.length > 1) return { valid: false, length: 0, reason: `these receipts come from ${issuers.length} DIFFERENT issuers — a chain must be issued end to end by one issuer` };
  let prev: string | null = null;
  let anchor: "genesis" | "segment" = "segment";
  for (let i = 0; i < vcs.length; i++) {
    const r = verifyReceipt(vcs[i], expectedIssuer);
    if (!r.valid) return { valid: false, length: i, reason: `receipt ${i} (${r.recordId ?? "?"}) invalid: ${r.reason}` };
    const cs = vcs[i]?.credentialSubject ?? {};
    if (i === 0) {
      anchor = (cs.prevHash ?? null) === null ? "genesis" : "segment";
    } else if ((cs.prevHash ?? null) !== prev) {
      return { valid: false, length: i, reason: `receipt ${i} does not follow receipt ${i - 1} directly (prevHash mismatch — either receipts between them are missing from this set, or the order/content is wrong; each receipt shown above verified individually)` };
    }
    prev = cs.contentHash;
  }
  return { valid: true, length: vcs.length, anchor };
}

/** The check commitment's algorithm, as sealed in `authority.checkCommitment.alg`. */
export const CHECK_COMMITMENT_ALG = "decidio.check-merkle.v1";
const CHECK_COMMITMENT_WIDTH = 32;
const CHECK_PROOF_LENGTH = 5;
const HEX64 = /^[0-9a-f]{64}$/;
const sha256Of = (...parts: Buffer[]): string => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest("hex");
};
const checkNode = (a: string, b: string): string =>
  sha256Of(Buffer.from([0x01]), Buffer.from(a <= b ? a : b, "hex"), Buffer.from(a <= b ? b : a, "hex"));

/** One entry as Decidio serves it (`GET /api/records/:id/check` → `entries[]`). */
export interface CheckDisclosure { entry: unknown; salt: string; proof: string[] }
export interface CheckEntryResult {
  valid: boolean;
  reason?: string;
  recordId?: string;
  /** The sealed root the entry was checked against. */
  root?: string;
  /** The entry's own claims — reported only when it verifies. */
  policyId?: string;
  policyVersion?: string;
  result?: string;
  decidingRule?: string;
}

function checkEntryShapeProblem(entry: unknown): string {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return "the entry is not an object";
  const e = entry as Record<string, unknown>;
  const keys = Object.keys(e).sort().join(",");
  if (keys !== "decidingRule,evaluatedLimits,firedRules,policyContentHash,policyId,policyVersion,result") return `the entry's keys are ${keys || "(none)"}, not { policyId, policyVersion, policyContentHash, result, decidingRule, firedRules, evaluatedLimits }`;
  if (typeof e.policyId !== "string" || !e.policyId || typeof e.policyVersion !== "string" || typeof e.decidingRule !== "string" || !e.decidingRule) return "the entry's policyId, policyVersion or decidingRule is not a string";
  if (typeof e.policyContentHash !== "string" || !HEX64.test(e.policyContentHash)) return "the entry's policyContentHash is not 64 lowercase hex";
  if (e.result !== "block" && e.result !== "route" && e.result !== "pass") return "the entry's result is not block, route or pass";
  if (!Array.isArray(e.firedRules) || !e.firedRules.every((r) => typeof r === "string")) return "the entry's firedRules are not strings";
  const limitOk = (l: unknown) => !!l && typeof l === "object" && !Array.isArray(l) && Object.keys(l).sort().join(",") === "type,unit,value"
    && typeof (l as Record<string, unknown>).type === "string" && typeof (l as Record<string, unknown>).value === "string"
    && ((l as Record<string, unknown>).unit === null || typeof (l as Record<string, unknown>).unit === "string");
  if (!Array.isArray(e.evaluatedLimits) || !e.evaluatedLimits.every(limitOk)) return "the entry's evaluatedLimits are not [{ type, value, unit }]";
  return "";
}

/** Verify ONE policy check entry against a Decidio Authority Receipt, offline: the receipt itself verifies (verifyReceipt,
 *  pinned to `expectedIssuer` when given), its sealed payload carries a `decidio.check-merkle.v1` commitment, and the
 *  entry's leaf — SHA-256(salt ‖ JCS(entry)) — folds through its proof to that sealed root. */
export function verifyCheckEntry(vc: any, disclosure: any, expectedIssuer?: string): CheckEntryResult {
  try {
    const r = verifyReceipt(vc, expectedIssuer);
    if (!r.valid) return { valid: false, recordId: r.recordId, reason: `the receipt itself does not verify: ${r.reason ?? "invalid"}` };
    let payload: any;
    try { payload = JSON.parse(vc.credentialSubject.recordCanonical); } catch { return { valid: false, recordId: r.recordId, reason: "the receipt's sealed record does not parse" }; }
    const c = payload && typeof payload === "object" ? payload.authority?.checkCommitment : undefined;
    if (c === undefined || c === null) return { valid: false, recordId: r.recordId, reason: "the receipt seals no check commitment (sealed before Decidio committed to its policy checks, or no policy applied to the request)" };
    if (typeof c !== "object" || Array.isArray(c) || Object.keys(c).sort().join(",") !== "alg,root" || c.alg !== CHECK_COMMITMENT_ALG || typeof c.root !== "string" || !HEX64.test(c.root)) {
      return { valid: false, recordId: r.recordId, reason: `the receipt's check commitment is not a ${CHECK_COMMITMENT_ALG} root` };
    }
    const d = disclosure && typeof disclosure === "object" && !Array.isArray(disclosure) ? disclosure : null;
    if (!d) return { valid: false, recordId: r.recordId, root: c.root, reason: "no disclosure: expected { entry, salt, proof }" };
    const shape = checkEntryShapeProblem(d.entry);
    if (shape) return { valid: false, recordId: r.recordId, root: c.root, reason: shape };
    if (typeof d.salt !== "string" || !HEX64.test(d.salt)) return { valid: false, recordId: r.recordId, root: c.root, reason: "the salt is not 32 bytes of lowercase hex" };
    if (!Array.isArray(d.proof) || d.proof.length !== CHECK_PROOF_LENGTH || !d.proof.every((s: unknown) => typeof s === "string" && HEX64.test(s))) {
      return { valid: false, recordId: r.recordId, root: c.root, reason: `the proof is not ${CHECK_PROOF_LENGTH} sibling hashes of 64 lowercase hex` };
    }
    let acc = sha256Of(Buffer.from(d.salt, "hex"), jcsBytes(d.entry));
    for (const s of d.proof as string[]) acc = checkNode(acc, s);
    if (acc !== c.root) return { valid: false, recordId: r.recordId, root: c.root, reason: "the entry is not in the sealed commitment: its leaf and proof do not reach the root" };
    const e = d.entry as Record<string, string>;
    return { valid: true, recordId: r.recordId, root: c.root, policyId: e.policyId, policyVersion: e.policyVersion, result: e.result, decidingRule: e.decidingRule };
  } catch (e: any) {
    return { valid: false, reason: String(e?.message ?? e) };
  }
}

/** The whole check as Decidio serves it to the workspace's admin (`GET /api/records/:id/check`): every entry with its salt
 *  (a proof, if present, is not needed) and the record's completeness key, 64 hex. */
export interface CheckCompleteness { entries: { entry: unknown; salt: string }[]; completenessKey: string }
export interface CheckCompleteResult {
  valid: boolean;
  reason?: string;
  recordId?: string;
  /** The sealed root the list was rebuilt against. */
  root?: string;
  /** How many policies checked the request, and each one's id in the order given — reported only when complete. */
  count?: number;
  policyIds?: string[];
}

/** Verify that a list of policy check entries is the WHOLE check a Decidio Authority Receipt commits to, offline: the
 *  receipt itself verifies (verifyReceipt, pinned to `expectedIssuer` when given), its sealed payload carries a
 *  `decidio.check-merkle.v1` commitment, and the k entries' leaves with the 32 − k pads the completeness key derives
 *  rebuild exactly the sealed root. Valid only then: an entry left out, added, given twice or changed, or another
 *  record's key, and the root moves. Takes the admin's `/check` answer as served (`{ entries, completenessKey }`). */
export function verifyCheckComplete(vc: any, disclosure: any, expectedIssuer?: string): CheckCompleteResult {
  try {
    const r = verifyReceipt(vc, expectedIssuer);
    if (!r.valid) return { valid: false, recordId: r.recordId, reason: `the receipt itself does not verify: ${r.reason ?? "invalid"}` };
    let payload: any;
    try { payload = JSON.parse(vc.credentialSubject.recordCanonical); } catch { return { valid: false, recordId: r.recordId, reason: "the receipt's sealed record does not parse" }; }
    const c = payload && typeof payload === "object" ? payload.authority?.checkCommitment : undefined;
    if (c === undefined || c === null) return { valid: false, recordId: r.recordId, reason: "the receipt seals no check commitment (sealed before Decidio committed to its policy checks, or no policy applied to the request)" };
    if (typeof c !== "object" || Array.isArray(c) || Object.keys(c).sort().join(",") !== "alg,root" || c.alg !== CHECK_COMMITMENT_ALG || typeof c.root !== "string" || !HEX64.test(c.root)) {
      return { valid: false, recordId: r.recordId, reason: `the receipt's check commitment is not a ${CHECK_COMMITMENT_ALG} root` };
    }
    const no = (reason: string): CheckCompleteResult => ({ valid: false, recordId: r.recordId, root: c.root, reason });
    const d = disclosure && typeof disclosure === "object" && !Array.isArray(disclosure) ? disclosure : null;
    if (!d) return no("no list: expected { entries, completenessKey }");
    if (typeof d.completenessKey !== "string" || !HEX64.test(d.completenessKey)) return no("no completeness key: expected 32 bytes of lowercase hex (Decidio serves it to the workspace's admin only)");
    if (!Array.isArray(d.entries) || d.entries.length < 1 || d.entries.length > CHECK_COMMITMENT_WIDTH) return no(`the list holds ${Array.isArray(d.entries) ? d.entries.length : "no"} entries, not 1 to ${CHECK_COMMITMENT_WIDTH}`);
    const leaves: string[] = [];
    for (const [i, item] of (d.entries as unknown[]).entries()) {
      if (!item || typeof item !== "object" || Array.isArray(item)) return no(`entry ${i + 1}: it is not { entry, salt }`);
      const { entry, salt } = item as Record<string, unknown>;
      const shape = checkEntryShapeProblem(entry);
      if (shape) return no(`entry ${i + 1}: ${shape}`);
      if (typeof salt !== "string" || !HEX64.test(salt)) return no(`entry ${i + 1}: the salt is not 32 bytes of lowercase hex`);
      const leaf = sha256Of(Buffer.from(salt, "hex"), jcsBytes(entry));
      if (leaves.includes(leaf)) return no(`entry ${i + 1} is given twice`);
      leaves.push(leaf);
    }
    const kr = Buffer.from(d.completenessKey, "hex");
    for (let i = 0; leaves.length < CHECK_COMMITMENT_WIDTH; i++) leaves.push(createHmac("sha256", kr).update(jcsBytes([i])).digest("hex"));
    let level = leaves.sort();
    while (level.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < level.length; i += 2) next.push(checkNode(level[i]!, level[i + 1]!));
      level = next;
    }
    if (level[0] !== c.root) return no("the list is not the whole check: its entries and the key's padding do not rebuild the sealed root (an entry is missing, added or changed, or the key is another record's)");
    return { valid: true, recordId: r.recordId, root: c.root, count: d.entries.length, policyIds: (d.entries as { entry: { policyId: string } }[]).map((x) => x.entry.policyId) };
  } catch (e: any) {
    return { valid: false, reason: String(e?.message ?? e) };
  }
}

/** Parse a receipt, REFUSING duplicate object keys. RFC 8785 §3.1 requires duplicate-free input,
 *  and JSON.parse silently keeps the last one — so a file containing
 *  `"issuer":"did:key:zEVIL","issuer":"<real>"` verifies while a human (or any parser that keeps the
 *  FIRST duplicate) reads the attacker's value. Same bytes, two different answers: refuse instead. */
export function parseReceiptStrict(text: string, file: string): unknown {
  const value = JSON.parse(text);
  const dup = findDuplicateKey(text);
  if (dup) throw new Error(`${file}: duplicate JSON key ${JSON.stringify(dup)} — RFC 8785 requires duplicate-free input, and different parsers disagree on which value is real`);
  return value;
}

function findDuplicateKey(text: string): string | null {
  const stack: Set<string>[] = [];
  let i = 0;
  const readString = (): string => {
    let out = "";
    i++;
    while (i < text.length) {
      const ch = text[i]!;
      if (ch === "\\") { out += text[i]! + text[i + 1]!; i += 2; continue; }
      if (ch === '"') { i++; return out; }
      out += ch; i++;
    }
    return out;
  };
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '"') {
      const s = readString();
      let j = i;
      while (j < text.length && /\s/.test(text[j]!)) j++;
      if (text[j] === ":" && stack.length > 0) {
        const key = JSON.parse(`"${s}"`) as string;
        const top = stack[stack.length - 1]!;
        if (top.has(key)) return key;
        top.add(key);
      }
      continue;
    }
    if (ch === "{") stack.push(new Set());
    else if (ch === "}") stack.pop();
    i++;
  }
  return null;
}


/** The ONE verifier CLI implementation — used by the decidio-verify bin today, and by
 *  `npx @decidio/sdk verify` once its dependency floor reaches a version exporting this (the sdk
 *  currently carries a strict-parse copy against the published verifier at the SAME version (the sdk
 *  pins it exactly at release time), locked to identical
 *  refusal semantics by the conformance runner's third door; follow-up: bump the sdk's dep floor
 *  after this publishes and delete the copy — equivalent-path rule). Returns lines + verdict. */
/** An issuer a Decidio verifier trusts with no --issuer. */
/** `host` is the address the release workflow checks the DID against (`https://<host>/api/did`) - the deployment's own
 *  onrender origin, which never moves. `alsoAt` lists the deployment's other public API addresses (custom domains); the
 *  sdk's grant and pause check matches them too, but the release never checks them live, because a custom domain can
 *  move between deployments (mcp.decidioai.com is staging's until the cutover window, production's after it). */
export interface KnownIssuer { readonly did: string; readonly host: string; readonly label: string; readonly alsoAt?: readonly string[] }
/** THE BUILT-IN TRUST ANCHORS (founder-approved 2026-09-24). A receipt names its own issuer, so pinning to that field
 *  is circular - any key can sign a file that names itself - and until now the only alternative was asking every
 *  reader to paste a DID. These are the issuers every CLI door trusts out of the box: Decidio's own deployments, each of
 *  which publishes its DID at https://<host>/api/did - staging (the lab) and production (launch plan L9, founder call
 *  F-1106-C1: production's DID was read from its live endpoint on 2026-11-10; its key is Ed25519 in AWS KMS, never
 *  exported - F-1110-L4 - and the verifier pins only the DID). Staging stays first: an entry's position means nothing
 *  to the verifier, which picks by the receipt's DID among these and nothing else. ONE list for every door of this package and of
 *  @decidio/sdk; the Python twin (decidio/verify.py KNOWN_ISSUERS) carries the same entries, and the three-door
 *  conformance gate fails if the doors disagree. NEVER the verification kit's published SAMPLE issuer: its private key
 *  is public on purpose, so trusting it by default would verify any forgery signed with it. A self-hosted deployment
 *  is not listed by design - its DID is pinned with --issuer (or remembered by the sdk at sign-in). */
export const KNOWN_ISSUERS: readonly KnownIssuer[] = Object.freeze([
  Object.freeze({ did: "did:key:z6MkmLGeR5NjJ87a1yU5ygqju49CtnUrt38esqM54Y9tXnKq", host: "decidio-api.onrender.com", label: "Decidio staging lab", alsoAt: Object.freeze(["mcp-staging.decidioai.com"]) }),
  Object.freeze({ did: "did:key:z6MkpBwpAT98VAqg2UpiSGJZieg7DGQpoNkdioDUEo4kQXnJ", host: "decidio-prod-api.onrender.com", label: "Decidio production", alsoAt: Object.freeze(["mcp.decidioai.com", "api.decidioai.com"]) }),
]);
/** No --issuer given: the built-in anchor these receipts select, or why none applies. The receipts' own `issuer` fields
 *  only CHOOSE among `known` - a claim can never add an anchor - and every receipt is then verified against the chosen
 *  DID exactly as with --issuer, so a file naming a built-in DID without holding its key still fails on the signature.
 *  Files that do not parse are left to runVerify, which names them. `known` is a parameter for the smokes only. */
export function builtInAnchor(files: string[], readFile: (f: string) => string, known: readonly KnownIssuer[] = KNOWN_ISSUERS): { anchor: KnownIssuer } | { refusal: string } {
  const claimed = new Set<string>();
  for (const f of files) {
    let vc: any;
    try { vc = parseReceiptStrict(readFile(f), f); } catch { continue; }
    claimed.add(String(vc?.issuer ?? ""));
  }
  const outside = [...claimed].filter((d) => !known.some((k) => k.did === d));
  if (outside.length) return { refusal: `${claimed.size === 1 ? "the receipt names" : "these receipts name"} ${outside.map((d) => d || "(no issuer)").join(", ")} as issuer, which is not a built-in Decidio issuer` };
  if (claimed.size > 1) return { refusal: `these receipts name ${claimed.size} different issuers - verify each issuer's receipts separately` };
  const anchor = known.find((k) => claimed.has(k.did)) ?? known[0];
  return anchor ? { anchor } : { refusal: "no built-in issuer is configured" };
}
/** The refusal every CLI door prints when no trust anchor applies (0.5.0: an unpinned VALID exited 0 for a receipt
 *  anyone could have forged, and scripts trust exit status; 3A: the built-in anchors are tried first, so this now
 *  fires for a receipt from an issuer this verifier does not know). `command` is the door's own spelling of itself, so
 *  the remedy is copy-pasteable where it is read; `why` says what was found. The LIBRARY keeps `verifyReceipt(vc)`
 *  unpinned-on-purpose: a caller reads `issuer` in the result; the CLIs are what scripts trust. */
export function pinRequiredMessage(command: string, why?: string): string {
  return [
    `✘ ${command} needs --issuer <did:key>${why ? ` here: ${why}` : ""} — without a pin, VALID only proves the file agrees with itself (any keyholder could have issued it).`,
    `  Built in (used when no --issuer is given): ${KNOWN_ISSUERS.map((k) => `${k.did} (${k.label}, ${k.host})`).join("; ")}.`,
    `  A receipt's own issuer field is a claim, never a trust anchor. For any other Decidio (self-hosted), take its DID from`,
    `  that host's /api/did - not from the receipt - and pin it:`,
    `    ${command} --issuer <did:key:...> <receipt.json>`,
    `  To check structure only, say so: --allow-unpinned (the verdict then carries the UNPINNED warning).`,
  ].join("\n");
}
/** `anchor` says where `expectedIssuer` came from (a CLI door's resolution: --issuer, remembered, built in); every run
 *  prints its trust anchor first, so a verdict can never be read without knowing what it was pinned to. */
export function runVerify(files: string[], expectedIssuer: string | undefined, readFile: (f: string) => string, anchor?: string): { ok: boolean; lines: string[] } {
  const lines: string[] = [expectedIssuer
    ? `trust anchor: ${expectedIssuer}  (${anchor ?? "--issuer"})`
    : `trust anchor: NONE — unpinned, a structural check only (any keyholder could have issued these files)`];
  const vcs: unknown[] = [];
  const parsedFiles: string[] = [];
  let anyParseFailed = false;
  for (const f of files) {
    try { vcs.push(parseReceiptStrict(readFile(f), f)); parsedFiles.push(f); }
    catch (e: any) {
      anyParseFailed = true;
      const msg = String(e?.message ?? e);
      lines.push(`✘ INVALID  ${f}${msg.startsWith(f) ? msg.slice(f.length) : `: ${msg}`}`);
    }
  }
  if (!vcs.length) return { ok: false, lines };
  let allOk = !anyParseFailed;
  let anyValid = false;
  vcs.forEach((vc, i) => {
    const r = verifyReceipt(vc, expectedIssuer);
    allOk = allOk && r.valid;
    anyValid = anyValid || r.valid;
    lines.push(`${r.valid ? "✔ VALID  " : "✘ INVALID"}  ${parsedFiles[i]}`);
    lines.push(`    record: ${r.recordId ?? "?"}   kind: ${r.recordKind ?? "?"}   issuer: ${r.issuer}${expectedIssuer ? "" : "  (UNPINNED — this only proves internal consistency; ANY keyholder could have issued it. Pass --issuer <your workspace DID> to verify WHO)"}`);
    lines.push(`    content-bound: ${r.contentBound}${r.reason ? `   reason: ${r.reason}` : ""}`);
    const s = r.sealedState;
    if (s) {
      const bits: string[] = [];
      if (s.result !== undefined) bits.push(`gate: ${s.result ?? "—"}`);
      if (s.confirmation !== undefined) bits.push(`confirmation: ${s.confirmation ?? "—"}`);
      if (s.ratified !== undefined) bits.push(`ratified: ${s.ratified ? "yes" : "no"}`);
      if (s.nominatedDeciders !== undefined) bits.push(`nominated deciders: ${s.nominatedDeciders}`);
      if (bits.length) lines.push(`    as sealed — ${bits.join("   ")}`);
      if (s.ratified === true && s.nominatedDeciders === 0) {
        lines.push(`      ("nominated deciders" lists anyone nominated in ADVANCE — none here; the person who adjudicated is recorded separately, as the ratifier)`);
      }
    }
  });
  if (anyParseFailed && files.length > 1) {
    lines.push(`
chain: not checked — ${files.length - vcs.length} file(s) failed to parse (see above); re-run with readable receipts to verify ordering.`);
  } else if (vcs.length > 1) {
    const c = verifyChain(vcs, expectedIssuer);
    allOk = allOk && c.valid;
    lines.push(`
chain: ${c.valid ? "✔ intact" : "✘ broken"} (${c.length}/${vcs.length})${c.valid && c.anchor === "segment" ? " — segment: ordering proven from the FIRST file forward; history before it is not covered by these receipts" : c.valid ? " — from genesis" : ""}${c.reason ? ` — ${c.reason}` : ""}`);
  }
  if (anyValid) {
    lines.push(`
what VALID proves: the CLAIMS in this record were sealed by that issuer and none of them
  has changed since. Not the bytes: the signature covers the record's CANONICAL form (JCS),
  so reformatting the file - reindenting it, minifying it, reordering keys - still verifies,
  and should, because none of that alters a single claim. If you need byte-for-byte custody,
  hash the file yourself and compare that separately; this proves the CONTENT, which is the
  thing an auditor is actually asking about.
what it does NOT prove: that the approved action ran. Execution is confirmed AFTER the
  seal, and a sealed receipt is immutable, so the "as sealed" fields above are a snapshot
  taken when the record was sealed — not current status. Ask the issuer for that.
  This check is cryptographic, not semantic: it does not evaluate business rules, timestamp
  plausibility, or whether the record was later superseded or revoked.`);
  }
  return { ok: allOk, lines };
}
