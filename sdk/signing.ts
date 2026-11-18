import { generateKeyPairSync, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, createHash, createHmac, randomUUID } from "node:crypto";
import { canonicalJson, type JsonValue } from "./canonical.js";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58encode(buf: Buffer): string {
  const digits = [0];
  for (const byte of buf) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) { carry += digits[i]! << 8; digits[i] = carry % 58; carry = (carry / 58) | 0; }
    while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let str = "";
  for (const b of buf) { if (b === 0) str += "1"; else break; }
  for (let i = digits.length - 1; i >= 0; i--) str += B58[digits[i]!];
  return str;
}

/** Sorted-key JCS — must match apps/api/src/canonical.ts byte-for-byte.
 *
 *  ONE IMPLEMENTATION (F-006). This was a module-local copy that reached `JSON.stringify` for every
 *  primitive, so it applied NONE of the strict rules the exported canonicalizer enforces — most
 *  sharply, it emitted an escaped lone surrogate instead of refusing it. The bytes a bound proof
 *  SIGNS and the bytes the digest BINDS are the two places that must never disagree with the value
 *  model, and they were the two places that did. Python already delegated (`signing.canonicalize` →
 *  `canonical_json`); this is the twin-parity repair on the TypeScript side. */
export function canonicalize(v: unknown): string {
  return canonicalJson(v as JsonValue, "canonicalize(...)");
}

/** Generate a fresh Ed25519 keypair LOCALLY. Returns the public `did:key` (register this)
 *  and the PKCS8 private key base64 (keep this in the agent host's env as DECIDIO_AGENT_KEY —
 *  it never goes back to Decidio). */
/** Derive the public did:key from a stored private key. Lets `doctor` prove that the key on
 *  this machine is actually the one registered for this agent — a mismatched restore otherwise
 *  looks healthy until a signed confirmation quietly fails to earn its tier weeks later. */
export function didFromPrivateKey(privateKeyBase64: string): string {
  const priv = createPrivateKey({ key: Buffer.from(privateKeyBase64, "base64"), format: "der", type: "pkcs8" });
  const jwk = createPublicKey(priv).export({ format: "jwk" }) as { x: string };
  return "did:key:z" + b58encode(Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.from(jwk.x, "base64url")]));
}

export function generateKeypair(): { did: string; privateKeyBase64: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  const raw = Buffer.from(jwk.x, "base64url");
  const did = "did:key:z" + b58encode(Buffer.concat([Buffer.from([0xed, 0x01]), raw]));
  const privateKeyBase64 = (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).toString("base64");
  return { did, privateKeyBase64 };
}

export interface RequesterIdentity {
  agentId: string; did: string; action: string; amount: number; scope?: string;
  workspaceId?: string;
  nonce: string; exp: number; proof: { protected: string; signature: string };
}

/** Sign the CONFIRM call (bound to {action:"confirm", scope:decisionId}) so the gate can
 *  prove the caller is the receipt's original requester before granting the wrapper tier
 *  (application_confirmed). Returns undefined when no signing key is configured (the server
 *  then caps the report at agent_asserted). Used by EVERY confirm path — inline, durable
 *  resume, and the engine adapters — so the production paths confirm with a proof too. Also
 *  binds `workspaceId` (D-B3.6) when configured, so the confirm proof is tenant-scoped too. */
export function signConfirm(
  decisionId: string,
  cfg: { agentId?: string; agentKey?: string; agentDid?: string; workspaceId?: string },
): RequesterIdentity | undefined {
  if (!cfg.agentKey || !cfg.agentDid || !cfg.agentId) return undefined;
  return signBoundProof(cfg.agentKey, { agentId: cfg.agentId, did: cfg.agentDid, action: "confirm", amount: 0, scope: decisionId, workspaceId: cfg.workspaceId });
}

/** Sign a request-bound identity proof. The returned object is sent verbatim as the
 *  `requesterIdentity` field of /agent/authorize. */
export function signBoundProof(
  privateKeyBase64: string,
  fields: { agentId: string; did: string; action: string; amount: number; scope?: string; workspaceId?: string; ttlMs?: number; now?: number; nonce?: string },
): RequesterIdentity {
  const key = createPrivateKey({ key: Buffer.from(privateKeyBase64, "base64"), format: "der", type: "pkcs8" });
  const nonce = fields.nonce ?? randomUUID();
  const exp = (fields.now ?? Date.now()) + (fields.ttlMs ?? 120_000);
  const payloadObj: Record<string, unknown> = { agentId: fields.agentId, did: fields.did, action: fields.action, amount: fields.amount, ...(fields.scope !== undefined ? { scope: fields.scope } : {}), ...(fields.workspaceId !== undefined ? { workspaceId: fields.workspaceId } : {}), nonce, exp };
  const payload = Buffer.from(canonicalize(payloadObj), "utf8").toString("base64url");
  const protectedHdr = Buffer.from(JSON.stringify({ alg: "EdDSA", kid: fields.did }), "utf8").toString("base64url");
  const signature = Buffer.from(edSign(null, Buffer.from(`${protectedHdr}.${payload}`, "utf8"), key)).toString("base64url");
  return { agentId: fields.agentId, did: fields.did, action: fields.action, amount: fields.amount, scope: fields.scope, workspaceId: fields.workspaceId, nonce, exp, proof: { protected: protectedHdr, signature } };
}

/** Refuse values that do not survive `JSON.stringify → JSON.parse` with their meaning intact,
 *  BEFORE anything is routed, signed, or parked. `NaN` canonicalizes to `null` and a `Map` to
 *  `{}` — an integrity signature over those bytes would verify while the function executed
 *  arguments that meant something else, so the gate refuses them instead. Throws naming the
 *  offending path. The supported data model is plain JSON: null, boolean, string, finite
 *  number, plain array, plain object. */
/** Typed refusal for values that cannot survive JSON with their meaning intact. `decisionId`
 *  is set only when a decision already exists (defense-in-depth refusals after routing). */
export class DecidioUnsafeArgumentsError extends Error {
  constructor(message: string, public decisionId?: string) {
    super(message);
    this.name = "DecidioUnsafeArgumentsError";
  }
}

export function assertJsonSafe(value: unknown, path = "args"): void {
  const seen = new Set<object>();
  const walk = (v: unknown, p: string): void => {
    if (v === null || typeof v === "boolean" || typeof v === "string") return;
    if (typeof v === "number") {
      if (!Number.isFinite(v)) throw new DecidioUnsafeArgumentsError(`[decidio] ${p} is ${String(v)} — a non-finite number does not survive JSON (it becomes null), so what a human approves would not be what executes. pass a finite number or a string.`);
      return;
    }
    if (typeof v === "undefined") throw new DecidioUnsafeArgumentsError(`[decidio] ${p} is undefined — JSON drops or nullifies it, so what a human approves would not be what executes. use null explicitly or omit the field.`);
    if (typeof v === "bigint") throw new DecidioUnsafeArgumentsError(`[decidio] ${p} is a BigInt — JSON cannot represent it. pass it as a string.`);
    if (typeof v === "function" || typeof v === "symbol") throw new DecidioUnsafeArgumentsError(`[decidio] ${p} is a ${typeof v} — it cannot be serialized for approval.`);
    if (typeof v === "object") {
      if (seen.has(v as object)) throw new DecidioUnsafeArgumentsError(`[decidio] ${p} is part of a circular structure — it cannot be serialized for approval.`);
      seen.add(v as object);
      if (Array.isArray(v)) { v.forEach((x, i) => walk(x, `${p}[${i}]`)); seen.delete(v as object); return; }
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) {
        const name = (v as any)?.constructor?.name ?? "a class instance";
        throw new DecidioUnsafeArgumentsError(`[decidio] ${p} is ${name === "Object" ? "an exotic object" : `a ${name}`} — only plain JSON objects survive serialization with their meaning intact (a Map, for example, becomes {}); convert it to plain JSON first.`);
      }
      if (typeof (v as any).toJSON === "function") throw new DecidioUnsafeArgumentsError(`[decidio] ${p} defines toJSON() — its serialized form would differ from the value the signature covers. pass the plain serialized form instead.`);
      for (const [k, x] of Object.entries(v as object)) walk(x, `${p}.${k}`);
      seen.delete(v as object);
      return;
    }
    throw new DecidioUnsafeArgumentsError(`[decidio] ${p} has unsupported type ${typeof v}.`);
  };
  walk(value, path);
}

/** The wire rule: a credentialed request must never ride plaintext http to a remote host — the
 *  rule is about the WIRE, not which credential (the interactive sign-in enforced this for
 *  session tokens while agent-token requests sailed through). localhost/127.0.0.1/[::1] stay
 *  allowed for local dev; https always allowed. Throws before anything is sent. */
/** The URL as it may be ECHOED in a refusal: userinfo masked. The SDK treats URL userinfo as a credential
 *  (it is refused as one), so no refusal may print it - every branch of assertSafeTransport echoes through
 *  this, not the raw string (invariant-guard, 0.3.5). */
export function redactUrl(u: string): string {
  return u.replace(/\/\/[^/?#]*@/, "//***@").replace(/^([^/?#@:]*:)(?!\/\/)[\/\\]*[^/?#]*@/, "$1***@");
}
/** Unicode SPACE and FORMAT characters a URL must never contain: the Zs/Zl/Zp separators (NBSP, ideographic
 *  space, …) and the zero-width formats. Spelled as an explicit list in BOTH runtimes so the answers cannot
 *  drift with a library's notion of whitespace (Python's urlsplit strips a leading NBSP; WHATWG does not). */
export const URL_UNICODE_SPACE = /[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\u200b-\u200d\u2060]/;

export function assertSafeTransport(url: string, hasCredential: boolean): void {
  if (typeof url !== "string") {
    throw new Error(`[decidio] the gate URL is ${url === null ? "null" : typeof url}, not a string, so there is no host to send to. Decidio needs a full https URL (or http://localhost for local dev). Nothing was sent.`);
  }
  for (const ch of url) {
    const cp = ch.codePointAt(0)!;
    if (cp <= 0x20 || (cp >= 0x7f && cp <= 0x9f) || cp === 0xfeff || URL_UNICODE_SPACE.test(ch)) {
      throw new Error(`[decidio] the gate URL ${JSON.stringify(redactUrl(url))} contains whitespace or a control character (U+${cp.toString(16).toUpperCase().padStart(4, "0")}) - a validator and a transport can read such a spelling differently, so it is refused as written. Remove it. Nothing was sent.`);
    }
  }
  let u: URL;
  try { u = new URL(url); }
  catch {
    const spelled = url.replace(/[\t\r\n]/g, "").replace(/^[\s\u0000-\u001f\u0085\ufeff]+/, "");
    if (/^http:/i.test(spelled)) {
      throw new Error(`[decidio] refusing to ${hasCredential ? "send credentials" : "send a request"} over plaintext http to ${JSON.stringify(redactUrl(url))} — that is not a complete absolute URL, so where the request would actually connect is undefined (the path is appended to it, which can turn it into a remote host). Set a full https URL, or http://localhost for local dev. Nothing was sent.`);
    }
    throw new Error(`[decidio] the gate URL ${JSON.stringify(redactUrl(url))} is not an absolute URL, so there is no host to send to — where a request would actually connect depends entirely on whichever transport resolves it. Decidio needs a full https URL (or http://localhost for local dev). Nothing was sent.`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`[decidio] the gate URL uses the ${u.protocol.replace(":", "")} scheme, which is not a Decidio endpoint — use https (or http://localhost for local dev). Nothing was sent.`);
  }
  if (u.username || u.password) {
    throw new Error(`[decidio] the gate URL carries credentials in the URL itself (${u.protocol}//user:***@${u.host}). Decidio authenticates with a bearer token; remove the user:password from the URL. Nothing was sent.`);
  }
  if (u.hostname === "") {
    throw new Error(`[decidio] the gate URL ${JSON.stringify(redactUrl(url))} has no host — there is nowhere for the request to go. Decidio needs a full https URL (or http://localhost for local dev). Nothing was sent.`);
  }
  {
    const spelled = url.replace(/[\t\r\n]/g, "").replace(/^[\s\u0000-\u001f\u0085\ufeff]+/, "").toLowerCase();
    const origin = `${u.protocol}//${u.host}`.toLowerCase();
    const next = spelled.charAt(origin.length);
    if (!spelled.startsWith(origin) || (next !== "" && next !== "/" && next !== "?" && next !== "#" && next !== ":")) {
      throw new Error(`[decidio] the gate URL ${JSON.stringify(redactUrl(url))} is not written in canonical form — this parser reads it as ${origin}, but the raw spelling is what a transport receives, and a parser that normalizes differently can read it as another host entirely. Write it as ${origin}. Nothing was sent.`);
    }
  }
  if (u.protocol !== "http:") return;
  const host = u.hostname.toLowerCase();
  const local = host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
  if (local) return;
  throw new Error(hasCredential
    ? `[decidio] refusing to send credentials over plaintext http to ${u.origin} — use https, or localhost for local dev. Nothing was sent.`
    : `[decidio] refusing to talk to ${u.origin} over plaintext http — Decidio is https, and an unauthenticated plaintext reply cannot be trusted to carry an authority decision. Use https, or localhost for local dev. Nothing was sent.`);
}

/** The ONE answer to "does this request carry a credential worth protecting?" (A6, 0.1.12).
 *  A signed identity proof is a credential too: sending it over remote plaintext disclosed
 *  request context and replay/front-run material even with no bearer configured. */
export const carriesCredential = (c: { apiToken?: string; agentKey?: string; agentDid?: string }): boolean =>
  !!c.apiToken || !!(c.agentKey && c.agentDid);

/** The agent-held secret a request commitment (and the LangGraph idempotency key) is keyed with. */
export interface BindingMaterial { readonly kind: "ed25519" | "api-token"; readonly secret: Buffer }

/** The key material this configuration binds approvals with: the Ed25519 signing key when signing is
 *  configured (`agentKey` AND `agentDid`, the same predicate the identity proof uses), else the API
 *  token, else none. Throws on a signing key that cannot be read - the identity proof would refuse the
 *  same key, and silently binding with the token instead would make two processes disagree. */
export function bindingMaterial(cfg: { agentKey?: string; agentDid?: string; apiToken?: string }): BindingMaterial | undefined {
  if (cfg.agentKey && cfg.agentDid) {
    let jwk: { crv?: string; d?: string };
    try {
      jwk = createPrivateKey({ key: Buffer.from(cfg.agentKey, "base64"), format: "der", type: "pkcs8" }).export({ format: "jwk" }) as { crv?: string; d?: string };
    } catch (e: any) {
      throw new Error(`[decidio] DECIDIO_AGENT_KEY is not a readable private key (PKCS8, base64): ${e?.message ?? e}. It binds this agent's approvals to their requests; restore the key \`init\` wrote, or unset DECIDIO_AGENT_KEY/DECIDIO_AGENT_DID. Nothing was sent or executed.`);
    }
    if (jwk.crv !== "Ed25519" || typeof jwk.d !== "string") {
      throw new Error(`[decidio] DECIDIO_AGENT_KEY is not an Ed25519 private key (got ${JSON.stringify(jwk.crv ?? null)}). Restore the key \`init\` wrote. Nothing was sent or executed.`);
    }
    return { kind: "ed25519", secret: Buffer.from(jwk.d, "base64url") };
  }
  if (cfg.apiToken) return { kind: "api-token", secret: Buffer.from(cfg.apiToken, "utf8") };
  return undefined;
}

function bindingSubkey(m: BindingMaterial, label: string): Buffer {
  return createHmac("sha256", m.secret).update(`${label}/${m.kind}`, "utf8").digest();
}

/** The exact request an approval covers. The core wrapper commits to what EXECUTES — the canonical
 *  argument snapshot plus the described action/amount/scope; an engine adapter cannot see inside its
 *  `run()` closure, so it commits to the whole described context (display details included). */
export interface CommittedRequest {
  action: string;
  amount: number;
  scope?: string | null;
  context?: Record<string, string | number> | null;
  args?: readonly unknown[];
  /** Python only (keyword arguments); present in the shape so the two languages share one model. */
  kwargs?: Record<string, unknown>;
}

/** The canonical bytes a commitment covers: optional members OMITTED when absent (null counts as
 *  absent), so the two languages hash the same bytes. */
export function committedRequestJson(request: CommittedRequest): string {
  const r: Record<string, unknown> = { action: request.action, amount: request.amount };
  if (request.scope !== undefined && request.scope !== null) r.scope = request.scope;
  if (request.context !== undefined && request.context !== null) r.context = request.context;
  if (request.args !== undefined && request.args !== null) r.args = request.args;
  if (request.kwargs !== undefined && request.kwargs !== null) r.kwargs = request.kwargs;
  return canonicalJson(r as JsonValue, "request commitment");
}

/** lowercase-hex HMAC-SHA256 over the canonical request, under the agent-held key. */
export function requestCommitment(material: BindingMaterial, request: CommittedRequest): string {
  return createHmac("sha256", bindingSubkey(material, "decidio.request-commitment.v1")).update(committedRequestJson(request), "utf8").digest("hex");
}

/** lowercase-hex idempotency key over an execution identity (e.g. LangGraph's thread + task +
 *  commitment), keyed so the host's thread ids never reach Decidio in the clear. */
export function idempotencyKey(material: BindingMaterial, identity: Record<string, JsonValue>): string {
  return createHmac("sha256", bindingSubkey(material, "decidio.idempotency-key.v1")).update(canonicalJson(identity, "idempotency identity"), "utf8").digest("hex");
}
/** THE REQUEST KEY A CALL SENDS BY DEFAULT (11f, founder 2026-10-30): an idempotency key over a per-call random id and
 *  the request's commitment, so the SDK's own retry of one call is the same request (the gate answers the decision it
 *  already made) while two calls stay two requests. Python twin: invocation_request_key. */
export function invocationRequestKey(material: BindingMaterial, invocationId: string, commitment: string): string {
  return idempotencyKey(material, { invocation: invocationId, commitment });
}
/** A CALLER'S OWN REQUEST KEY (11f), e.g. an order id: keyed like every other identity, so the caller's id never reaches
 *  Decidio in the clear. Deliberately NOT over the commitment: the same key for a changed request is the gate's 409
 *  IDEMPOTENCY_CONFLICT, never a silent second request. Python twin: own_request_key. */
export function ownRequestKey(material: BindingMaterial, key: string): string {
  return idempotencyKey(material, { requestKey: key });
}
/** The Claude Code hook's request scope: `cmd-` + 16 hex of a KEYED digest over the command text and its subject
 *  (chat approvals follow-up, invariant-guard 2026-10-15). The text may carry a credential the display redacts; an
 *  unkeyed digest sealed beside the redacted text would be an offline oracle for a weak password. Keyed under its own
 *  domain, so it is deterministic for this agent and nothing to anyone without the key material. */
export function boundScope(material: BindingMaterial, text: string): string {
  return "cmd-" + createHmac("sha256", bindingSubkey(material, "decidio.hook-scope.v1")).update(text, "utf8").digest("hex").slice(0, 16);
}

/** A signed, DOMAIN-SEPARATED, versioned attestation that THIS agent reported THIS captured
 *  response for THIS decision. Distinct from the identity proof (`signConfirm`) in every field
 *  that matters, so a report can never be lifted from one decision onto another: the decision id,
 *  the workspace, the agent's did, the source, the response digest, the digest algorithm, the
 *  canonicalization version, a nonce and an expiry are ALL inside the signed bytes.
 *
 *  HONEST SCOPE — say this out loud rather than let a reader assume more: this proves integrity
 *  and agent attribution of the REPORT. It does not prove the downstream system committed
 *  anything; only the source system can attest that, and the gate's evidence tier is what
 *  records how strong that attestation is. */
export interface ExecutionReport {
  v: 1;
  purpose: "decidio.execution-report";
  decisionId: string;
  agentId: string;
  did: string;
  workspaceId?: string;
  source: string;
  resultDigest: string;
  digestAlg: "sha-256";
  canonicalization: "decidio-jcs-1";
  nonce: string;
  exp: number;
  proof: { protected: string; signature: string };
}

export function signExecutionReport(
  privateKeyBase64: string,
  fields: { decisionId: string; agentId: string; did: string; workspaceId?: string; source: string; resultDigest: string; ttlMs?: number; now?: number; nonce?: string },
): ExecutionReport {
  const key = createPrivateKey({ key: Buffer.from(privateKeyBase64, "base64"), format: "der", type: "pkcs8" });
  const nonce = fields.nonce ?? randomUUID();
  const exp = (fields.now ?? Date.now()) + (fields.ttlMs ?? 300_000);
  const body = {
    v: 1 as const,
    purpose: "decidio.execution-report" as const,
    decisionId: fields.decisionId,
    agentId: fields.agentId,
    did: fields.did,
    ...(fields.workspaceId !== undefined ? { workspaceId: fields.workspaceId } : {}),
    source: fields.source,
    resultDigest: fields.resultDigest,
    digestAlg: "sha-256" as const,
    canonicalization: "decidio-jcs-1" as const,
    nonce,
    exp,
  };
  const payload = Buffer.from(canonicalize(body), "utf8").toString("base64url");
  const protectedHdr = Buffer.from(JSON.stringify({ alg: "EdDSA", kid: fields.did, typ: "decidio-execution-report+jws" }), "utf8").toString("base64url");
  const signature = Buffer.from(edSign(null, Buffer.from(`${protectedHdr}.${payload}`, "utf8"), key)).toString("base64url");
  return { ...body, proof: { protected: protectedHdr, signature } };
}

/** Verify an ExecutionReport LOCALLY — same rules the server applies before persisting it.
 *  Returns why it failed rather than a bare false, so a caller can say something useful. */
export function verifyExecutionReport(report: unknown, expect: { decisionId: string; did?: string; now?: number }): { valid: boolean; reason?: string } {
  const r = report as ExecutionReport | null;
  if (!r || r.purpose !== "decidio.execution-report" || r.v !== 1) return { valid: false, reason: "not a v1 decidio execution report" };
  if (r.decisionId !== expect.decisionId) return { valid: false, reason: "report is bound to a DIFFERENT decision" };
  if (expect.did && r.did !== expect.did) return { valid: false, reason: "report was signed by a different agent key" };
  if (typeof r.exp !== "number" || (expect.now ?? Date.now()) > r.exp) return { valid: false, reason: "report expired" };
  if (r.digestAlg !== "sha-256" || r.canonicalization !== "decidio-jcs-1") return { valid: false, reason: "unsupported digest/canonicalization" };
  try {
    const { proof, ...body } = r as any;
    const payload = Buffer.from(canonicalize(body), "utf8").toString("base64url");
    const mc = b58decode(String(r.did).slice("did:key:z".length));
    if (mc[0] !== 0xed || mc[1] !== 0x01) return { valid: false, reason: "issuer did is not Ed25519" };
    const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(mc.subarray(2)).toString("base64url") } as any, format: "jwk" });
    const ok = edVerify(null, Buffer.from(`${proof.protected}.${payload}`, "utf8"), pub, Buffer.from(proof.signature, "base64url"));
    return ok ? { valid: true } : { valid: false, reason: "signature does not verify against the agent did" };
  } catch (e: any) { return { valid: false, reason: `malformed report (${e?.message ?? e})` }; }
}

/** sha-256 over the canonical JSON of an already-canonical value — the digest an ExecutionReport
 *  binds. Both languages produce identical bytes for identical values. */
export function resultDigest(canonicalValue: unknown): string {
  return createHash("sha256").update(canonicalize(canonicalValue), "utf8").digest("hex");
}

function b58decode(s: string): Buffer {
  const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const bytes: number[] = [0];
  for (const ch of s) {
    const val = A.indexOf(ch);
    if (val < 0) throw new Error("bad base58 character");
    let carry = val;
    for (let i = 0; i < bytes.length; i++) { carry += bytes[i]! * 58; bytes[i] = carry & 0xff; carry >>= 8; }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (const ch of s) { if (ch === A[0]) bytes.push(0); else break; }
  return Buffer.from(bytes.reverse());
}
