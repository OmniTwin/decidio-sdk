import { createServer, type Server } from "node:http";
import { createHash, generateKeyPairSync, randomBytes, sign as edSign } from "node:crypto";
import { jcsCanonicalize } from "@decidio/verify";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58(buf: Buffer): string {
  const digits: number[] = [0];
  for (const byte of buf) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) { carry += digits[i]! << 8; digits[i] = carry % 58; carry = (carry / 58) | 0; }
    while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = "";
  for (const b of buf) { if (b === 0) out += B58[0]; else break; }
  return out + digits.reverse().map((d) => B58[d]).join("");
}

export interface DemoGate {
  /** http://127.0.0.1:<port> — point the tour here. */
  url: string;
  /** The did:key of the key generated for THIS run (never the hosted issuer's). */
  issuerDid: string;
  /** Whether the hosted relay answered (the web/phone door exists) — null until session-link was asked. */
  relayReachable: () => boolean | null;
  close(): Promise<void>;
}

export interface DemoGateOptions {
  /** Base URL of the hosted relay; null = offline (terminal-only). Default: the lab's API (decidio-api.onrender.com) - the demo's relay stays on the lab. */
  relayBase?: string | null;
  /** Milliseconds to wait for the relay on each call. */
  relayTimeoutMs?: number;
}

const DECISION_ID = "D-DEMO-1";
const D_NUMBER = "D·0001";

export async function startDemoGate(opts: DemoGateOptions = {}): Promise<DemoGate> {
  const relayBase = opts.relayBase === undefined ? "https://decidio-api.onrender.com" : opts.relayBase;
  const relayTimeoutMs = opts.relayTimeoutMs ?? 2000;
  const issuerKey = generateKeyPairSync("ed25519");
  const issuerRaw = Buffer.from(issuerKey.publicKey.export({ format: "der", type: "spki" })).subarray(-32);
  const issuerDid = "did:key:z" + b58(Buffer.concat([Buffer.from([0xed, 0x01]), issuerRaw]));
  const sealedAt = new Date().toISOString();

  let verdict: "approve" | "reject" | null = null;
  let withdrawnDemo = false;
  let decidedBy: string = "the human at the terminal";
  let lastReason: string = "quickstart";
  let relayCode: string | null = null;
  let relayOk: boolean | null = null;
  let committed: string | null = null;
  let claimedBy: string | null = null;

  const relayFetch = async (path: string, init: RequestInit = {}): Promise<any | null> => {
    if (!relayBase) return null;
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), relayTimeoutMs);
    try {
      const r = await fetch(`${relayBase.replace(/\/$/, "")}${path}`, { ...init, signal: ctl.signal, headers: { "content-type": "application/json", ...(init.headers ?? {}) } });
      if (r.status === 204) return {};
      if (!r.ok) return null;
      return await r.json().catch(() => ({}));
    } catch { return null; } finally { clearTimeout(t); }
  };

  const issueReceipt = (kind: "approval" | "denial") => {
    const canonical = jcsCanonicalize({ accountableParty: "[PERSON_1]", action: "payInvoice", amount: 86000, currency: "USD", decidedBy, reason: lastReason, recordKind: kind, recordSeries: "local-demo" });
    const contentHash = createHash("sha256").update(canonical, "utf8").digest("hex");
    const context = ["https://www.w3.org/ns/credentials/v2"];
    const doc = {
      "@context": context,
      type: ["VerifiableCredential", "DecidioAuthorityRecord"],
      issuer: issuerDid,
      validFrom: sealedAt,
      credentialSubject: { id: `urn:decidio:decision:${DECISION_ID}`, recordId: DECISION_ID, dNumber: D_NUMBER, contentHash, prevHash: null, recordCanonical: canonical },
    };
    const cfg = {
      "@context": context, type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022",
      created: sealedAt, verificationMethod: `${issuerDid}#${issuerDid.slice("did:key:".length)}`, proofPurpose: "assertionMethod",
    };
    const signingInput = Buffer.concat([
      createHash("sha256").update(Buffer.from(jcsCanonicalize(cfg), "utf8")).digest(),
      createHash("sha256").update(Buffer.from(jcsCanonicalize(doc), "utf8")).digest(),
    ]);
    return { ...doc, proof: { ...cfg, proofValue: "z" + b58(edSign(null, signingInput, issuerKey.privateKey)) } };
  };

  const server: Server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", async () => {
      let body: any; try { body = raw ? JSON.parse(raw) : undefined; } catch { body = undefined; }
      const path = (req.url ?? "").split("?")[0]!;
      const send = (o: unknown, status = 200) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
      try {
        if (path === "/api/health") return send({ ok: true, demo: true });
        if (path === "/api/did") return send({ did: issuerDid, method: "did:key", alg: "Ed25519", demo: true });
        if (path === "/api/decisions/cards") return send({ cards: [] });
        if (path === "/api/agents/register") return send({ agentId: body?.agentId, did: body?.did });
        if (path === "/api/workspace/agent-token" && req.method === "POST") return send({ token: "demo-agent-token", workspaceId: "local-demo", jti: `jti-demo-${randomBytes(4).toString("hex")}`, expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
        if (path === "/api/workspace/agent-token" && req.method === "GET") return send({ tokens: [] });
        if (/^\/api\/workspace\/agent-token\/[^/]+$/.test(path) && req.method === "DELETE") return send({ ok: true, changed: true });
        if (path === "/agent/authorize") {
          verdict = null;
          claimedBy = null;
          committed = typeof body?.requestCommitment === "string" && /^[0-9a-f]{64}$/.test(body.requestCommitment) ? body.requestCommitment : null;
          return send({ decision: "route", decisionId: DECISION_ID, receiptId: "R-DEMO-1", requestCommitment: committed });
        }
        if (path.startsWith("/agent/status/")) {
          if (!verdict && relayCode) {
            const r = await relayFetch(`/demo/relay/${relayCode}`);
            if (r && (r.verdict === "approve" || r.verdict === "reject")) { verdict = r.verdict; decidedBy = "the demo page (web or phone), through the relay"; lastReason = "decided on the demo page"; }
          }
          if (withdrawnDemo && !verdict) return send({ state: "rejected", reason: "quickstart: withdrawn — the tour stopped waiting", requestCommitment: committed });
          return send(verdict === "reject" ? { state: "rejected", reason: "quickstart: rejected by the approver", requestCommitment: committed } : { state: verdict === "approve" ? "approved" : "pending", requestCommitment: committed });
        }
        if (path.startsWith("/agent/claim/")) {
          const key = typeof body?.claimKey === "string" && /^[A-Za-z0-9._:-]{16,128}$/.test(body.claimKey) ? body.claimKey : null;
          if (!key) return send({ code: "VALIDATION", message: "claimKey must be 16-128 characters of letters, digits, dot, colon, underscore or dash" }, 400);
          if (verdict !== "approve") return send({ code: "NOT_CLAIMABLE", decisionId: DECISION_ID, state: verdict === "reject" ? "rejected" : "pending", message: "only a person's approval is collected here" }, 409);
          if (claimedBy && claimedBy !== key) return send({ code: "ALREADY_USED", decisionId: DECISION_ID, state: "approved", message: "another caller already collected this approval - ask again for a new one" }, 409);
          const again = claimedBy === key;
          claimedBy = key;
          return send({ ok: true, claimed: true, decisionId: DECISION_ID, again });
        }
        if (path.startsWith("/agent/withdraw/")) {
          if (verdict) return send({ code: "NOT_OPEN", state: verdict === "approve" ? "approved" : "rejected", decisionId: DECISION_ID }, 409);
          withdrawnDemo = true;
          return send({ ok: true, withdrawn: true, state: "rejected", decisionId: DECISION_ID, reason: "requester_stopped_waiting" });
        }
        if (/^\/api\/decisions\/[^/]+\/(approve|reject)$/.test(path)) {
          const already = verdict !== null;
          verdict = path.endsWith("/reject") ? "reject" : "approve";
          if (!already) {
            lastReason = typeof body?.reason === "string" && body.reason ? body.reason : "quickstart";
            decidedBy = /automated/i.test(lastReason) ? "automated: the --auto-approve-demo flag (not a human in the moment)" : "the human at the terminal";
          }
          if (relayCode && !already) void relayFetch(`/demo/relay/${relayCode}`, { method: "PUT", body: JSON.stringify({ verdict }) });
          return send({ ok: true, decisionId: DECISION_ID, sealed: true, ...(already ? { alreadyResolved: true } : {}) });
        }
        if (path === "/agent/confirm") return send({ ok: true, confirmation: "application_confirmed", recordId: DECISION_ID });
        if (path === "/demo/session-link") {
          const r = await relayFetch("/demo/relay", { method: "POST", body: JSON.stringify({ decisionId: DECISION_ID }) });
          if (r && typeof r.code === "string" && /^[0-9A-HJKMNP-TV-Z]{13}$/.test(r.code) && typeof r.link === "string" && /^https?:\/\//.test(r.link)) {
            relayCode = r.code; relayOk = true;
            return send({ status: "ok", link: r.link, qr: typeof r.qr === "string" ? r.qr : null, expiresAt: r.expiresAt ?? null });
          }
          relayOk = false;
          return send({ status: "unavailable", error: "the demo relay is unreachable — this run is terminal-only" }, 503);
        }
        if (/^\/api\/records\/[^/]+\/verify$/.test(path)) {
          const cred = issueReceipt(verdict === "reject" ? "denial" : "approval");
          return send({ dNumber: D_NUMBER, issuer: issuerDid, expectedIssuer: issuerDid, alg: "Ed25519", valid: true, signatureValid: true, contentBound: true, matchesRecord: true, payloadMatches: true, hash: cred.credentialSubject.contentHash, prevHash: null, credential: cred });
        }
        if (/^\/api\/records\/[^/]+$/.test(path)) return send({ record: { confirmation: verdict === "approve" ? { status: "application_confirmed", confirmed: true } : { status: "pending", confirmed: false } } });
        return send({ error: "not part of the local demo" }, 404);
      } catch (e: any) {
        return send({ error: String(e?.message ?? e) }, 500);
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as any).port as number;
  return {
    url: `http://127.0.0.1:${port}`,
    issuerDid,
    relayReachable: () => relayOk,
    close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }),
  };
}
