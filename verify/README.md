# @decidio/verify

**Standalone, zero-dependency verifier for Decidio Authority Receipts.** Verify a sealed receipt's signature, content binding, and chain order **offline — with no Decidio dependency**. A record you can verify only with the vendor's software isn't really owned; this is what makes "the customer owns the record" true rather than rhetorical.

```bash
# A receipt from Decidio's hosted service: no flag needed - the trust anchor is built in.
npx @decidio/verify receipt.json
npx @decidio/verify r1.json r2.json r3.json      # each + the chain order (one issuer end to end)

# Any other issuer (a self-hosted Decidio): pin its DID yourself - take it from that host's
# <api>/api/did, never from the receipt. An explicit --issuer always wins over the built-in anchor.
npx @decidio/verify --issuer did:key:z6Mk… receipt.json

# A structural check only is a named choice, and its verdict carries the UNPINNED warning:
npx @decidio/verify --allow-unpinned receipt.json
```

**Every run prints its trust anchor first** — the issuer the verdict is pinned to, and where that
came from (`--issuer`, or `built in: Decidio staging lab, decidio-api.onrender.com`). The
built-in list (`KNOWN_ISSUERS`, exported) holds Decidio's own deployments, each published at its
host's `/api/did`: production, `did:key:z6MkpBwpAT98VAqg2UpiSGJZieg7DGQpoNkdioDUEo4kQXnJ`
(https://decidio-prod-api.onrender.com/api/did), and staging (the lab),
`did:key:z6MkmLGeR5NjJ87a1yU5ygqju49CtnUrt38esqM54Y9tXnKq` (https://decidio-api.onrender.com/api/did).
The receipt's own issuer field only picks between them; the signature must then match. With no `--issuer`, a receipt naming any other issuer is
refused (exit 2) with that remedy: a receipt's own `issuer` field is a claim, never a trust anchor,
so the verifier never pins to it. The list deliberately does **not** include the verification kit's
published sample issuer — its private key is public, so trusting it would verify forgeries.

### What VALID means (read this before scripting on the exit code)
Verification answers two separate questions, and only one of them is free:

- **Is this document internally consistent and unmodified?** Answered with `--allow-unpinned`.
- **Was it issued by the party you expect?** Answered by the trust anchor — the built-in Decidio
  issuer, or the one you pin with `--issuer`.

A receipt signed by a **self-generated key** is internally consistent, so an unpinned check
reports `VALID` and exits `0` — correctly, because nothing was asked about *who* signed it. That is
why the CLI never runs unpinned unless you say `--allow-unpinned`: an external review forged exactly
such a receipt and the exit code said yes. A
forged pair even reports an intact chain: a chain proves the links hold, not the origin. So
`decidio-verify receipts/*.json && promote` promotes only receipts issued by the trust anchor the
run prints; a wrong signer exits non-zero, naming the issuer as the problem rather than blaming the
content.

```ts
import { verifyReceipt, verifyChain } from "@decidio/verify";
const r = verifyReceipt(vc);   // { valid, issuer, contentBound, recordId, reason? }
```

## What it checks (offline, using only the public DID in the receipt)
1. **Content binding** — re-derives `sha256((prevHash||"") + recordCanonical)` and confirms it equals the signed `contentHash`, so the signature commits to the actual content (tamper-evident).
2. **Signature** — verifies a W3C Data Integrity proof (`DataIntegrityProof`, cryptosuite
   `eddsa-jcs-2022`, Ed25519 via `did:key`) over the WHOLE receipt: the signing input is
   `SHA-256(JCS(proof options))` followed by `SHA-256(JCS(receipt without proof))`, per
   [Data Integrity EdDSA Cryptosuites v1.0](https://www.w3.org/TR/vc-di-eddsa/) §3.3.
   Verification needs only SHA-256, Ed25519, base58 and RFC 8785 — no JSON-LD, no context
   fetching, no DID resolution, no network.
   *Receipts sealed before 2026-08-04 carry a pre-standard Decidio format under the name
   `eddsa-2022`; those are refused with an explicit reason, not reported as tampered.*
3. **Chain** (`verifyChain`) — each receipt's `prevHash` links to the prior `contentHash`, and every receipt independently verifies.

Signature + content + chain verify **offline**. Revocation/status is a separate, network-bound check by design — a receipt is tamper-evidence, not a liveness check.

## One policy check, proven against the seal (`verifyCheckEntry`)
An agent receipt's sealed record names, in the clear, the policies that **decided** the request
(`authority.decidingPolicies`: every policy that blocked it, else every one that sent it to a person,
else — every policy passed — the first of them alone), and commits to **every** policy that checked it
with one root (`authority.checkCommitment`, algorithm `decidio.check-merkle.v1`) that says neither
which policies nor how many. Decidio hands a person each check they may see — its facts, a salt and a
proof — and anyone can confirm it offline against the receipt:

```ts
import { verifyCheckEntry } from "@decidio/verify";
const r = verifyCheckEntry(vc, { entry, salt, proof }, "did:key:z6Mk…"); // { valid, policyId, result, reason? }
```

It verifies the receipt first (pinned when you pass the issuer), then folds the entry's leaf —
`SHA-256(salt ‖ JCS(entry))` — through the five sibling hashes of its proof, each node
`SHA-256(0x01 ‖ min ‖ max)`, and compares the result with the sealed root. The 32 leaves are the
entries and the record's keyed padding, sorted, so a proof's length and position say nothing about how
many policies were checked. A valid entry proves what that one policy concluded about this request —
nothing about any other. Receipts sealed before Decidio committed to its checks carry no root and
are reported as such.

## The whole check, proven complete (`verifyCheckComplete`)
An entry proves it is in the commitment; it cannot prove that no other entry was left out. For that,
Decidio hands the **workspace's admin** — who may see every policy, so is shown every entry — the
record's **completeness key**: the key of that record's padding, and of no other record's. With it,
the full list rebuilds the sealed root:

```ts
import { verifyCheckComplete } from "@decidio/verify";
// `check` is the admin's answer from GET /api/records/:id/check: { entries, completenessKey, … }
const r = verifyCheckComplete(vc, check, "did:key:z6Mk…"); // { valid, count, policyIds, reason? }
```

It verifies the receipt, computes each entry's leaf, adds the 32 − k pads
`HMAC-SHA256(completenessKey, JCS([i]))` for i = 0, 1, …, sorts the 32 leaves and rebuilds the tree.
It is valid only when that root is the sealed one: an entry left out, added, given twice or changed,
or a wrong key, and the root moves. The key tells its holder how many policies checked the request,
which is why Decidio gives it to no one but the admin. A verifier that has only `verifyCheckEntry`
checks the same receipts' entries exactly as before: to it, a pad is just a sibling hash.

`verifyCheckEntry` and `verifyCheckComplete` are in this TypeScript package only; the Python verifier
does not have them yet.

## Parity
A Python verifier ships in `decidio[verify]` (`python -m decidio.verify`). Both verifiers accept the **same** real Decidio seals — proven in the cross-language conformance suite. Zero dependencies beyond `node:crypto` (TS) / `cryptography` (Python).

