#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { builtInAnchor, KNOWN_ISSUERS, pinRequiredMessage, runVerify } from "./verify.js";

const VERSION: string = (() => {
  try { return createRequire(import.meta.url)("../package.json").version; } catch { return "unknown"; }
})();
const USAGE = `decidio-verify — verify Decidio Authority Receipts OFFLINE (no network, no account)

usage: decidio-verify [--issuer <did:key>] <receipt.json> [more.json ...]

  One file  → verify that receipt (signature + content binding).
  Many files → verify each AND their chain order (segment semantics).
  Every run prints its TRUST ANCHOR first - the issuer the verdict is pinned to:
  (no flag)            the built-in Decidio issuer: ${KNOWN_ISSUERS.map((k) => `${k.did} (${k.label}, ${k.host})`).join("; ")}.
                       A receipt from any other issuer is refused (exit 2) until you pin one - its own
                       issuer field is a claim, never a trust anchor.
  --issuer <did:key>   pin the expected issuer yourself (a self-hosted Decidio: take the DID from that
                       host's /api/did, never from the receipt). Wins over the built-in anchor.
  --allow-unpinned     structural check only; the verdict carries the UNPINNED warning.

Exit codes: 0 all verified · 1 verification failed or file unreadable · 2 usage error, or no trust
anchor for these receipts.
The same implementation ships inside @decidio/sdk as \`npx @decidio/sdk verify\`.`;

/** EXPORTED so the argument parser can be tested without spawning a process. It was private, and
 *  the only way to exercise a flag was to run the binary — which is why the `=`-form bug (a
 *  silently dropped `--issuer=did:...` reporting VALID, unpinned) shipped in the first place. The
 *  Python twin already exported `run` for exactly this reason. */
export function main(argv: string[]): number {
  const args = argv.slice(2);
  if (args[0] === "--version" || args[0] === "-v" || args[0] === "-V" || args[0] === "version") { console.log(VERSION); return 0; }
  if (args[0] === "--help" || args[0] === "-h" || args[0] === "help") { console.log(USAGE); return 0; }
  if (args.length === 0) { console.error(USAGE); return 2; }
  let expectedIssuer: string | undefined;
  let allowUnpinned = false;
  const files: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") { files.push(...args.slice(i + 1)); break; }
    if (a === "--allow-unpinned") { allowUnpinned = true; continue; }
    if (a === "--issuer") {
      const v = args[i + 1];
      if (v === undefined || v === "" || v.startsWith("-")) {
        console.error("✘ --issuer needs a did:key value (a bare or EMPTY --issuer must not silently verify unpinned).");
        return 2;
      }
      if (expectedIssuer !== undefined && expectedIssuer !== v) { console.error(`✘ --issuer given twice with different values (${expectedIssuer} then ${v}) — refusing to choose which one you meant to pin to.`); return 2; }
      expectedIssuer = v; i++;
    } else if (a.startsWith("--issuer=")) {
      const v = a.slice("--issuer=".length);
      if (!v) { console.error("✘ --issuer needs a did:key value (a bare --issuer must not silently verify unpinned)."); return 2; }
      if (expectedIssuer !== undefined && expectedIssuer !== v) { console.error(`✘ --issuer given twice with different values (${expectedIssuer} then ${v}) — refusing to choose which one you meant to pin to.`); return 2; }
      expectedIssuer = v;
    } else if (a.startsWith("-")) {
      console.error(`✘ unknown option "${a}" — refusing to guess (a flag you meant to matter must never be silently ignored).`);
      console.error("usage: decidio-verify [--issuer <did:key>] <receipt.json> [more.json ...]   (or --allow-unpinned)");
      return 2;
    } else {
      files.push(a);
    }
  }
  if (files.length === 0) {
    console.error("usage: decidio-verify [--issuer <did:key>] <receipt.json> [more.json ...]   (or --allow-unpinned)");
    return 2;
  }
  if (expectedIssuer !== undefined && allowUnpinned) { console.error("✘ --allow-unpinned and --issuer together — an unpinned check and a pinned one are different questions; ask one."); return 2; }
  const texts = new Map<string, string>();
  for (const f of files) {
    try { texts.set(f, readFileSync(f, "utf8")); }
    catch (e: any) { console.error(`✘ cannot read ${f}: ${e?.code === "ENOENT" ? "no such file" : e?.message ?? e} (nothing was verified)`); return 1; }
  }
  const read = (f: string) => texts.get(f)!;
  let anchor = expectedIssuer !== undefined ? "--issuer" : undefined;
  if (expectedIssuer === undefined && !allowUnpinned) {
    const pick = builtInAnchor(files, read);
    if ("refusal" in pick) { console.error(pinRequiredMessage("decidio-verify", pick.refusal)); return 2; }
    expectedIssuer = pick.anchor.did;
    anchor = `built in: ${pick.anchor.label}, ${pick.anchor.host}`;
  }
  const { ok, lines } = runVerify(files, expectedIssuer, read, anchor);
  for (const l of lines) console.log(l);
  return ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(main(process.argv));
