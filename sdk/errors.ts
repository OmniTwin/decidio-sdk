const RETRYABLE_STATUS = (status: number) => status === 408 || status === 429 || (status >= 500 && status !== 501);

function sideEffectNote(endpoint: string, code?: string, unanswered = false): string {
  if (endpoint.startsWith("/agent/confirm")) {
    if (code === "TERMINALLY_DENIED" && unanswered) {
      return " Nobody decided this request by its deadline, so no authority was granted - and your action appears to have run anyway. Decidio will NOT attach execution evidence to it. Do NOT re-run it — find out why the action executed without an approval.";
    }
    if (code === "TERMINALLY_DENIED") {
      return " A human DENIED this decision, and your action appears to have run anyway. Decidio recorded the refusal and will NOT attach execution evidence to a denied decision. Do NOT re-run it — investigate why the action executed without an approval.";
    }
    if (code === "NOT_AUTHORIZED") {
      return " This decision is not an approved, sealed decision, so no execution evidence can attach to it yet. If your action already ran, it ran WITHOUT authority — do NOT re-run it; investigate. If you are confirming early, wait for the approval and confirm then.";
    }
    return " Your action ALREADY RAN — only its report failed. Do NOT re-run it.";
  }
  if (endpoint.startsWith("/agent/status")) {
    return " This call is a read, so it changed nothing; the decision itself is unaffected.";
  }
  return " Nothing was routed or executed.";
}

function serverSaid(body: unknown): string | null {
  const b = body as { message?: unknown; error?: unknown } | null;
  const said = typeof b?.message === "string" ? b.message : typeof b?.error === "string" ? b.error : null;
  return said ? said.slice(0, 400) : null;
}

export class DecidioHttpError extends Error {
  readonly retryable: boolean;
  constructor(public status: number, public endpoint: string, public body?: unknown) {
    const credential = status === 401 || status === 403;
    const retryable = !credential && RETRYABLE_STATUS(status);
    const code = typeof (body as { code?: unknown } | null)?.code === "string" ? (body as { code: string }).code : undefined;
    super(
      `[decidio] ${endpoint} refused this call (HTTP ${status})` +
      (credential
        ? ` — the credential was rejected. The agent token may have expired or been revoked (re-running \`init\` for the same agent revokes the previous one). Mint a fresh one: npx @decidio/sdk init <agent-name>, then restart this process.`
        : status === 402
          ? ` — your workspace's plan doesn't cover this. It isn't a sign-in problem: signing in again won't change it.${serverSaid(body) ? ` Decidio says: ${serverSaid(body)}` : ""}`
        : code === "AGENT_REMOVED"
          ? ` — this agent was removed from its workspace, so it can't make new requests (the requests it made before stay as they are). Register a new agent under a new name: npx @decidio/sdk init <new-name>, then restart this process.`
        : retryable
          ? (/\/agent\/confirm/.test(endpoint)
            ? ` — this looks transient. Your action ALREADY RAN; do NOT re-run it — only its report failed to land, and the door's own note says whether a report was kept to re-send.`
            : /\/agent\/status/.test(endpoint)
              ? ` — this looks transient; polling again is safe (a status read changes nothing).`
              : /\/agent\/authorize/.test(endpoint)
                ? ` — this looks transient. This SDK already retried it with the same request key (a request still waiting is answered with the one already waiting); retrying is safe and can never double-execute.`
                : ` — this looks transient; retrying is safe and can never double-execute.`)
          : ` — the server refused the request itself, so retrying it unchanged will fail the same way. Fix the request (or the decision it names) first.`) +
      sideEffectNote(endpoint, code, (body as { closedBy?: { reason?: unknown } | null } | null)?.closedBy?.reason === "unanswered"),
    );
    this.name = "DecidioHttpError";
    this.retryable = retryable;
  }
}

/** ONE rule for what counts as a usable decision id, returning a REASON rather than throwing, so
 *  every door can apply the same check and raise its own error type. (`resume.ts` cannot import
 *  `index.ts`, which is why the check was copy-pasted into four places and drifted.)
 *
 *  All four copies tested truthiness only, so `"   "` passed every one of them: the blocking path
 *  would poll `/agent/status/%20%20%20`, the durable path would park under a whitespace key, and
 *  the confirmation would attest a decision nobody can look up. Control characters are refused for
 *  the same reason a reason-string is sanitised — an id goes into a URL path, a filename and an
 *  audit line. Nothing is silently trimmed: an id that needs trimming is not the id the server
 *  sent, and quietly rewriting an identifier is how two systems end up disagreeing about which
 *  decision they mean. */
export function decisionIdProblem(raw: unknown): string | null {
  if (typeof raw !== "string") return `it is ${raw === null ? "null" : typeof raw}, not a string`;
  if (raw.length === 0) return "it is empty";
  if (raw.trim().length === 0) return "it is only whitespace";
  if (raw !== raw.trim()) return "it has leading or trailing whitespace (ids are used verbatim in URLs, filenames and audit lines — this SDK will not silently trim one)";
  for (const ch of raw) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x20 || cp === 0x7f) return "it contains control characters";
  }
  if (raw.length > 128) return `it is ${raw.length} characters long (limit 128)`;
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(raw)) return "it is not letters, digits, dot, dash or underscore starting with a letter or digit (an opaque id needs nothing else, and every other character is a way to make two different strings look like the same decision)";
  return null;
}
