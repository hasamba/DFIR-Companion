// The Terraform client note on CloudTrail rows (#2607).
//
// A CloudTrail row shows its user agent in a clipped `[ua: …]` tail — 30 characters on IAM and
// logging rows, 40 on SSM rows, 80 elsewhere. Terraform's user agent starts
// "APN/1.0 HashiCorp/1.0 Terraform/…", so the 30-character clip ends at "Terrafor" and the word never
// appears; newer provider builds put "aws-sdk-go-v2/…" first and push it past 80 too. Synthesis then
// read Terraform's set-up and state-refresh calls as hands-on attacker activity.
//
// So the importer reads the RAW field and, when it carries a Terraform token, ends the row with one
// FIXED note. The note never echoes caller text, and it says the user agent CLAIMS Terraform: the
// field is caller-chosen, so an attacker can set it — or run real Terraform. Severity, MITRE and the
// aggregation key never change because of it.
//
// It is the LAST element of the description, inside the 600-character budget each renderer
// reserves for it, because the model-facing shortener keeps the head and the last 40 characters
// (promptDescription.ts) — a note in the middle of a long row would be cut out of the prompt.
//
// The note is only worth anything if caller text cannot produce it. The echoed user agent has its
// brackets swapped for parentheses (shownUserAgent), and every rendered body is scrubbed of the note
// text before the real one is appended (withClientHint), so a policy document or tag selector that
// spells it out reads "(user agent claims Terraform)" instead.

/** Characters of the raw user agent scanned. Real Terraform agents are ~300; a token past this is not read. */
export const CLIENT_HINT_SCAN_MAX = 1024;

/** The fixed note. Short enough to sit inside the 40-character tail promptDescription keeps. */
export const TERRAFORM_CLAIM_HINT = "[user agent claims Terraform]";

const TERRAFORM_TOKEN_RE = /terraform\/|terraform-provider-/i;
const FORGED_HINT_RE = /\[(\s*user agent claims terraform\s*)\]/gi;
// The note on an importer's AWS row, optionally behind the Sigma title the import grade prefixes.
const AWS_ROW_HINT_RE = /^(?:Sigma: [^\n]*? - )?AWS [^\n]*\[user agent claims Terraform\]/;

/** True when the raw user agent's first CLIENT_HINT_SCAN_MAX characters carry a Terraform token. */
export function terraformClaimed(userAgent: unknown): boolean {
  if (typeof userAgent !== "string" || !userAgent) return false;
  return TERRAFORM_TOKEN_RE.test(userAgent.slice(0, CLIENT_HINT_SCAN_MAX));
}

/** The note for a raw user agent: TERRAFORM_CLAIM_HINT, or "" when it makes no claim. */
export function clientHint(userAgent: unknown): string {
  return terraformClaimed(userAgent) ? TERRAFORM_CLAIM_HINT : "";
}

/** The user agent as a row echoes it: brackets become parentheses, clipped to `max`. */
export function shownUserAgent(client: string, max: number): string {
  return client.replace(/\[/g, "(").replace(/\]/g, ")").slice(0, max);
}

/** The room a renderer reserves at the end of its budget for the note and its separator. */
export function hintRoom(hint: string): number {
  return hint ? hint.length + 1 : 0;
}

/** The body with any spelled-out copy of the note neutralised (same length), then the real note. */
export function withClientHint(body: string, hint: string): string {
  const scrubbed = body.replace(FORGED_HINT_RE, "($1)");
  return hint ? `${scrubbed} ${hint}` : scrubbed;
}

/** True when an AWS row's description carries the generated note. */
export function carriesTerraformClaim(description: string): boolean {
  return AWS_ROW_HINT_RE.test(description ?? "");
}

/** Clip to `max`, keeping a trailing note whole: a prefix (a Sigma title) must not push it off. */
export function clipKeepingClientHint(text: string, max: number): string {
  if (text.length <= max) return text;
  const tail = ` ${TERRAFORM_CLAIM_HINT}`;
  if (!text.endsWith(tail) || max <= tail.length) return text.slice(0, max);
  return `${text.slice(0, max - tail.length)}${tail}`;
}
