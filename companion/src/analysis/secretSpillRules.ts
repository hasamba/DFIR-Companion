// Deterministic "credential material in plaintext" grading, applied to event TEXT rather than to a
// process command line. This is the surface-agnostic sibling of `tradecraftRules.ts`, and it exists
// for the same reason that module's Linux section does: the SAME secret graded differently — or not
// at all — depending on which importer happened to carry it.
//
// Measured on the EvidenceForge `spillage-full-matrix-test` benchmark (11 planted secrets across 5
// surfaces): every one was extracted correctly, but only 2 reached the forensic timeline, and both
// only because they happened to ride inside a Windows Sysmon EID 1 process-create event that the
// Sysmon grader already scored. The AWS key in bash history, the Slack token and shared secret in
// syslog, the GCP key / fine-grained PAT / Stripe key / JWT in web-log URLs and Referer headers,
// and the database URI in Linux ECAR process telemetry ALL graded Info — and Info is demoted to the
// analyst-only super-timeline, which AI synthesis never reads. Nine of eleven spills were therefore
// invisible to the model no matter how good the model was. Grading belongs here, in one shared
// table every importer consults, not in whichever importer got lucky.
//
// Severity contribution is Medium, never High, and that is deliberate. A structurally-valid token
// in a log line is a real exposure and must be VISIBLE to synthesis, but it is a lead rather than a
// verdict: the value may be revoked, a test fixture, or an example in documentation. This mirrors
// the "weak" tier in tradecraftRules (dual-use → Medium) and the same call bashHistoryImport
// already makes for `cat .env`.
//
// False-positive discipline (see the "does not fire on ordinary text" tests): every rule is
// anchored on a vendor-specific literal prefix plus a minimum length of key material, so ordinary
// auth chatter ("Failed password for invalid user admin", "authentication failure") cannot match.
// Values that are already masked / redacted are excluded — re-flagging a redacted value
// manufactures a Medium out of evidence that the secret was handled correctly. Masking is judged
// per OCCURRENCE, never per line: the first version ran the mask check over the whole line once,
// before any rule, and a `note=REDACTED` anywhere on the line hid a real token beside it (#930
// item 3 found it while reusing this table on decoded request targets).
//
// Pure + table-driven + unit-tested. No AI.

export interface SecretSpillRule {
  /** Vendor/family label, matching the EvidenceForge spillage family names. */
  family: string;
  re: RegExp;
}

// A run of characters that reads as MASKED rather than as key material: three or more consecutive
// mask characters, or a bracketed redaction marker. Checked against each occurrence's own text.
const MASKED = /\*{3,}|x{6,}|•{3,}|\[?\bREDACTED\b\]?|<[A-Z_]{3,}>|\.{5,}/i;

// Key material must not be a single repeated character (AAAAAAAA…) — generator placeholders and
// column-padding both look like that, and neither is a secret.
const DEGENERATE = /^(.)\1+$/;

export const SECRET_SPILL_RULES: SecretSpillRule[] = [
  // ───────────── Cloud provider keys ─────────────
  // AWS access key id: AKIA/ASIA/AGPA/AIDA + 16 uppercase-alnum. The prefix is assigned by AWS and
  // does not occur in prose, so the literal + fixed length is enough on its own.
  { family: "aws_iam", re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b/ },
  // Google/GCP API key: AIza + 35 url-safe chars.
  { family: "gcp_api_key", re: /\bAIza[A-Za-z0-9_-]{35}\b/ },

  // ───────────── Source-control tokens ─────────────
  // Fine-grained PAT first: `github_pat_` would also satisfy a loose `ghp_`-style rule, and matching
  // the more specific family keeps the reported label accurate.
  { family: "github_fine_pat", re: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/ },
  // Classic PAT / OAuth / refresh / server / user-to-server tokens: 36+ chars after the prefix.
  { family: "github_pat", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/ },

  // ───────────── SaaS tokens ─────────────
  // Slack bot/user/app/refresh token: xoxb- / xoxp- / xoxa- / xoxr- / xoxs- plus at least two
  // hyphen-separated segments, the last of which is the secret half.
  { family: "slack_token", re: /\bxox[baprs]-[A-Za-z0-9]{8,}-[A-Za-z0-9-]{16,}\b/ },
  // Stripe secret / restricted key. The publishable `pk_` prefix is deliberately NOT here: it is
  // designed to be public and appears in every checkout page's source.
  { family: "stripe_key", re: /\b(?:sk|rk)_(?:test|live)_[A-Za-z0-9]{16,}\b/ },

  // ───────────── Structured tokens ─────────────
  // JWT: three base64url segments. The header segment is anchored on the `eyJ` that any JSON header
  // base64-encodes to, and BOTH remaining segments are required so a bare header (which carries no
  // secret) does not match.
  { family: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },

  // ───────────── Connection strings ─────────────
  // A database/broker URI carrying inline credentials — `scheme://user:password@host`. The password
  // group is required, so an ordinary credential-free DSN (`postgres://db-01:5432/reports`) does not
  // match. `:` and `@` are excluded from the password class so a bare `host:port` cannot masquerade.
  // The password is the captured value, so masking is judged on it alone — a redacted USERNAME
  // beside a real password is still a spill.
  {
    family: "db_uri",
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|jdbc:[a-z]+|ftp|sftp):\/\/[^\s:/@]+:([^\s:/@]{4,})@/i,
  },

  // ───────────── Generic assigned secrets ─────────────
  // The catch-all, and the only rule that is not anchored on a vendor literal — so it is the most
  // constrained. A credential NOUN, then an assignment (`=`/`:`) or a single space, then 12+ chars
  // of material that must contain BOTH cases plus a digit or punctuation mark. That last constraint
  // is what separates `shared secret EvidenceForgeFake-wPndDbHjZm!` (flagged) from
  // `password authentication failed` and `Starting Secret Service daemon` (not flagged) — ordinary
  // English words following the noun are single-case and carry no digits or symbols.
  {
    family: "password_generic",
    re: /\b(?:pass(?:word|wd|phrase)?|pwd|secret|api[_-]?key|api[_-]?token|auth[_-]?token|access[_-]?token|bearer)\b["']?\s*[=:]?\s*["']?([A-Za-z0-9][A-Za-z0-9!@#$%^&*()_+=.,\/~-]{11,})/i,
  },
];

// Every occurrence of the rule is inspected until one is real or the text is exhausted. A
// masked-shaped occurrence — `AKIAXXXX…` (a vendor's own masked example), `password=****…` — is
// evidence of correct handling and is skipped, but it must not hide a real token later on the same
// line, and no occurrence cap is applied: a cap of N is exactly N decoys before the real key.
// Exhaustion is bounded by the caller's text — every caller passes ONE line (a command, a syslog
// message, a request line + Referer). The global regex is built per call from the rule's source: a
// shared `/g` instance carries `lastIndex` between calls, and a leaked index skips the start of the
// next line.
function hasRealOccurrence(rule: SecretSpillRule, text: string): boolean {
  const re = new RegExp(rule.re.source, rule.re.flags.includes("g") ? rule.re.flags : `${rule.re.flags}g`);
  for (let m = re.exec(text); m; m = re.exec(text)) {
    // Masking is judged on the secret-bearing VALUE (the capture group where a rule has one), not
    // the whole match: a redacted username beside a real password is still a spill. The generic
    // rule's value must also clear the key-material gate.
    const material = m[1] ?? m[0];
    if (rule.family === "password_generic" ? looksLikeKeyMaterial(material) : !MASKED.test(material))
      return true;
    // A rejected occurrence may have swallowed the NEXT value — the generic value class runs over
    // `&`, `=` and `,`, so `TOKEN=xxxxxxxxxxxx&TOKEN=<real>` is one match whose masked head hides
    // the real tail. Resume just past the rejected match's START, not its end.
    re.lastIndex = m.index + 1;
  }
  return false;
}

// Extra gate for the generic rule only: the captured value must look like key material rather than
// like the next English word in a sentence.
function looksLikeKeyMaterial(value: string): boolean {
  if (value.length < 12) return false;
  if (DEGENERATE.test(value)) return false;
  if (MASKED.test(value)) return false;
  const hasUpper = /[A-Z]/.test(value);
  const hasLower = /[a-z]/.test(value);
  const hasDigitOrSymbol = /[0-9!@#$%^&*()_+=.,\/~-]/.test(value);
  return hasUpper && hasLower && hasDigitOrSymbol;
}

/**
 * The credential families a piece of event text exposes in plaintext, or null.
 *
 * Surface-agnostic by design: callers pass whatever text they already build for the event
 * description (a shell command, a syslog message, a request line + Referer, a process command
 * line), so the same secret grades identically regardless of which sensor reported it.
 */
export function secretSpillSignal(text: string): { families: string[]; mitre: string[] } | null {
  if (!text || !text.trim()) return null;

  const families = new Set<string>();
  for (const rule of SECRET_SPILL_RULES) {
    if (hasRealOccurrence(rule, text)) families.add(rule.family);
  }
  if (!families.size) return null;
  // T1552.001 (Unsecured Credentials: Credentials In Files) is the technique every surface here
  // maps to — the credential is at rest in a log, a history file, or a URL that gets logged.
  return { families: [...families], mitre: ["T1552.001"] };
}
