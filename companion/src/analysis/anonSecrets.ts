import { isBasicCredential, redactCliFlagSecrets, redactKeyedSecrets } from "./anonSecretKeys.js";

// The one-way secret pass of the anonymizer: credentials, API keys and tokens are replaced with a
// placeholder before text reaches the AI, and NOTHING maps the placeholder back. This is the
// counterpart of the reversible tokenizing in anonymize.ts, which calls redactSecretText().
//
// The vendor shapes are ported from socprime/logtotal-sanitizer (src/rules/definitions/secrets.ts,
// Apache-2.0, https://github.com/socprime/logtotal-sanitizer). Its "aggressive" high-entropy hex and
// base64 patterns are deliberately NOT ported: they would clobber hashes, and hashes are case IOCs.
//
// Detection grading (secretSpillRules.ts) keeps its own table on purpose: grading wants few false
// positives, redaction wants recall. Do not merge the two.

export const SECRET_PLACEHOLDER = "[REDACTED_SECRET]";

// Private-key blocks in every armor this is likely to meet: PEM (RSA / EC / DSA / OPENSSH /
// ENCRYPTED PKCS#8 / bare PKCS#8), the PGP form (which ends "PRIVATE KEY BLOCK", not "PRIVATE KEY"),
// and the SSH2 export form ("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----" — four dashes, inner spaces).
//
// The trailing alternation is the point. A key spilled into a log is exactly where the tail gets
// TRUNCATED, and demanding a matching END delimiter would then redact NOTHING at all — the whole
// body would go to the model in cleartext. When no END is found we fall back to the base64 body, so
// the key material still goes. Both branches are length-bounded (a 4096-bit RSA PEM is ~3.2 KB):
// that bounds the over-redaction a stray header can cause, and it keeps the scan linear, since an
// unbounded lazy scan re-walks the rest of the input for EVERY begin marker.
const PEM_PRIVATE_KEY =
  /-{4,5} ?BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)? ?-{4,5}(?:[\s\S]{0,8192}?-{4,5} ?END [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)? ?-{4,5}|[A-Za-z0-9+/=\s]{0,8192})/g;

// Fixed-shape secrets, replaced whole. Each is anchored on a vendor literal, so ordinary text and
// hashes cannot match. Order matters only where one prefix contains another (sk-proj- before sk-).
const VENDOR_SECRETS: RegExp[] = [
  /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g, // AWS access key id
  /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b/g, // JWT
  /\bgithub_pat_[A-Za-z0-9_]{22,}/g, // GitHub fine-grained token
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, // GitHub classic tokens
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
  /\bAIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g, // Google API key
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g, // Stripe secret / restricted key
  /(?<![A-Za-z0-9_-])sk-(?:proj|ant)-[A-Za-z0-9_-]{16,}/g, // OpenAI project / Anthropic key
  /(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{20,}(?![A-Za-z0-9_-])/g, // OpenAI legacy key
  /\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, // SendGrid key
  /\bnpm_[A-Za-z0-9]{36,}/g, // npm token
  // Twilio SID / key: AC or SK + 32 hex, ONLY beside a Twilio label — on its own the shape is just
  // hex. The look-ahead runs first, so the bounded look-behind is tried only at real candidates.
  /\b(?=(?:AC|SK)[0-9A-F]{32}\b)(?<=(?:twilio[^\n]{0,60}|\b(?:account_?sid|auth_?token)["']?[ \t]{0,4}[=:][ \t]{0,4}["']?))(?:AC|SK)[0-9A-F]{32}\b/gi,
];

// Slack incoming-webhook URL: the host stays (it says what the URL is), the path segments go.
const SLACK_WEBHOOK_RE =
  /(\bhooks\.slack\.com\/services\/)[A-Za-z0-9_-]{1,64}(?:\/[A-Za-z0-9_-]{1,64}){0,3}/gi;

// Azure SAS: `sig=` is a signature only in a query string that also carries the SAS version
// (`sv=`). A bare `sig=` elsewhere can be another protocol's value or an IOC, so it is kept.
const QUERY_RE = /\?[^\s"'<>#]{1,4096}/g;
const SAS_SIG_RE = /([?&]sig=)[^&\s"'<>#]{8,}/gi;
const SAS_VERSION_RE = /[?&]sv=/i;

// Bare auth-scheme credentials outside any `key:` assignment. Basic must decode to `user:pass`, and
// a bare Bearer value must contain a digit or a symbol — that is what keeps "Basic authentication
// failed" and "bearer authentication" readable. An all-letter opaque Bearer token is therefore only
// caught under a key (`Authorization:`): a recall trade-off for prose.
const BARE_BASIC_RE = /\b(Basic[ \t]{1,4})([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])/gi;
const BARE_BEARER_RE = /\b(Bearer[ \t]{1,4})([A-Za-z0-9._~+/=-]{8,})/gi;

// URL userinfo password (scheme://user:pass@host) — the password only; the user is tokenized later.
const URL_USERINFO_RE = /([a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)([^\s:@/]+)(@)/gi;

function redactPrefixed(text: string): string {
  let out = text.replace(SLACK_WEBHOOK_RE, (_m, host: string) => `${host}${SECRET_PLACEHOLDER}`);
  out = out.replace(QUERY_RE, (q) =>
    SAS_VERSION_RE.test(q) ? q.replace(SAS_SIG_RE, (_m, k: string) => `${k}${SECRET_PLACEHOLDER}`) : q,
  );
  out = out.replace(BARE_BASIC_RE, (m, scheme: string, cred: string) =>
    isBasicCredential(cred) ? `${scheme}${SECRET_PLACEHOLDER}` : m,
  );
  out = out.replace(BARE_BEARER_RE, (m, scheme: string, cred: string) =>
    /[0-9._~+/=-]/.test(cred) ? `${scheme}${SECRET_PLACEHOLDER}` : m,
  );
  return out.replace(
    URL_USERINFO_RE,
    (_m, a: string, _pw: string, c: string) => `${a}${SECRET_PLACEHOLDER}${c}`,
  );
}

/** One-way redact every credential in `text`. Pure; the result never contains a reversible token. */
export function redactSecretText(text: string): string {
  let out = text.replace(PEM_PRIVATE_KEY, SECRET_PLACEHOLDER);
  for (const re of VENDOR_SECRETS) out = out.replace(re, SECRET_PLACEHOLDER);
  out = redactPrefixed(out);
  out = redactCliFlagSecrets(out, SECRET_PLACEHOLDER);
  return redactKeyedSecrets(out, SECRET_PLACEHOLDER);
}
