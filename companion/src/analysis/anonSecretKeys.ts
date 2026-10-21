import {
  isFlagValue,
  readBare,
  readQuoted,
  readSecretArray,
  skipSpaces,
  type Span,
} from "./anonSecretValues.js";

// One-way redaction of a secret by the NAME it is assigned to: `client_secret=…`, a JSON
// `"accessToken": "…"`, a Python repr `'password': '…'`, escaped JSON `\"apiKey\":\"…\"`, and
// `--password …` on a command line. The key stays; only the value goes.
//
// The key tables are ported from socprime/logtotal-sanitizer (src/rules/definitions/secrets.ts,
// Apache-2.0, https://github.com/socprime/logtotal-sanitizer) with two deliberate removals:
// `signature` (AV and EDR logs write `Signature: Trojan:Win32/…` — a detection name, an IOC) and
// `auth` (too generic in service logs). `passwordHash` / `pwdHash` stay: a dumped credential hash
// is credential material. File hashes sit under non-secret keys (`SHA256=`, `Hashes:`) and are kept.

// Keys are compared after this normalization, so `client_secret`, `client-secret`, `Client.Secret`
// and `clientSecret` are one key.
function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-_. ]/g, "");
}

const EXACT_KEYS = new Set(
  [
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "token",
    "authorization",
    "bearer",
    "apiKey",
    "accessToken",
    "refreshToken",
    "idToken",
    "clientSecret",
    "privateKey",
    "secretKey",
    "apiSecret",
    "credentials",
    "xApiKey",
    "awsSecretAccessKey",
    "accessKey",
    "accessKeyId",
    "secretAccessKey",
    "awsSessionToken",
    "xAmzSecurityToken",
    "bearerToken",
    "authToken",
    "authKey",
    "apiToken",
    "appSecret",
    "consumerSecret",
    "oauthToken",
    "oauthTokenSecret",
    "masterKey",
    "encryptionKey",
    "sharedKey",
    "sharedSecret",
    "webhookSecret",
    "signingSecret",
    "signingKey",
    "connectionString",
    "connStr",
    "passphrase",
    "passwordHash",
    "pwdHash",
    "otp",
    "totp",
    "mfaCode",
    "oneTimePassword",
    "verificationCode",
    "recoveryCode",
    "sshKey",
    "subscriptionKey",
    "ocpApimSubscriptionKey",
    "xAuthToken",
    "xAccessToken",
    "proxyAuthorization",
    "sasToken",
    "vaultToken",
    "xVaultToken",
    "jwt",
    "samlResponse",
    "samlAssertion",
    "pinBlock",
  ].map(normalizeKey),
);

const KEY_FRAGMENTS = [
  "password",
  "passwd",
  "secret",
  "apikey",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "authtoken",
  "bearertoken",
  "privatekey",
  "credential",
  "passphrase",
  "connectionstring",
];

// A fragment match is NOT a secret when the key names metadata ABOUT the secret. AD recon output
// (`passwordLastSet`, `PasswordNeverExpires`, `PasswordNotRequired`) and file evidence
// (`credentialDumpPath`, `privateKeyFile`) are what the analyst needs to read. Suffix-only: a
// substring test would let `storageSecret` or `passwordResetToken` escape. Exact keys never lose.
const METADATA_SUFFIXES = [
  "lastset",
  "changed",
  "expires",
  "expired",
  "expiration",
  "notrequired",
  "required",
  "policy",
  "age",
  "length",
  "count",
  "history",
  "complexity",
  "path",
  "file",
  "filename",
  "dir",
  "directory",
  "source",
  "type",
  "name",
  "id",
];

export function isSecretKey(key: string): boolean {
  const k = normalizeKey(key);
  // A plural key (`recoveryCodes`, `tokens`) holds a list of the same secret.
  if (EXACT_KEYS.has(k) || (k.endsWith("s") && EXACT_KEYS.has(k.slice(0, -1)))) return true;
  if (METADATA_SUFFIXES.some((s) => k.endsWith(s))) return false;
  return KEY_FRAGMENTS.some((f) => k.includes(f));
}

// An assignment: an optionally quoted identifier key, then `:` or `=`. The look-behind stops a
// suffix of a longer key (or of a `--flag`) from reading as a key of its own. Pretty-printed JSON
// puts newlines around the separator, so whitespace there is unbounded; nothing after it can
// backtrack, so each key start still scans its own blank run once.
const KEY_RE = /(?<![\w.\\-])(\\"|"|')?([A-Za-z][\w.-]{0,127})\1(\s*)[:=](\s*)/g;

const CLI_FLAG_RE =
  /(?<![\w-])--(?:password|secret|token|api-key|apikey|access-token|client-secret)(?:[ \t]{1,16}|=)/gi;

// An auth scheme word inside a value: the scheme is kept and the credential after it goes.
const SCHEME_RE = /^(bearer|basic|negotiate|ntlm|digest)([ \t]+)/i;

/**
 * True when a Basic credential decodes to `user:pass`. Real Basic credentials always do, and this
 * is what keeps `Authorization: Basic authentication failed` readable. UTF-8, so a non-ASCII
 * username still counts; a decode with replacement or control characters is not a credential.
 */
export function isBasicCredential(b64: string): boolean {
  if (!/^[A-Za-z0-9+/]{4,}={0,2}$/.test(b64)) return false;
  const decoded = Buffer.from(b64, "base64").toString("utf8");
  return decoded.includes(":") && !/[\u0000-\u001f\u007f�]/.test(decoded);
}

// The part of a value to redact once an auth scheme word is taken into account. Digest carries
// named parameters, not one credential, so it is kept and its parameters are scanned as keys.
function schemeAware(text: string, span: Span, quoted: boolean, placeholder: string): Span[] | null {
  const value = text.slice(span[0], span[1]);
  const scheme = SCHEME_RE.exec(value);
  if (quoted) {
    if (!scheme) return [span];
    if (scheme[1].toLowerCase() === "digest") return [];
    const from = span[0] + scheme[0].length;
    const cred = text.slice(from, span[1]);
    if (cred.startsWith(placeholder)) return [];
    if (scheme[1].toLowerCase() === "basic" && !isBasicCredential(cred.trim())) return [];
    return [[from, span[1]]];
  }
  // A bare value stops at whitespace, so `Bearer` arrives alone and its credential is the next word.
  if (!/^(bearer|basic|negotiate|ntlm|digest)$/i.test(value))
    return isFlagValue(text, span) ? [] : [[span[0], span[1], true]];
  if (value.toLowerCase() === "digest") return [];
  const at = skipSpaces(text, span[1]);
  if (at === span[1] || text.startsWith(placeholder, at)) return [];
  const cred = readBare(text, at);
  if (!cred) return [];
  if (value.toLowerCase() === "basic" && !isBasicCredential(text.slice(cred[0], cred[1]))) return [];
  return [cred];
}

// The spans to redact for the value that starts at `i`, and where scanning resumes. A nested
// object is not consumed: its own keys are matched by the scanner as it continues.
function valueSpans(text: string, i: number, placeholder: string): { spans: Span[]; after: number } | null {
  if (text.startsWith(placeholder, i) || text[i] === "{") return null;
  if (text[i] === "[") return readSecretArray(text, i);
  const quoted = readQuoted(text, i);
  if (quoted) {
    const spans = schemeAware(text, quoted.span, true, placeholder);
    return spans ? { spans, after: quoted.after } : null;
  }
  const bare = readBare(text, i);
  if (!bare) return null;
  const spans = schemeAware(text, bare, false, placeholder) ?? [];
  return { spans, after: spans.length ? spans[spans.length - 1][1] : bare[1] };
}

// A span flagged `true` replaces a bare value under a JSON key (a number), so the placeholder gets quotes and
// the line stays valid JSON.
function splice(text: string, spans: Span[], placeholder: string): string {
  let out = "";
  let last = 0;
  for (const [s, e, quote] of spans) {
    out += text.slice(last, s) + (quote ? `"${placeholder}"` : placeholder);
    last = e;
  }
  return out + text.slice(last);
}

/** Redact the value of every secret-named key. A non-secret key's value is rescanned, so
 *  `message="password=…"` still loses the password. */
export function redactKeyedSecrets(text: string, placeholder: string): string {
  const re = new RegExp(KEY_RE.source, "g");
  const spans: Span[] = [];
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (!isSecretKey(m[2])) continue;
    // A newline around the separator belongs to JSON only. After a bare `Enter password:` it is the
    // end of a prompt, and the next line's first word is not the password.
    if (!m[1] && /\n/.test(m[3] + m[4])) continue;
    const found = valueSpans(text, re.lastIndex, placeholder);
    if (!found) continue;
    const json = m[1] === '"';
    for (const [s, e, bare] of found.spans) {
      if (e > s) spans.push([s, e, json && bare === true]);
    }
    re.lastIndex = Math.max(found.after, re.lastIndex);
  }
  return spans.length ? splice(text, spans, placeholder) : text;
}

/** Redact the value of a `--password` style command-line flag, quoted in either style or bare. */
export function redactCliFlagSecrets(text: string, placeholder: string): string {
  const re = new RegExp(CLI_FLAG_RE.source, "gi");
  const spans: Span[] = [];
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const i = re.lastIndex;
    // A value that starts with "-" is the next option: the flag had no value.
    if (text[i] === "-" || text.startsWith(placeholder, i)) continue;
    const quoted = readQuoted(text, i);
    const span = quoted ? quoted.span : readBare(text, i, true);
    if (!span || span[1] <= span[0]) continue;
    spans.push(span);
    re.lastIndex = quoted ? quoted.after : span[1];
  }
  return spans.length ? splice(text, spans, placeholder) : text;
}
