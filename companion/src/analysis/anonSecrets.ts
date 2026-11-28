import { isBasicCredential, redactCliFlagSecrets, redactKeyedSecrets } from "./anonSecretKeys.js";
import { redactRegistryCredentialPairs } from "./anonSecretRegPairs.js";

// The one-way secret pass of the anonymizer: credentials, API keys and tokens are replaced with a
// placeholder before text reaches the AI, and NOTHING maps the placeholder back. This is the
// counterpart of the reversible tokenizing in anonymize.ts, which calls redactSecretText() through
// anonSecretCustom.ts (a custom value that overlaps a secret is redacted with it).
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

// Top-level domains an e-mail address glued to a JWT is read under (#3034): common and internal ones.
const MAIL_TLDS =
  "com|net|org|edu|gov|mil|int|info|biz|io|ai|app|dev|cloud|online|local|localdomain|internal|intranet|lan|corp|home|private";

// AWS key id: the edges are case-aware (#3005). A key is upper-case + digits, so lower-case text,
// "_" or "." beside it is a seam, not more key. An upper-case hex hash never matches: every
// 20-character stretch inside one has a hex digit beside it.
const AWS_KEY = /(?<![0-9A-Z])(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![0-9A-Z])/g;
// ... glued after a run of digits that starts at a seam (12345 + key, #3034). A letter G-Z must be
// in it: AKIA/ASIA/ABIA hold one, and an ACCA key's body must, so an upper-case hex hash (A-F only)
// with digits before ACCA stays readable.
const AWS_AFTER_DIGITS =
  /(?=(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![0-9A-Z]))(?<=(?<![0-9A-Z])[0-9]{1,16})(?=[0-9A-Z]{0,19}[G-Z])(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![0-9A-Z])/g;
const LEGACY_SK = /(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{20,}(?![A-Za-z0-9])/g; // OpenAI legacy key

// Fixed-shape secrets, replaced whole. Each is anchored on a vendor literal, so ordinary text and
// hashes cannot match. Order matters only where one prefix contains another (sk-proj- before sk-).
export const VENDOR_SECRETS: readonly RegExp[] = [
  AWS_KEY,
  AWS_AFTER_DIGITS,
  // ... glued to a digit on either side (<key>9, 20240101T1200<key>, #3041). A real key id body is
  // base32: A-Z and 2-7, never 0, 1, 8 or 9, so a year or an "01" suffix is not key body. It must hold
  // a 2-7 digit directly followed by a letter, so WORD + digits (ACCAPAYABLESARCHIVE2023) is not one,
  // and a letter G-Z, so an upper-case hex hash is not one.
  /(?<![A-Z])(?=[A-Z2-7]{0,19}[G-Z])(?:AKIA|ASIA|ABIA|ACCA)(?=[A-Z2-7]{0,14}[2-7][A-Z])[A-Z2-7]{16}(?![A-Z])/g,
  // GitHub App installation token since 2026: ghs_<app id>_<JWT>, ~520 characters. Before the JWT
  // rules, so the app id goes with it. "eyJ" (a JSON header) keeps `highs_2024_x.final.docx` apart.
  /ghs_[0-9]{1,20}_eyJ[A-Za-z0-9_-]{1,512}\.[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{4,}/g,
  /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b/g, // JWT
  /eyJ[A-Za-z0-9_-]{6,256}\.eyJ[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{4,}/g, // JWT glued to a word: JSON header AND payload
  // ... or a long mixed signature (16+, upper, lower and a digit) as a real one has, whatever the payload (#3041):
  // after DOMAIN\user or a dotless e-mail domain. A file name's extension is never such a segment.
  /eyJ[A-Za-z0-9_-]{6,256}\.[A-Za-z0-9_-]{6,256}\.(?=[A-Za-z0-9_-]{0,256}[A-Z])(?=[A-Za-z0-9_-]{0,256}[a-z])(?=[A-Za-z0-9_-]{0,256}[0-9])[A-Za-z0-9_-]{16,}/g,
  // ... glued straight after an e-mail domain (<user>@<internal domain> + token, #3034). The label right before
  // it must read as a top-level domain (two letters, or a common or internal one), so a host such as
  // x@<host>.<internal domain> (turkeyJerky01) is not one. A dotless domain counts only when it is
  // localhost or one of those names (svc@localhost + token, #3041). The #3028 growth sends the whole
  // address one way.
  new RegExp(
    `(?=eyJ)(?<=@(?:[A-Za-z0-9-]{1,63}(?:\\.[A-Za-z0-9-]{1,63}){0,8}\\.(?:[A-Za-z]{2}|${MAIL_TLDS})|localhost|${MAIL_TLDS}))` +
      "eyJ[A-Za-z0-9_-]{6,256}\\.[A-Za-z0-9_-]{6,256}\\.[A-Za-z0-9_-]{4,}",
    "g",
  ),
  /github_pat_[A-Za-z0-9_]{22,}/g, // GitHub fine-grained token
  /\bgh[pousr]_[A-Za-z0-9]{20,}(?![A-Za-z0-9])/g, // GitHub classic tokens ("_x" after is a seam)
  /gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9]{4})/g, // ... glued to a word: the real 36-character body
  /xox[abeprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])/g, // Slack tokens (xoxe-: a rotated / refresh token)
  // Slack app-level / workflow token: xapp-1-A0123…, versioned, so `xapp-sn-watcher` is not one.
  /(?<![A-Za-z0-9])x(?:app|wfp)-\d{1,3}-[A-Za-z0-9-]{20,}(?![A-Za-z0-9-])/g,
  /AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-]{4})/g, // Google API key (up to 3 glued characters after)
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g, // Stripe secret / restricted key
  // ... a live key glued to a word: mixed case, so a hex hash after `task_live_` is not one.
  /(?:sk|rk)_live_(?=[0-9a-z]{0,256}[A-Z])(?=[0-9A-Z]{0,256}[a-z])[A-Za-z0-9]{16,}/g,
  /(?<![A-Za-z0-9_-])sk-(?:proj|ant)-[A-Za-z0-9_-]{16,}/g, // OpenAI project / Anthropic key
  // OpenAI service-account / admin key: an upper-case letter in it, so `sk-admin-fileserver-01` is a name.
  /(?<![A-Za-z0-9_-])sk-(?:svcacct|admin)-(?=[0-9a-z_-]{0,256}[A-Z])[A-Za-z0-9_-]{16,}/g,
  // ... an Anthropic key glued to a word (api03, admin01, ...): mixed case, so a hex hash is not one.
  /sk-ant-[a-z]{2,10}\d{2}-(?=[0-9a-z_-]{0,256}[A-Z])[A-Za-z0-9_-]{16,}/g,
  /sk-[A-Za-z0-9_-]{8,200}T3BlbkFJ[A-Za-z0-9_-]{8,}/g, // ... an OpenAI key glued to a word (its "OpenAI" marker)
  LEGACY_SK,
  // ... glued after a name in an account, path, e-mail or host (CORP\bob + key, #3029): after a "\"
  // or "/" in the same word, or before a ".", "@" or "\". At least three digits, upper- and lower-case
  // letters, so a host or folder name such as kiosk-FrontDesk01 is not one; a bare word such as
  // desk-Ab12Cd34... stays readable (#3005).
  /(?:(?<=[\\/][A-Za-z0-9._$-]{0,64})|(?=sk-[A-Za-z0-9]{20,256}[.@\\]))sk-(?=(?:[A-Za-z]{0,64}\d){3})(?=(?:[a-z0-9]{0,64}[A-Z]){3})(?=(?:[A-Z0-9]{0,64}[a-z]){3})[A-Za-z0-9]{20,}(?![A-Za-z0-9])/g,
  /\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, // SendGrid key
  /SG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{40,46}(?![A-Za-z0-9_-])/g, // ... glued to a word: ~69 characters
  /\bnpm_[A-Za-z0-9]{36,}/g, // npm token
  /npm_[A-Za-z0-9]{36}(?![A-Za-z0-9]{4})/g, // ... glued to a word
  // Twilio SID / key: AC or SK + 32 hex, ONLY beside a Twilio label — on its own the shape is just
  // hex. The look-ahead runs first, so the bounded look-behind is tried only at real candidates.
  /\b(?=(?:AC|SK)[0-9A-F]{32}\b)(?<=(?:twilio[^\n]{0,60}|\b(?:account_?sid|auth_?token)["']?[ \t]{0,4}[=:][ \t]{0,4}["']?))(?:AC|SK)[0-9A-F]{32}\b/gi,
];

// #3003: inside a name the vendor shapes are tested with no edge guard: every "\b" and every negative
// look-around that is one character class (with an optional count) is removed. Positive look-arounds
// stay (mixed case, the "eyJ" header, the Twilio label), so the shapes keep what tells a key from a
// hash or a word. Derived from VENDOR_SECRETS, so a later edge change there follows here.
const EDGE_GUARD = /\\b|\(\?<?!\[[^\]]*\](?:\{\d+(?:,\d*)?\})?\)/g;
const stripEdges = (re: RegExp, flags: string) => new RegExp(re.source.replace(EDGE_GUARD, ""), flags);

// #3044: stripped, the legacy sk- shape read any 20 characters after "sk-" as a key, so a name such as
// disk-0123... went one way. Glued, the body must hold a letter: a digit-only body is a name. Every
// other body stays one way, as before (no key length or alphabet is assumed).
const GLUED_SK = /sk-(?=[0-9]{0,256}[A-Za-z])[A-Za-z0-9]{20,}/;
// In a domain label only a body a real key has: 32+ characters with a letter and a digit (a 32-hex or
// 48-character body). A shorter one (kiosk-frontdesklobbyscreen0123, desk-OperatorWorkstation01) is a host.
const SK_LONG = "(?=[A-Za-z]{0,256}[0-9])(?=[0-9]{0,256}[A-Za-z])[A-Za-z0-9]{32,}";
const LABEL_SK = new RegExp(`sk-${SK_LONG}`, "g");

/** The vendor shapes with their edge guards removed (anonGluedSecret.ts tests a name with them). */
export const GLUED_VENDOR_SECRETS: readonly RegExp[] = VENDOR_SECRETS.map((re) =>
  re === LEGACY_SK ? GLUED_SK : stripEdges(re, re.flags.replace("g", "")),
);

// #3041: a key glued inside an e-mail or UPN domain label (bob@SRV<key>.corp.local) is missed by the
// edge-guarded shapes, and the e-mail or account pass then held it in a reversible token. Each label is
// tested with the edge-free shapes, except those that cannot be told from a host label: a dotted shape
// (a JWT or SendGrid key spans labels: x@<host>.<internal domain> (turkeyJerky01)), the [0-9A-Z] AWS shapes (the
// base32 one stays, so ASIAPACIFICFILESERVER01 is a host) and the plain legacy sk- (disk-0123...),
// whose long body (LABEL_SK) is tested instead (#3044). The #3028 growth then sends the whole address
// one way, before the account pass could mint the domain of a UPN as a reversible DOMAIN token. Every
// label is read whole, however long the label or the domain (#3044).
const NOT_IN_LABEL = new Set<RegExp>([AWS_KEY, AWS_AFTER_DIGITS, LEGACY_SK]);
const LABEL_SECRETS = [
  ...VENDOR_SECRETS.filter((re) => !NOT_IN_LABEL.has(re) && !re.source.includes("\\.")).map((re) =>
    stripEdges(re, re.flags),
  ),
  LABEL_SK,
];
const MAIL_DOMAIN = /(?<=[A-Za-z0-9._%+-]@)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*/g;

function redactDomainLabels(text: string): string {
  if (!text.includes("@")) return text;
  return text.replace(MAIL_DOMAIN, (domain) =>
    domain
      .split(".")
      .map((label) => LABEL_SECRETS.reduce((l, re) => l.replace(re, SECRET_PLACEHOLDER), label))
      .join("."),
  );
}

// A token that ends in a hex character and is glued to an IPv6 address has taken the address's hex
// head (`fd00` of `fd00::2`), so the rest (`::2`) would go out in clear or be tokenized as the wrong
// address (#3016), or be split by the address pass so part of it shows (`::ffff:10.0.0.5` followed
// by more digits, #3005). This optional tail takes the rest of the address-character run into the
// same placeholder, once a "::" plus a hex digit follows within the first groups: digits, ":", a
// "." before a digit and hex letters, up to 64 characters. That hides more than the address when
// digits are glued after it, never less. It stops before a word that starts with hex letters
// (`eyJ…`, `From…`, `corp…`), so the next token, command or name is still found, and before the
// last characters ahead of an "@", which start an e-mail. Requiring "::" plus a hex digit keeps
// `:12:34:56`, MAC addresses and `::Method()` out of it. The VENDOR_SECRETS sources stay as they
// are, so code that derives regexes from them does not meet the tail.
const HEX_WORD_AHEAD = "[A-Fa-f]{0,64}[G-Zg-z_]";
const GLUED_V6_TAIL =
  "(?:(?<=[0-9A-Fa-f])(?=(?::[0-9A-Fa-f]{1,4}){0,6}::[0-9A-Fa-f])" +
  `(?:[0-9:]|[A-Fa-f](?!${HEX_WORD_AHEAD})|\\.(?=\\d)){3,64}` +
  `(?:(?![0-9A-Fa-f:@]|\\.\\d)|(?=[0-9A-Fa-f]{1,4}@)|(?=${HEX_WORD_AHEAD})))?`;
const VENDOR_SECRETS_GLUED_V6 = VENDOR_SECRETS.map((re) => new RegExp(re.source + GLUED_V6_TAIL, re.flags));

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
// The Bearer value also takes a glued IPv6 address (#3016); the digit-or-symbol test reads the value only.
const BARE_BASIC_RE = /\b(Basic[ \t]{1,4})([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])/gi;
const BARE_BEARER_RE = new RegExp(`\\b(Bearer[ \\t]{1,4})([A-Za-z0-9._~+/=-]{8,})(${GLUED_V6_TAIL})`, "gi");

// URL userinfo password (scheme://user:pass@host) — the password only; the user is tokenized later.
// A match starts only where a run of scheme characters starts (#2967). Without that, a long run with
// no "://" (a long word, dotted words with no space) was rescanned to its end from every position in
// it: quadratic. A leading digit or "+.-" before the scheme's first letter joins group 1 and is
// written back unchanged, so the output is what the unanchored form gave.
const URL_USERINFO_RE = /(?<![a-z0-9+.-])([0-9+.-]*[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)([^\s:@/]+)(@)/gi;

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
  out = redactPrefixed(out);
  out = redactCliFlagSecrets(out, SECRET_PLACEHOLDER);
  out = redactKeyedSecrets(out, SECRET_PLACEHOLDER);
  out = redactRegistryCredentialPairs(out, SECRET_PLACEHOLDER); // name and data apart (#3021)
  // Vendor shapes last (#3005): a keyed or flag value that holds a vendor shape plus a glued tail
  // is hidden whole first; the vendor pass then catches shapes outside any key.
  for (const re of VENDOR_SECRETS_GLUED_V6) out = out.replace(re, SECRET_PLACEHOLDER);
  return redactDomainLabels(out);
}
