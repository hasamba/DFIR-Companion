import {
  createAnonymizer,
  SECRET_PLACEHOLDER,
  type AnonCategory,
  type CustomEntity,
  type KnownEntities,
} from "./anonymize.js";
import { escapeRegExp } from "./regexEscape.js";
import { bareUsername, isGuardedUsername } from "./anonUsernames.js";

// Fail-closed redaction of server log text bound for a support bundle (#1735). The bundle leaves
// the analyst's machine for the maintainer, who needs NONE of the case vocabulary — so unlike the
// redacted case export (which keeps adversary infrastructure visible), everything that could name
// a case, a file, a host, a person, a network or a secret is replaced. When in doubt, redact.
//
// One instance per bundle: the same real value maps to the same token in every file. The
// real→token maps live only inside the closure and are never serialized; summary() reports
// distinct counts per category, never a value.

export interface SupportRedactorInput {
  cases: Array<{ caseId: string; title?: string }>;
  fileNames: string[];
  secrets: string[];
  roots: string[];
  known: KnownEntities;
}

export interface SupportRedactor {
  redactText(text: string): string;
  redactLog(text: string, opts?: { maxLineBytes?: number; withheldCaseIds?: string[] }): string;
  summary(): Record<string, number>;
}

const MIN_SECRET_LENGTH = 6;
const MIN_LITERAL_LENGTH = 2;
const DEFAULT_MAX_LINE_BYTES = 16384;
const WITHHELD_LINE = "<line withheld: case vocabulary unavailable>";
const SECRET_ENV_KEY = /KEY|TOKEN|SECRET|PASS|AUTH|CREDENTIAL|COOKIE|WEBHOOK|DSN/i;
// Flags only. A NUMBER from a secret-named key is kept: a numeric password is still a password.
const NON_SECRET_VALUE = /^(?:true|false|yes|no|on|off|null|undefined|none)$/i;

/** Raw values of every secret-named env var, minus on/off flags. Short and numeric values stay. */
export function collectEnvSecrets(env: Record<string, string | undefined>): string[] {
  const out = new Set<string>();
  for (const [key, raw] of Object.entries(env)) {
    if (!SECRET_ENV_KEY.test(key) || typeof raw !== "string") continue;
    const value = raw.trim();
    if (!value || NON_SECRET_VALUE.test(value)) continue;
    out.add(value);
  }
  return [...out];
}

/** Every spelling a secret takes in a log line: raw, JSON-escaped, URL-encoded, base64(url). */
export function secretVariants(values: string[]): string[] {
  const out = new Set<string>();
  for (const v of values) {
    if (typeof v !== "string" || v.length < MIN_SECRET_LENGTH) continue;
    const b64 = Buffer.from(v, "utf8").toString("base64");
    const forms = [v, JSON.stringify(v).slice(1, -1), encodeURIComponent(v), b64, b64.replace(/=+$/, "")];
    forms.push(Buffer.from(v, "utf8").toString("base64url"));
    for (const f of forms) if (f.length >= MIN_SECRET_LENGTH) out.add(f);
  }
  return [...out].sort((a, b) => b.length - a.length || a.localeCompare(b));
}

// ── patterns ──
const W = String.raw`\p{L}\p{N}_`;
const SEGC = String.raw`[^\s/\\:*?"'<>|]`;
const SEG = `${SEGC}+`;
/** An inner WINDOWS path segment may hold single spaces ("Program Files") because a backslash
 * follows it. POSIX paths get no such allowance: "GET /a/b 200 in 5ms; text/plain" would swallow
 * the prose between two slashes. */
const SEGSP = `${SEG}(?: ${SEG})*`;
const TRAILING_PUNCT = /[.,;:!?)\]}]+$/;
// A credential by its label, whatever its value looks like: "token=…", "Cookie: sid=…", a JSON
// "apiKey":"…", or a bare "Bearer …" / "Basic …". The label stays; the value goes.
const KV_SECRET_RE =
  /\b([A-Za-z0-9_.-]{0,40}?(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|auth[a-z]*|cookie|session(?:id)?|credential|signature|private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]{0,40})(["']?\s*[:=]\s*["']?)(?:(?:bearer|basic)\s+)?([^\s"'<>,;&]{3,})/gi;
const SCHEME_SECRET_RE = /\b(bearer|basic|negotiate|ntlm)(\s+)[A-Za-z0-9._~+/=-]{6,}/gi;
const TOKEN_LITERAL = /ANON_(?=[A-Za-z]+_\d)/gi;
const URL_RE = /(?<![\p{L}\p{N}_])[a-z][a-z0-9+.-]{1,31}:\/\/[^\s'"<>`]*/giu;
const QUOTED_PATH_RE = /(['"])((?:[A-Za-z]:[\\/]|\\\\|~?\/)[^'"\r\n]+?)\1/g;
const DRIVE_PATH_RE = new RegExp(String.raw`(?<![${W}])[A-Za-z]:[\\/](?:${SEGSP}[\\/])*(?:${SEG})?`, "gu");
const UNC_PATH_RE = new RegExp(String.raw`\\\\(?:[?.]\\)?(?:${SEGSP}\\)*${SEG}`, "gu");
const POSIX_PATH_RE = new RegExp(String.raw`(?<![${W}.~:/\\-])~?/(?:${SEG}/)*${SEG}/?`, "gu");
const RELATIVE_PATH_RE = new RegExp(String.raw`(?<![${W}.~:/\\-])${SEG}(?:[\\/]${SEG}){2,}[\\/]?`, "gu");
const FQDN_RE =
  /(?<![\p{L}\p{N}_.@-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+(ANON_[A-Z]+_\d+|[A-Za-z]{2,63})(?![\p{L}\p{N}_-]|\.[A-Za-z0-9])/gu;
const ADDR_RE = /(?<![\p{L}\p{N}_.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9._-]*[A-Za-z0-9]/gu;
const BLOB_RE =
  /(?<![A-Za-z0-9+/_-])(?=[A-Za-z0-9+/_-]*\d)(?=[A-Za-z0-9+/_-]*[A-Za-z])[A-Za-z0-9+/_-]{32,}={0,2}/g;
const FILE_EXTS = new Set(
  "json jsonl csv tsv psv log txt xml html htm md yaml yml evtx etl db sqlite sqlite3 ps1 psm1 bat cmd vbs js mjs cjs ts py sh exe dll sys lnk pf dat ini cfg conf tmp bak gz zip 7z rar tar pdf docx xlsx pptx png jpg jpeg webp gif plaso raw mem dmp vmem pcap pcapng reg hve".split(
    " ",
  ),
);
// The "[import] <caseId> <label>: …" lines (logging/importLog.ts). The label is a file name the
// analyst or an adversary chose, so it is replaced by position, whether the redactor knows it or not.
const IMPORT_LABEL_RE = /(\[import\] [^\s:]+ )([^\r\n]+?)(?=: )/g;
const ALL_BUT_PATH: Record<AnonCategory, boolean> = {
  IP: true,
  EMAIL: true,
  USER: true,
  HOST: true,
  DOMAIN: true,
  PATH: false,
  CMD: true,
  REG: true,
  CARD: true,
  PHONE: true,
  NATID: true,
};

function literalRegExp(values: string[], minLength = MIN_LITERAL_LENGTH): RegExp | null {
  const uniq = [...new Set(values.filter((v) => v.length >= minLength))];
  if (uniq.length === 0) return null;
  uniq.sort((a, b) => b.length - a.length || a.localeCompare(b));
  return new RegExp(`(?<![${W}])(?:${uniq.map(escapeRegExp).join("|")})(?![${W}])`, "giu");
}

function isAbsoluteRoot(r: string): boolean {
  return (
    typeof r === "string" &&
    r.length > 1 &&
    (r.startsWith("/") || /^[A-Za-z]:[\\/]/.test(r) || r.startsWith("\\\\"))
  );
}

function extOf(name: string): string {
  const m = /\.([A-Za-z0-9]{1,10})$/.exec(name);
  return m ? `.${m[1].toLowerCase()}` : "";
}

/** Split trailing sentence punctuation off a match so "x/y." and "x/y" share one token. */
function splitTrail(m: string): [string, string] {
  const t = TRAILING_PUNCT.exec(m)?.[0] ?? "";
  return t && t.length < m.length ? [m.slice(0, -t.length), t] : [m, ""];
}

function knownForAnonymizer(known: KnownEntities): KnownEntities {
  // Hosts and accounts go through the custom list so ONE longest-first pass orders them: without
  // that, the bare user "alice" would fire inside host "WKS-ALICE" before the host pass ran.
  const custom: CustomEntity[] = (known.custom ?? []).filter((c) => c.category !== "PATH");
  for (const h of known.hosts) custom.push({ value: h, category: "HOST" });
  // A USER entity is tokenized by its bare name (#1780), so "CORP\alice", "alice@corp.example" and
  // a bare "alice" share one token. Common words ("admin", "test") are never replaced bare.
  for (const a of known.accounts) {
    custom.push({ value: a, category: "USER" });
    const bare = bareUsername(a);
    if (!isGuardedUsername(bare)) custom.push({ value: bare, category: "USER" });
  }
  for (const u of known.usernames ?? []) {
    if (!isGuardedUsername(u)) custom.push({ value: u, category: "USER" });
  }
  // `suppressed` is dropped on purpose: the analyst's "do not redact" vetoes are for their own
  // exports, not for a bundle that leaves the machine.
  return { hosts: known.hosts, accounts: known.accounts, internalDomains: known.internalDomains, custom };
}

export function createSupportRedactor(input: SupportRedactorInput): SupportRedactor {
  const secrets = secretVariants(input.secrets);
  // A configured secret shorter than MIN_SECRET_LENGTH is still replaced, but only as a whole
  // word: a raw substring match on "4821" would also eat timestamps and counters.
  const shortSecretRe = literalRegExp(
    input.secrets
      .map((v) => (typeof v === "string" ? v.trim() : ""))
      .filter((v) => v && v.length < MIN_SECRET_LENGTH),
    1,
  );
  const roots = [...new Set(input.roots.filter(isAbsoluteRoot))].sort((a, b) => b.length - a.length);
  const rootRes = roots.map((r) => new RegExp(`${escapeRegExp(r)}(?:[\\\\/]${SEG})*[\\\\/]?`, "giu"));
  const customPaths = literalRegExp(
    (input.known.custom ?? []).filter((c) => c.category === "PATH").map((c) => c.value),
  );
  const anonymizer = createAnonymizer(
    { enabled: true, categories: ALL_BUT_PATH, redactSecrets: true, maskPublicIps: true },
    knownForAnonymizer(input.known),
  );

  // Case ids and titles share the case's number.
  const caseNum = new Map<string, number>();
  input.cases.forEach((c, i) => {
    for (const v of [c.caseId, c.title ?? ""].map((s) => s.trim()))
      if (v.length >= MIN_LITERAL_LENGTH && !caseNum.has(v.toLowerCase()))
        caseNum.set(v.toLowerCase(), i + 1);
  });
  const caseRe = literalRegExp(input.cases.flatMap((c) => [c.caseId.trim(), (c.title ?? "").trim()]));

  // Stored "NNNN_name.ext" and original "name.ext" share one number; the extension is kept.
  const fileTok = new Map<string, string>();
  const baseNum = new Map<string, number>();
  for (const raw of input.fileNames) {
    const name = raw.trim();
    const base = name.replace(/^\d{4}_/, "");
    if (base.length < MIN_LITERAL_LENGTH) continue;
    let n = baseNum.get(base.toLowerCase());
    if (n === undefined) baseNum.set(base.toLowerCase(), (n = baseNum.size + 1));
    for (const v of [name, base])
      if (!fileTok.has(v.toLowerCase())) fileTok.set(v.toLowerCase(), `ANON_FILE_${n}${extOf(base)}`);
  }
  const fileRe = literalRegExp([...fileTok.keys()]);
  /** The token for any file name, known or not; a new name continues the same numbering. */
  function fileToken(raw: string): string {
    const name = raw.trim();
    const known = fileTok.get(name.toLowerCase());
    const tok = known ?? mintNewFile(name);
    hit("FILE", tok.replace(/\..*$/, ""));
    return tok;
  }
  function mintNewFile(name: string): string {
    const base = name.replace(/^\d{4}_/, "");
    let n = baseNum.get(base.toLowerCase());
    if (n === undefined) baseNum.set(base.toLowerCase(), (n = baseNum.size + 1));
    const tok = `ANON_FILE_${n}${extOf(base)}`;
    fileTok.set(name.toLowerCase(), tok);
    fileTok.set(base.toLowerCase(), tok);
    return tok;
  }

  const hits = new Map<string, Set<string>>(); // category -> distinct real keys (never serialized)
  const minted = new Map<string, Map<string, string>>();
  function hit(cat: string, key: string): void {
    if (!hits.has(cat)) hits.set(cat, new Set());
    hits.get(cat)?.add(key);
  }
  function mint(cat: string, key: string): string {
    hit(cat, key);
    let byKey = minted.get(cat);
    if (!byKey) minted.set(cat, (byKey = new Map()));
    let tok = byKey.get(key);
    if (!tok) byKey.set(key, (tok = `ANON_${cat}_${byKey.size + 1}`));
    return tok;
  }
  const mintTrimmed = (cat: string, m: string): string => {
    const [core, trail] = splitTrail(m);
    return mint(cat, core) + trail;
  };

  function redactSecretValues(t: string): string {
    let out = t;
    for (const s of secrets) {
      if (!out.includes(s)) continue;
      hit("SECRET", s);
      out = out.split(s).join(SECRET_PLACEHOLDER);
    }
    if (shortSecretRe)
      out = out.replace(shortSecretRe, (m) => {
        hit("SECRET", m);
        return SECRET_PLACEHOLDER;
      });
    out = out.replace(KV_SECRET_RE, (_m, k: string, sep: string, v: string) => {
      hit("SECRET", v);
      return k + sep + SECRET_PLACEHOLDER;
    });
    return out.replace(SCHEME_SECRET_RE, (m, k: string, sp: string) => {
      hit("SECRET", m);
      return k + sp + SECRET_PLACEHOLDER;
    });
  }

  function redactPathsPass(t: string): string {
    let out = t;
    for (const re of rootRes) out = out.replace(re, (m) => mintTrimmed("PATH", m));
    if (customPaths) out = out.replace(customPaths, (m) => mint("PATH", m.toLowerCase()));
    out = out.replace(QUOTED_PATH_RE, (_m, q: string, p: string) => q + mint("PATH", p) + q);
    out = out.replace(UNC_PATH_RE, (m) => mintTrimmed("PATH", m));
    out = out.replace(DRIVE_PATH_RE, (m) => mintTrimmed("PATH", m));
    out = out.replace(POSIX_PATH_RE, (m) => mintTrimmed("PATH", m));
    return out.replace(RELATIVE_PATH_RE, (m) => mintTrimmed("PATH", m));
  }

  function redactLiterals(t: string): string {
    let out = t;
    if (caseRe)
      out = out.replace(caseRe, (m) => {
        const n = caseNum.get(m.toLowerCase()) ?? 0; // 0 only if Unicode case folding disagrees
        hit("CASE", String(n));
        return `ANON_CASE_${n}`;
      });
    if (fileRe) out = out.replace(fileRe, (m) => fileToken(m));
    return out;
  }

  function redactResidual(t: string): string {
    let out = t.replace(ADDR_RE, (m) => mintTrimmed("ADDR", m));
    // Every dotted name with a letter-only last label goes: no suffix list is complete (.company,
    // .photography, …). A last label that is a file extension makes it a file name instead.
    out = out.replace(FQDN_RE, (m, tld: string) =>
      FILE_EXTS.has(tld.toLowerCase()) ? fileToken(m) : mint("FQDN", m.toLowerCase()),
    );
    return out.replace(BLOB_RE, (m) => {
      hit("BLOB", m);
      return SECRET_PLACEHOLDER;
    });
  }

  function redactText(text: string): string {
    if (!text) return text;
    let t = text.replace(TOKEN_LITERAL, "ANON-LITERAL_"); // a pre-existing token must not read as ours
    t = redactSecretValues(t);
    t = t.replace(IMPORT_LABEL_RE, (_m, head: string, label: string) => head + fileToken(label));
    t = t.replace(URL_RE, (m) => mintTrimmed("URL", m));
    t = redactPathsPass(t);
    t = redactLiterals(t);
    t = anonymizer.apply(t);
    return redactResidual(t);
  }

  // Fail-closed: ANY mention of a withheld case id — its "[id]" scope, an "[import] id:" line or
  // the id in prose — withholds the line, since that case's hosts and users are unknown here.
  function isWithheld(line: string, withheld: string[]): boolean {
    const lower = line.toLowerCase();
    return withheld.some((id) => lower.includes(id));
  }

  function redactLog(text: string, opts: { maxLineBytes?: number; withheldCaseIds?: string[] } = {}): string {
    const max = opts.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES;
    const withheld = (opts.withheldCaseIds ?? []).map((id) => id.trim().toLowerCase()).filter(Boolean);
    return text
      .split("\n")
      .map((raw) => {
        const cr = raw.endsWith("\r") ? "\r" : "";
        const line = cr ? raw.slice(0, -1) : raw;
        const bytes = Buffer.byteLength(line, "utf8");
        if (bytes > max) return `<line omitted: ${bytes} bytes>${cr}`;
        if (isWithheld(line, withheld)) return WITHHELD_LINE + cr;
        return redactText(line) + cr;
      })
      .join("\n");
  }

  function summary(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const [cat, set] of hits) out[cat] = set.size;
    for (const d of anonymizer.discoveries()) out[d.category] = (out[d.category] ?? 0) + 1;
    return out;
  }

  return { redactText, redactLog, summary };
}
