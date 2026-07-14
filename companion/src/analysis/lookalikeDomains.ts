// Deterministic lookalike / typosquat domain detection — the offline, OPSEC-safe counterpart to
// Timesketch's `phishy_domains` analyzer. Timesketch uses MinHash-Jaccard against a watched list
// (config + top-visited-from-timeline + Alexa top-10). MinHash is overkill for short domain strings,
// so this uses three sharper, explainable signals against a bundled list of commonly-impersonated
// brands (plus any the analyst adds via DFIR_LOOKALIKE_EXTRA_DOMAINS):
//
//   1. Homoglyph  — the domain's "skeleton" (punycode-decoded, confusable Unicode + ASCII homoglyphs
//      folded to a canonical form, separators dropped) equals a brand's skeleton, but the actual
//      registrable domain differs. Catches `microsöft.com`, `xn--microsft-...`, `paypa1.com`,
//      `g00gle.com`. Very low false-positive — near-zero benign reason to skeleton-match a brand.
//   2. Typosquat  — small Levenshtein edit distance to a brand's registrable label (1 edit for short
//      labels, 2 for long) without being equal. Catches `gooogle.com`, `micosoft.com`, `paypall.com`.
//   3. Impersonation — a brand token (≥5 chars) appears in the domain, but the registrable domain is
//      NOT the brand and the brand is NOT a legitimate parent. Catches `microsoft-login.com`,
//      `okta.secure-verify.com`, `login-paypal.com`, and the classic `paypal.com.evil.tld`.
//
// A hit is SUSPICIOUS (Medium), never malicious: a legitimate regional/partner domain can look close.
// Exact brand matches and their own subdomains are never flagged. Pure, offline, unit-tested.

import { domainToUnicode } from "node:url";

// Commonly-impersonated registrable domains (eTLD+1). Curated, not exhaustive — the analyst can add
// their own org/customer domains via DFIR_LOOKALIKE_EXTRA_DOMAINS (comma-separated). Kept in
// registrable form so a brand's own subdomains (accounts.google.com) resolve to the brand and are
// never flagged.
const DEFAULT_BRAND_DOMAINS = [
  // Microsoft / M365 estate
  "microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com",
  "sharepoint.com", "onedrive.com", "windows.com", "azure.com",
  // Google
  "google.com", "gmail.com", "googlemail.com",
  // Identity / collaboration / dev
  "okta.com", "duosecurity.com", "onelogin.com", "auth0.com", "github.com", "gitlab.com",
  "atlassian.com", "slack.com", "zoom.us", "webex.com", "docusign.com", "dropbox.com", "box.com",
  "wetransfer.com", "adobe.com", "salesforce.com", "servicenow.com", "linkedin.com",
  // Consumer / cloud
  "apple.com", "icloud.com", "amazon.com", "netflix.com", "facebook.com", "instagram.com",
  "paypal.com", "stripe.com", "intuit.com",
  // Banks
  "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com", "capitalone.com",
  "hsbc.com", "barclays.co.uk", "santander.com", "lloydsbank.com",
  // Crypto
  "coinbase.com", "binance.com", "kraken.com", "metamask.io", "ledger.com",
];

// Multi-part public suffixes we recognise so registrable(host) takes 3 labels not 2 (barclays.co.uk,
// not co.uk). Small practical set — not a full PSL; unknown TLDs fall back to the last two labels.
const MULTIPART_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "net.au", "org.au", "co.nz",
  "com.br", "com.cn", "co.in", "co.za", "com.mx", "com.sg", "com.tr",
]);

// Confusable / homoglyph folds → the ASCII letter they imitate. Covers the practical set seen in
// real phishing: Latin diacritics, Cyrillic / Greek lookalikes, and ASCII digit / shape homoglyphs.
const CONFUSABLES: Record<string, string> = {
  // Latin diacritics
  "á": "a", "à": "a", "â": "a", "ä": "a", "ã": "a", "å": "a", "ā": "a",
  "é": "e", "è": "e", "ê": "e", "ë": "e", "ē": "e",
  "í": "i", "ì": "i", "î": "i", "ï": "i", "ī": "i",
  "ó": "o", "ò": "o", "ô": "o", "ö": "o", "õ": "o", "ø": "o", "ō": "o",
  "ú": "u", "ù": "u", "û": "u", "ü": "u", "ū": "u",
  "ñ": "n", "ç": "c", "ý": "y",
  // Cyrillic lookalikes
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "к": "k", "м": "m",
  "н": "h", "т": "t", "в": "b", "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ɡ": "g",
  // Greek lookalikes
  "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "υ": "u", "κ": "k", "ι": "i",
  // ASCII digit / shape homoglyphs
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
};

function stripWww(host: string): string {
  return host.replace(/^www\./, "");
}

// The registrable domain (eTLD+1) — best-effort without a full public-suffix list.
export function registrable(host: string): string {
  const labels = stripWww(host.toLowerCase().replace(/\.$/, "")).split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  return MULTIPART_SUFFIXES.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

// The label of a registrable domain (the part before the TLD), used for distance comparison.
function baseLabel(reg: string): string {
  const parts = reg.split(".");
  return parts.length > 1 ? parts.slice(0, -1).join(".") : reg;
}

// Try to decode an IDN/punycode host to Unicode so confusables can be folded. Node's url module
// handles this; on any error the original is returned (so a malformed xn-- label degrades gracefully).
function toUnicode(host: string): string {
  if (!host.includes("xn--")) return host;
  try {
    return domainToUnicode(host) || host;
  } catch {
    return host;
  }
}

// A domain's canonical "skeleton": punycode-decoded, lowercased, confusables + homoglyphs folded to
// ASCII, and all separators (dots / hyphens) removed. Two hosts with the same skeleton look identical
// to a human even when their bytes differ.
export function skeleton(host: string): string {
  const uni = toUnicode(stripWww(host.toLowerCase().replace(/\.$/, "")));
  let out = "";
  for (const ch of uni) out += CONFUSABLES[ch] ?? ch;
  return out.replace(/[.\-_]/g, "");
}

// Levenshtein edit distance, capped implicitly by string length (domains are short).
function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let cur = new Array<number>(n + 1);
  for (let i = 1; i <= m; i++) {
    cur[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, cur] = [cur, prev];
  }
  return prev[n];
}

export type LookalikeKind = "homoglyph" | "typosquat" | "impersonation";

export interface LookalikeVerdict {
  brand: string;         // the impersonated registrable brand domain (e.g. "microsoft.com")
  kind: LookalikeKind;
  distance: number;      // edit distance to the brand label (0 for homoglyph / impersonation)
  note: string;          // human-readable summary
}

export interface LookalikeOptions {
  brands?: string[];     // override / extend the bundled brand list (registrable domains)
}

// Read the effective brand list: bundled defaults + DFIR_LOOKALIKE_EXTRA_DOMAINS (comma-separated),
// deduped and normalised to registrable form. Read at call time so deployment/tests can set it.
export function lookalikeBrands(extra?: string[]): string[] {
  const envExtra = (process.env.DFIR_LOOKALIKE_EXTRA_DOMAINS ?? "")
    .split(",").map((s) => s.trim()).filter(Boolean);
  const all = [...DEFAULT_BRAND_DOMAINS, ...envExtra, ...(extra ?? [])].map((d) => registrable(d));
  return [...new Set(all)].filter(Boolean);
}

// Is `reg` the brand itself or a subdomain of it? (never flagged)
function isBrandOrSub(reg: string, brand: string): boolean {
  return reg === brand;
}

// Decide whether an observed domain is a lookalike of any watched brand. Returns the strongest match
// (homoglyph > impersonation > typosquat) or null. `host` is a raw domain (may include subdomains).
export function detectLookalike(host: string, opts: LookalikeOptions = {}): LookalikeVerdict | null {
  const cleaned = stripWww(String(host || "").toLowerCase().trim().replace(/\.$/, ""));
  if (!cleaned || !cleaned.includes(".")) return null;
  const reg = registrable(cleaned);
  const brands = opts.brands ? opts.brands.map((d) => registrable(d)) : lookalikeBrands();
  const brandSet = new Set(brands);

  // Exact brand or a brand's own subdomain → legitimate, never a lookalike.
  if (brandSet.has(reg)) return null;

  const regLabel = baseLabel(reg);
  const regSkel = skeleton(reg);

  let best: LookalikeVerdict | null = null;
  const rank: Record<LookalikeKind, number> = { homoglyph: 3, impersonation: 2, typosquat: 1 };
  const consider = (v: LookalikeVerdict): void => {
    if (!best || rank[v.kind] > rank[best.kind] || (rank[v.kind] === rank[best.kind] && v.distance < best.distance)) best = v;
  };

  for (const brand of brands) {
    if (isBrandOrSub(reg, brand)) continue;
    const brandLabel = baseLabel(brand);
    if (brandLabel.length < 4) continue; // too short to reason about safely

    // 1. Homoglyph — identical skeletons, different real domains.
    if (regSkel && regSkel === skeleton(brand)) {
      consider({ brand, kind: "homoglyph", distance: 0,
        note: `Domain "${cleaned}" is a homoglyph of ${brand} (identical when confusable characters are normalised)` });
      continue;
    }

    // 2. Typosquat — small edit distance to the brand label, not equal.
    const dist = levenshtein(regLabel, brandLabel);
    const maxEdits = brandLabel.length >= 9 ? 2 : 1;
    if (dist > 0 && dist <= maxEdits && regLabel.length >= 4) {
      consider({ brand, kind: "typosquat", distance: dist,
        note: `Domain "${cleaned}" is ${dist} edit${dist === 1 ? "" : "s"} from ${brand} (possible typosquat)` });
      continue;
    }

    // 3. Impersonation — the brand label appears as a token in a different registrable domain.
    // Requires a boundary (separator or subdomain) so "amazon.com" doesn't match inside "amazonia".
    if (brandLabel.length >= 5) {
      const tokenRe = new RegExp(`(^|[.\\-_])${brandLabel.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([.\\-_]|$)`);
      if (tokenRe.test(cleaned)) {
        consider({ brand, kind: "impersonation", distance: 0,
          note: `Domain "${cleaned}" embeds the ${brand} brand but is not ${brand} (possible impersonation)` });
      }
    }
  }

  return best;
}
