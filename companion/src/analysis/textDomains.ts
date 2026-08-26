// The free-text DOMAIN scraper, shared by every importer that reads a human message, a command
// line, or a collected script block.
//
// Its own module because both callers are frozen by the file-size ledger (#384), and because one
// copy is the point: a C2 domain must be recognized identically whether it arrives in a SIEM
// message, a bash history line, or a Velociraptor PowerShell script block. It lived inside
// siemImport.ts until velociraptorImport.ts needed it too — the gap that let a real case (a Lunar
// Spider simulation) produce 566 IOCs with zero of type `domain` while the C2 IPs sitting in the
// same script text came through.
//
// Extraction is deliberately conservative. Free text on a Windows endpoint is FULL of dotted
// tokens that are not domains — file names, .NET namespaces, framework paths, registry keys,
// version strings — and a false positive costs an analyst a manual triage. Each guard below names
// the shape it exists to reject.

// The label loop is bounded at 127 — the DNS maximum — rather than left open with `+`, and that
// bound is what keeps this regex LINEAR. Unbounded, a failed attempt walks every remaining label
// before giving up, so a long dotted run with no valid TLD ("x.x.x.x…") costs O(n) per start
// position and O(n^2) overall: 10 KB took 138 ms, 50 KB took 4.3 s. Capped, each failed attempt
// gives up after 127 labels, so the whole scan is O(127n) — 400 KB now costs 380 ms, and the cost
// grows with the input instead of squaring it. No real domain is lost: >127 labels is not resolvable.
const TEXT_DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,127}[a-z]{2,}\b/gi;
// Internal-only zones — an AD/mDNS hostname is an asset, not an indicator; don't flood the IOC list.
export const TEXT_DOMAIN_SKIP_RE = /\.(?:local|localdomain|internal|lan|home|corp|arpa)$/i;
// A "domain" ending in a common file extension is really a filename (evil.exe, payload.bin, report.json)
// — keep it out of the domain IOCs (the URL/path importers already capture files where relevant).
//
// A 3+ letter extension that is absent from KNOWN_TLDS is already rejected downstream, so this list
// earns its keep on the TWO-letter extensions: hasPlausibleTld accepts every two-letter last label
// on sight (the ccTLD space), which makes "History.db" or "NOTEPAD.EXE-A1B2C3D4.pf" read as domains.
// The five below are the two-letter extensions a Velociraptor collection is actually full of —
// notes and READMEs (.md), runtime-compiled .NET source (.cs/.vb), SQLite stores (.db), prefetch
// (.pf). Each shadows a real ccTLD; losing "evil.md" is the cheaper of the two errors, because a
// domain IOC an analyst must dismiss by hand costs more than the rare domain on Moldova's registry.
export const TEXT_FILE_EXT_RE =
  /\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|jar|sh|bin|conf|log|txt|json|xml|yml|yaml|cfg|ini|py|pl|so|gz|tar|zip|7z|rar|tmp|bak|dat|pid|sock|key|pem|crt|doc|docx|xls|xlsx|pdf|png|jpg|gif|md|cs|vb|db|pf)$/i;

// Real, commonly-registered TLDs — 3+ letter last labels must be on this list to count as a domain.
// Without this, ANY dot-separated identifier (a Velociraptor artifact id like
// "DetectRaptor.Windows.Detection.Amcache", a JSON/schema field path like "artifacts.precondition", a
// module/class reference) reads as a "domain.tld" shape and gets misclassified — false positives an
// analyst then has to manually mark benign. Real attacker infra overwhelmingly sits on a genuine
// gTLD/ccTLD, so this loses almost nothing while cutting out code/config noise. 2-letter last labels
// are accepted unconditionally (nearly the entire ccTLD space is exactly 2 letters — enumerating all
// ISO-3166 codes buys nothing over just accepting the shape).
const KNOWN_TLDS = new Set([
  "com",
  "net",
  "org",
  "edu",
  "gov",
  "mil",
  "int",
  "info",
  "biz",
  "pro",
  "io",
  "co",
  "ai",
  "app",
  "dev",
  "cloud",
  "tech",
  "xyz",
  "top",
  "site",
  "online",
  "store",
  "shop",
  "live",
  "win",
  "fun",
  "space",
  "click",
  "link",
  "download",
  "icu",
  "vip",
  "work",
  "run",
  "me",
  "tv",
  "cc",
  "ws",
  "la",
  "fm",
  "im",
  "gg",
  "sh",
  "to",
  "pw",
  "gq",
  "ml",
  "cf",
  "ga",
  "tk",
  "asia",
  "mobi",
  "tel",
  "cat",
  "onion",
]);
export function hasPlausibleTld(domain: string): boolean {
  const labels = domain.split(".");
  const tld = (labels[labels.length - 1] ?? "").toLowerCase();
  return tld.length === 2 || KNOWN_TLDS.has(tld);
}

// A dotted token that sits inside a Windows FILE or REGISTRY path is a path component, not a
// domain: "C:\Windows\Microsoft.NET\Framework64" would otherwise register "microsoft.net", and
// PowerShell script blocks are full of those. The guard is the SINGLE backslash immediately before
// the match — a UNC host is written "\\evil.com\share" with two, so real attacker infrastructure
// reached over SMB is still extracted.
function isWindowsPathComponent(text: string, start: number): boolean {
  return text[start - 1] === "\\" && text[start - 2] !== "\\";
}

// A CHAINED code namespace needs no guard — greedy matching runs past it to a last label no TLD
// table accepts ("System.Net.WebClient" ends in "webclient", "[System.IO.File]" in "file"). A
// TERMINAL one is the problem: "using namespace System.Net", "[System.IO]::Path", "Microsoft.NET"
// all end on a label that IS a real TLD, and PowerShell script blocks are full of them.
//
// The check is a PAIR, not a root list, because the roots spell real domains too: rejecting every
// "microsoft.*" would lose microsoft.com. Only <root>.<child> with exactly two labels is rejected,
// so acct.blob.core.windows.net and system.example.com are untouched. The cost is the rare domain
// that is literally "system.io" or "windows.net" — the same trade the two-letter extensions make,
// and the same way round, because a false IOC an analyst must dismiss by hand costs more.
const NS_ROOTS = new Set(["system", "microsoft", "windows", "java", "javax", "mscorlib", "newtonsoft"]);
const NS_CHILDREN = new Set(["net", "io", "ui"]);
function isCodeNamespace(labels: string[]): boolean {
  return labels.length === 2 && NS_ROOTS.has(labels[0]) && NS_CHILDREN.has(labels[1]);
}

/**
 * Every domain in `text`, lower-cased and de-duplicated, in first-seen order.
 *
 * LINEAR in the length of `text` (see TEXT_DOMAIN_RE's label bound), so callers run it on the whole
 * message rather than a truncated prefix — a cap bounds one call but not the total, since this runs
 * per record, and it would silently drop the indicator past the cap.
 */
export function extractDomains(text: string): string[] {
  const out = new Set<string>();
  if (!text) return [];
  for (const m of text.matchAll(TEXT_DOMAIN_RE)) {
    const d = m[0].toLowerCase();
    const start = m.index ?? 0;
    if ((text[start + m[0].length] ?? "") === "@") continue; // local-part of user@host, not a domain
    if (isWindowsPathComponent(text, start)) continue;
    // A version string ("10.0.22621.2506", "v4.0.30319") and a bare IPv4 both need no guard of
    // their own: TEXT_DOMAIN_RE requires an ALPHABETIC last label, so neither can match at all.
    if (TEXT_DOMAIN_SKIP_RE.test(d) || TEXT_FILE_EXT_RE.test(d)) continue;
    if (!hasPlausibleTld(d)) continue; // e.g. "artifacts.precondition", "system.net.webclient"
    if (isCodeNamespace(d.split("."))) continue; // e.g. "system.net", "microsoft.net", "java.io"
    out.add(d);
  }
  return [...out];
}
