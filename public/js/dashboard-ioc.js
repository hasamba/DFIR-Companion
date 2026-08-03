// IOC verdicts, de-duplication, display order and ATT&CK links (#415).
//
// NOT AN ES MODULE, AND NOT DEFERRED. See js/dashboard-escape.js for the whole argument; the
// short form is that dashboard.html's inline script calls these by bare name at 427 sites, one of
// them while the page is still parsing, so the declarations have to be real globals that exist
// before <script nonce> at line 6538 runs.
//
// worstIocVerdict() ranks malicious > suspicious > harmless > unknown and returns `undefined` for
// an IOC with no enrichments at all -- not "unknown". Callers distinguish "we looked and found
// nothing" from "we never looked", and the tests pin that difference.

// Threat-intel enrichment badges for an IOC (VirusTotal / MalwareBazaar / AbuseIPDB).
function verdictColor(v) {
  return v === "malicious" ? "#ff6b6b" : v === "suspicious" ? "#ffd93b" : v === "harmless" ? "#6bcB77" : "#9aa4b2";
}

// Link a MITRE technique id (T1059 / T1059.001) to its attack.mitre.org page.
function attackUrl(id) {
  const m = /^T(\d{4})(?:\.(\d{3}))?$/.exec(String(id).trim().toUpperCase());
  if (!m) return null;
  return m[2] ? `https://attack.mitre.org/techniques/T${m[1]}/${m[2]}/` : `https://attack.mitre.org/techniques/T${m[1]}/`;
}

function mitreLinks(ids) {
  return (ids || []).map(id => {
    const u = attackUrl(id);
    return u ? `<a href="${escAttr(u)}" target="_blank" rel="noopener" data-safe-style="color:var(--accent)">${esc(id)}</a>` : esc(id);
  }).join(", ");
}

// Worst threat-intel verdict across an IOC's enrichments (mirrors the server-side helper in
// assetGraph.ts — no client-side equivalent existed to reuse).
function worstIocVerdict(ioc) {
  const order = ["malicious", "suspicious", "harmless", "unknown"];
  let best;
  for (const e of (ioc.enrichments || [])) {
    if (best === undefined || order.indexOf(e.verdict) < order.indexOf(best)) best = e.verdict;
  }
  return best;
}

// True when the score line already shows this tag (matched as a bounded token, so "US" isn't
// matched inside "Russia") — used to drop redundant context chips: the IP-infrastructure
// providers (GeoIP/WHOIS/…) put the same country/ASN/org in both score and tags.
function scoreCoversTag(score, tag) {
  const t = String(tag || "").trim();
  if (!t) return true;
  const re = t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^a-z0-9])${re}([^a-z0-9]|$)`, "i").test(score);
}

function enrichBadges(ioc) {
  if (!ioc.enrichments) return ""; // not enriched yet
  if (!ioc.enrichments.length) return ` <span data-safe-style="color:var(--text-faint);font-size:11px">· checked, no intel</span>`;
  return " " + ioc.enrichments.map(e => {
    const c = verdictColor(e.verdict);
    const score = e.score ? String(e.score) : "";
    // Drop tag chips already present in the score so they don't read as duplicated.
    const shownTags = (e.tags || []).filter(t => !scoreCoversTag(score, t)).slice(0, 3);
    const tags = shownTags.length ? ` — ${esc(shownTags.join(", "))}` : "";
    // The IP-infrastructure providers (Reverse DNS / WHOIS / GeoIP / Shodan) return verdict
    // "unknown" because they give CONTEXT, not a threat call. When there's data to show, omit
    // the literal "unknown" so the badge reads as info — not "we don't know".
    const asContext = e.verdict === "unknown" && (score || tags);
    const label = asContext
      ? `${esc(e.source)}${score ? `: ${esc(score)}` : ""}${tags}`
      : `${esc(e.source)}: ${esc(e.verdict)}${score ? ` (${esc(score)})` : ""}${tags}`;
    const inner = `<span data-safe-style="display:inline-block;vertical-align:middle;color:${c};border:1px solid ${c};border-radius:4px;padding:0 6px;font-size:11px;white-space:normal;word-break:break-word">${label}</span>`;
    return e.link ? `<a href="${escAttr(e.link)}" target="_blank" rel="noopener" data-safe-style="text-decoration:none">${inner}</a>` : inner;
  }).join(" ");
}

// Render the IOC list. Extracted from render() so paintIocImportMeta() can re-render it to paint
// the "new since last import" highlight (green accent + NEW badge) without a full state re-render.
// An IOC is "flagged" when any enrichment engine returned a malicious or suspicious verdict.
function iocFlagged(i) {
  return (i.enrichments || []).some(e => e.verdict === "malicious" || e.verdict === "suspicious");
}

// A case file can end up with more than one IOC row sharing the same id (a known bug where
// concurrent imports racing on the same case's state can each assign the same next-sequential
// id before either save lands — see server-side state locking). Collapse those here as a
// display-layer safety net so a stale/corrupted case doesn't show visible duplicates; the fix
// for the underlying data is a separate server-side de-dup, not this render function's job.
function dedupeIocsById(iocs) {
  const seen = new Set();
  const out = [];
  for (const i of iocs) {
    const key = i.id || `${i.type}:${i.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(i);
  }
  return out;
}

// Deterministic display order — grouped by type, then alphabetical by value — instead of raw
// insertion/id order (which is meaningless to an analyst and buries duplicates at the tail).
function sortIocsForDisplay(iocs) {
  return [...iocs].sort((a, b) =>
    (a.type || "").localeCompare(b.type || "") || (a.value || "").localeCompare(b.value || "", undefined, { sensitivity: "base" }));
}

// Published for the inline script and the other helper modules. EVERY function this file
// defines is listed: a helper that stays private here but is still called by name from
// dashboard.html is a ReferenceError, which is the mistake #414 shipped and then fixed.
window.DfirIoc = {
  verdictColor,
  attackUrl,
  mitreLinks,
  worstIocVerdict,
  iocFlagged,
  dedupeIocsById,
  sortIocsForDisplay,
  scoreCoversTag,
  enrichBadges,
};
