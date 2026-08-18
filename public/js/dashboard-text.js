// Text parsing, normalisation and shape-fingerprinting helpers (#415).
//
// NOT AN ES MODULE, AND NOT DEFERRED. See js/dashboard-escape.js for the whole argument; the
// short form is that dashboard.html's inline script calls these by bare name at 427 sites, one of
// them while the page is still parsing, so the declarations have to be real globals that exist
// before <script nonce> at line 6538 runs.
//
// The prevalence trio (clientCommandShape / clientPatternKey / buildClientPrevalence) is the
// interesting one: it reduces a command line to a shape by replacing hashes, GUIDs, paths, quoted
// strings and numbers with placeholders, so "the same command with different arguments" counts as
// one pattern across hosts. It had never been reachable from a test.

// --- Case Details (human-authored report-meta) ------------------------------
// List/table fields are edited as one-entry-per-line text; the server normalizes.
function parseRows(text, keys) {
  return text.split("\n").map(l => l.trim()).filter(Boolean).map(line => {
    const parts = line.split("|").map(p => p.trim());
    const obj = {};
    keys.forEach((k, i) => obj[k] = parts[i] || "");
    return obj;
  });
}

function rowsToText(arr, keys) {
  return (arr || []).map(o => keys.map(k => o[k] || "").join(" | ")).join("\n");
}

function linesToArray(text) { return text.split("\n").map(l => l.trim()).filter(Boolean); }

function truncate(s, n) { s = String(s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

// Nearly every deterministic importer (Chainsaw/Sigma, the generic Windows/Sysmon mapper,
// Velociraptor's own mapGeneric, …) joins a human rule/finding NAME with its raw technical
// trailer (EID/Image/CommandLine/host/etc.) using " - ", e.g. "Potential Shim Database
// Persistence via Sdbinst.EXE - Sysmon Process create (EID 1) - Image=... - CommandLine=...".
// Split at the FIRST such separator so the row shows just the finding name; the raw trailer
// moves into the [details] panel instead of always rendering inline. No separator (a plain
// one-sentence description) → the whole thing is the title, nothing to split off.
function splitEventTitle(desc) {
  const i = desc.indexOf(" - ");
  return i < 0 ? { title: desc, rest: "" } : { title: desc.slice(0, i), rest: desc.slice(i + 3) };
}

// Indicator harvesting for EVENT hunts. Events often carry indicators only in free text — a
// Suricata/Zeek alert puts the domain + IPs in its description, not in structured fields — so a
// hunt built purely from structured fields wrongly shows "nothing to pivot on". Refang the text,
// then (a) regex out the unambiguous types (IPv4 / hash / URL) and (b) match any case IOC whose
// value appears in it. (b) reuses the deterministic, correctly-typed IOC extraction, so a
// defanged "soulversr .com" in the description maps to the clean soulversr.com domain IOC.
function huntRefang(s) {
  return String(s || "")
    .replace(/hxxp(s?)\b/gi, "http$1")                                   // hxxp[s] -> http[s]
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\bdot\b/gi, ".")       // evil[.]com / evil(dot)com / evil dot com
    .replace(/\[:\]/g, ":")
    .replace(/\s*\.\s*/g, ".");                                          // collapse spaces around dots: "soulversr .com" -> "soulversr.com"
}

function egShortHost(v) { return String(v || "").toLowerCase().replace(/^https?:\/\//, "").split(/[\/:?]/)[0].split(".")[0]; }

// Minimal, safe Markdown → HTML (headings, ordered/unordered lists, bold, inline code, paras).
// HTML is escaped first, so AI output can't inject markup.
function mdToHtml(src) {
  const esc = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const inline = s => esc(s).replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/`([^`]+)`/g, "<code>$1</code>");
  let html = "", list = null;
  const close = () => { if (list) { html += "</" + list + ">"; list = null; } };
  for (const raw of String(src || "").split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, "");
    let m;
    if ((m = line.match(/^(#{1,6})\s+(.*)$/))) { close(); const h = Math.min(5, m[1].length + 1); html += "<h" + h + ">" + inline(m[2]) + "</h" + h + ">"; continue; }
    if ((m = line.match(/^\s*\d+\.\s+(.*)$/))) { if (list !== "ol") { close(); html += "<ol>"; list = "ol"; } html += "<li>" + inline(m[1]) + "</li>"; continue; }
    if ((m = line.match(/^\s*[-*]\s+(.*)$/))) { if (list !== "ul") { close(); html += "<ul>"; list = "ul"; } html += "<li>" + inline(m[1]) + "</li>"; continue; }
    if (line.trim() === "") { close(); continue; }
    close(); html += "<p>" + inline(line) + "</p>";
  }
  close();
  return html;
}

// AI prose → display paragraphs. The Executive Summary and the Narrative Timeline both arrive as
// ONE unbroken block: the model writes no blank lines, so a 400-word narrative rendered as a single
// paragraph spanning the full grid width, and the eye lost its place on every carriage return.
//
// DISPLAY ONLY. The stored text is never rewritten — the narrative editor and the report read the
// raw string, and rejoining these paragraphs with a space is not required to reproduce it.
//
// TWO THINGS ARE LEFT ALONE, because breaking them would be worse than a long paragraph:
//   - text the author already split (blank lines between blocks), which is kept block for block
//   - a block with any line structure in it (a list, a hand-typed narrative), which is one paragraph
// Only an undivided wall longer than the target gets cut, and it is cut at sentence ends.
function proseParagraphs(text, targetChars) {
  const src = String(text == null ? "" : text).replace(/\r\n?/g, "\n").trim();
  if (!src) return [];
  const target = targetChars || 420;
  const out = [];
  for (const block of src.split(/\n[ \t]*\n+/).map(b => b.trim()).filter(Boolean)) {
    if (block.indexOf("\n") >= 0 || block.length <= target) { out.push(block); continue; }
    const start = out.length;
    let cur = "";
    for (const sentence of proseSentences(block)) {
      cur = cur ? cur + " " + sentence : sentence;
      if (cur.length >= target) { out.push(cur); cur = ""; }
    }
    // The tail. A short remainder joins the paragraph before it rather than standing alone as a
    // one-line orphan -- but only if THIS block produced that paragraph, never a previous one.
    if (cur) {
      if (cur.length < target / 3 && out.length > start) out[out.length - 1] += " " + cur;
      else out.push(cur);
    }
  }
  return out;
}

// One block of prose → its sentences. Split after .!? (plus any closing quote or bracket) when the
// next sentence opens with a capital or a digit; a hostname or a version — "win11.windomain.local",
// "v1.2" — never matches, because what follows its dot is not whitespace.
//
// A LOCAL, NOT A MODULE-LEVEL CONST. A top-level `const` in a classic script joins the global
// LEXICAL environment, reachable by bare name from every other script on the page and invisible to
// the own-property gate that would otherwise catch a leak (see js/dashboard-escape.js).
function proseSentences(block) {
  // Sentence ends that are really abbreviations: "e.g.", "Inc.", a lone initial ("A. Smith"). Each
  // has the exact shape the split fires on, so the piece after one is glued back. Not exhaustive
  // and does not need to be — a miss costs a paragraph break in an odd place, not lost text.
  const abbrev = /(?:\b[A-Za-z]|\b(?:e\.g|i\.e|etc|vs|approx|fig|dr|mr|ms|jr|sr|st|inc|ltd|no|al))\.["')\]]?$/i;
  const out = [];
  for (const part of String(block == null ? "" : block).split(/(?<=[.!?]["')\]]?)\s+(?=["'“(\[]?[A-Z0-9])/)) {
    if (out.length && abbrev.test(out[out.length - 1])) out[out.length - 1] += " " + part;
    else out.push(part);
  }
  return out;
}

function custodyGroupByArtifact(records) {
  const byPath = new Map();
  for (const r of records) {
    const chain = byPath.get(r.artifactPath);
    if (chain) chain.push(r); else byPath.set(r.artifactPath, [r]);
  }
  return byPath;
}

function clientCommandShape(text) {
  return String(text || "").toLowerCase()
    .replace(/\b[a-f0-9]{32,64}\b/g, "<hash>")
    .replace(/\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?/g, "<guid>")
    .replace(/\\\\[^\s"']+/g, "<unc>").replace(/[a-z]:\\[^\s"']*/g, "<path>")
    .replace(/(?:\/[^\s"'/]+){2,}\/?/g, "<path>")
    .replace(/"[^"]*"/g, "<str>").replace(/'[^']*'/g, "<str>")
    .replace(/\b\d[\d.,:]*\b/g, "<n>").replace(/\s+/g, " ").trim().slice(0, 200);
}

function clientPatternKey(e) {
  const hash = String(e.sha256 || e.md5 || "").trim().toLowerCase();
  if (hash) return "hash:" + hash;
  const proc = String(e.processName || "").trim().toLowerCase();
  const shape = clientCommandShape(e.description);
  if (proc) return "proc:" + proc + "|" + shape;
  return shape ? "desc:" + shape : "";
}

function buildClientPrevalence(events) {
  const idx = new Map();
  for (const e of (events || [])) {
    const k = clientPatternKey(e);
    if (!k) continue;
    let st = idx.get(k);
    if (!st) { st = { count: 0, hosts: new Set() }; idx.set(k, st); }
    st.count++; if (e.asset) st.hosts.add(String(e.asset).toLowerCase());
  }
  return idx;
}

// Chunked ArrayBuffer → base64 (avoids the call-stack limit of String.fromCharCode(...bytes)
// and O(n^2) string concatenation for large screenshots/evidence).
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

// Published for the inline script and the other helper modules. EVERY function this file
// defines is listed: a helper that stays private here but is still called by name from
// dashboard.html is a ReferenceError, which is the mistake #414 shipped and then fixed.
window.DfirText = {
  parseRows,
  rowsToText,
  linesToArray,
  truncate,
  splitEventTitle,
  huntRefang,
  proseParagraphs,
  proseSentences,
  mdToHtml,
  egShortHost,
  arrayBufferToBase64,
  custodyGroupByArtifact,
  clientCommandShape,
  clientPatternKey,
  buildClientPrevalence,
};
