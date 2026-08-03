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
  mdToHtml,
  egShortHost,
  arrayBufferToBase64,
  custodyGroupByArtifact,
  clientCommandShape,
  clientPatternKey,
  buildClientPrevalence,
};
