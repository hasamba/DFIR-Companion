// Import minimum-severity preference — the floor below which imported findings are dropped
// (#415 tier 3).
//
// NO INITIALIZER: both statements the splitter reported at load are guard stanzas left by the
// unified import and unified export extractions, and they stay in the page.
(function () {
  // ── Import minimum-severity preference (per-browser) ──────────────────────
  // Stored as { value, remember }. When remember is set, askMinSeverity() returns the
  // saved value WITHOUT showing the dialog. Settings → General → Import severity manages it.
  const IMPORT_SEV_KEY = "dfir_import_min_severity";
  const VALID_SEV = ["critical", "high", "medium", "low", "info"];
  function getImportSevPref() {
    try {
      const o = JSON.parse(localStorage.getItem(IMPORT_SEV_KEY) || "null");
      return o && typeof o === "object" ? o : null;
    } catch (e) {
      return null;
    }
  }
  function setImportSevPref(value, remember) {
    try {
      if (!remember) localStorage.removeItem(IMPORT_SEV_KEY);
      else
        localStorage.setItem(
          IMPORT_SEV_KEY,
          JSON.stringify({ value, remember: true }),
        );
    } catch (e) {
      /* quota — non-fatal */
    }
  }
  // Resolve the minimum severity for an import batch. Returns a normalized severity string,
  // or null if the user cancelled the whole import. A remembered choice skips the dialog.
  function askMinSeverity() {
    return new Promise((resolve) => {
      const pref = getImportSevPref();
      if (pref && pref.remember && VALID_SEV.includes(pref.value)) {
        resolve(pref.value);
        return;
      }
      const overlay = document.getElementById("importSevOverlay");
      const sel = document.getElementById("importSevSelect");
      const remember = document.getElementById("importSevRemember");
      sel.value = pref && VALID_SEV.includes(pref.value) ? pref.value : "info";
      remember.checked = false;
      overlay.classList.add("open");
      const cleanup = () => {
        overlay.classList.remove("open");
        document.getElementById("importSevOk").onclick = null;
        document.getElementById("importSevCancel").onclick = null;
        overlay.onclick = null;
      };
      document.getElementById("importSevOk").onclick = () => {
        const value = sel.value.trim().toLowerCase();
        setImportSevPref(value, remember.checked);
        syncImportSevDefaultSelect();
        cleanup();
        resolve(value);
      };
      const cancel = () => {
        cleanup();
        resolve(null);
      };
      document.getElementById("importSevCancel").onclick = cancel;
      overlay.onclick = (ev) => {
        if (ev.target.id === "importSevOverlay") cancel();
      };
    });
  }
  // Mirror the remembered preference into the Settings → General select (and react to edits there).
  function syncImportSevDefaultSelect() {
    const el = document.getElementById("importSevDefault");
    if (!el) return;
    const pref = getImportSevPref();
    el.value =
      pref && pref.remember && VALID_SEV.includes(pref.value) ? pref.value : "";
  }

  // ── Web/proxy log trailer format (#993) ────────────────────────────────
  // Whether Squid access/proxy logs in this browser use the squid_combined LogFormat (appends a
  // cache-result field after the User-Agent). It's a fact about the deployment, not a per-import
  // choice, so it's a plain persisted preference (Settings → General) rather than a per-batch
  // prompt: without it, the server never labels the field (webRecordFields.ts — declared, never
  // inferred from the tokens' shape).
  const WEB_TRAILER_KEY = "dfir_weblog_squid_trailer";
  function getWebTrailerProfile() {
    try {
      return localStorage.getItem(WEB_TRAILER_KEY) === "1";
    } catch (e) {
      return false;
    }
  }
  function setWebTrailerProfile(on) {
    try {
      if (on) localStorage.setItem(WEB_TRAILER_KEY, "1");
      else localStorage.removeItem(WEB_TRAILER_KEY);
    } catch (e) {
      /* quota — non-fatal */
    }
  }

  // ── "Asset for this import" (#1496) ─────────────────────────────────────
  // A Windows log export downloaded from the Velociraptor GUI or a notebook names no collector, so
  // every name the machine ever had becomes its own host. The probe below is the UX hint that
  // decides whether to ASK; the server decides nothing from it. It is structural, not lexical: the
  // first records of a JSON array / NDJSON file (or a CSV header) are read with the same key
  // vocabulary the server's resolver uses — a record key (Computer / ComputerName / Host, or
  // System.Computer under Event, _Event or SystemData) present, and no Fqdn / Hostname with a
  // real value anywhere in the sample. Asked PER FILE, never remembered: a host is per file by
  // nature, and an answer must never spill onto a file that was not looked at.
  const PROBE_BYTES = 256 * 1024;
  const PROBE_RECORDS = 50;
  const ABSENT = { "": 1, "-": 1, "n/a": 1 };
  function keyCI(obj, name) {
    if (!obj || typeof obj !== "object") return undefined;
    const want = name.toLowerCase();
    for (const k of Object.keys(obj))
      if (k.toLowerCase() === want) return obj[k];
    return undefined;
  }
  function pathCI(obj, path) {
    let cur = obj;
    for (const seg of path.split(".")) {
      cur = keyCI(cur, seg);
      if (cur === undefined) return undefined;
    }
    return cur;
  }
  function presentValue(v) {
    return typeof v === "string" && !ABSENT[v.trim().toLowerCase()];
  }
  function recordComputerOf(rec) {
    const keys = [
      "Computer",
      "ComputerName",
      "Host",
      "System.Computer",
      "Event.System.Computer",
      "_Event.System.Computer",
      "SystemData.Computer",
    ];
    for (const k of keys) {
      const v = pathCI(rec, k);
      if (presentValue(v)) return v.trim();
    }
    return "";
  }
  function collectorOf(rec) {
    for (const k of ["Fqdn", "Hostname"]) {
      const v = keyCI(rec, k);
      if (presentValue(v)) return v.trim();
    }
    return "";
  }
  function sampleRecords(text) {
    const head = text.slice(0, PROBE_BYTES).trimStart();
    if (head.startsWith("[")) {
      // A JSON array: parse whole when small, else cut at the last complete object in the sample.
      try {
        const arr = JSON.parse(
          text.length <= PROBE_BYTES
            ? text
            : head.slice(0, head.lastIndexOf("},") + 1) + "]",
        );
        return Array.isArray(arr) ? arr.slice(0, PROBE_RECORDS) : [];
      } catch (e) {
        return [];
      }
    }
    if (head.startsWith("{")) {
      const out = [];
      for (const line of head.split(/\r?\n/)) {
        if (out.length >= PROBE_RECORDS) break;
        const t = line.trim();
        if (!t.startsWith("{")) continue;
        try {
          out.push(JSON.parse(t));
        } catch (e) {
          /* a cut line at the end of the sample */
        }
      }
      return out;
    }
    return [];
  }
  // A CSV export (Hayabusa): the header names the columns and the first rows say whether a
  // collector column holds a real value — a `Hostname` column of `-` is no collector, exactly as
  // the server reads it. Quoted fields with commas are honoured; a cut last line is dropped.
  function parseCsvLine(line) {
    const out = [];
    let cur = "";
    let q = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (q) {
        if (ch === '"' && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else if (ch === '"') q = false;
        else cur += ch;
      } else if (ch === '"') q = true;
      else if (ch === ",") {
        out.push(cur);
        cur = "";
      } else cur += ch;
    }
    out.push(cur);
    return out;
  }
  function csvSays(text) {
    const lines = text.slice(0, PROBE_BYTES).split(/\r?\n/);
    const header = (lines[0] || "").trim();
    if (!header.includes(",")) return null;
    const cols = parseCsvLine(header).map((c) => c.trim().toLowerCase());
    const recordCol = cols.findIndex((c) => c === "computer" || c === "computername" || c === "host");
    if (recordCol < 0) return null;
    const collectorCols = cols.map((c, i) => (c === "fqdn" || c === "hostname" ? i : -1)).filter((i) => i >= 0);
    const computers = [];
    let rows = 0;
    for (let i = 1; i < lines.length && rows < PROBE_RECORDS; i++) {
      if (!lines[i].trim()) continue;
      const cells = parseCsvLine(lines[i]);
      if (cells.length < cols.length && i === lines.length - 1) break; // the cut last line of the sample
      rows++;
      for (const ci of collectorCols) if (presentValue(cells[ci] || "")) return { bare: false, computers: [] };
      const c = (cells[recordCol] || "").trim();
      if (presentValue(c) && !computers.some((x) => x.toLowerCase() === c.toLowerCase()) && computers.length < 5)
        computers.push(c);
    }
    return { bare: rows > 0 && computers.length > 0, computers };
  }
  // { bare: boolean, computers: string[] } — `computers` are the distinct record names seen (≤ 5),
  // shown to the analyst so a multi-host export is visible before they answer.
  function probeBareWindowsExport(text) {
    const csv = csvSays(text);
    if (csv) return csv;
    const recs = sampleRecords(text);
    if (!recs.length) return { bare: false, computers: [] };
    const computers = [];
    let anyRecord = false;
    for (const rec of recs) {
      if (collectorOf(rec)) return { bare: false, computers: [] };
      const c = recordComputerOf(rec);
      if (!c) continue;
      anyRecord = true;
      if (
        !computers.some((x) => x.toLowerCase() === c.toLowerCase()) &&
        computers.length < 5
      )
        computers.push(c);
    }
    return { bare: anyRecord, computers };
  }
  // Ask which host ONE bare file came from. Resolves the host name ("" = leave the names inside
  // the records), or null when the analyst cancelled this file.
  function askImportAssetHost(fileName, computers) {
    return new Promise((resolve) => {
      const overlay = document.getElementById("importAssetOverlay");
      const input = document.getElementById("importAssetHost");
      const fileEl = document.getElementById("importAssetFile");
      const seenEl = document.getElementById("importAssetSeen");
      fileEl.textContent = fileName;
      seenEl.textContent = computers.length
        ? `Names inside the records: ${computers.join(", ")}`
        : "The records name no machine at all.";
      input.value = "";
      overlay.classList.add("open");
      const cleanup = () => {
        overlay.classList.remove("open");
        document.getElementById("importAssetOk").onclick = null;
        document.getElementById("importAssetSkip").onclick = null;
        document.getElementById("importAssetCancel").onclick = null;
        overlay.onclick = null;
      };
      document.getElementById("importAssetOk").onclick = () => {
        const host = input.value.trim();
        cleanup();
        resolve(host);
      };
      document.getElementById("importAssetSkip").onclick = () => {
        cleanup();
        resolve("");
      };
      const cancel = () => {
        cleanup();
        resolve(null);
      };
      document.getElementById("importAssetCancel").onclick = cancel;
      overlay.onclick = (ev) => {
        if (ev.target.id === "importAssetOverlay") cancel();
      };
      input.focus();
    });
  }

  window.askMinSeverity = askMinSeverity;
  window.probeBareWindowsExport = probeBareWindowsExport;
  window.askImportAssetHost = askImportAssetHost;
  window.setImportSevPref = setImportSevPref;
  window.syncImportSevDefaultSelect = syncImportSevDefaultSelect;
  window.getWebTrailerProfile = getWebTrailerProfile;
  window.setWebTrailerProfile = setWebTrailerProfile;
})();
