// Bulk finding operations, and the hunt-query builders (VQL / KQL / SPL / Sigma) — extracted
// from dashboard.html (issue #415, tier 3).
//
// This block reported eight state escapes for most of #415 and had none. Five were const-declared
// arrow-function helpers the inventory was counting as state (baseName, cleanWinPath, hasAny, hq,
// pushUniq); the other three were not this feature's at all. veloEnabled and enabledHuntPlatforms
// are /health capability flags read by seven and two extracted modules respectively, so they moved
// up to sit with the page's other capability vocabulary. huntLabel is written and read only by
// js/dashboard-sigma-hunt.js, so it went there.
//
// No initializer: nothing here runs at load. The seven guard stanzas that used to sit inside this
// section's line range belong to OTHER features and stayed in the page — the split script refuses
// a range that encloses one now.
//
// showToast travels with this block because that is where it is declared, not because it belongs:
// it is a generic UI helper, and js/dashboard-tickets.js and js/dashboard-sigma-hunt.js both use
// it. Giving it a proper home is its own change.
(function () {
  "use strict";

  function updateFindingBulkBar() {
    const bar = document.getElementById("findingBulkBar");
    if (!bar) return;
    if (DfirSelection.findings.count() > 0) {
      bar.classList.add("active");
      document.getElementById("findingBulkCount").textContent =
        `${DfirSelection.findings.count()} finding${DfirSelection.findings.count() !== 1 ? "s" : ""} selected`;
    } else {
      bar.classList.remove("active");
    }
  }
  function clearFindingSelection() {
    DfirSelection.findings.clear();
    document.querySelectorAll(".finding-row-cb").forEach((cb) => {
      cb.checked = false;
      const row = cb.closest(".finding");
      if (row) row.classList.remove("finding-selected");
    });
    const sa = document.getElementById("findingSelectAll");
    if (sa) {
      sa.checked = false;
      sa.indeterminate = false;
    }
    updateFindingBulkBar();
  }
  function bulkTagFindings() {
    if (DfirSelection.findings.count())
      openBulkTagModal(DfirSelection.findings.ids(), "finding");
  }
  // Opens the mark-FP modal on the first selected finding as the anchor; the rest ride along as
  // extraRefs. Findings are marked by TITLE (not id) — see fpBtn("finding", f.title) above and
  // buildFalsePositiveMarker on the server, which uses `ref` as the marker key for this kind.
  function bulkMarkFindingsFalsePositive() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !DfirSelection.findings.count()) return;
    const ids = DfirSelection.findings.ids();
    const titleById = new Map(
      (DfirState.lastState()?.findings || []).map((f) => [f.id, f.title]),
    );
    const [firstId, ...restIds] = ids;
    const firstTitle = titleById.get(firstId) ?? firstId;
    const extraRefs = restIds.map((id) => ({
      kind: "finding",
      ref: titleById.get(id) ?? id,
      label: titleById.get(id) ?? id,
    }));
    openFalsePositiveModal("finding", firstTitle, firstTitle, extraRefs, () => {
      DfirSelection.findings.clear();
      if (DfirState.lastState()) render(DfirState.lastState());
    });
  }
  // One-click exclude for the offending IOC rows the analyst already has selected: adds an
  // exact-match exclude rule per selected value (one POST per value — mirrors how bulk mark-FP
  // has no dedicated batch route either). The server purges + pushes updated state per call.
  async function bulkExcludeIocs() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !DfirSelection.iocs.count()) return;
    const iocById = new Map(
      (DfirState.lastState()?.iocs || []).map((i) => [i.id, i.value]),
    );
    const values = DfirSelection.iocs
      .ids()
      .map((id) => iocById.get(id))
      .filter(Boolean);
    if (!values.length) return;
    if (
      !confirm(
        `Permanently exclude ${values.length} IOC value(s) from this case?\n\nThey are removed now and will never be re-imported or enriched. This cannot be undone (deleting the exclude rule later will not bring them back).`,
      )
    )
      return;
    const statusEl = document.getElementById("status");
    statusEl.textContent = `excluding ${values.length} IOC(s)…`;
    let purged = 0;
    let succeeded = 0;
    for (const value of values) {
      try {
        const r = await fetch(
          `/cases/${encodeURIComponent(caseId)}/ioc-exclude`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ match: "exact", pattern: value }),
          },
        );
        if (r.ok) {
          const j = await r.json();
          purged += j.purged || 0;
          succeeded++;
        }
      } catch {}
    }
    statusEl.textContent =
      succeeded === values.length
        ? `excluded ${succeeded} value(s), purged ${purged} IOC(s) total`
        : `excluded ${succeeded} of ${values.length} value(s) (${values.length - succeeded} failed), purged ${purged} IOC(s) total`;
    DfirSelection.iocs.clear();
    if (DfirState.lastState()) renderIocs(DfirState.lastState().iocs || []);
  }
  function bulkCopyIocs() {
    const iocById = new Map(
      (DfirState.lastState()?.iocs || []).map((i) => [i.id, i.value]),
    );
    const text = DfirSelection.iocs
      .ids()
      .map((id) => iocById.get(id) ?? id)
      .join("\n");
    navigator.clipboard
      .writeText(text)
      .then(() => {
        const statusEl = document.getElementById("status");
        statusEl.textContent = `copied ${DfirSelection.iocs.count()} IOC value${DfirSelection.iocs.count() !== 1 ? "s" : ""} to clipboard`;
      })
      .catch(() => {});
  }

  // Which hunt-query platforms the server allows (DFIR_HUNT_PLATFORMS); replaced from /health.
  // Defaults to all so the modal is fully populated before /health returns. Keys match huntPlatforms.ts.
  function huntChip(kind, id) {
    return (
      `<button class="hunt-add" data-hk="${escAttr(kind)}" data-hi="${escAttr(String(id))}" ` +
      `title="Generate hunt / pivot queries (Velociraptor, Defender KQL, Elastic ES|QL, Splunk, Sigma, YARA, Suricata)">${ICON_HUNT}</button>`
    );
  }
  // Explain button for forensic events (#141): one AI call per click, no state change.
  function explainChip(id) {
    return `<button class="explain-btn" data-exid="${escAttr(String(id))}" title="Explain this event in context (AI) — what happened, why it matters, ATT&amp;CK mapping, pivot queries">${ICON_EXPLAIN}</button>`;
  }
  const HUNT_IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const HUNT_HASH = /\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi;
  const HUNT_URL = /\bhttps?:\/\/[^\s)<>"']+/gi;
  const isIpv4 = (v) =>
    v.split(".").length === 4 &&
    v.split(".").every((o) => o !== "" && +o >= 0 && +o <= 255);
  const pushUniq = (arr, v) => {
    const lv = String(v).toLowerCase();
    if (v && !arr.some((x) => String(x).toLowerCase() === lv)) arr.push(v);
  };
  function huntHarvestText(text, c) {
    const t = huntRefang(text);
    (t.match(HUNT_IPV4) || []).forEach((v) => {
      if (isIpv4(v)) pushUniq(c.ips, v);
    });
    (t.match(HUNT_HASH) || []).forEach((v) =>
      pushUniq(c.hashes, v.toLowerCase()),
    );
    (t.match(HUNT_URL) || []).forEach((v) =>
      pushUniq(c.urls, v.replace(/[).,]+$/, "")),
    );
    const tl = t.toLowerCase();
    for (const ioc of (DfirState.lastState() && DfirState.lastState().iocs) ||
      []) {
      const val = String(ioc.value || "");
      if (!val) continue;
      const esc = val.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      if (!new RegExp(`(^|[^a-z0-9.])${esc}([^a-z0-9.]|$)`).test(tl)) continue; // boundary-matched
      if (ioc.type === "ip") pushUniq(c.ips, val);
      else if (ioc.type === "domain") pushUniq(c.domains, val);
      else if (ioc.type === "url") pushUniq(c.urls, val);
      else if (ioc.type === "hash") pushUniq(c.hashes, val);
      else if (ioc.type === "file") pushUniq(c.paths, val);
      else if (ioc.type === "process") pushUniq(c.processes, val);
    }
  }
  // Pull the indicators an entity carries into typed buckets the generators consume.
  function huntContextFor(kind, e) {
    const c = {
      hashes: [],
      ips: [],
      domains: [],
      urls: [],
      paths: [],
      processes: [],
      parent: "",
      host: "",
      label: "",
    };
    if (kind === "ioc") {
      const v = String(e.value || "");
      c.label = `${e.type}: ${v}`;
      if (e.type === "hash") c.hashes.push(v);
      else if (e.type === "ip") c.ips.push(v);
      else if (e.type === "domain") c.domains.push(v);
      else if (e.type === "url") c.urls.push(v);
      else if (e.type === "file") c.paths.push(v);
      else if (e.type === "process") c.processes.push(v);
      else c.paths.push(v); // "other" — treat as a free string to match on
    } else {
      c.label = e.description || e.id;
      if (e.sha256) c.hashes.push(e.sha256);
      if (e.md5) c.hashes.push(e.md5);
      if (e.path) c.paths.push(e.path);
      if (e.processName) c.processes.push(e.processName);
      if (e.parentName) c.parent = e.parentName;
      if (e.asset) c.host = e.asset;
      // Network/IDS alerts (and many others) carry the real indicators in the description text and
      // as linked case IOCs — harvest those so the hunt has something to pivot on.
      huntHarvestText(e.description || "", c);
    }
    return c;
  }
  const hq = (s) => `"${String(s).replace(/"/g, '\\"')}"`; // quote a value for a query
  const hasAny = (c) =>
    c.hashes.length ||
    c.ips.length ||
    c.domains.length ||
    c.urls.length ||
    c.paths.length ||
    c.processes.length;
  // Tools (Sysmon, EDR, the artifact) report image paths with a device prefix like
  // `\\.\C:\…` or `\\?\C:\…` — strip it so the path is a usable filesystem path.
  const cleanWinPath = (p) =>
    String(p)
      .trim()
      .replace(/^\\\\[.?]\\/, "");
  // Velociraptor's glob() accessor uses FORWARD slashes — a `\\.\C:\…\x.exe` path is unusable as-is.
  const vqlGlob = (p) => cleanWinPath(p).replace(/\\/g, "/");
  const baseName = (p) => {
    const parts = cleanWinPath(p).split(/[\\/]/);
    return parts[parts.length - 1] || cleanWinPath(p);
  };
  // Velociraptor HUNT artifact VQL — client-side pivot queries (one per `--` block), each becomes a
  // source of the CLIENT artifact the "Run hunt (all clients)" button packages, so glob()/pslist()/
  // netstat() run ON each endpoint. (These are client-side plugins: pasted into a server-side notebook
  // cell they'd run against the SERVER and find nothing — use the notebook query below for that.)
  // Paths are normalized for the glob accessor; process/IP matches are exact (IN / lowcase).
  function huntVql(c) {
    const out = [];
    if (c.processes.length) {
      const names = c.processes
        .map((p) => hq(baseName(p).toLowerCase()))
        .join(", ");
      out.push(
        `-- running process (live)\nSELECT Pid, Ppid, Name, CommandLine, Exe\nFROM pslist()\nWHERE lowcase(string=Name) IN (${names})${c.parent ? `\n-- expected parent: ${baseName(c.parent)}` : ""}`,
      );
    }
    if (c.paths.length) {
      out.push(
        `-- file presence (exact path) + its hashes\nSELECT OSPath, Size, Mtime, hash(path=OSPath) AS Hashes\nFROM glob(globs=${hq(vqlGlob(c.paths[0]))})`,
      );
      out.push(
        `-- or locate it anywhere on C: by name\nSELECT OSPath, Size, Mtime FROM glob(globs=${hq("C:/**/" + baseName(c.paths[0]))})`,
      );
    }
    if (c.hashes.length) {
      out.push(
        `-- on-disk hash sweep (narrow the glob root — hashing every file is expensive)\nSELECT OSPath, Size, Mtime, hash(path=OSPath) AS Hashes\nFROM glob(globs="C:/Users/**")\nWHERE hash(path=OSPath).SHA256 =~ ${hq("(?i)" + c.hashes[0])}`,
      );
    }
    if (c.ips.length) {
      out.push(
        `-- active network connections\nSELECT Pid, Name, Status, Laddr.IP AS Local, Raddr.IP AS Remote, Raddr.Port AS RemotePort\nFROM netstat()\nWHERE Raddr.IP IN (${c.ips.map(hq).join(", ")})`,
      );
    }
    return out.join("\n\n");
  }
  // Velociraptor NOTEBOOK query — runs against ONE client from a notebook cell. A notebook runs
  // server-side VQL, so to reach an endpoint you COLLECT a built-in artifact on it
  // (collect_client), wait for the flow to finish (watch_monitoring on System.Flow.Completion), then
  // read the rows (source()) — the documented collect_client → source idiom. Each indicator maps to
  // the artifact that finds it: processes/hashes → Windows.System.Pslist (collection-side
  // ProcessRegex; Hash.SHA256 filter), files → Windows.Search.FileFinder (glob), on-disk hash →
  // FileFinder + Calculate_Hash, IPs → Windows.Network.Netstat.
  function huntVqlNotebook(c) {
    // A regex-safe process name with NO backslashes (so it never breaks the VQL double-quoted
    // string): keep word chars / dot / hyphen, turn any other char into `.` (regex any). The
    // unescaped `.` matching any char is a harmless over-match for an exe-name pivot.
    const rxSafe = (s) => baseName(s).replace(/[^\w.\- ]/g, ".");
    const wait = (v) =>
      `LET _ <= SELECT * FROM watch_monitoring(artifact="System.Flow.Completion")\n         WHERE FlowId = ${v}.flow_id LIMIT 1`;
    const blocks = [];
    if (c.processes.length) {
      const rx = c.processes.map((p) => rxSafe(p)).join("|");
      blocks.push(
        `-- Running processes matching the indicator (filtered at collection via ProcessRegex)\n` +
          `LET proc_flow <= collect_client(client_id=client_id, artifacts="Windows.System.Pslist",\n    env=dict(ProcessRegex=${hq("(?i)^(" + rx + ")$")}))\n` +
          `${wait("proc_flow")}\n` +
          `SELECT Pid, Ppid, Name, CommandLine, Exe, Hash.SHA256 AS SHA256\n` +
          `FROM source(client_id=client_id, flow_id=proc_flow.flow_id, artifact="Windows.System.Pslist")`,
      );
    }
    if (c.paths.length) {
      blocks.push(
        `-- File presence by path / name (FileFinder glob on the client)\n` +
          `LET file_flow <= collect_client(client_id=client_id, artifacts="Windows.Search.FileFinder",\n    env=dict(SearchFilesGlobTable=${hq("Glob\\n" + vqlGlob(c.paths[0]))}))\n` +
          `${wait("file_flow")}\n` +
          `SELECT OSPath, Size, Mtime FROM source(client_id=client_id, flow_id=file_flow.flow_id, artifact="Windows.Search.FileFinder")`,
      );
    }
    if (c.hashes.length) {
      blocks.push(
        `-- On-disk file(s) matching the hash (FileFinder hashes under the glob root — narrow it; hashing is expensive)\n` +
          `LET hash_flow <= collect_client(client_id=client_id, artifacts="Windows.Search.FileFinder",\n    env=dict(SearchFilesGlobTable="Glob\\nC:/Users/**", Calculate_Hash="Y"))\n` +
          `${wait("hash_flow")}\n` +
          `SELECT OSPath, Size, Mtime, Hash.SHA256 AS SHA256\n` +
          `FROM source(client_id=client_id, flow_id=hash_flow.flow_id, artifact="Windows.Search.FileFinder")\n` +
          `WHERE SHA256 =~ ${hq("(?i)" + c.hashes[0])}`,
      );
    }
    if (c.ips.length) {
      blocks.push(
        `-- Active network connections — collect all sockets, then look for the indicator IP(s): ${c.ips.join(", ")}\n` +
          `LET net_flow <= collect_client(client_id=client_id, artifacts="Windows.Network.Netstat", env=dict())\n` +
          `${wait("net_flow")}\n` +
          `SELECT * FROM source(client_id=client_id, flow_id=net_flow.flow_id, artifact="Windows.Network.Netstat")`,
      );
    }
    if (!blocks.length) return "";
    const header =
      `-- ── Velociraptor NOTEBOOK query — runs against ONE client (paste into a notebook cell) ──\n` +
      `-- Set client_id below, then run. Find it with:\n` +
      `--   SELECT client_id, os_info.hostname FROM clients() WHERE os_info.hostname =~ "HOSTNAME"\n` +
      `LET client_id <= "C.0000000000000000"`;
    return header + "\n\n" + blocks.join("\n\n");
  }
  // Microsoft Defender / Sentinel KQL — one runnable query per relevant table.
  function huntKql(c) {
    const out = [];
    if (c.host)
      out.push(
        `// scope to the affected host: | where DeviceName =~ ${hq(c.host)}`,
      );
    if (c.hashes.length)
      out.push(
        `DeviceFileEvents\n| where SHA256 in~ (${c.hashes.map(hq).join(", ")}) or MD5 in~ (${c.hashes.map(hq).join(", ")})`,
      );
    if (c.processes.length)
      out.push(
        `DeviceProcessEvents\n| where FileName in~ (${c.processes.map((p) => hq(baseName(p))).join(", ")})${c.parent ? `\n| where InitiatingProcessFileName =~ ${hq(baseName(c.parent))}` : ""}`,
      );
    if (c.ips.length)
      out.push(
        `DeviceNetworkEvents\n| where RemoteIP in~ (${c.ips.map(hq).join(", ")})`,
      );
    if (c.domains.length || c.urls.length)
      out.push(
        `DeviceNetworkEvents\n| where RemoteUrl has_any (${[...c.domains, ...c.urls].map(hq).join(", ")})`,
      );
    // Match on FileName (reliable) + FolderPath (device prefix stripped, native backslashes kept).
    if (c.paths.length)
      out.push(
        `DeviceFileEvents\n| where FileName has_any (${c.paths.map((p) => hq(baseName(p))).join(", ")}) or FolderPath has_any (${c.paths.map((p) => hq(cleanWinPath(p))).join(", ")})`,
      );
    return out.join("\n\n");
  }
  // Splunk SPL.
  function huntSpl(c) {
    const terms = [];
    if (c.hashes.length)
      terms.push(
        `(${c.hashes.map((h) => `SHA256=${hq(h)} OR MD5=${hq(h)}`).join(" OR ")})`,
      );
    if (c.processes.length)
      terms.push(
        `(${c.processes.map((p) => `process_name=${hq(baseName(p))}`).join(" OR ")})`,
      );
    if (c.parent) terms.push(`parent_process_name=${hq(baseName(c.parent))}`);
    if (c.ips.length)
      terms.push(
        `(${c.ips.map((ip) => `dest_ip=${hq(ip)} OR src_ip=${hq(ip)}`).join(" OR ")})`,
      );
    if (c.domains.length || c.urls.length)
      terms.push(
        `(${[...c.domains, ...c.urls].map((d) => `query="*${d}*" OR url="*${d}*"`).join(" OR ")})`,
      );
    // Match on file name (avoids backslash-escaping the full path).
    if (c.paths.length)
      terms.push(
        `(${c.paths.map((p) => `file_name=${hq(baseName(p))} OR file_path="*${baseName(p)}*"`).join(" OR ")})`,
      );
    if (!terms.length) return "";
    return `index=* ${c.host ? `host=${hq(c.host)} ` : ""}${terms.join(" OR ")}\n| table _time host process_name parent_process_name dest_ip url file_path`;
  }
  // Sigma rule skeleton — only meaningful for process/hash indicators.
  function huntSigma(c) {
    if (!c.processes.length && !c.hashes.length) return "";
    const sel = [];
    if (c.processes.length)
      sel.push(`    Image|endswith: '\\${baseName(c.processes[0])}'`);
    if (c.parent)
      sel.push(`    ParentImage|endswith: '\\${baseName(c.parent)}'`);
    if (c.hashes.length) sel.push(`    Hashes|contains: '${c.hashes[0]}'`);
    const tags =
      DfirState.lastState() && Array.isArray(c._mitre) && c._mitre.length
        ? c._mitre
            .map((t) => `  - attack.${String(t).toLowerCase()}`)
            .join("\n")
        : "  - attack.execution";
    return `title: Hunt - ${String(c.label).slice(0, 60)}\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n${sel.join("\n")}\n  condition: selection\nlevel: high\ntags:\n${tags}`;
  }

  // Sigma draft export (#89) and the hunt-query modal moved to js/dashboard-sigma-hunt.js
  // (#415 tier 3). showToast stayed: it is a page-wide helper that happened to sit under the
  // same banner, and js/dashboard-tickets.js calls it.
  let toastTimer = null;
  function showToast(text, kind) {
    const statusEl = document.getElementById("status");
    if (statusEl) statusEl.textContent = text;
    let el = document.getElementById("toast");
    if (!el) {
      el = document.createElement("div");
      el.id = "toast";
      document.body.appendChild(el);
    }
    el.className = "toast" + (kind === "warn" ? " warn" : "");
    el.textContent = text;
    // Force a reflow, then add .show, so the opacity transition has a frame to animate FROM.
    // Deliberately NOT requestAnimationFrame: rAF does not fire while the tab is hidden, which
    // would leave the toast permanently at opacity 0 — the failure this whole change exists to fix.
    void el.offsetWidth;
    el.classList.add("show");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(
      () => {
        el.classList.remove("show");
      },
      kind === "warn" ? 6000 : 3500,
    ); // a refusal needs longer to read than a confirmation
  }
  // Velociraptor triage moved to js/dashboard-velo-triage.js (#415 tier 3). Three bindings that
  // lived here but were only used by js/dashboard-velo-bundles.js and js/dashboard-velo-monitors.js
  // went to those modules; the four genuinely shared ones stayed put behind accessors.

  // Live CLIENT_EVENT monitoring (#84) moved to js/dashboard-velo-monitors.js (#415 tier 3).

  window.baseName = baseName;
  window.bulkCopyIocs = bulkCopyIocs;
  window.bulkExcludeIocs = bulkExcludeIocs;
  window.bulkMarkFindingsFalsePositive = bulkMarkFindingsFalsePositive;
  window.bulkTagFindings = bulkTagFindings;
  window.cleanWinPath = cleanWinPath;
  window.clearFindingSelection = clearFindingSelection;
  window.explainChip = explainChip;
  window.hasAny = hasAny;
  window.hq = hq;
  window.huntChip = huntChip;
  window.huntContextFor = huntContextFor;
  window.huntKql = huntKql;
  window.huntSigma = huntSigma;
  window.huntSpl = huntSpl;
  window.huntVql = huntVql;
  window.huntVqlNotebook = huntVqlNotebook;
  window.pushUniq = pushUniq;
  window.showToast = showToast;
  window.updateFindingBulkBar = updateFindingBulkBar;
})();
