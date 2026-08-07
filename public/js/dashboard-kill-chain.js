// Kill chain tactic phase view — extracted from dashboard.html (issue #415, tier 3).
//
// This is the correction to a claim I made two commits ago. I reported that extraction had hit a
// floor of ~3,850 lines because 3,379 remained in sections flagged core machinery. That was wrong,
// and the error was reading SECTION size as spine size. The actual spine — render, connect,
// proceedConnect, renderIocs, renderTimelineEvents, dfirFeatureUnavailable — is 843 lines. The rest
// of those sections is ordinary feature code filed under a banner that happens to also contain one
// spine function.
//
// "Activity Log (#238)" was 1,145 lines holding at least ten features and two spine functions.
// Splitting the Kill Chain out of it leaves 163 lines with ZERO escapes — directly extractable,
// and invisible while the whole block read as core.
(function () {
  "use strict";

  // Reunited with renderKillChain below (#415). These 120 lines — the technique→tactic map,
  // the keyword fallback, the context refinement, the tactic ordering and the whole detail
  // pane — sat 800 lines up under the "Screenshot OCR full-text search" banner, which is why
  // that section reported five state escapes: every one was a Kill Chain name read by Kill
  // Chain code. A banner is where a feature was written down, not where it lives.
  // Kill-chain tactic phase view — technique→tactic map replicated from mitreTactics.ts.
  const KC_TECHNIQUE_TACTIC = {
    T1566: "Initial Access",
    T1190: "Initial Access",
    T1133: "Initial Access",
    T1078: "Initial Access",
    T1195: "Initial Access",
    T1199: "Initial Access",
    T1189: "Initial Access",
    T1091: "Initial Access",
    T1200: "Initial Access",
    T1059: "Execution",
    T1204: "Execution",
    T1203: "Execution",
    T1106: "Execution",
    T1569: "Execution",
    T1047: "Execution",
    T1129: "Execution",
    T1559: "Execution",
    T1610: "Execution",
    T1648: "Execution",
    T1547: "Persistence",
    T1543: "Persistence",
    T1136: "Persistence",
    T1505: "Persistence",
    T1546: "Persistence",
    T1574: "Persistence",
    T1098: "Persistence",
    T1137: "Persistence",
    T1037: "Persistence",
    T1176: "Persistence",
    T1554: "Persistence",
    T1053: "Persistence",
    T1197: "Persistence",
    T1548: "Privilege Escalation",
    T1134: "Privilege Escalation",
    T1068: "Privilege Escalation",
    T1484: "Privilege Escalation",
    T1611: "Privilege Escalation",
    T1070: "Defense Evasion",
    T1027: "Defense Evasion",
    T1036: "Defense Evasion",
    T1112: "Defense Evasion",
    T1562: "Defense Evasion",
    T1218: "Defense Evasion",
    T1140: "Defense Evasion",
    T1497: "Defense Evasion",
    T1480: "Defense Evasion",
    T1055: "Defense Evasion",
    T1564: "Defense Evasion",
    T1222: "Defense Evasion",
    T1127: "Defense Evasion",
    T1006: "Defense Evasion",
    T1620: "Defense Evasion",
    T1535: "Defense Evasion",
    T1207: "Defense Evasion",
    T1014: "Defense Evasion",
    T1003: "Credential Access",
    T1110: "Credential Access",
    T1555: "Credential Access",
    T1552: "Credential Access",
    T1558: "Credential Access",
    T1556: "Credential Access",
    T1187: "Credential Access",
    T1212: "Credential Access",
    T1040: "Credential Access",
    T1539: "Credential Access",
    T1649: "Credential Access",
    T1087: "Discovery",
    T1083: "Discovery",
    T1057: "Discovery",
    T1018: "Discovery",
    T1082: "Discovery",
    T1016: "Discovery",
    T1049: "Discovery",
    T1033: "Discovery",
    T1007: "Discovery",
    T1069: "Discovery",
    T1482: "Discovery",
    T1135: "Discovery",
    T1046: "Discovery",
    T1518: "Discovery",
    T1010: "Discovery",
    T1124: "Discovery",
    T1201: "Discovery",
    T1012: "Discovery",
    T1614: "Discovery",
    T1021: "Lateral Movement",
    T1570: "Lateral Movement",
    T1550: "Lateral Movement",
    T1563: "Lateral Movement",
    T1080: "Lateral Movement",
    T1072: "Lateral Movement",
    T1210: "Lateral Movement",
    T1534: "Lateral Movement",
    T1005: "Collection",
    T1114: "Collection",
    T1056: "Collection",
    T1560: "Collection",
    T1113: "Collection",
    T1119: "Collection",
    T1213: "Collection",
    T1074: "Collection",
    T1115: "Collection",
    T1039: "Collection",
    T1125: "Collection",
    T1071: "Command and Control",
    T1105: "Command and Control",
    T1571: "Command and Control",
    T1572: "Command and Control",
    T1090: "Command and Control",
    T1219: "Command and Control",
    T1095: "Command and Control",
    T1102: "Command and Control",
    T1568: "Command and Control",
    T1573: "Command and Control",
    T1104: "Command and Control",
    T1008: "Command and Control",
    T1041: "Exfiltration",
    T1048: "Exfiltration",
    T1567: "Exfiltration",
    T1029: "Exfiltration",
    T1020: "Exfiltration",
    T1011: "Exfiltration",
    T1052: "Exfiltration",
    T1030: "Exfiltration",
    T1486: "Impact",
    T1490: "Impact",
    T1489: "Impact",
    T1485: "Impact",
    T1491: "Impact",
    T1561: "Impact",
    T1499: "Impact",
    T1498: "Impact",
    T1531: "Impact",
    T1496: "Impact",
    T1565: "Impact",
    T1657: "Impact",
  };
  // Context refinement for multi-tactic techniques — mirrors CONTEXT_REFINEMENT in mitreTactics.ts.
  // T1078 (Valid Accounts) is pinned to Initial Access, but a remote/explicit-credential logon
  // reusing existing creds is lateral movement, not first entry — keeps EID 4648 host-to-host
  // logons out of the Initial Access lane.
  const KC_CONTEXT_REFINEMENT = {
    T1078: [
      [
        /\b(explicit credentials|eid\s*4648|remote desktop|rdp|winrm|psexec|wmiexec|pass-?the-?(?:hash|ticket)|accepted\s+(?:password|publickey)|ssh\s+login)\b/i,
        "Lateral Movement",
      ],
    ],
  };
  const KC_KEYWORD_TACTIC = [
    [
      /\b(ransom\w*|encrypt(ed|ion)? for impact|vssadmin\s+delete|shadow\s*cop(y|ies)\s+delet|inhibit\s+recovery|wbadmin\s+delete)\b/i,
      "Impact",
    ],
    [/\b(exfiltrat\w+|data\s+staged|rclone|megacmd)\b/i, "Exfiltration"],
    [
      /\b(mimikatz|lsass|sekurlsa|kerberoast|asreproast|dcsync|ntds\.dit|credential\s+dump\w*|hashdump|wdigest|pass-?the-?(hash|ticket))\b/i,
      "Credential Access",
    ],
    [
      /\b(psexec|wmiexec|smbexec|lateral\s+move\w*|remote\s+desktop|\brdp\b|winrm|\bwmic\b\s+\/node|pass-?the-?)\b/i,
      "Lateral Movement",
    ],
    [
      /\b(uac\s*bypass|fodhelper|token\s+manipulation|sedebugprivilege|getsystem|named\s+pipe\s+impersonat)\b/i,
      "Privilege Escalation",
    ],
    [
      /\b(run\s*key|currentversion\\run|scheduled\s+task|schtasks|new-?service|sc\s+create|webshell|web\s+shell|autorun|wmi\s+event\s+subscription)\b/i,
      "Persistence",
    ],
    [
      /\b(defender\s+tamper\w*|disable\s+(defender|antivirus|amsi)|amsi\s+bypass|clear(ed)?\s+event\s+log|wevtutil\s+cl|obfuscat\w+|process\s+(injection|hollow\w*)|rundll32|mshta|regsvr32)\b/i,
      "Defense Evasion",
    ],
    [
      /\b(c2|c&c|command\s+and\s+control|beacon\w*|cobalt\s*strike|reverse\s+shell|ingress\s+tool\s+transfer)\b/i,
      "Command and Control",
    ],
    [
      /\b(phish\w+|spear-?phish\w*|malicious\s+(attachment|link)|drive-?by|exploit\s+public)\b/i,
      "Initial Access",
    ],
    [
      /\b(bloodhound|sharphound|adfind|net\s+(group|user|view)|nltest|whoami\s+\/|domain\s+trust|reconnaissance)\b/i,
      "Discovery",
    ],
    [
      /\b(powershell|cmd\.exe|wscript|cscript|\bwmi\b|invoke-expression|iex\s*\(|encodedcommand)\b/i,
      "Execution",
    ],
  ];
  const KC_TACTIC_PRIORITY = [
    "Impact",
    "Exfiltration",
    "Credential Access",
    "Lateral Movement",
    "Privilege Escalation",
    "Persistence",
    "Collection",
    "Command and Control",
    "Initial Access",
    "Discovery",
    "Defense Evasion",
    "Execution",
  ];
  const KC_CHAIN_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
  ];
  // CSS-var strings (not literals) so the kill-chain/phase swatches — rendered into DOM inline
  // styles — follow the active theme automatically (no re-render needed). See themeColor() for canvas.
  const KC_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"];

  function kcTacticForEvent(e) {
    const techs = e.mitreTechniques || [];
    const desc = e.description || "";
    const found = new Set();
    for (const t of techs) {
      const base = ((/T\d{4}/i.exec(t) || [])[0] || t).toUpperCase();
      // A description-keyed refinement overrides the table default for multi-tactic techniques.
      const refinements = KC_CONTEXT_REFINEMENT[base];
      let tac = KC_TECHNIQUE_TACTIC[base];
      if (refinements)
        for (const [re, rtac] of refinements)
          if (re.test(desc)) {
            tac = rtac;
            break;
          }
      if (tac) found.add(tac);
    }
    if (found.size > 0) return KC_TACTIC_PRIORITY.find((t) => found.has(t));
    for (const [re, tac] of KC_KEYWORD_TACTIC) if (re.test(desc)) return tac;
    return null;
  }

  let kcSelectedTac = null;
  let kcByTactic = {}; // last-rendered tactic→events grouping, so kcSelect can fill the detail panel

  function kcSelect(tac) {
    kcSelectedTac = kcSelectedTac === tac ? null : tac;
    document
      .querySelectorAll(".kc-phase")
      .forEach((p) =>
        p.classList.toggle("kc-active", p.dataset.tac === kcSelectedTac),
      );
    renderKcDetail();
  }

  // Render the selected tactic's events into the full-width panel below the strip.
  function renderKcDetail() {
    const box = document.getElementById("kcDetail");
    if (!box) return;
    const events = (kcSelectedTac && kcByTactic[kcSelectedTac]) || [];
    if (!kcSelectedTac || !events.length) {
      box.hidden = true;
      box.innerHTML = "";
      return;
    }
    const maxSev = KC_SEV_ORDER.find((s) =>
      events.some((e) => e.severity === s),
    );
    const topColor = maxSev ? KC_SEV_COLOR[maxSev] : "var(--text-muted)";
    const rows = events
      .map((e) => {
        const desc = String(e.description || "")
          .replace(/\s*\[corroborated by \d+ sources?:[^\]]*\]\s*$/i, "")
          .replace(/\s*\[more\]$/, "");
        return (
          `<div class="kc-event-row">` +
          `<span class="kc-ev-time sev-${esc(e.severity)}">${esc(e.timestamp || "(undated)")}</span>` +
          `<span class="kc-ev-desc">${esc(desc)}</span>` +
          `${e.mitreTechniques && e.mitreTechniques.length ? `<small class="kc-ev-mitre">${mitreLinks(e.mitreTechniques)}</small>` : ""}` +
          `</div>`
        );
      })
      .join("");
    box.innerHTML =
      `<div class="kc-detail-head"><span data-safe-style="color:${topColor}">${esc(kcSelectedTac)}</span>` +
      `<span data-safe-style="color:var(--text-muted);font-weight:400;font-size:12px">${events.length} event${events.length === 1 ? "" : "s"}</span></div>` +
      `<div class="kc-detail-rows">${rows}</div>`;
    box.hidden = false;
  }

  function renderKillChain(ft) {
    const total = (ft || []).length;
    ft = applyGlobalEventFilter(ft); // honor the global search-bar filter (text + time range)
    const byTactic = {};
    for (const tac of KC_CHAIN_ORDER) byTactic[tac] = [];
    byTactic["Uncategorized"] = [];
    for (const e of ft) {
      const tac = kcTacticForEvent(e);
      if (tac && byTactic[tac]) byTactic[tac].push(e);
      else byTactic["Uncategorized"].push(e);
    }
    kcByTactic = byTactic;
    // Drop a stale selection if the re-rendered data no longer has events for it.
    if (kcSelectedTac && !(byTactic[kcSelectedTac] || []).length)
      kcSelectedTac = null;
    const order = [...KC_CHAIN_ORDER, "Uncategorized"];
    const cards = order
      .map((tac) => {
        const events = byTactic[tac] || [];
        const count = events.length;
        const isEmpty = count === 0;
        const maxSev = KC_SEV_ORDER.find((s) =>
          events.some((e) => e.severity === s),
        );
        const topColor = maxSev ? KC_SEV_COLOR[maxSev] : "var(--border-color)";
        const isActive = kcSelectedTac === tac && !isEmpty;
        return (
          `<div class="kc-phase${isEmpty ? " kc-empty" : ""}${isActive ? " kc-active" : ""}" ` +
          `data-tac="${escAttr(tac)}" ` +
          `data-act="kcSelect" data-tac="${escAttr(tac)}">` +
          `<div class="kc-phase-header" data-safe-style="border-top-color:${topColor}">` +
          `<span class="kc-tac">${esc(tac)}</span>` +
          `<span class="kc-count" data-safe-style="color:${isEmpty ? "#2a2f3a" : topColor}">${count}</span>` +
          `</div>` +
          `</div>`
        );
      })
      .join("");
    const filterNote = _hasActiveFilter()
      ? `<div data-safe-style="font-size:11px;color:var(--text-muted);margin-bottom:6px">Filtered to ${ft.length} of ${total} events matching the search.</div>`
      : "";
    document.getElementById("killChain").innerHTML =
      filterNote +
      `<div class="kc-strip">${cards}</div><div id="kcDetail" class="kc-detail" hidden></div>`;

    renderKcDetail();
  }
  window.kcSelect = kcSelect;
  window.renderKcDetail = renderKcDetail;
  window.renderKillChain = renderKillChain;
})();
