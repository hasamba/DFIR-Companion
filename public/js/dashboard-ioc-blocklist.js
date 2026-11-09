// IOC block-list export — the case's indicators as a block list for a firewall or proxy, in
// several formats (#415 tier 3).
(function () {
  // ── IOC block-list export (#87) ──────────────────────────────────────────
  function openIocBlocklist() {
    document.getElementById("iocBlocklistOverlay").classList.add("open");
    refreshBlocklistCount();
  }
  function closeIocBlocklist() {
    document.getElementById("iocBlocklistOverlay").classList.remove("open");
  }

  // The dialog's filter controls; a change to any of them refreshes the match count (#1807).
  const BL_TYPE_CONTROLS = [
    ["blTypeIp", "ip"],
    ["blTypeDomain", "domain"],
    ["blTypeUrl", "url"],
    ["blTypeHash", "hash"],
    ["blTypeEmail", "email"],
  ];

  // One query builder for the download and the match-count summary, so the count always describes
  // the file the analyst would get.
  function blocklistParams(format) {
    const types = BL_TYPE_CONTROLS.filter(
      ([id]) => document.getElementById(id).checked,
    ).map(([, type]) => type);
    const params = new URLSearchParams({
      format,
      minSeverity: document.getElementById("blMinSev").value,
      types: types.join(","),
    });
    if (document.getElementById("blVerdictOnly").checked)
      params.set("verdictOnly", "true");
    return params;
  }

  // #2468: "Matches 0 of 21 IOCs" still handed a header-only file to the firewall team and closed
  // the dialog. The newest summary's match count is kept; a known zero disables the three download
  // buttons and the count line stays as the reason. null means unknown (a summary pending or
  // failed) and never blocks — a stale count must not stop a download.
  const BL_DOWNLOAD_BUTTONS = ["blDlTxt", "blDlCsv", "blDlStix"];
  const BL_NOTHING_TITLE = "No IOC matches these filters — the file would hold only a header. Widen the filters above.";
  let blLastMatched = null;
  function setBlocklistMatched(matched) {
    blLastMatched = matched;
    for (const id of BL_DOWNLOAD_BUTTONS) {
      const btn = document.getElementById(id);
      if (!btn) continue;
      btn.disabled = matched === 0;
      btn.title = matched === 0 ? BL_NOTHING_TITLE : "";
    }
  }

  function downloadIocBlocklist(format) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || blLastMatched === 0) return;
    const c = encodeURIComponent(caseId);
    window.location.href = `/cases/${c}/export/ioc-blocklist?${blocklistParams(format)}`;
    closeIocBlocklist();
  }

  // Why IOCs were left out, in the order the analyst can most often act on.
  const BL_REASON_TEXT = [
    ["below-min-severity", "below minimum severity"],
    ["no-actionable-intel", "with no usable threat-intel verdict"],
    ["ineligible-type", "ineligible or unselected type"],
    ["not-verdict-confirmed", "not verdict-confirmed"],
    ["retired", "retired"],
    ["client-reported", "client-reported"],
  ];

  function blocklistCountText(summary) {
    const excluded = summary.excluded || {};
    const reasons = BL_REASON_TEXT.filter(([key]) => excluded[key] > 0).map(
      ([key, text]) => `${excluded[key]} ${text}`,
    );
    const head = `Matches ${summary.matched} of ${summary.total} IOCs`;
    return reasons.length ? `${head} — ${reasons.join(", ")}` : head;
  }

  // Each request takes a generation number; a response that is no longer the newest is dropped,
  // so a slow answer for an old filter never overwrites the count for the current one.
  let blSummaryGen = 0;
  async function refreshBlocklistCount() {
    const out = document.getElementById("blMatchCount");
    const caseId = document.getElementById("caseId").value.trim();
    const gen = ++blSummaryGen;
    setBlocklistMatched(null); // the old count no longer describes the filters
    if (!out) return;
    if (!caseId) {
      out.textContent = "";
      return;
    }
    let text = "";
    let matched = null;
    try {
      const res = await fetch(
        `/cases/${encodeURIComponent(caseId)}/export/ioc-blocklist?${blocklistParams("summary")}`,
      );
      const body = await res.json();
      if (res.ok && typeof body.matched === "number") {
        text = blocklistCountText(body);
        matched = body.matched;
      }
    } catch {
      text = "";
    }
    if (gen !== blSummaryGen) return;
    out.textContent = text;
    setBlocklistMatched(matched);
  }

  // Redacted case export (#54) moved to js/dashboard-redacted-export.js (#415 tier 3).
  // ZIP case archive moved to js/dashboard-zip-archive.js (#415 tier 3).

  // The controls the page bound at module scope. Order unchanged.
  function initIocBlocklist() {
    document.getElementById("blDlTxt").onclick = () =>
      downloadIocBlocklist("txt");
    document.getElementById("blDlCsv").onclick = () =>
      downloadIocBlocklist("csv");
    document.getElementById("blDlStix").onclick = () =>
      downloadIocBlocklist("stix");
    document.getElementById("blCancel").onclick = closeIocBlocklist;
    for (const id of ["blMinSev", "blVerdictOnly", ...BL_TYPE_CONTROLS.map(([c]) => c)]) {
      document.getElementById(id).addEventListener("change", refreshBlocklistCount);
    }
    document
      .getElementById("iocBlocklistOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "iocBlocklistOverlay") closeIocBlocklist();
      });
  }

  window.openIocBlocklist = openIocBlocklist;
  window.closeIocBlocklist = closeIocBlocklist;
  window.downloadIocBlocklist = downloadIocBlocklist;
  window.initIocBlocklist = initIocBlocklist;
})();
