// IOC block-list export — the case's indicators as a block list for a firewall or proxy, in
// several formats (#415 tier 3).
(function () {
  // ── IOC block-list export (#87) ──────────────────────────────────────────
  function openIocBlocklist() {
    document.getElementById("iocBlocklistOverlay").classList.add("open");
  }
  function closeIocBlocklist() {
    document.getElementById("iocBlocklistOverlay").classList.remove("open");
  }
  function downloadIocBlocklist(format) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const c = encodeURIComponent(caseId);
    const minSev = document.getElementById("blMinSev").value;
    const types = [];
    if (document.getElementById("blTypeIp").checked) types.push("ip");
    if (document.getElementById("blTypeDomain").checked) types.push("domain");
    if (document.getElementById("blTypeUrl").checked) types.push("url");
    if (document.getElementById("blTypeHash").checked) types.push("hash");
    if (document.getElementById("blTypeEmail").checked) types.push("email");
    const verdictOnly = document.getElementById("blVerdictOnly").checked;
    const params = new URLSearchParams({
      format,
      minSeverity: minSev,
      types: types.join(","),
    });
    if (verdictOnly) params.set("verdictOnly", "true");
    window.location.href = `/cases/${c}/export/ioc-blocklist?${params}`;
    closeIocBlocklist();
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
