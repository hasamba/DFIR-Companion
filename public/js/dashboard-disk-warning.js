// Disk-space warning (#1) — the banner shown when the case volume is running out of room
// (#415 tier 3).
//
// ITS INITIALIZER TAKES A DECLARATION WITH IT, which is the point worth noting. The dismiss button
// was captured by `const diskWarnDismissBtn = document.getElementById(…)` at module scope: that
// reads as module body, and in a <head> script it evaluates to null before the markup exists, so
// the line below it would bind nothing and the banner could never be dismissed. The lookup and its
// wiring move together.
(function () {
  // ── Disk-space warning (#119) ───────────────────────────────────────────
  // Poll GET /disk-stats once on load. Shows a banner when the cases-root
  // filesystem is at warning / danger / critical level. Dismissed per-session.
  let diskWarnDismissed = false;
  function loadDiskStats() {
    if (diskWarnDismissed) return;
    fetch("/disk-stats")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!d || d.level === "none") {
          hideDiskWarn();
          return;
        }
        const banner = document.getElementById("diskWarnBanner");
        const text = document.getElementById("diskWarnText");
        if (!banner || !text) return;
        const usedGb = ((d.totalBytes - d.freeBytes) / 1e9).toFixed(1);
        const totalGb = (d.totalBytes / 1e9).toFixed(1);
        const pct = d.usedPct.toFixed(1);
        text.textContent =
          `Disk space ${d.level.toUpperCase()}: ${usedGb} GB used of ${totalGb} GB (${pct}%) on the cases folder filesystem.` +
          (d.level === "critical"
            ? " Free space is very low — consider archiving or moving closed cases."
            : d.level === "danger"
              ? " Consider archiving or moving closed cases before this fills."
              : " Monitor disk usage and archive closed cases if needed.");
        banner.className = `dw-${d.level}`;
        banner.hidden = false;
      })
      .catch(() => {});
  }
  function hideDiskWarn() {
    const el = document.getElementById("diskWarnBanner");
    if (el) el.hidden = true;
  }

  // The statements the inline block ran at module scope, in order.
  function initDiskWarning() {
    const diskWarnDismissBtn = document.getElementById("diskWarnDismiss");
    if (diskWarnDismissBtn)
      diskWarnDismissBtn.onclick = () => {
        diskWarnDismissed = true;
        hideDiskWarn();
      };
  }

  window.loadDiskStats = loadDiskStats;
  window.initDiskWarning = initDiskWarning;
})();
