// Settings → Built-in HTTPS (#2285): what the server presents, and the local-CA download link when
// that CA vouches for it. Called by js/dashboard-env-settings.js each time the settings load.
(function () {
  async function renderTlsInfo() {
    const line = document.getElementById("tls-info-line");
    const link = document.getElementById("tls-ca-download");
    if (!line || !link) return;
    try {
      const r = await fetch("/tls/info");
      if (!r.ok) return;
      const info = await r.json();
      const day = (d) => String(d || "").slice(0, 10);
      const parts = [info.enabled ? `HTTPS is ON (${info.source === "user" ? "your certificate" : "local CA"})` : "HTTPS is off"];
      if (info.server) parts.push(`certificate SHA-256 ${info.server.fingerprint256}, expires ${day(info.server.validTo)}`);
      if (info.ca && info.caDownload) parts.push(`local CA SHA-256 ${info.ca.fingerprint256}`);
      for (const w of info.warnings || []) parts.push(`⚠ ${w}`);
      line.textContent = parts.join(" · ") + ".";
      link.hidden = !info.caDownload;
    } catch {
      /* the line keeps its placeholder; nothing here is essential */
    }
  }


  window.renderTlsInfo = renderTlsInfo;
})();
