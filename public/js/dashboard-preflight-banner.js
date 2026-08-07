// Startup pre-flight banner — the warning strip shown when the server's own checks fail
// (#415 tier 3).
//
// One statement runs at load and becomes the initializer; the case-lifecycle guard that follows it
// in this range stays in the page.
(function () {
  // ── Startup pre-flight banner (#179) ───────────────────────────────────
  // Fetches /diagnostics/preflight once on load (cached 30s server-side).
  // Shows a red banner only when a CRITICAL check (AI provider) failed.
  // "Disable checks" persists the setting so the banner never reappears.
  let preflightDismissed = false;
  function loadPreflightBanner() {
    if (preflightDismissed) return;
    fetch("/diagnostics/preflight")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!d || !d.report || d.report.disabled || !d.report.anyCriticalFailed)
          return;
        const banner = document.getElementById("preflightBanner");
        if (!banner || banner.__preflightShown) return;
        banner.__preflightShown = true;
        const failed = d.report.items.filter((i) => !i.ok && i.critical);
        const details = failed
          .map((i) => esc(i.name) + ": " + esc(i.detail))
          .join(" &bull; ");
        const span = document.createElement("span");
        span.innerHTML =
          "⚠ Pre-flight check failed — " +
          details +
          ' &nbsp;<span data-safe-style="color:#ffaaaa;font-size:11px">You can disable these checks in Settings → Diagnostics.</span>';
        const openBtn = document.createElement("button");
        openBtn.type = "button";
        openBtn.style.cssText = "margin-left:10px";
        openBtn.textContent = "Open Diagnostics";
        openBtn.onclick = () => openSettingsTab("diagnostics");
        const disableBtn = document.createElement("button");
        disableBtn.type = "button";
        disableBtn.textContent = "Disable checks";
        disableBtn.onclick = () => {
          fetch("/diagnostics/preflight/control", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ disabled: true }),
          })
            .then(() => {
              preflightDismissed = true;
              banner.hidden = true;
            })
            .catch(() => {});
        };
        const btn = document.createElement("button");
        btn.type = "button";
        btn.title = "Dismiss for this session";
        btn.textContent = "✕";
        btn.onclick = () => {
          preflightDismissed = true;
          banner.hidden = true;
        };
        banner.innerHTML = "";
        banner.appendChild(span);
        banner.appendChild(openBtn);
        banner.appendChild(disableBtn);
        banner.appendChild(btn);
        banner.hidden = false;
      })
      .catch(() => {});
  }

  // The controls the inline block bound at module scope.
  function initPreflightBanner() {
    loadPreflightBanner();
  }

  window.initPreflightBanner = initPreflightBanner;
})();
