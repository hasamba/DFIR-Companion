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
  //
  // The banner is a fixed strip at the bottom of the viewport, not an in-flow block (#1827): the
  // answer arrives after first paint, and an in-flow banner then pushed all of <main> down — a
  // load-time layout shift. An overlay moves nothing. --preflight-banner-h gives the page bottom
  // padding of the banner's height so the end of the page is not hidden under it; padding at the
  // end of the document moves nothing above it either.
  const BANNER_HEIGHT_VAR = "--preflight-banner-h";
  let preflightDismissed = false;
  let bannerResize = null;

  function syncBannerHeight(banner) {
    const rootStyle = document.documentElement.style;
    if (banner.hidden) rootStyle.removeProperty(BANNER_HEIGHT_VAR);
    else rootStyle.setProperty(BANNER_HEIGHT_VAR, banner.offsetHeight + "px");
  }

  function hideBanner(banner) {
    preflightDismissed = true;
    banner.hidden = true;
    if (bannerResize) bannerResize.disconnect();
    bannerResize = null;
    syncBannerHeight(banner);
  }
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
            .then(async (r) => {
              // Hide only when the server saved the setting; otherwise the warning still holds and
              // the analyst is told why, so the button does not look dead.
              if (r && r.ok) return hideBanner(banner);
              const data = await r.json().catch(() => null);
              throw new Error((data && data.error) || `server returned ${r ? r.status : "no answer"}`);
            })
            .catch((err) => {
              if (typeof showToast === "function")
                showToast(`Could not disable the pre-flight checks: ${err.message}`, "warn");
            });
        };
        const btn = document.createElement("button");
        btn.type = "button";
        btn.title = "Dismiss for this session";
        btn.setAttribute("aria-label", "Dismiss the pre-flight warning for this session");
        btn.textContent = "✕";
        btn.onclick = () => hideBanner(banner);
        banner.innerHTML = "";
        banner.appendChild(span);
        banner.appendChild(openBtn);
        banner.appendChild(disableBtn);
        banner.appendChild(btn);
        banner.hidden = false;
        if (typeof ResizeObserver !== "undefined") {
          // Follows the banner when it wraps (narrow window) and fires once on observe.
          bannerResize = new ResizeObserver(() => syncBannerHeight(banner));
          bannerResize.observe(banner);
        } else {
          syncBannerHeight(banner);
        }
      })
      .catch(() => {});
  }

  // The controls the inline block bound at module scope.
  function initPreflightBanner() {
    loadPreflightBanner();
  }

  window.initPreflightBanner = initPreflightBanner;
})();
