// Responsive toolbar: collapse the button row into an overflow menu when it will not fit
// (#415 tier 3).
//
// WIRING ONLY — one statement forty lines long, no declarations and no state. So the module
// publishes only its initializer, and in a <head> script that statement would measure a toolbar
// that does not exist yet and collapse nothing.
(function () {
  // The statements the inline block ran at module scope, in their original order.
  function initResponsiveToolbar() {
    (function () {
      const tb = document.getElementById("toolbarMain");
      if (!tb) return;
      let queued = false;
      function fitToolbar() {
        if (queued) return;
        queued = true;
        requestAnimationFrame(() => {
          queued = false;
          tb.classList.remove("icons-only"); // measure with full labels showing
          const btn = tb.querySelector("button");
          const rowH = btn ? btn.offsetHeight : 34; // one action-row height
          if (tb.scrollHeight > rowH * 1.6) tb.classList.add("icons-only"); // it wrapped → collapse
        });
      }
      // React to viewport width changes via the (full-width, height-stable) header, so toggling
      // the class on toolbarMain — which only changes its HEIGHT — never re-triggers a loop.
      const hdr = document.querySelector("header");
      if (window.ResizeObserver && hdr) {
        let lastW = -1;
        new ResizeObserver((es) => {
          const w = es[0].contentRect.width;
          if (Math.abs(w - lastW) > 1) {
            lastW = w;
            fitToolbar();
          }
        }).observe(hdr);
      } else {
        window.addEventListener("resize", fitToolbar);
      }
      // React to dynamic label changes (Enrich/Anon/AI toggle text, Collapse/Expand, case load).
      // Observe text/children only — NOT attributes — so our own class toggle doesn't loop.
      if (window.MutationObserver) {
        new MutationObserver((changes) => {
          const affectsToolbarLayout = changes.some((change) => {
            const target =
              change.target.nodeType === 1
                ? change.target
                : change.target.parentElement;
            return !target || !target.closest("#jobsMenu");
          });
          if (affectsToolbarLayout) fitToolbar();
        }).observe(tb, { childList: true, characterData: true, subtree: true });
      }
      fitToolbar();
    })();
  }

  window.initResponsiveToolbar = initResponsiveToolbar;
})();
