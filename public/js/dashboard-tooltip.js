// Custom tooltip — the hover card the dashboard shows instead of the browser's own title text
// (#415 tier 3).
//
// Wiring only. The responsive-toolbar guard that sits at the end of this range belongs to another
// extraction and stays in the page.
(function () {
  // ── Custom tooltip ────────────────────────────────────────────────────────
  // Native `title` tooltips can't be CSS-styled (Chrome rendered the first line brighter
  // than the rest). For toolbar controls we use `data-tip` + this one styled element,
  // positioned below the control and clamped to the viewport. Uniform flat colour.

  // The statements the inline block ran at module scope.
  function initTooltip() {
    (function () {
      const tip = document.createElement("div");
      tip.className = "tip";
      tip.style.display = "none";
      document.body.appendChild(tip);
      let cur = null;
      function show(el) {
        const t = el.getAttribute("data-tip");
        if (!t) return;
        tip.textContent = t;
        tip.style.display = "block";
        const r = el.getBoundingClientRect();
        let left = Math.min(r.left, window.innerWidth - tip.offsetWidth - 8);
        if (left < 8) left = 8;
        let top = r.bottom + 6;
        if (top + tip.offsetHeight > window.innerHeight - 8)
          top = r.top - tip.offsetHeight - 6;
        tip.style.left = left + "px";
        tip.style.top = Math.max(8, top) + "px";
      }
      function hide() {
        tip.style.display = "none";
        cur = null;
      }
      document.addEventListener("mouseover", (e) => {
        const el = e.target.closest && e.target.closest("[data-tip]");
        if (el && el !== cur) {
          cur = el;
          show(el);
        }
      });
      document.addEventListener("mouseout", (e) => {
        const el = e.target.closest && e.target.closest("[data-tip]");
        if (el && el === cur) hide();
      });
      document.addEventListener("focusin", (e) => {
        const el = e.target.closest && e.target.closest("[data-tip]");
        if (el) {
          cur = el;
          show(el);
        }
      });
      document.addEventListener("focusout", hide);
      window.addEventListener("scroll", hide, true);
    })();
  }

  window.initTooltip = initTooltip;
})();
