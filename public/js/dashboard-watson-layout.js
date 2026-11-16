// The Watson panel's layout: its width and the full-screen board's Next steps column.
//
// Width: the analyst drags the panel's left edge (or uses the arrow keys on it). The width is kept
// between MIN_WIDTH and MAX_SHARE of the window, saved in this browser, and set as --watson-width,
// which the panel and the page padding read (dashboard-watson.css). A double click resets it.
// Board: in full screen, Key questions and Next steps are two <details> columns; each can be
// collapsed, and the choice is saved. Next steps come from the case state (most important first).
// initDataAct (dashboard-data-act.js) calls initWatsonLayout once at load.
(function () {
  const WIDTH_KEY = "dfir.watson.width";
  const SEC_KEY = "dfir.watson.board.";
  const DEFAULT_WIDTH = 360;
  const MIN_WIDTH = 300;
  const MAX_SHARE = 0.7;
  const KEY_STEP = 20;

  const store = {
    get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* a blocked store must not break the panel */ } },
  };
  const maxWidth = () => Math.max(MIN_WIDTH, Math.floor((Number(window.innerWidth) || 1280) * MAX_SHARE));
  // The saved width is the analyst's preferred width; the applied width is that, clamped to the
  // current window. A resize re-applies the preferred width and never saves (Codex review #5).
  let applied = 0;
  const currentWidth = () => applied || Number(store.get(WIDTH_KEY)) || DEFAULT_WIDTH;

  function applyWidth(px) {
    applied = Math.min(maxWidth(), Math.max(MIN_WIDTH, Math.round(Number(px) || DEFAULT_WIDTH)));
    document.documentElement.style.setProperty("--watson-width", applied + "px");
    return applied;
  }

  function watsonSetWidth(px) {
    const w = applyWidth(px);
    store.set(WIDTH_KEY, String(w));
    return w;
  }

  function onResize() {
    const saved = Number(store.get(WIDTH_KEY));
    if (saved || applied) applyWidth(saved || applied);
  }

  function watsonNextStepsHtml(steps) {
    const list = Array.isArray(steps) ? steps : [];
    if (!list.length) return `<div class="watson-empty">There are no next steps.</div>`;
    return list
      .map(
        (s) =>
          `<div class="watson-q"><span class="watson-step-pri watson-step-${escAttr(String(s.priority || ""))}">${esc(String(s.priority || "").toUpperCase())}</span> ` +
          `<strong>${esc(s.action)}</strong>` +
          (s.rationale ? `<div>${esc(s.rationale)}</div>` : "") +
          (s.pointer ? `<div class="watson-why">→ ${esc(s.pointer)}</div>` : "") +
          `</div>`,
      )
      .join("");
  }

  function paintSteps(st) {
    const steps = st && Array.isArray(st.nextSteps) ? st.nextSteps : [];
    Array.from(document.querySelectorAll('[data-w="boardnext"]')).forEach((el) => { el.innerHTML = watsonNextStepsHtml(steps); });
    Array.from(document.querySelectorAll('[data-w="boardnextcount"]')).forEach((el) => { el.textContent = steps.length ? ` (${steps.length})` : ""; });
  }

  // Drag the left edge: the width is the distance from the pointer to the window's right edge.
  function startDrag(e) {
    e.preventDefault();
    const move = (ev) => watsonSetWidth((Number(window.innerWidth) || 0) - ev.clientX);
    const stop = () => {
      document.removeEventListener("pointermove", move);
      document.removeEventListener("pointerup", stop);
      document.body.classList.remove("watson-resizing");
    };
    document.body.classList.add("watson-resizing");
    document.addEventListener("pointermove", move);
    document.addEventListener("pointerup", stop);
  }

  function onKey(e) {
    if (e.key === "ArrowLeft") watsonSetWidth(currentWidth() + KEY_STEP);
    else if (e.key === "ArrowRight") watsonSetWidth(currentWidth() - KEY_STEP);
    else return;
    e.preventDefault();
  }

  const onHandle = (e) => !!(e.target && e.target.closest && e.target.closest(".watson-resize"));

  function initWatsonLayout() {
    const saved = Number(store.get(WIDTH_KEY));
    if (saved) applyWidth(saved);
    if (typeof window.addEventListener === "function") window.addEventListener("resize", onResize);
    document.addEventListener("pointerdown", (e) => { if (onHandle(e)) startDrag(e); });
    document.addEventListener("dblclick", (e) => { if (onHandle(e)) watsonSetWidth(DEFAULT_WIDTH); });
    document.addEventListener("keydown", (e) => { if (onHandle(e)) onKey(e); });
    // A column's open or closed state is saved per browser.
    document.addEventListener(
      "toggle",
      (e) => {
        const sec = e.target && e.target.dataset ? e.target.dataset.wSec : "";
        if (sec) store.set(SEC_KEY + sec, e.target.open ? "open" : "closed");
      },
      true,
    );
    Array.from(document.querySelectorAll("[data-w-sec]")).forEach((d) => {
      if (store.get(SEC_KEY + d.dataset.wSec) === "closed") d.open = false;
    });
    if (typeof DfirState !== "undefined" && DfirState.onLastStateChange) DfirState.onLastStateChange(paintSteps);
  }

  window.watsonSetWidth = watsonSetWidth;
  window.watsonNextStepsHtml = watsonNextStepsHtml;
  window.initWatsonLayout = initWatsonLayout;
})();
