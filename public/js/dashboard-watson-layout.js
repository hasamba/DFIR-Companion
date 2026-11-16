// The Watson panel's layout: its width and the full-screen board's Next steps column.
//
// Width: the analyst drags the panel's left edge (or uses the arrow keys on it). The width is kept
// between MIN_WIDTH and MAX_SHARE of the window, saved in this browser, and set as --watson-width,
// which the panel and the page padding read (dashboard-watson.css). A double click resets it.
// Board: in full screen, Key questions and Next steps are two <details> columns on the left. A closed
// column is a thin book spine with its title and count (closed is the default); the choice is saved.
// Next steps come from the case state (most important first).
// Jump: when the chat is not scrolled to its end, an arrow at the bottom centre scrolls to the latest.
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

  const each = (sel, fn) => Array.from(document.querySelectorAll(sel)).forEach(fn);
  const countText = (n) => ` (${n})`;

  function paintSteps(st) {
    const steps = st && Array.isArray(st.nextSteps) ? st.nextSteps : [];
    const questions = st && Array.isArray(st.keyQuestions) ? st.keyQuestions : [];
    each('[data-w="boardnext"]', (el) => { el.innerHTML = watsonNextStepsHtml(steps); });
    each('[data-w="boardnextcount"]', (el) => { el.textContent = countText(steps.length); });
    each('[data-w="boardqcount"]', (el) => { el.textContent = countText(questions.length); });
  }

  // The jump arrow shows when the log is more than JUMP_SLACK px above its end.
  const JUMP_SLACK = 40;
  const atEnd = (log) => log.scrollHeight - log.scrollTop - log.clientHeight <= JUMP_SLACK;
  function watsonJumpSync() {
    each(".watson-logwrap", (wrap) => {
      const log = wrap.querySelector(".watson-log");
      const btn = wrap.querySelector(".watson-jump");
      if (log && btn) btn.hidden = atEnd(log);
    });
  }
  function watsonJumpEnd(btn) {
    const log = btn.closest(".watson-logwrap") && btn.closest(".watson-logwrap").querySelector(".watson-log");
    if (!log) return;
    if (typeof log.scrollTo === "function") log.scrollTo({ top: log.scrollHeight, behavior: "smooth" });
    else log.scrollTop = log.scrollHeight;
    btn.hidden = true;
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

  // The message box's height: dragged from the handle on its top edge (up = taller), kept between
  // INPUT_MIN and INPUT_MAX_SHARE of the window, saved in this browser. A double click resets it.
  const INPUT_KEY = "dfir.watson.inputHeight";
  const INPUT_MIN = 48;
  const INPUT_MAX_SHARE = 0.6;
  const inputs = () => Array.from(document.querySelectorAll(".watson-input"));
  function watsonSetInputHeight(px) {
    const max = Math.max(INPUT_MIN, Math.floor((Number(window.innerHeight) || 800) * INPUT_MAX_SHARE));
    const h = px === null ? null : Math.min(max, Math.max(INPUT_MIN, Math.round(Number(px) || INPUT_MIN)));
    inputs().forEach((ta) => { ta.style.height = h === null ? "" : h + "px"; });
    store.set(INPUT_KEY, h === null ? "" : String(h));
    return h;
  }
  const onGrip = (e) => !!(e.target && e.target.closest && e.target.closest(".watson-input-grip"));
  function startInputDrag(e) {
    e.preventDefault();
    const ta = e.target.closest(".watson-composer") && e.target.closest(".watson-composer").querySelector(".watson-input");
    if (!ta) return;
    const startY = e.clientY;
    const startH = ta.offsetHeight;
    const move = (ev) => watsonSetInputHeight(startH + (startY - ev.clientY));
    const stop = () => {
      document.removeEventListener("pointermove", move);
      document.removeEventListener("pointerup", stop);
      document.body.classList.remove("watson-resizing-input");
    };
    document.body.classList.add("watson-resizing-input");
    document.addEventListener("pointermove", move);
    document.addEventListener("pointerup", stop);
  }

  function initWatsonLayout() {
    const saved = Number(store.get(WIDTH_KEY));
    if (saved) applyWidth(saved);
    if (typeof window.addEventListener === "function") window.addEventListener("resize", onResize);
    document.addEventListener("pointerdown", (e) => { if (onHandle(e)) startDrag(e); else if (onGrip(e)) startInputDrag(e); });
    document.addEventListener("dblclick", (e) => { if (onHandle(e)) watsonSetWidth(DEFAULT_WIDTH); else if (onGrip(e)) watsonSetInputHeight(null); });
    const savedInput = Number(store.get(INPUT_KEY));
    if (savedInput) watsonSetInputHeight(savedInput);
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
    each("[data-w-sec]", (d) => {
      if (store.get(SEC_KEY + d.dataset.wSec) === "open") d.open = true;
    });
    // Scroll events do not bubble: listen in the capture phase for the chat logs.
    document.addEventListener(
      "scroll",
      (e) => { if (e.target && e.target.classList && e.target.classList.contains("watson-log")) watsonJumpSync(); },
      true,
    );
    if (typeof DfirState !== "undefined" && DfirState.onLastStateChange) DfirState.onLastStateChange(paintSteps);
  }

  window.watsonSetWidth = watsonSetWidth;
  window.watsonNextStepsHtml = watsonNextStepsHtml;
  window.initWatsonLayout = initWatsonLayout;
  window.watsonJumpSync = watsonJumpSync;
  window.watsonSetInputHeight = watsonSetInputHeight;
  window.watsonJumpEnd = watsonJumpEnd;
})();
