// Watson's status: one pill in the panel header, one bar above the message box and a dot on the rail.
// They say what Watson does now. The first state that applies wins: working on an answer, a launch that
// needs recovery (uncertain or stalled: waiting for the analyst), waiting for Velociraptor (a launched collection whose result has not come back), waiting for the analyst (cards
// that need Apply, Reject or Launch), or ready. dashboard-watson-run.js calls watsonStatusSync on every
// render. "Show card" scrolls the log to the first card that waits. Every model string goes through esc().
(function () {
  const LABEL = {
    working: "Working",
    velo: "Waiting for Velociraptor",
    you: "Waiting for you",
    ready: "Ready",
  };

  const pending = (chat) =>
    (chat.proposals || []).filter((p) => p.status === "pending" && !p.stalled && !(p.kind === "velo_launch" && p.launching));
  // A launch whose outcome is unknown (uncertain), or one no live request owns (launching + stalled),
  // waits for the analyst's Mark as launched or Try again on its card. It is never "in flight".
  const needsRecovery = (p) => p.kind === "velo_launch" && (p.status === "uncertain" || (p.status === "launching" && !!p.stalled));
  const recovery = (chat) => (chat.proposals || []).filter(needsRecovery);
  const watching = (chat) =>
    (chat.proposals || []).find(
      (p) =>
        p.kind === "velo_launch" &&
        !needsRecovery(p) &&
        ((p.launched && p.watch && p.watch.state === "watching") || (!p.launched && p.launching)),
    );
  const nameOf = (p) => {
    const a = p.after || {};
    return String(p.title || a.question || a.title || a.text || p.question || p.text || p.summary || "this card");
  };

  function workingBar(run) {
    return run && run.kind === "reaction" ? "Watson is working on the new case events." : "Watson is working on an answer.";
  }

  // The first waiting card's own buttons, so the analyst acts without scrolling. A risky launch keeps
  // its risk review on the card; a round's super-timeline promotion has Apply only (as on the card).
  const btn = (pid, verb, label) =>
    `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="${verb}" data-pid="${escAttr(pid)}">${label}</button> `;
  function actionsOf(p) {
    if (p.kind === "velo_launch") return p.risk ? "" : btn(p.id, "apply", "Launch") + btn(p.id, "reject", "Reject");
    if (p.kind === "event_promote" && p.source === "supertimeline") return btn(p.id, "apply", watsonApplyLabel(p.kind));
    return btn(p.id, "apply", watsonApplyLabel(p.kind)) + btn(p.id, "reject", "Reject");
  }

  function youBar(cards) {
    const first = cards[0];
    const stuck = needsRecovery(first);
    const action = stuck
      ? `Check "${esc(nameOf(first))}": mark it as launched or try again.`
      : first.kind === "velo_launch"
        ? `Launch "${esc(nameOf(first))}".`
        : `Add ${watsonApplyNoun(first.kind)} "${esc(nameOf(first))}" to the case, or reject it.`;
    const more = cards.length - 1;
    const tail = more === 0 ? "" : more === 1 ? " 1 more card waits for you." : ` ${more} more cards wait for you.`;
    const show = `<button type="button" class="watson-mini watson-status-show" data-act="watsonStatusShow" data-w-status-show="${escAttr(first.id)}">Show card</button>`;
    return `${action}${tail} <span class="watson-status-actions">${stuck ? "" : actionsOf(first)}${show}</span>`;
  }

  function watsonStatusOf(chat, localBusy) {
    if (!chat) return { state: "none", pill: "", bar: "", pid: "" };
    const pill = (state, extra) =>
      `<span class="watson-status watson-status-${state}" role="status">${LABEL[state]}${extra || ""}</span>`;
    if (chat.running || localBusy) return { state: "working", pill: pill("working"), bar: workingBar(chat.running), pid: "" };
    const youOf = (cards) => ({ state: "you", pill: pill("you", ` · ${cards.length}`), bar: youBar(cards), pid: cards[0].id });
    const stuck = recovery(chat);
    if (stuck.length) return youOf([...stuck, ...pending(chat)]);
    const out = watching(chat);
    if (out) {
      const bar = `Velociraptor collects "${esc(nameOf(out))}". Watson reads the result when it arrives.`;
      return { state: "velo", pill: pill("velo"), bar, pid: out.id };
    }
    const cards = pending(chat);
    if (cards.length) return youOf(cards);
    return { state: "ready", pill: pill("ready"), bar: "", pid: "" };
  }

  function watsonStatusSync(chat, localBusy) {
    const s = watsonStatusOf(chat, localBusy);
    const each = (slot, fn) => Array.from(document.querySelectorAll(`[data-w="${slot}"]`)).forEach(fn);
    each("status", (el) => { el.innerHTML = s.pill; });
    each("statusbar", (el) => {
      el.innerHTML = s.bar ? `<span class="watson-status-dot watson-status-${s.state}"></span>${s.bar}` : "";
      el.hidden = !s.bar;
    });
    each("railstatus", (el) => { el.className = s.state === "none" ? "" : `watson-status-dot watson-status-${s.state}`; });
  }

  // "Show card" (data-act="watsonStatusShow", dashboard-data-act.js): scroll the log to the card and flash it.
  function watsonStatusShow(btn) {
    const pid = btn.getAttribute("data-w-status-show");
    const root = btn.closest(".watson-root") || document;
    const card = Array.from(root.querySelectorAll(".watson-prop[data-pid]")).find((el) => el.getAttribute("data-pid") === pid);
    if (!card) return;
    if (card.scrollIntoView) card.scrollIntoView({ block: "center", behavior: "smooth" });
    card.classList.add("watson-flash");
    setTimeout(() => card.classList.remove("watson-flash"), 1600);
  }

  // A case with no events or findings gives Watson nothing to work with. With a Velociraptor server,
  // the Best Practice bundle collects a detection base; the button opens its run form in the
  // Velociraptor panel (dashboard-velo-collect.js), so the analyst picks the OS and labels and runs it.
  const EMPTY_TEXT = "This case has no forensic-timeline events or findings. Until it has some, Watson has no data for an answer.";
  const BUNDLE_ID = "best-practice";
  function watsonEmptyCaseHtml(chat) {
    if (!chat || !chat.veloConnected) return `<div class="watson-empty">${EMPTY_TEXT} Import evidence first.</div>`;
    return (
      `<div class="watson-empty">${EMPTY_TEXT} To get a detection base, run the Best Practice bundle on your endpoints, or import evidence.` +
      ` <button type="button" class="watson-mini" data-act="watsonBestPractice">Run the Best Practice bundle</button></div>`
    );
  }
  function watsonBestPractice() {
    if (typeof toggleVeloRunForm !== "function") return;
    const form = document.querySelector(`.velo-run-form[data-id="${BUNDLE_ID}"]`);
    if (form && form.style.display !== "block") toggleVeloRunForm(BUNDLE_ID);
    const target = form || document.querySelector(".velo-run-form");
    if (target && target.scrollIntoView) target.scrollIntoView({ block: "center", behavior: "smooth" });
  }

  window.watsonStatusOf = watsonStatusOf;
  window.watsonStatusSync = watsonStatusSync;
  window.watsonStatusShow = watsonStatusShow;
  window.watsonEmptyCaseHtml = watsonEmptyCaseHtml;
  window.watsonBestPractice = watsonBestPractice;
})();
