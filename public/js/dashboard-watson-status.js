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
  // The card's own words: a next step's action, a finding's title, a question, a report text. A long
  // one is cut at NAME_MAX characters (the card has all of it).
  const NAME_MAX = 90;
  const nameOf = (p) => {
    const a = p.after && typeof p.after === "object" ? p.after : p.before && typeof p.before === "object" ? p.before : {};
    const text = typeof p.after === "string" ? p.after : "";
    const rows = p.kind === "event_promote" && Array.isArray(p.events) ? `${p.events.length} row${p.events.length === 1 ? "" : "s"}` : "";
    const name = String(p.title || a.action || a.question || a.title || a.text || text || rows || p.summary || "the card").trim();
    return name.length > NAME_MAX ? name.slice(0, NAME_MAX - 1) + "…" : name;
  };

  function workingBar(run) {
    return run && run.kind === "reaction" ? "Watson is working on the new case events." : "Watson is working on an answer.";
  }

  // The first waiting card's own buttons, so the analyst acts without scrolling. A risky launch keeps
  // its Launch (and its risk review) on the card, but Reject is safe from here; a round's
  // super-timeline promotion has Apply only (as on the card).
  const btn = (pid, verb, label) =>
    `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="${verb}" data-pid="${escAttr(pid)}">${label}</button> `;
  function actionsOf(p) {
    if (p.kind === "velo_launch") return (p.risk ? "" : btn(p.id, "apply", "Launch")) + btn(p.id, "reject", "Reject");
    if (p.kind === "event_promote" && p.source === "supertimeline") return btn(p.id, "apply", watsonApplyLabel(p.kind));
    return btn(p.id, "apply", watsonApplyLabel(p.kind)) + btn(p.id, "reject", "Reject");
  }

  function youBar(cards) {
    const first = cards[0];
    const stuck = needsRecovery(first);
    const action = stuck
      ? `Check "${esc(nameOf(first))}": mark it as launched or try again.`
      : first.kind === "velo_launch" && first.risk
        ? `Review the risky launch "${esc(nameOf(first))}" on its card, or reject it.`
        : first.kind === "velo_launch"
        ? `Launch "${esc(nameOf(first))}", or reject it.`
        : first.kind === "cs_search"
        ? `Run the CrowdStrike search "${esc(nameOf(first))}", or reject it.`
        : `Add ${watsonApplyNoun(first.kind)} "${esc(nameOf(first))}" to the case, or reject it.`;
    const more = cards.length - 1;
    const tail = more === 0 ? "" : more === 1 ? " 1 more card waits for you." : ` ${more} more cards wait for you.`;
    const show = `<button type="button" class="watson-mini watson-status-show" data-act="watsonStatusShow" data-w-status-show="${escAttr(first.id)}">Show card</button>`;
    return `${action}${tail} <span class="watson-status-actions">${stuck ? "" : actionsOf(first)}${show}</span>`;
  }

  // A reaction round that is due (the server's quiet window after a case event, or a wait for a
  // synthesis): Watson is working from the event on, not only once the round starts. The GET carries
  // it; a POST reply does not, and an analyst's message reads the events itself.
  function dueBar(due) {
    return due.waitingForSynthesis
      ? "Watson reads the new case events after the synthesis finishes."
      : "Watson reads the new case events in a moment.";
  }

  // The run mode the GET last sent (a POST reply has none): in Auto mode a finished cycle says so.
  let lastMode = "";
  const AUTO_DONE =
    "Watson finished. Auto mode has nothing more to run now. It starts again when new evidence comes in or when you send a message.";

  function watsonStatusOf(chat, localBusy) {
    if (!chat) return { state: "none", pill: "", bar: "", pid: "" };
    if (typeof chat.runMode === "string") lastMode = chat.runMode;
    const pill = (state, extra) =>
      `<span class="watson-status watson-status-${state}" role="status">${LABEL[state]}${extra || ""}</span>`;
    if (chat.running || localBusy) return { state: "working", pill: pill("working"), bar: workingBar(chat.running), pid: "" };
    if (chat.reactionDue) return { state: "working", pill: pill("working"), bar: dueBar(chat.reactionDue), pid: "" };
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
    return { state: "ready", pill: pill("ready"), bar: lastMode === "auto" ? AUTO_DONE : "", pid: "" };
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
    if (typeof watsonJumpSync === "function") watsonJumpSync(); // the jump-to-latest arrow (dashboard-watson-layout.js)
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
  // the Best Practice bundle collects a detection base; the button opens its run form in the Fleet
  // Collection section (dashboard-velo-collect.js), so the analyst picks the OS and labels and runs it.
  // When Watson cannot get there, a notice in the panel says why (never an unrelated form). The notice
  // is module state, so a re-render of the panel keeps it.
  const EMPTY_TEXT = "This case has no forensic-timeline events or findings. Until it has some, Watson has no data for an answer.";
  const BUNDLE_ID = "best-practice";
  const SECTION_ID = "sec-fleet-collection";
  const BP_NOTE = {
    section: "Watson cannot find the Fleet Collection section on this dashboard. Make sure that the Velociraptor server is connected.",
    hidden: "The current dashboard view does not show the Fleet Collection section. Show the section in Settings, or select the Analyst view.",
    form: "Watson cannot find the Best Practice bundle. Open the Fleet Collection section and run the bundle from its list.",
  };
  let bpNote = "";
  const bpNoteHtml = () => `<div class="watson-why watson-warn" data-w="bpnote" role="status"${bpNote ? "" : " hidden"}>${esc(bpNote)}</div>`;
  function setBpNote(text) {
    bpNote = text;
    Array.from(document.querySelectorAll('[data-w="bpnote"]')).forEach((el) => {
      el.textContent = text;
      el.hidden = !text;
    });
  }
  function watsonEmptyCaseHtml(chat) {
    if (!chat || !chat.veloConnected) return `<div class="watson-empty">${EMPTY_TEXT} Import evidence first.</div>`;
    return (
      `<div class="watson-empty">${EMPTY_TEXT} To get a detection base, run the Best Practice bundle on your endpoints, or import evidence.` +
      ` <button type="button" class="watson-mini" data-act="watsonBestPractice">Run the Best Practice bundle</button>${bpNoteHtml()}</div>`
    );
  }
  const bpForm = () => document.querySelector(`.velo-run-form[data-id="${BUNDLE_ID}"]`);
  const isShown = (el) => !!el && !el.hidden && !(el.style && el.style.display === "none");

  // Leave full screen, show the Fleet Collection section, load the bundle list if its form is not
  // there yet, then open and focus the Best Practice run form. Resolves to the note shown ("" = opened).
  async function watsonBestPractice() {
    setBpNote("");
    const body = document.body;
    if (body && body.classList && body.classList.contains("watson-full-open") && typeof setWatsonPanelState === "function") {
      setWatsonPanelState("open");
    }
    const sec = document.getElementById(SECTION_ID);
    if (!sec) return fail(BP_NOTE.section);
    if (typeof revealSection === "function") revealSection(SECTION_ID);
    else if (sec.classList) sec.classList.remove("collapsed");
    if (!isShown(sec)) return fail(BP_NOTE.hidden);
    if (!bpForm() && typeof loadVeloBundles === "function") {
      try { await loadVeloBundles(); } catch { /* a failed load leaves no form: the note below says so */ }
    }
    const form = bpForm();
    if (!form || typeof toggleVeloRunForm !== "function") return fail(BP_NOTE.form);
    if (form.style.display !== "block") toggleVeloRunForm(BUNDLE_ID);
    if (form.style.display !== "block") return fail(BP_NOTE.form);
    if (form.scrollIntoView) form.scrollIntoView({ block: "center", behavior: "smooth" });
    const first = form.querySelector ? form.querySelector("select, input, button") : null;
    if (first && first.focus) first.focus();
    return "";
  }
  function fail(text) {
    setBpNote(text);
    return text;
  }

  // The footer's model: "· Model: claude-… (anthropic)". The GET carries it; a POST reply does not,
  // so the last one the GET sent is kept. The text is escaped: it comes from Settings.
  let footModel = null;
  function watsonModelFoot(chat) {
    if (chat && Object.prototype.hasOwnProperty.call(chat, "watsonModel")) footModel = chat.watsonModel || null;
    if (!footModel || !footModel.model) return "";
    const who = footModel.provider ? ` (${esc(String(footModel.provider))})` : "";
    return ` · Model: ${esc(String(footModel.model))}${who}`;
  }

  window.watsonStatusOf = watsonStatusOf;
  window.watsonModelFoot = watsonModelFoot;
  window.watsonStatusSync = watsonStatusSync;
  window.watsonStatusShow = watsonStatusShow;
  window.watsonEmptyCaseHtml = watsonEmptyCaseHtml;
  window.watsonBestPractice = watsonBestPractice;
})();
