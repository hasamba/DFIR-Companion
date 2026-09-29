// Presidio approval panel (analyst-reviewed anonymization) — extracted from dashboard.html
// (issue #415, tier 3).
//
// presidioPending was the section's one state escape, written from three places outside it —
// two in the page and one in dashboard-search-scope.js — and every one of them did the same
// pair: assign the findings, then call renderPresidioPending(). That pair is one operation, and
// splitting it across four files means the day someone assigns without rendering, the badge goes
// quietly stale. setPresidioPending() is that operation, owned here.
(function () {
  // Moved here from dashboard.html (#415). All six of the anonymization block's bindings —
  // ANON_CATEGORIES, ANON_ENTITY_CATEGORIES, anonAuto, anonControl, anonCustom, anonSuppressed —
  // were read by THIS module and nothing else, while the page held the declarations and the four
  // loaders. Same shape as the pinned-findings repair: the panel moved out, its state did not.
  const ANON_CATEGORIES = [
    ["IP", "IP addresses"],
    ["USER", "Usernames"],
    ["HOST", "Hostnames"],
    ["DOMAIN", "Internal domains"],
    ["EMAIL", "Emails"],
    ["PATH", "User paths"],
    ["CMD", "Encoded commands"],
    ["REG", "SIDs"],
    ["CARD", "Credit cards"],
    ["PHONE", "Phone numbers"],
    ["NATID", "ID numbers"],
  ];
  const ANON_ENTITY_CATEGORIES = [
    "HOST",
    "USER",
    "DOMAIN",
    "IP",
    "EXTIP",
    "EMAIL",
    "PATH",
    "CMD",
    "REG",
    "CARD",
    "PHONE",
    "NATID",
    "PERSON",
    "OTHER",
  ];
  let anonControl = null; // { enabled, categories, redactSecrets, screenshotWarning }
  let anonAuto = {
    hosts: [],
    accounts: [],
    internalDomains: [],
    ips: [],
    extIps: [],
    emails: [],
    paths: [],
    other: [],
  };
  let anonCustom = []; // working copy: [{ value, category }]
  // #1839: the custom list as loaded, its server version, and the case it belongs to. Save sends the
  // version; a stale one is refused (409) and the list is rebased, never overwritten.
  let anonCustomBase = [];
  let anonCustomVersion = null;
  let anonCustomCase = null;
  let anonSuppressed = []; // values removed from auto-discovery (server-persisted)
  // Whether the CONFIGURED analyzer actually answers — a different fact from anonControl's
  // presidioConfigured, which only says DFIR_PRESIDIO_URL is non-empty. null until the modal has
  // asked; { probing: true } while it is asking.
  let presidioHealth = null;

  function renderAnonToggle() {
    const b = document.getElementById("anonToggle");
    if (!anonControl) {
      b.textContent = "Anon: …";
      b.classList.remove("on", "na");
      return;
    }
    b.textContent = anonControl.enabled ? "Anon: on" : "Anon: off";
    b.classList.remove("na");
    b.classList.toggle("on", anonControl.enabled);
  }
  function anonUnavailable() {
    const b = document.getElementById("anonToggle");
    b.textContent = "Anon: ?";
    b.classList.remove("on");
    b.classList.add("na");
    b.setAttribute("data-tip", "Anon control endpoint missing");
    document.getElementById("status").textContent =
      "Anon control endpoint missing — restart the companion server (stop it, then `npm run dev`) to load the latest endpoints.";
  }
  function loadAnonToggle(caseId) {
    fetch(`/cases/${caseId}/anon-control`)
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((c) => {
        anonControl = c;
        renderAnonToggle();
      })
      .catch(() => anonUnavailable());
  }
  const currentCase = () => document.getElementById("caseId")?.value.trim();
  // `customToo` is only for the modal's first load. Every other refresh (after Hide from AI, or an
  // auto-list remove/restore) updates the auto lists alone, so it never drops unsaved editor edits.
  function loadAnonEntities(caseId, customToo) {
    return fetch(`/cases/${caseId}/anon-entities`)
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((d) => {
        if (currentCase() !== caseId) return; // a late answer for a case the analyst has left
        anonAuto = d.auto || {};
        anonSuppressed = d.suppressed || [];
        if (customToo === true) setCustomBase(caseId, d.custom, d.customVersion);
      });
  }
  function setCustomBase(caseId, list, version) {
    anonCustomBase = (list || []).map((e) => ({ ...e }));
    anonCustom = anonCustomBase.map((e) => ({ ...e }));
    anonCustomVersion = typeof version === "number" ? version : null;
    anonCustomCase = caseId;
  }
  // #1839: re-apply the analyst's unsaved edits on top of the list another window saved. Additions
  // and category changes are kept. A removal is NOT re-applied: the other window may have just hidden
  // that value again, and the stricter choice wins — the analyst removes it again on purpose.
  function rebaseAnonCustom(base, working, server, max) {
    const key = (e) => e.value.trim().toLowerCase();
    const baseBy = new Map(base.map((e) => [key(e), e]));
    const workBy = new Set(working.map(key));
    const merged = server.map((e) => ({ ...e }));
    const at = new Map(merged.map((e, i) => [key(e), i]));
    let kept = 0;
    let dropped = 0;
    for (const w of working) {
      const b = baseBy.get(key(w));
      if (b && b.value === w.value && b.category === w.category) continue; // not an edit
      if (at.has(key(w))) merged[at.get(key(w))] = { ...w };
      else if (merged.length >= max) {
        dropped++;
        continue;
      } else {
        at.set(key(w), merged.length);
        merged.push({ ...w });
      }
      kept++;
    }
    const removed = base.filter((e) => !workBy.has(key(e)) && at.has(key(e))).map((e) => e.value);
    return { merged, kept, dropped, removed };
  }
  function renderAutoEntities() {
    const caseId = document.getElementById("caseId").value.trim();
    const a = anonAuto || {};
    // Groups (incl. entities discovered from screenshots), only those with entries.
    const groups = [
      ["Hosts", a.hosts],
      ["Accounts", a.accounts],
      ["Internal domains", a.internalDomains],
      ["IPs", a.ips],
      ["External IPs", a.extIps],
      ["Emails", a.emails],
      ["Paths", a.paths],
      ["Other", a.other],
    ].filter(([, arr]) => (arr || []).length);
    const chip = (v) =>
      `<span class="anon-chip">${esc(v)} <button class="anon-auto-rm" data-value="${escAttr(v)}" title="Remove — stop anonymizing this value">✕</button></span>`;
    const grp = (label, arr) =>
      `<div class="anon-auto-grp"><div class="asset-subhead">${esc(label)} (${arr.length})</div><div>${arr.map(chip).join(" ")}</div></div>`;
    let html = groups.length
      ? groups.map(([l, arr]) => grp(l, arr)).join("")
      : "<em data-safe-style='color:var(--text-muted)'>none yet</em>";
    const sup = anonSuppressed || [];
    if (sup.length) {
      const supChip = (v) =>
        `<span class="anon-chip anon-chip-sup">${esc(v)} <button class="anon-auto-restore" data-value="${escAttr(v)}" title="Restore — anonymize this again">↺</button></span>`;
      html += `<div class="anon-auto-grp"><div class="asset-subhead">Removed (${sup.length}) — not anonymized</div><div>${sup.map(supChip).join(" ")}</div></div>`;
    }
    const el = document.getElementById("anonAuto");
    el.innerHTML = html;
    el.querySelectorAll(".anon-auto-rm").forEach(
      (b) =>
        (b.onclick = () =>
          suppressAutoEntity(caseId, b.getAttribute("data-value"))),
    );
    el.querySelectorAll(".anon-auto-restore").forEach(
      (b) =>
        (b.onclick = () =>
          unsuppressAutoEntity(caseId, b.getAttribute("data-value"))),
    );
  }
  // Remove a wrong auto-discovered entity → server suppresses it (stops anonymizing it), then refresh.
  function suppressAutoEntity(caseId, value) {
    if (!caseId || !value) return;
    fetch(`/cases/${caseId}/anon-entities/suppress`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value }),
    })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(() => loadAnonEntities(caseId))
      .then(() => renderAutoEntities())
      .catch(() => {
        document.getElementById("anonMsg").textContent =
          "could not remove entity — restart the server if this persists";
      });
  }
  function unsuppressAutoEntity(caseId, value) {
    if (!caseId || !value) return;
    fetch(`/cases/${caseId}/anon-entities/unsuppress`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value }),
    })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(() => loadAnonEntities(caseId))
      .then(() => renderAutoEntities())
      .catch(() => {
        document.getElementById("anonMsg").textContent =
          "could not restore entity — restart the server if this persists";
      });
  }

  ("use strict");

  // The gate is the PERSISTED store, not the 409 — an import runs fire-and-forget (202 + a
  // background pipeline job) so there is no synchronous response to carry a 409 when the gate
  // fires mid-import; it only ever surfaces as an ai_status "error" over the WebSocket. So this
  // list is loaded on case connect AND whenever ai_status goes to "error" (see applyAiStatus),
  // with the 409 fast-path (see doAsk/synthesize/runSecondOpinion) as an optimisation on top —
  // never the only way the panel appears.
  let presidioPending = [];
  function loadPresidioPending(caseId) {
    if (!caseId) return;
    fetch(`/cases/${caseId}/presidio-pending`)
      .then((r) => (r.ok ? r.json() : { pending: [] }))
      .then((d) => {
        // A late answer for a case the analyst has left must not fill this case's panel (#1782).
        if (document.getElementById("caseId")?.value.trim() !== caseId) return;
        presidioPending = d.pending || [];
        renderPresidioPending();
      })
      .catch(() => {});
  }
  // The one operation the three outside writers used to open-code as an assign-then-render pair.
  function setPresidioPending(findings) {
    presidioPending = findings || [];
    renderPresidioPending();
  }

  // A 409 `presidio_approval_required` is a QUESTION, not a failure (#1782): the gate stopped the AI
  // call so the analyst can decide on new values first. Every button that can hit the gate asks
  // this one predicate, so the wording is the same everywhere and nobody is told to restart the
  // server. It also refreshes the ⚠ Presidio badge at once. Only the error code is read: the rest
  // of the hold's encoding may change, so a hold without a findings list re-reads the pending store
  // instead of clearing the badge.
  //
  // The badge is refreshed from the server's per-case pending store, NOT from the 409's findings:
  // the answer can arrive after the analyst has switched case, and the response's values belong to
  // the case that asked. Re-reading the store for the case on screen can never show one case's
  // values in another's Anonymization panel.
  function presidioHold(status, body) {
    if (status !== 409 || !body || body.error !== "presidio_approval_required") return false;
    loadPresidioPending(document.getElementById("caseId")?.value.trim());
    return true;
  }
  function presidioHoldText(what) {
    return `${what} held for Presidio approval — review in Anonymization`;
  }

  function renderPresidioPending() {
    const badge = document.getElementById("presidioPendingBadge");
    if (badge) {
      if (presidioPending.length > 0) {
        badge.style.display = "";
        badge.textContent = "⚠ Presidio: " + presidioPending.length;
      } else badge.style.display = "none";
    }
    const el = document.getElementById("presidioPending");
    if (!el) return;
    if (presidioPending.length === 0) {
      el.innerHTML = "";
      return;
    }
    el.innerHTML =
      `<div data-safe-style="margin-top:10px;padding:8px;border-radius:6px;background:var(--warning-bg);color:var(--tag-orange-text);font-size:12px">` +
      `<b>Presidio found ${presidioPending.length} new value(s) in this case.</b> ` +
      `Decide each one: hide it from the AI from now on, or leave it visible because it isn't PII. ` +
      `The AI call was not sent — re-run it once you have resolved these.` +
      // #1799: the NER model tags tool names, timestamps and ATT&CK ids as PERSON at the same score
      // as a real name. "Hide from AI" on those masks them in every later prompt, so say so.
      `<div data-safe-style="margin-top:4px">Tool and malware names, timestamps, file names and ATT&amp;CK ids are ` +
      `not PII — leave them visible, or the AI loses them in every later prompt.</div>` +
      (presidioPending.length > 1
        ? `<button data-presidio-suppress-all data-safe-style="margin-top:6px" ` +
          `title="Leave every value listed here visible to the AI. Check the list first: hide any real person's name one by one.">` +
          `Leave all ${presidioPending.length} visible — none are PII</button>`
        : "") +
      `</div>` +
      // Label the ACTION, not the verdict. "Approve" was ambiguous in the one direction that
      // matters: the gate is holding an AI call, so "Approve" reads as "approve the send" —
      // the exact opposite of what it does (it masks the value). "Not PII" then sounds like
      // the same kind of affirmative. Both buttons now say what will happen to the value.
      presidioPending
        .map(
          (e) =>
            // The row's layout is a stylesheet rule (.presidio-row in dashboard-panels.css), not
            // an inline data-safe-style as it was: it needs flex-shrink control on four items, and
            // the buttons are wrapped in .presidio-actions so the pair stays together and stays
            // one size when a long value wraps beneath it.
            `<div class="presidio-row">` +
            `<code>${esc(e.value)}</code><span class="presidio-cat">${esc(e.category)}</span>` +
            `<span class="presidio-actions">` +
            `<button data-presidio-approve="${escAttr(e.value)}" data-presidio-cat="${escAttr(e.category)}" ` +
            `title="Replace this value with a token before anything is sent to the AI. It is restored in the answer you see.">Hide from AI</button>` +
            `<button data-presidio-suppress="${escAttr(e.value)}" ` +
            `title="Leave this value visible to the AI. It won't be flagged again in this case.">Leave visible — not PII</button>` +
            `</span></div>`,
        )
        .join("");
    el.querySelectorAll("[data-presidio-approve]").forEach((btn) =>
      btn.addEventListener("click", () => {
        const caseId = document.getElementById("caseId").value.trim();
        if (!caseId) return;
        fetch(`/cases/${caseId}/presidio-pending/approve`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            value: btn.getAttribute("data-presidio-approve"),
            category: btn.getAttribute("data-presidio-cat"),
          }),
        })
          .then((r) => readDecision(r, "presidio_custom_list_full", CUSTOM_FULL_TEXT))
          .then((d) => {
            presidioPending = d.pending || [];
            renderPresidioPending();
            // Clearing the LAST finding lifts the gate. The server kicks the held run, but that
            // kick emits nothing until it starts, so re-derive rather than leave the pill reading
            // "on hold" over a case that no longer is — the exact bug reported for this gate.
            refreshAiState(caseId);
            loadAnonEntities(caseId)
              .then(renderAutoEntities)
              .catch(() => {});
          })
          .catch(() => {});
      }),
    );
    el.querySelectorAll("[data-presidio-suppress]").forEach((btn) =>
      btn.addEventListener("click", () => {
        const caseId = document.getElementById("caseId").value.trim();
        if (!caseId) return;
        postPresidioSuppress(caseId, btn.getAttribute("data-presidio-suppress"))
          .then((r) => readDecision(r, "presidio_not_pending", NOT_LEFT_VISIBLE_TEXT))
          .then((d) => {
            presidioPending = d.pending || [];
            renderPresidioPending();
            refreshAiState(caseId); // same reason as the approve path above
          })
          .catch(() => {});
      }),
    );
    el.querySelectorAll("[data-presidio-suppress-all]").forEach((btn) =>
      btn.addEventListener("click", () => {
        const caseId = document.getElementById("caseId").value.trim();
        if (caseId) suppressAllPresidioPending(caseId);
      }),
    );
  }
  // #1822: the stricter choice wins. The server refuses "Leave visible" (409 presidio_not_pending)
  // for a value that is already hidden from the AI or that another window decided first, and
  // refuses "Hide from AI" (409 presidio_custom_list_full) when the custom list is full. Both answers
  // carry the current list; the panel shows it and says why the click did nothing.
  const NOT_LEFT_VISIBLE_TEXT =
    "Not left visible: this value is already hidden from the AI, or another window decided it first. " +
    "Hidden values stay hidden.";
  const CUSTOM_FULL_TEXT =
    "Could not hide this value: the custom entity list is full. Remove entries you do not need, then try again.";
  function setAnonMsg(text) {
    const m = document.getElementById("anonMsg");
    if (m) m.textContent = text;
  }
  function refusalBody(r, code) {
    if (r.status !== 409) return Promise.resolve(null);
    return r.json().then(
      (d) => (d && d.error === code ? d : null),
      () => null,
    );
  }
  function readDecision(r, code, text) {
    if (r.ok) return r.json();
    return refusalBody(r, code).then((d) => {
      if (!d) return { pending: presidioPending };
      setAnonMsg(text);
      return d;
    });
  }
  function postPresidioSuppress(caseId, value) {
    return fetch(`/cases/${caseId}/presidio-pending/suppress`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value }),
    });
  }
  // #1799: one click for a list that is all tool names and timestamps. One request per value, in
  // order, through the same endpoint as the per-row button. A failed request stops the run, and the
  // list is then re-read from the server so it shows exactly what is still pending.
  //
  // Every decision button is off while it runs, and a value is posted only while the latest server
  // answer still lists it. #1822: a value the server refuses (already hidden from the AI, or decided
  // in another window) is skipped, not a stop — and the panel says how many were skipped.
  function suppressAllPresidioPending(caseId) {
    const values = presidioPending.map((e) => e.value);
    const el = document.getElementById("presidioPending");
    if (el) el.querySelectorAll("button").forEach((b) => (b.disabled = true));
    const stillPending = (value) => presidioPending.some((e) => e.value === value);
    let skipped = 0;
    const skip = (d) => {
      skipped++;
      return d;
    };
    const tellSkipped = () => {
      if (skipped > 0)
        setAnonMsg(
          `${skipped} value(s) not left visible: already hidden from the AI, or decided in another window. ` +
            "Hidden values stay hidden.",
        );
    };
    return values
      .reduce(
        (chain, value) =>
          chain
            .then(() => (stillPending(value) ? postPresidioSuppress(caseId, value) : null))
            .then((r) => {
              if (!r) return skip({ pending: presidioPending });
              if (r.ok) return r.json();
              return refusalBody(r, "presidio_not_pending").then((d) => {
                if (!d) throw new Error("HTTP " + r.status);
                return skip(d);
              });
            })
            .then((d) => {
              presidioPending = d.pending || [];
            }),
        Promise.resolve(),
      )
      .then(renderPresidioPending, () => loadPresidioPending(caseId))
      .then(tellSkipped)
      .then(() => refreshAiState(caseId));
  }
  function renderCustomEntities() {
    document.getElementById("anonCustom").innerHTML = anonCustom.length
      ? anonCustom
          .map(
            (e, i) =>
              `<div class="anon-cust-row"><span class="anon-chip">${esc(e.value)}</span><span data-safe-style="color:var(--text-muted);font-size:11px">${esc(e.category)}</span><button data-i="${i}" class="anon-cust-rm" title="remove">✕</button></div>`,
          )
          .join("")
      : "<em data-safe-style='color:var(--text-muted)'>none added</em>";
    [...document.querySelectorAll(".anon-cust-rm")].forEach(
      (btn) =>
        (btn.onclick = () => {
          anonCustom.splice(Number(btn.getAttribute("data-i")), 1);
          renderCustomEntities();
        }),
    );
  }
  function addCustomEntity() {
    const valEl = document.getElementById("anonCustVal");
    const val = valEl.value.trim();
    const cat = document.getElementById("anonCustCat").value;
    if (!val) return;
    if (!anonCustom.some((e) => e.value.toLowerCase() === val.toLowerCase()))
      anonCustom.push({ value: val, category: cat });
    valEl.value = "";
    renderCustomEntities();
  }
  // Real names are the one thing on this screen that NO built-in pattern can find: PERSON tokens
  // are minted solely from Presidio findings (see anonymize.ts — "PERSON is token-only"). So the
  // row is appended as a STATUS row, not a toggle — it deliberately carries no `anon-cb` class,
  // is always disabled, and saveAnon() never reads it back.
  //
  // Only this row greys out when Presidio is absent. The categories above it — including Credit
  // cards, Phone numbers and ID numbers — are local detectors (Luhn + issuer prefix; E.164 /
  // Israeli / separated NANP; checksummed national ID) that run with or without Presidio, so
  // greying THEM would tell the analyst their card numbers reach the model when they do not.
  // Presidio widens those four; it does not provide them.
  function renderPresidioCategory() {
    // Two independent facts, and the row must not conflate them: whether an analyzer is CONFIGURED
    // (DFIR_PRESIDIO_URL, startup-only, server-side) and whether this case USES it (per-case, live).
    // Configured is what makes the switch operable at all; used is what the switch holds.
    const configured = !!(anonControl && anonControl.presidioConfigured);
    const on = configured && !(anonControl && anonControl.presidio === false);
    const tip = !configured
      ? "No pattern can find a name — this needs Presidio. Until then, add known names below as PERSON."
      : on
        ? "Found by Presidio on the already-masked text. Each new name pauses the AI call until you decide below. Untick to stand the layer down without losing the configuration."
        : "Switched off for this case — names are NOT detected. The analyzer stays configured; tick to resume.";
    document.getElementById("anonCategories").insertAdjacentHTML(
      "beforeend",
      // Full-width row of its own, not a cell in the two-column category grid. The status
      // phrase is longer than any category label, so in a half-width cell it wraps mid-phrase
      // and pulls the whole grid out of alignment. It is not a category either (see above), so
      // standing apart from them is also what it should look like.
      `<label data-safe-style="grid-column:1/-1;display:flex;align-items:center;gap:6px;font-size:13px;margin:6px 0 2px;opacity:${configured ? "1" : ".55"}" title="${escAttr(tip)}">` +
        // Deliberately carries no category class: this box holds AnonControl.presidio, not a
        // category. PERSON has no entry in AnonControl.categories, so letting saveAnon read it
        // back with the category checkboxes would post a key the server drops on the floor.
        `<input type="checkbox" id="anonPresidioEnabled" ${configured ? "" : "disabled"} ${on ? "checked" : ""}> ` +
        // The reachability result lands in this span, never on the row itself. The probe answers
        // after the modal is already open, so the analyst may have unticked the box in the
        // meantime — rebuilding the row would restore the tick from anonControl and throw that
        // decision away.
        `Real names (people) — <span id="anonPresidioStatus" data-safe-style="white-space:nowrap">${esc(presidioStatusText(configured, on))}</span></label>`,
    );
    document.getElementById("anonPresidioNote").innerHTML = presidioNoteHtml(
      configured,
      on,
    );
    renderPresidioReachability();
  }
  // The note as configuration alone describes it. Kept separate because the reachability probe has
  // to be able to put it back: a retry that finds the container up again must undo its own warning.
  function presidioNoteHtml(configured, on) {
    return !configured
      ? "<strong>Presidio is not configured.</strong> Names, non-Israeli national IDs and IBANs go undetected. Nothing else changes: cards, phones, IDs and emails are matched by the built-in patterns either way. Set <code>DFIR_PRESIDIO_URL</code> in Settings → AI (needs a restart); until then add known names below as <code>PERSON</code>."
      : on
        ? "<strong>Presidio is on.</strong> It catches what no pattern can — names, non-Israeli national IDs, IBANs — plus card / phone / email formats the built-ins miss. New values pause the AI call for your decision below. If the analyzer is down or too slow, untick this to keep working — the URL stays configured."
        : "<strong>Presidio is configured but switched off for this case.</strong> Names, non-Israeli national IDs and IBANs reach the model unmasked and no approval gate fires — everything else is still anonymized by the built-in patterns. Tick to turn scanning back on; no restart needed.";
  }
  // The phrase after the dash, as configuration alone describes it. Same reason presidioNoteHtml
  // exists: the probe overwrites it, and a retry that finds the container up has to put it back.
  function presidioStatusText(configured, on) {
    return !configured
      ? "needs Presidio"
      : on
        ? "via Presidio"
        : "Presidio off for this case";
  }
  // Paints the probe result. Touches exactly two elements — the status span and the note — and
  // never the checkbox or anonControl: an outage is not a reason to change what gets saved.
  function renderPresidioReachability() {
    const status = document.getElementById("anonPresidioStatus");
    const note = document.getElementById("anonPresidioNote");
    if (!status || !note) return;
    const h = presidioHealth;
    const configured = !!(anonControl && anonControl.presidioConfigured);
    const on = configured && !(anonControl && anonControl.presidio === false);
    const plain = esc(presidioStatusText(configured, on));
    // Nothing to report: no analyzer configured, the layer is off for this case anyway, or the
    // probe has not answered yet. The configuration note already says what those states mean.
    if (!configured || !on || !h) {
      status.innerHTML = plain;
      return;
    }
    if (h.probing) {
      status.innerHTML = `${plain} <span data-safe-style="color:var(--text-muted)">(checking…)</span>`;
      return;
    }
    if (h.reachable === false) {
      status.innerHTML =
        `<strong data-safe-style="color:var(--badge-danger-text)">analyzer unreachable</strong>` +
        ` <button id="anonPresidioRetry" class="anon-presidio-retry" title="Probe the analyzer again">retry</button>`;
      const where = h.url ? `<code>${esc(h.url)}</code>` : "the configured URL";
      note.innerHTML =
        `<strong>Presidio is enabled, but the analyzer at ${where} does not answer.</strong> ` +
        `AI calls on this case will FAIL until it does — the layer fails closed rather than ` +
        `silently skipping the scan and letting names through. Start the container, or untick ` +
        `this row to stand the layer down for this case; the URL stays configured either way.` +
        (h.error
          ? ` <span data-safe-style="color:var(--text-muted)">(${esc(h.error)})</span>`
          : "");
      const retry = document.getElementById("anonPresidioRetry");
      if (retry) retry.onclick = () => probePresidioHealth();
      return;
    }
    status.innerHTML = plain;
    note.innerHTML = presidioNoteHtml(configured, on);
  }
  // Asks the server, which is the only side that knows DFIR_PRESIDIO_URL — it is startup-only and
  // never sent to the page. Skipped entirely when no analyzer is configured: there is nothing to
  // probe, and the row already says so.
  function probePresidioHealth() {
    if (!(anonControl && anonControl.presidioConfigured)) return;
    presidioHealth = { probing: true };
    renderPresidioReachability();
    fetch("/system/presidio-health")
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((h) => {
        presidioHealth = h;
        renderPresidioReachability();
      })
      // An older server without this endpoint must leave the row exactly as configuration drew it,
      // not accuse a healthy analyzer of being down.
      .catch(() => {
        presidioHealth = null;
        renderPresidioReachability();
      });
  }
  function openAnonModal() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) {
      document.getElementById("status").textContent = "connect to a case first";
      return;
    }
    if (!anonControl) return;
    fillAnonControlFields();
    document.getElementById("anonCustCat").innerHTML =
      ANON_ENTITY_CATEGORIES.map(
        (c) => `<option value="${escAttr(c)}">${esc(c)}</option>`,
      ).join("");
    const warn = document.getElementById("anonWarning");
    if (anonControl.screenshotWarning) {
      warn.style.display = "block";
      warn.textContent =
        "⚠ Screenshots are OCR-redacted (best-effort) before being sent to the external vision model — text matching the entities below is blacked out on an in-memory copy; the original on disk is untouched. OCR can miss text, so don't rely on it for highly sensitive screens. Point DFIR_VISION_MODEL at a local Ollama vision model to keep screenshots fully on-box. Imported CSV/log text and synthesis are anonymized.";
    } else {
      warn.style.display = "none";
    }
    document.getElementById("anonMsg").textContent = "loading entities…";
    // Fresh settings too, so a modal opened after another window saved does not start stale.
    fetch(`/cases/${caseId}/anon-control`)
      .then((r) => (r.ok ? r.json() : null))
      .then((c) => {
        // Unchanged: leave the fields alone, the analyst may already be editing them.
        if (!c || currentCase() !== caseId || (anonControl && c.version === anonControl.version)) return;
        anonControl = c;
        renderAnonToggle();
        fillAnonControlFields();
      })
      .catch(() => {});
    anonCustomVersion = null; // Save waits for this load (#1839)
    anonCustomCase = null;
    loadAnonEntities(caseId, true)
      .then(() => {
        renderAutoEntities();
        renderCustomEntities();
        document.getElementById("anonMsg").textContent = "";
      })
      .catch(() => {
        anonAuto = {};
        anonCustom = [];
        anonSuppressed = [];
        renderAutoEntities();
        renderCustomEntities();
        document.getElementById("anonMsg").textContent =
          "failed to load entities — restart the server if this persists";
      });
    // Re-fetch rather than trust whatever loadPresidioPending last populated at case-connect —
    // state can change elsewhere (another dashboard tab, an import landing) between connect and
    // this modal being opened, and a stale pending list here would show the wrong count/values.
    loadPresidioPending(caseId);
    // Configured is not reachable. Ask now, while the analyst is looking at the row, rather than
    // letting them find out from a failed AI call an hour later.
    probePresidioHealth();
    document.getElementById("anonOverlay").classList.add("open");
  }
  function fillAnonControlFields() {
    document.getElementById("anonEnabled").checked = !!anonControl.enabled;
    document.getElementById("anonRedactSecrets").checked =
      anonControl.redactSecrets !== false;
    document.getElementById("anonCategories").innerHTML = ANON_CATEGORIES.map(
      ([k, label]) =>
        `<label data-safe-style="display:flex;align-items:center;gap:6px;font-size:13px;margin:2px 0"><input type="checkbox" class="anon-cb" value="${escAttr(k)}" ${anonControl.categories && anonControl.categories[k] ? "checked" : ""}> ${esc(label)}</label>`,
    ).join("");
    renderPresidioCategory();
  }
  function saveAnon() {
    const caseId = document.getElementById("caseId").value.trim();
    const enabled = document.getElementById("anonEnabled").checked;
    const redactSecrets = document.getElementById("anonRedactSecrets").checked;
    const categories = {};
    ANON_CATEGORIES.forEach(([k]) => {
      categories[k] = false;
    });
    [...document.querySelectorAll(".anon-cb:checked")].forEach((cb) => {
      categories[cb.value] = true;
    });
    // Read the switch only when an analyzer is configured. With none, the box is rendered disabled
    // and unchecked, and posting that `false` would persist "off" for a case that never had the
    // layer — so a later DFIR_PRESIDIO_URL would come up silently dead on this case.
    const presidioBox = document.getElementById("anonPresidioEnabled");
    const presidio =
      anonControl && anonControl.presidioConfigured && presidioBox
        ? presidioBox.checked
        : undefined;
    const msg = document.getElementById("anonMsg");
    // #1839: both halves are versioned saves. The list goes first; a stale list stops the settings
    // too, so a stale window never half-applies. Nothing saves before the list has loaded.
    if (anonCustomVersion === null || anonCustomCase !== caseId) {
      msg.textContent = "The hidden-values list has not loaded yet. Wait a moment, or close and reopen this window, then press Save again.";
      return;
    }
    const version = anonControl && anonControl.version;
    const control =
      presidio === undefined
        ? { enabled, categories, redactSecrets, version }
        : { enabled, categories, redactSecrets, presidio, version };
    msg.textContent = "saving…";
    postJson(`/cases/${caseId}/anon-entities`, { entities: anonCustom, version: anonCustomVersion })
      .then(({ r, d }) => {
        if (currentCase() !== caseId) throw new Error("case changed");
        if (r.status === 409 && d.error === "anon_entities_stale") return staleCustom(caseId, d);
        if (!r.ok) throw new Error("entities HTTP " + r.status);
        setCustomBase(caseId, d.custom, d.customVersion);
        return postJson(`/cases/${caseId}/anon-control`, control).then(({ r: rc, d: c }) => {
          if (currentCase() !== caseId) throw new Error("case changed");
          if (rc.status === 409 && c.error === "anon_control_stale") return staleControl(c.control);
          if (!rc.ok) throw new Error("control HTTP " + rc.status);
          anonControl = c;
          renderAnonToggle();
          document.getElementById("anonOverlay").classList.remove("open");
          document.getElementById("status").textContent = enabled
            ? "Anonymization on — sensitive data tokenized before the AI"
            : "Anonymization off";
        });
      })
      .catch((e) => (msg.textContent = "failed: " + e.message));
  }
  function postJson(url, body) {
    return fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => r.json().then((d) => ({ r, d }), () => ({ r, d: {} })));
  }
  // Another window saved the list first. Show its list with this window's edits on top; save nothing.
  function staleCustom(caseId, d) {
    const x = rebaseAnonCustom(anonCustomBase, anonCustom, d.custom || [], 500);
    setCustomBase(caseId, d.custom, d.customVersion);
    anonCustom = x.merged;
    renderCustomEntities();
    document.getElementById("anonMsg").textContent =
      `Nothing was saved: another window changed the hidden-values list. It is reloaded below with ${x.kept} unsaved change(s) of yours kept. ` +
      (x.dropped ? `${x.dropped} addition(s) did not fit: the list is full. ` : "") +
      (x.removed.length
        ? `You had removed ${x.removed.join(", ")}; still hidden — remove again if you meant it. `
        : "") +
      "Check the list, then press Save again.";
  }
  // Another window changed the settings. Show the current ones; the analyst makes the change again.
  function staleControl(c) {
    anonControl = c;
    renderAnonToggle();
    fillAnonControlFields();
    document.getElementById("anonMsg").textContent =
      "Hidden values saved. The settings were NOT saved: another window changed them. The current settings are shown — make your change again, then press Save.";
  }

  function setAi(kind, text) {
    const el = document.getElementById("aiStatus");
    el.className = "ai-" + kind;
    el.textContent = "AI: " + text;
    el.title = "AI: " + text; // full text on hover (the badge truncates in the tight icons-only toolbar)
  }

  // Import progress bar helpers moved to js/dashboard-import-progress.js (#415 tier 3).
  // AI status banner moved to js/dashboard-ai-status.js (#415 tier 3).

  // The badge lives in the page header, so this binds at load, not on module evaluation.
  function initPresidio() {
    document
      .getElementById("presidioPendingBadge")
      ?.addEventListener("click", openAnonModal);
  }

  window.loadPresidioPending = loadPresidioPending;
  window.renderPresidioPending = renderPresidioPending;
  window.setPresidioPending = setPresidioPending;
  window.suppressAllPresidioPending = suppressAllPresidioPending;
  window.presidioHold = presidioHold;
  window.presidioHoldText = presidioHoldText;
  window.addCustomEntity = addCustomEntity;
  window.openAnonModal = openAnonModal;
  window.saveAnon = saveAnon;
  window.setAi = setAi;
  window.loadAnonEntities = loadAnonEntities;
  window.rebaseAnonCustom = rebaseAnonCustom;
  window.loadAnonToggle = loadAnonToggle;
  window.renderAnonToggle = renderAnonToggle;
  window.renderAutoEntities = renderAutoEntities;
  window.initPresidio = initPresidio;
})();
