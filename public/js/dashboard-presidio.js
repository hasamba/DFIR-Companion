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
  let anonSuppressed = []; // values removed from auto-discovery (server-persisted)

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
  function loadAnonEntities(caseId) {
    return fetch(`/cases/${caseId}/anon-entities`)
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((d) => {
        anonAuto = d.auto || {};
        anonCustom = (d.custom || []).map((e) => ({ ...e }));
        anonSuppressed = d.suppressed || [];
      });
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
      `The AI call was not sent — re-run it once you have resolved these.</div>` +
      // Label the ACTION, not the verdict. "Approve" was ambiguous in the one direction that
      // matters: the gate is holding an AI call, so "Approve" reads as "approve the send" —
      // the exact opposite of what it does (it masks the value). "Not PII" then sounds like
      // the same kind of affirmative. Both buttons now say what will happen to the value.
      presidioPending
        .map(
          (e) =>
            `<div data-safe-style="display:flex;align-items:center;gap:8px;margin:4px 0">` +
            `<code>${esc(e.value)}</code><span data-safe-style="color:var(--text-muted);font-size:11px">${esc(e.category)}</span>` +
            `<button data-presidio-approve="${escAttr(e.value)}" data-presidio-cat="${escAttr(e.category)}" ` +
            `title="Replace this value with a token before anything is sent to the AI. It is restored in the answer you see.">Hide from AI</button>` +
            `<button data-presidio-suppress="${escAttr(e.value)}" ` +
            `title="Leave this value visible to the AI. It won't be flagged again in this case.">Leave visible — not PII</button>` +
            `</div>`,
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
          .then((r) => (r.ok ? r.json() : { pending: presidioPending }))
          .then((d) => {
            presidioPending = d.pending || [];
            renderPresidioPending();
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
        fetch(`/cases/${caseId}/presidio-pending/suppress`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            value: btn.getAttribute("data-presidio-suppress"),
          }),
        })
          .then((r) => (r.ok ? r.json() : { pending: presidioPending }))
          .then((d) => {
            presidioPending = d.pending || [];
            renderPresidioPending();
          })
          .catch(() => {});
      }),
    );
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
      `<label data-safe-style="display:flex;align-items:center;gap:6px;font-size:13px;margin:2px 0;opacity:${configured ? "1" : ".55"}" title="${escAttr(tip)}">` +
        // Deliberately carries no category class: this box holds AnonControl.presidio, not a
        // category. PERSON has no entry in AnonControl.categories, so letting saveAnon read it
        // back with the category checkboxes would post a key the server drops on the floor.
        `<input type="checkbox" id="anonPresidioEnabled" ${configured ? "" : "disabled"} ${on ? "checked" : ""}> ` +
        `Real names (people) — ${!configured ? "needs Presidio" : on ? "via Presidio" : "Presidio off for this case"}</label>`,
    );
    document.getElementById("anonPresidioNote").innerHTML = !configured
      ? "<strong>Presidio is not configured.</strong> Names, non-Israeli national IDs and IBANs go undetected. Nothing else changes: cards, phones, IDs and emails are matched by the built-in patterns either way. Set <code>DFIR_PRESIDIO_URL</code> in Settings → AI (needs a restart); until then add known names below as <code>PERSON</code>."
      : on
        ? "<strong>Presidio is on.</strong> It catches what no pattern can — names, non-Israeli national IDs, IBANs — plus card / phone / email formats the built-ins miss. New values pause the AI call for your decision below. If the analyzer is down or too slow, untick this to keep working — the URL stays configured."
        : "<strong>Presidio is configured but switched off for this case.</strong> Names, non-Israeli national IDs and IBANs reach the model unmasked and no approval gate fires — everything else is still anonymized by the built-in patterns. Tick to turn scanning back on; no restart needed.";
  }
  function openAnonModal() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) {
      document.getElementById("status").textContent = "connect to a case first";
      return;
    }
    if (!anonControl) return;
    document.getElementById("anonEnabled").checked = !!anonControl.enabled;
    document.getElementById("anonRedactSecrets").checked =
      anonControl.redactSecrets !== false;
    document.getElementById("anonCategories").innerHTML = ANON_CATEGORIES.map(
      ([k, label]) =>
        `<label data-safe-style="display:flex;align-items:center;gap:6px;font-size:13px;margin:2px 0"><input type="checkbox" class="anon-cb" value="${escAttr(k)}" ${anonControl.categories && anonControl.categories[k] ? "checked" : ""}> ${esc(label)}</label>`,
    ).join("");
    renderPresidioCategory();
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
    loadAnonEntities(caseId)
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
    document.getElementById("anonOverlay").classList.add("open");
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
    msg.textContent = "saving…";
    Promise.all([
      fetch(`/cases/${caseId}/anon-control`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          presidio === undefined
            ? { enabled, categories, redactSecrets }
            : { enabled, categories, redactSecrets, presidio },
        ),
      }).then((r) => {
        if (!r.ok) throw new Error("control HTTP " + r.status);
        return r.json();
      }),
      fetch(`/cases/${caseId}/anon-entities`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ entities: anonCustom }),
      }).then((r) => {
        if (!r.ok) throw new Error("entities HTTP " + r.status);
        return r.json();
      }),
    ])
      .then(([c]) => {
        anonControl = c;
        renderAnonToggle();
        document.getElementById("anonOverlay").classList.remove("open");
        document.getElementById("status").textContent = enabled
          ? "Anonymization on — sensitive data tokenized before the AI"
          : "Anonymization off";
      })
      .catch((e) => (msg.textContent = "failed: " + e.message));
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
  window.addCustomEntity = addCustomEntity;
  window.openAnonModal = openAnonModal;
  window.saveAnon = saveAnon;
  window.setAi = setAi;
  window.loadAnonEntities = loadAnonEntities;
  window.loadAnonToggle = loadAnonToggle;
  window.renderAnonToggle = renderAnonToggle;
  window.renderAutoEntities = renderAutoEntities;
  window.initPresidio = initPresidio;
})();
