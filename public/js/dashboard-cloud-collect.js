// Cloud Collection panel (#2311): collect AWS / Microsoft / GCP logs live with one of the case's
// cloud accounts, watch each collection's progress per source, and Resume one that stopped.
//
// Every page the cloud returns is saved as case evidence with its SHA-256 in an append-only
// manifest (<case>/evidence/cloud/<collection>/manifest.jsonl). The result is complete, partial
// (which windows are missing, and why) or failed. A collection the server was running when it
// stopped shows Resume — resuming re-opens the account's credential and never loses or duplicates
// evidence or events.
//
// Accounts are managed in Settings → Cloud accounts; this panel only picks one. Until a provider's
// live collector ships (#2313 AWS, #2314 GCP, #2315 Microsoft) the server lists it as not
// available and says so. On the public demo every cloud route answers 403 and the panel hides.
// Analyst-named and cloud-returned strings are written with textContent only, never innerHTML.
//
// #2312: Start first runs a PRE-CHECK and shows it — the windows outside each source's retention,
// "off by default" warnings, the ingestion-delay overlap, and for Microsoft this companion's own use
// of the tenant's daily query quota ("used by this companion (estimate)", never "tenant remaining")
// — and only "Confirm and start" starts. A collection's row shows each source's acquired cutoff and
// every incomplete window with its reason (too dense, budget used, …).
//
// #2363: an AWS account gets a REGION PICKER — the regions enabled on the account (asked with
// ec2:DescribeRegions, opt-in regions included), all ticked. Without that permission the server
// answers with the default list and a note; the note is shown in the picker, the pre-check and the
// result. Unticked regions are sent as `excludeRegions` and named in the result as skipped by
// choice. Any change to the form clears the pre-check, so "Confirm and start" can only send the
// body that was checked.
(function () {
  "use strict";

  const POLL_MS = 3000;
  const RESUMABLE = new Set(["interrupted", "failed", "partial"]);
  const STATUS_TEXT = {
    running: "running",
    interrupted: "interrupted — press Resume",
    complete: "complete",
    partial: "partial",
    failed: "failed",
  };

  let pollTimer = null;
  let pollCase = "";

  const byId = (id) => document.getElementById(id);

  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  }

  function caseNow() {
    const box = byId("caseId");
    return box && typeof box.value === "string" ? box.value.trim() : "";
  }

  const base = (caseId) => `/cases/${encodeURIComponent(caseId)}/cloud-collect`;

  async function getJson(url) {
    try {
      const res = await fetch(url);
      let body = {};
      try {
        body = await res.json();
      } catch {
        body = {};
      }
      return { ok: res.ok, status: res.status, body };
    } catch (e) {
      return { ok: false, status: 0, body: { error: e.message } };
    }
  }

  async function post(url, body) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      });
      let out = {};
      try {
        out = await res.json();
      } catch {
        out = {};
      }
      return { ok: res.ok, status: res.status, body: out };
    } catch (e) {
      return { ok: false, status: 0, body: { error: e.message } };
    }
  }

  function setMsg(text, isError) {
    const box = byId("cloudCollectMsg");
    if (!box) return;
    box.textContent = text || "";
    box.style.color = isError ? "var(--badge-danger-text)" : "";
  }

  function stopPolling() {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null;
  }

  function schedulePoll(caseId) {
    stopPolling();
    pollCase = caseId;
    // Case-scoped: a tick for a case the analyst has left does nothing.
    pollTimer = setTimeout(() => {
      pollTimer = null;
      if (pollCase === caseNow()) loadCloudCollect(pollCase);
    }, POLL_MS);
  }

  function labelled(text, control) {
    const wrap = el("label", null, "cc-field");
    wrap.appendChild(el("span", text));
    wrap.appendChild(control);
    return wrap;
  }

  function toLocalInput(d) {
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function sourceBoxes(provider) {
    const box = el("fieldset", null, "cc-sources");
    box.appendChild(el("legend", "Log sources"));
    if (!provider || !provider.available) {
      box.appendChild(el("p", provider ? provider.notice : "Pick an account first.", "cc-note"));
      return box;
    }
    for (const s of provider.sources) {
      const input = el("input");
      input.type = "checkbox";
      input.value = s.id;
      input.checked = true;
      input.className = "cc-source";
      box.appendChild(labelled(s.label, input));
    }
    // What the provider does NOT collect, and where to get it instead (#2315: Microsoft mailbox
    // audit, transport rules and message trace → MES and the #2300 matrix).
    for (const n of provider.notes || []) box.appendChild(el("p", n, "cc-note"));
    return box;
  }

  function splitCsv(value) {
    return String(value || "")
      .split(",")
      .filter(Boolean);
  }

  // The picker for one account. `state` is the form's: a stale answer (the analyst picked another
  // account while this one loaded) is dropped by its sequence number.
  function regionPicker(caseId, accountId, state, onChange) {
    const box = el("fieldset", null, "cc-regions");
    box.appendChild(el("legend", "Regions"));
    const status = el("p", "Listing the regions enabled on this account…", "cc-note");
    box.appendChild(status);
    const seq = ++state.seq;
    state.listing = null;
    state.error = "";
    post(`${base(caseId)}/regions`, { accountId }).then((res) => {
      if (seq !== state.seq) return;
      if (!res.ok || !Array.isArray(res.body.regions)) {
        state.error = res.body.error || `HTTP ${res.status}`;
        status.textContent = `Regions could not be listed (${state.error}). The server lists them when the collection starts, and the result says which list was used.`;
        status.className = "cc-missing";
        onChange();
        return;
      }
      state.listing = res.body;
      status.remove();
      const tools = el("div", null, "cc-region-tools");
      const all = el("button", "Tick all");
      all.type = "button";
      const none = el("button", "Untick all");
      none.type = "button";
      tools.append(all, none);
      box.appendChild(tools);
      for (const r of res.body.regions) {
        const input = el("input");
        input.type = "checkbox";
        input.value = r;
        input.checked = true;
        input.className = "cc-region";
        box.appendChild(labelled(r === res.body.home ? `${r} (account region)` : r, input));
      }
      const setAll = (on) => {
        for (const b of box.querySelectorAll(".cc-region")) b.checked = on;
        onChange();
      };
      all.addEventListener("click", () => setAll(true));
      none.addEventListener("click", () => setAll(false));
      if (res.body.note) box.appendChild(el("p", res.body.note, "cc-missing"));
      onChange();
    });
    return box;
  }

  // What the picker sends, and the lines the pre-check shows about it.
  function regionChoice(box, state) {
    if (!state.listing || !box) return null;
    const boxes = [...box.querySelectorAll(".cc-region")];
    return {
      regions: boxes.filter((b) => b.checked).map((b) => b.value),
      excludeRegions: boxes.filter((b) => !b.checked).map((b) => b.value),
    };
  }

  function regionLines(state, choice) {
    if (state.error)
      return [[`Regions could not be listed (${state.error}). The server lists them when the collection starts, and the result says which list was used.`, "cc-missing"]];
    if (!state.listing || !choice) return [];
    const total = choice.regions.length + choice.excludeRegions.length;
    const lines = [[`Regions: ${choice.regions.length} of ${total} ticked${choice.excludeRegions.length ? ` — skipped by choice: ${choice.excludeRegions.join(", ")}` : ""}`, ""]];
    if (state.listing.note) lines.push([state.listing.note, "cc-missing"]);
    return lines;
  }

  function startForm(caseId, accounts, providers) {
    const form = el("form", null, "cc-form");
    form.setAttribute("aria-label", "Start a cloud collection");
    const select = el("select");
    select.id = "cloudCollectAccount";
    for (const a of accounts) {
      const opt = el("option", `${a.name} (${a.provider})`);
      opt.value = a.id;
      opt.dataset.provider = a.provider;
      select.appendChild(opt);
    }
    if (accounts.length) select.value = accounts[0].id; // what a browser shows first, made explicit
    const providerOf = () => providers.find((p) => p.provider === select.selectedOptions[0]?.dataset.provider);
    const start = el("input");
    start.type = "datetime-local";
    start.id = "cloudCollectStart";
    start.value = toLocalInput(new Date(Date.now() - 7 * 86400000));
    const end = el("input");
    end.type = "datetime-local";
    end.id = "cloudCollectEnd";
    end.value = toLocalInput(new Date());
    let sources = sourceBoxes(providerOf());
    const regionState = { seq: 0, listing: null, error: "" };
    const checkBox = el("div", null, "cc-precheck");
    checkBox.setAttribute("aria-live", "polite");
    // Any edit invalidates a shown pre-check: Confirm would otherwise start the old body.
    const invalidate = () => checkBox.replaceChildren();
    const pickerFor = () => {
      const p = providerOf();
      if (p && p.available && p.regionPicker) return regionPicker(caseId, select.value, regionState, invalidate);
      regionState.seq++; // drop an answer still in flight for the previous account
      regionState.listing = null;
      regionState.error = "";
      return el("div", null, "cc-regions-none");
    };
    let regions = pickerFor();
    select.addEventListener("change", () => {
      const next = sourceBoxes(providerOf());
      sources.replaceWith(next);
      sources = next;
      const nextRegions = pickerFor();
      regions.replaceWith(nextRegions);
      regions = nextRegions;
    });
    const overlap = el("input");
    overlap.type = "number";
    overlap.min = "0";
    overlap.max = "1440";
    overlap.id = "cloudCollectOverlap";
    overlap.placeholder = "provider default";
    const go = el("button", "Check and start…");
    go.type = "submit";
    form.addEventListener("change", invalidate);
    form.addEventListener("input", invalidate);
    form.append(
      labelled("Account", select),
      labelled("From", start),
      labelled("To", end),
      labelled("Ingestion overlap (min)", overlap),
      sources,
      regions,
      go,
      checkBox,
    );
    const bodyOf = (chosen, picked) => ({
      accountId: select.value,
      sources: chosen,
      start: new Date(start.value).toISOString(),
      end: new Date(end.value).toISOString(),
      ...(overlap.value !== "" ? { overlapMinutes: Number(overlap.value) } : {}),
      ...(picked ? picked : {}),
    });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const chosen = [...form.querySelectorAll(".cc-source")].filter((b) => b.checked).map((b) => b.value);
      const provider = providerOf();
      if (!provider || !provider.available) return setMsg(provider ? provider.notice : "Pick an account.", true);
      if (!chosen.length) return setMsg("Pick at least one log source.", true);
      const picked = regionChoice(regions, regionState);
      if (picked && !picked.regions.length) return setMsg("Tick at least one region.", true);
      go.disabled = true;
      const body = bodyOf(chosen, picked);
      const extra = regionLines(regionState, picked);
      const check = await post(`${base(caseId)}/precheck`, body);
      go.disabled = false;
      if (!check.ok) return setMsg(check.body.error || `Pre-check failed (HTTP ${check.status})`, true);
      renderPrecheck(checkBox, check.body, extra, async (confirm) => {
        confirm.disabled = true;
        const res = await post(base(caseId), body);
        confirm.disabled = false;
        setMsg(res.ok ? "Collection started — progress below and in Background jobs." : res.body.error || `Start failed (HTTP ${res.status})`, !res.ok);
        if (res.ok) loadCloudCollect(caseId);
      });
    });
    return form;
  }

  function renderPrecheck(box, check, extra, onConfirm) {
    box.replaceChildren();
    box.appendChild(el("strong", "Before you start"));
    const list = el("ul", null, "cc-lines");
    for (const s of check.sources || []) {
      const mins = Math.round((s.overlapMs || 0) / 60000);
      list.appendChild(el("li", `${s.label}: ingestion overlap ${mins} min (a default, not a completeness guarantee)`));
      for (const w of s.warnings || []) list.appendChild(el("li", `${s.label}: ${w}`, "cc-missing"));
    }
    if (check.quota) list.appendChild(el("li", check.quota.note, check.quota.enough ? "" : "cc-missing"));
    for (const [text, cls] of extra || []) list.appendChild(el("li", text, cls));
    box.appendChild(list);
    const confirm = el("button", "Confirm and start");
    confirm.type = "button";
    confirm.addEventListener("click", () => onConfirm(confirm));
    const cancel = el("button", "Cancel");
    cancel.type = "button";
    cancel.addEventListener("click", () => box.replaceChildren());
    box.append(confirm, cancel);
  }

  function perSource(cp) {
    const by = new Map();
    const rank = { done: 0, incomplete: 1, pending: 2, failed: 3 };
    for (const sw of cp.subWindows || []) {
      const prev = by.get(sw.source) || { pages: 0, records: 0, state: "done" };
      // A split parent's pages count, its state does not: its children carry it (#2312).
      const mine = sw.state === "split" ? "done" : sw.state === "capped" ? "pending" : sw.state;
      const state = (rank[mine] || 0) > (rank[prev.state] || 0) ? mine : prev.state;
      // The cloud's own status while a request waits (#2315): a Graph audit query can run 10+ min.
      const status = sw.providerStatus || prev.status;
      by.set(sw.source, { pages: prev.pages + sw.pages, records: prev.records + sw.records, state, status });
    }
    return [...by.entries()].map(
      ([source, v]) =>
        `${source}: ${v.pages} page(s), ${v.records} record(s), ${v.state}${v.status && v.state === "pending" ? ` — ${v.status}` : ""}`,
    );
  }

  // The region scope the start recorded in the manifest header (#2363) — shown even when no page
  // was saved, so a fallback list is never silent.
  function regionScopeLines(filters) {
    const f = filters || {};
    if (!f.regions) return [];
    const lines = [[`Regions collected: ${splitCsv(f.regions).join(", ")}`, ""]];
    if (f.regionsSkippedByChoice) lines.push([`Regions skipped by choice (unticked): ${splitCsv(f.regionsSkippedByChoice).join(", ")}`, "cc-note"]);
    if (f.regionsNoLongerEnabled)
      lines.push([`Ticked but not enabled on the account when the collection started, not collected: ${splitCsv(f.regionsNoLongerEnabled).join(", ")}`, "cc-missing"]);
    if (f.regionList === "fallback")
      lines.push([`The regions enabled on this account could not be listed (${f.regionListReason || "unknown error"}) — the default region list was used, so an opt-in region may be missing. Grant ec2:DescribeRegions.`, "cc-missing"]);
    return lines;
  }

  function collectionRow(caseId, c) {
    const cp = c.checkpoint;
    const row = el("div", null, "cc-row");
    row.setAttribute("role", "listitem");
    const head = el("div", null, "cc-head");
    head.appendChild(el("strong", (c.header && c.header.accountName) || cp.accountId));
    head.appendChild(el("span", ` ${cp.provider} · ${cp.window.start} → ${cp.window.end} · `, "cc-meta"));
    head.appendChild(el("span", STATUS_TEXT[cp.status] || cp.status, `cc-status cc-${cp.status}`));
    row.appendChild(head);
    const lines = el("ul", null, "cc-lines");
    for (const line of perSource(cp)) lines.appendChild(el("li", line));
    for (const [text, cls] of regionScopeLines(c.header && c.header.filters)) lines.appendChild(el("li", text, cls));
    lines.appendChild(el("li", `${c.pages} page(s) saved (${c.bytes} bytes, SHA-256 in the manifest); ${cp.imported.length} imported`));
    for (const cov of cp.coverage || []) {
      const cut = cov.acquiredCutoff ? `acquired up to ${cov.acquiredCutoff}` : "end of window not acquired";
      lines.appendChild(el("li", `${cov.source}: ${cut}`));
      for (const n of cov.notes || []) lines.appendChild(el("li", `${cov.source}: ${n}`, "cc-note"));
    }
    if (cp.stopReason) lines.appendChild(el("li", `Stopped early: ${cp.stopReason}`, "cc-missing"));
    for (const m of cp.missing || []) lines.appendChild(el("li", `Missing ${m.source} ${m.window.start} → ${m.window.end}: ${m.reason}`, "cc-missing"));
    for (const q of cp.quarantined || [])
      lines.appendChild(el("li", `Quarantined (${q.reason}): ${q.file}${q.sha256 ? ` sha256 ${q.sha256}` : ""}`, "cc-quarantine"));
    if (cp.error) lines.appendChild(el("li", `Stopped: ${cp.error}`, "cc-missing"));
    row.appendChild(lines);
    if (RESUMABLE.has(cp.status)) {
      const resume = el("button", "Resume");
      resume.type = "button";
      resume.setAttribute("aria-label", `Resume collection ${cp.collectionId}`);
      resume.addEventListener("click", async () => {
        resume.disabled = true;
        const res = await post(`${base(caseId)}/${encodeURIComponent(cp.collectionId)}/resume`);
        setMsg(res.ok ? "Resuming — the account's credential was opened again." : res.body.error || `Resume failed (HTTP ${res.status})`, !res.ok);
        loadCloudCollect(caseId);
      });
      row.appendChild(resume);
    }
    return row;
  }

  async function loadCloudCollect(caseId) {
    const box = byId("cloudCollect");
    const section = byId("sec-cloud-collect");
    if (!box) return;
    const id = caseId || caseNow();
    stopPolling();
    if (!id) {
      box.textContent = "Open a case to collect cloud logs.";
      return;
    }
    const [list, accounts] = await Promise.all([getJson(base(id)), getJson(`/cases/${encodeURIComponent(id)}/cloud-accounts`)]);
    if (id !== caseNow()) return; // the analyst moved on while this loaded
    const button = byId("cloudCollectBtn");
    if (list.status === 403 && list.body.demo) {
      if (section) section.hidden = true;
      if (button) button.hidden = true;
      return;
    }
    box.replaceChildren();
    if (!list.ok) {
      box.appendChild(el("p", list.body.error || `Cloud collection is not available (HTTP ${list.status}).`, "cc-note"));
      return;
    }
    const usable = (accounts.ok && accounts.body.accounts) || [];
    if (usable.length) box.appendChild(startForm(id, usable, list.body.providers || []));
    else box.appendChild(el("p", "No cloud account is attached to this case. Add one in Settings → Cloud accounts.", "cc-note"));
    const msg = el("span", "", "cc-msg");
    msg.id = "cloudCollectMsg";
    msg.setAttribute("role", "status");
    box.appendChild(msg);
    const rows = el("div", null, "cc-list");
    rows.setAttribute("role", "list");
    rows.setAttribute("aria-label", "Cloud collections of this case");
    for (const c of list.body.collections || []) rows.appendChild(collectionRow(id, c));
    if (!(list.body.collections || []).length) rows.appendChild(el("p", "No collections yet.", "cc-note"));
    box.appendChild(rows);
    if ((list.body.collections || []).some((c) => c.checkpoint.status === "running")) schedulePoll(id);
  }

  function initCloudCollect() {
    const button = byId("cloudCollectBtn");
    if (!button) return;
    // The page's reveal idiom: a view profile may hide the section, and scrollIntoView() on a
    // display:none element is a silent no-op.
    button.addEventListener("click", () => {
      const section = byId("sec-cloud-collect");
      if (section) {
        if (typeof markSectionRevealed === "function") markSectionRevealed("sec-cloud-collect");
        section.classList.remove("collapsed");
        section.scrollIntoView({ behavior: "smooth", block: "start" });
      }
      loadCloudCollect(caseNow());
    });
  }

  window.initCloudCollect = initCloudCollect;
  window.loadCloudCollect = loadCloudCollect;
})();
