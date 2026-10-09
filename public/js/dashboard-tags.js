// Analyst triage tags — extracted from dashboard.html (issue #415, tier 3).
//
// Two escapes, and they cross in opposite directions, so they get different answers.
//
// tagTarget was WRITTEN from js/dashboard-bulk-select.js — `tagTarget = { bulk: true, ... }` —
// to aim the tag modal at a multi-selection. That is an operation, not a variable, so it is
// setBulkTagTarget(). tagsByTarget was READ by two modules, one iterating every list and one
// looking a single target up, so it exports the two questions they actually ask rather than the
// Map: eachTagList() and tagsForTarget().
//
// None of the three could be published as the binding itself — the manifest requires published
// names to be callable.
(function () {
  "use strict";

  // Hand labels on any entity, independent of AI severity. Stored in a per-case side file
  // (state/tags.json); survive synthesis. Shown inline as colored pills + a 🏷 add button.
  let tagsByTarget = new Map(); // "type:id" -> [tag]
  let tagTarget = null; // currently-open { type, id } in the tag modal
  const SUGGESTED_TAGS = [
    "confirmed-malicious",
    "false-positive",
    "needs-review",
    "benign-admin",
    "key-evidence",
    "pivot-point",
    "persistence",
    "lateral-movement",
    "c2-comms",
    "exfil",
    "credential-access",
    "initial-access",
  ];

  // An annotation's keys (#1715): its own `type:id`, plus the event it lives on today when correlation
  // folded the one it was made on into another (the server adds resolvedTargetId for that case only).
  function annotationKeys(a) {
    const keys = [targetKey(a.targetType, a.targetId)];
    if (a.resolvedTargetId) keys.push(targetKey(a.targetType, a.resolvedTargetId));
    return keys;
  }

  // ---- the automatic tagger's labels, carried by the pages (#2059) ----
  // GET /tags carries analyst tags only: on an auto-tagged case the tagger's event tags are one per
  // matched event and label (~10 MB), and every tag change made every dashboard re-read them all. They
  // now arrive with each timeline page — `eventTaggerTags` on /state and /super-timeline, keyed by row
  // id — and gather here, so a row shows exactly the pills it did. A page names only its own rows, so
  // pages only ever ADD to what is known; a removal shows up as a new tagger version on the tag list
  // (X-Tagger-Tags-Version), and then every row held is asked again.
  const TAGGER_ASK_CHUNK = 5000; // the server's per-request bound (analysis/taggerRowTags.ts)
  let taggerCase = null;
  let taggerByEvent = new Map(); // event id -> [{ id, label, author }]
  let taggerKnown = new Set(); // event ids whose tagger tags are known, or asked for
  let taggerVersion = null;

  function taggerForCase(caseId) {
    if (!caseId || caseId === taggerCase) return;
    taggerCase = caseId;
    taggerByEvent = new Map();
    taggerKnown = new Set();
    taggerVersion = null;
  }

  // A page landed (a /state reply, a push, a super-timeline page). Rows it describes are taken as
  // given; rows nobody has described yet (a push carries no page tags) are asked about once.
  function absorbPage(data, rows) {
    if (!data || !Array.isArray(rows)) return;
    if (typeof data.caseId === "string") taggerForCase(data.caseId);
    const carried = data.eventTaggerTags && typeof data.eventTaggerTags === "object" ? data.eventTaggerTags : null;
    const unknown = [];
    rows.forEach((e) => {
      const id = e && typeof e.id === "string" ? e.id : null;
      if (!id) return;
      if (carried && Object.prototype.hasOwnProperty.call(carried, id) && Array.isArray(carried[id])) {
        taggerByEvent.set(id, carried[id]);
        taggerKnown.add(id);
      } else if (!taggerKnown.has(id)) {
        if (carried) taggerKnown.add(id);
        else unknown.push(id);
      }
    });
    if (unknown.length) askTaggerTags(unknown);
  }

  function heldRowIds() {
    // Read through the accessors, never cached (tests/dashboard/dashboardState.test.ts).
    const rows = [].concat(
      (DfirState.lastState() && DfirState.lastState().forensicTimeline) || [],
      (DfirState.lastSuperData() && DfirState.lastSuperData().events) || [],
    );
    return [...new Set(rows.map((e) => e && e.id).filter((id) => typeof id === "string"))];
  }

  // Ask the server for these rows' tagger tags (bounded chunks), replace what is known of them, repaint.
  function askTaggerTags(ids) {
    const caseId = taggerCase;
    if (!caseId || !ids.length) return;
    ids.forEach((id) => taggerKnown.add(id));
    const chunks = [];
    for (let i = 0; i < ids.length; i += TAGGER_ASK_CHUNK) chunks.push(ids.slice(i, i + TAGGER_ASK_CHUNK));
    chunks
      .reduce(
        (prev, chunk) =>
          prev.then(() =>
            fetch(`/cases/${encodeURIComponent(caseId)}/tags/tagger-for`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ ids: chunk }),
            })
              .then((r) => {
                if (!r.ok) throw new Error("HTTP " + r.status);
                return r.json();
              })
              .then((body) => {
                if (taggerCase !== caseId) return;
                const found = (body && body.eventTaggerTags) || {};
                chunk.forEach((id) => {
                  if (Object.prototype.hasOwnProperty.call(found, id) && Array.isArray(found[id])) taggerByEvent.set(id, found[id]);
                  else taggerByEvent.delete(id);
                });
              }),
          ),
        Promise.resolve(),
      )
      .then(() => {
        if (taggerCase === caseId) repaintTags();
      })
      .catch(() => {
        // Left unknown, so the next page or tag change asks again; the pills shown stay as they were.
        if (taggerCase === caseId) ids.forEach((id) => taggerKnown.delete(id));
      });
  }

  if (typeof DfirState !== "undefined" && DfirState.onLastStateChange) {
    DfirState.onLastStateChange((next) => absorbPage(next, next && next.forensicTimeline));
    DfirState.onLastSuperDataChange((next) => absorbPage(next, next && next.events));
  }

  // The tagger tags of one event, shaped like the list's tags so the pills and the modal read both.
  function taggerTagsOf(type, id) {
    if (type !== "event") return [];
    const key = String(id);
    return (taggerByEvent.get(key) || []).map((t) => ({
      id: t.id,
      targetType: "event",
      targetId: key,
      label: t.label,
      author: t.author,
    }));
  }
  function tagsOf(type, id) {
    return taggerTagsOf(type, id).concat(tagsByTarget.get(targetKey(type, id)) || []);
  }

  function tagPills(type, id) {
    // One pill per label: a tag on an event correlation folded into this one (#1715) may repeat a label.
    const list = tagsOf(type, id).filter(
      (t, i, all) =>
        !(t.label === "starred" && t.targetType === "event") &&
        all.findIndex((o) => o.label === t.label) === i,
    );
    return list
      .map((t) => {
        const c = tagColor(t.label);
        return `<span class="tag-pill" data-safe-style="color:${c};border-color:${c}" title="tag by ${escAttr(t.author)}">${esc(t.label)}</span>`;
      })
      .join("");
  }
  function tagAddBtn(type, id) {
    return `<button class="tag-add" data-tt="${escAttr(type)}" data-ti="${escAttr(String(id))}" title="Add / edit triage tags">${ICON_TAG}</button>`;
  }
  function tagChip(type, id) {
    return tagPills(type, id) + tagAddBtn(type, id);
  }

  // Repaint what shows tags from what is held — no fetch.
  function repaintTags() {
    if (DfirState.lastState()) render(DfirState.lastState());
    if (typeof refreshSuperRows === "function") refreshSuperRows();
    if (tagTarget) renderTagModal();
  }

  // The tagger version on the list moved: the tagger tags the pages carried may be stale.
  function noteTaggerVersion(version) {
    if (typeof version !== "string" || !version) return;
    const moved = taggerVersion !== null && version !== taggerVersion;
    taggerVersion = version;
    if (moved) askTaggerTags(heldRowIds());
  }

  // Every tag change broadcasts tags_changed, and a bulk star sends one per event (#2059). One fetch
  // runs at a time; whatever arrives meanwhile is answered by ONE trailing fetch after it.
  let tagsInFlight = false;
  let tagsAgain = null; // the case a change arrived for while a fetch was out
  function loadTags(caseId) {
    if (tagsInFlight) {
      tagsAgain = caseId;
      return;
    }
    tagsInFlight = true;
    fetchTags(caseId)
      .catch(() => {})
      .then(() => {
        tagsInFlight = false;
        const next = tagsAgain;
        tagsAgain = null;
        if (next !== null) loadTags(next);
      });
  }

  function fetchTags(caseId) {
    taggerForCase(caseId);
    return fetch(`/cases/${caseId}/tags`)
      .then((r) => {
        const version = r.headers && r.headers.get ? r.headers.get("X-Tagger-Tags-Version") : null;
        return r.json().then((list) => ({ list, version }));
      })
      .then(({ list, version }) => {
        if (tagsAgain !== null && tagsAgain !== caseId) return; // the analyst moved to another case meanwhile
        noteTaggerVersion(version);
        tagsByTarget = new Map();
        (list || []).forEach((t) => {
          // A tag on an event correlation later folded into another (#1715) shows on both: the raw
          // super-timeline row keeps its own id, and the forensic event lives on as resolvedTargetId.
          annotationKeys(t).forEach((k) => {
            let arr = tagsByTarget.get(k);
            if (!arr) {
              arr = [];
              tagsByTarget.set(k, arr);
            }
            arr.push(t);
          });
        });
        deriveStarred(); // stars are tags — rebuild the star lookup with every tag load
        migrateLocalStars(caseId); // one-time: push legacy localStorage stars up as tags
        if (DfirState.lastState()) render(DfirState.lastState()); // refresh inline pills
        // A tag change alters the super-timeline's Tags filter facet + tag-filtered results (both now
        // server-driven by tags), so reload it rather than a cache re-render — but only when its section
        // has already been loaded, so we don't fire a fetch on the initial case-load loadTags().
        if (DfirState.lastSuperData()) loadSuperTimeline();
        if (tagTarget) renderTagModal(); // refresh an open editor (live collaboration)
      });
  }

  function openTagModal(type, id) {
    tagTarget = { type, id };
    document.getElementById("tagOverlay").classList.add("open");
    renderTagModal();
    document.getElementById("tagInput").focus();
  }
  function closeTagModal() {
    tagTarget = null;
    document.getElementById("tagOverlay").classList.remove("open");
    document.getElementById("tagInput").value = "";
    document.getElementById("tagMsg").textContent = "";
  }
  function renderTagModal() {
    if (!tagTarget) return;
    // Bulk mode: tag N entities at once (current tags not shown, only add-flow)
    if (tagTarget.bulk) {
      const t = tagTarget.targetType || "event";
      document.getElementById("tagTitle").textContent =
        `Add tags to ${tagTarget.ids.length} selected ${t}${tagTarget.ids.length !== 1 ? "s" : ""}`;
      document.getElementById("tagCurrent").innerHTML =
        `<div data-safe-style='color:var(--text-muted);font-size:12px'>Tags will be added to all selected ${t}s. Individual existing tags are not shown in bulk mode.</div>`;
      const sug = document.getElementById("tagSuggest");
      sug.innerHTML = SUGGESTED_TAGS.map((l) => {
        const c = tagColor(l);
        return `<button class="tag-suggest-btn" data-safe-style="color:${c};border-color:${c}" data-label="${escAttr(l)}">+ ${esc(l)}</button>`;
      }).join("");
      sug
        .querySelectorAll(".tag-suggest-btn")
        .forEach(
          (b) => (b.onclick = () => addTag(b.getAttribute("data-label"))),
        );
      return;
    }
    // Single-target mode
    const list = tagsOf(tagTarget.type, tagTarget.id); // the tagger's too, each removable (#2059)
    document.getElementById("tagTitle").textContent =
      `Tags on ${tagTarget.type} ${tagTarget.id}`;
    const cur = document.getElementById("tagCurrent");
    cur.innerHTML = list.length
      ? list
          .map((t) => {
            const c = tagColor(t.label);
            return (
              `<span class="tag-current-pill" data-safe-style="color:${c};border-color:${c}" title="by ${escAttr(t.author)}">${esc(t.label)}` +
              `<button class="tag-del" data-id="${escAttr(t.id)}" title="Remove">✕</button></span>`
            );
          })
          .join("")
      : "<div data-safe-style='color:var(--text-muted);font-size:12px'>No tags yet.</div>";
    cur
      .querySelectorAll(".tag-del")
      .forEach((b) => (b.onclick = () => deleteTag(b.getAttribute("data-id"))));
    const applied = new Set(list.map((t) => t.label));
    const sug = document.getElementById("tagSuggest");
    sug.innerHTML = SUGGESTED_TAGS.filter((l) => !applied.has(l))
      .map((l) => {
        const c = tagColor(l);
        return `<button class="tag-suggest-btn" data-safe-style="color:${c};border-color:${c}" data-label="${escAttr(l)}">+ ${esc(l)}</button>`;
      })
      .join("");
    sug
      .querySelectorAll(".tag-suggest-btn")
      .forEach((b) => (b.onclick = () => addTag(b.getAttribute("data-label"))));
  }
  function addTag(label) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !tagTarget || !String(label || "").trim()) return;
    const msg = document.getElementById("tagMsg");
    msg.textContent = "adding…";
    // Bulk mode: add the tag to every selected entity. Serialize the POSTs — the server's
    // TagsStore.add() is read-modify-write on tags.json, so concurrent requests clobber each
    // other (last write wins) and only one tag would survive. Await each before the next.
    if (tagTarget.bulk) {
      (async () => {
        try {
          const ids = tagTarget.ids;
          const bulkTargetType = tagTarget.targetType || "event";
          for (let i = 0; i < ids.length; i++) {
            msg.textContent = `adding… (${i + 1}/${ids.length})`;
            const r = await fetch(`/cases/${caseId}/tags`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                targetType: bulkTargetType,
                targetId: ids[i],
                author: investigatorName(),
                label,
              }),
            });
            if (!r.ok) throw new Error("HTTP " + r.status);
          }
          document.getElementById("tagInput").value = "";
          msg.textContent = "";
          loadTags(caseId);
        } catch (e) {
          msg.textContent = "failed: " + e.message;
        }
      })();
      return;
    }
    // Single-target mode
    fetch(`/cases/${caseId}/tags`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        targetType: tagTarget.type,
        targetId: tagTarget.id,
        author: investigatorName(),
        label,
      }),
    })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(() => {
        document.getElementById("tagInput").value = "";
        msg.textContent = "";
        loadTags(caseId);
      })
      .catch((e) => (msg.textContent = "failed: " + e.message));
  }
  function deleteTag(id) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    fetch(`/cases/${caseId}/tags/${id}`, { method: "DELETE" })
      .then(() => loadTags(caseId))
      .catch(() => {});
  }

  // The modal's four controls, which had been left in the page's wiring block and read their
  // handlers at LOAD — with this module extracted a 404 would throw there before the facade could
  // report anything. Fourteenth wrong-owner case in this PR.
  function initTagModal() {
    document.getElementById("tagAddBtn").onclick = () =>
      addTag(document.getElementById("tagInput").value);
    document.getElementById("tagClose").onclick = closeTagModal;
    document.getElementById("tagOverlay").addEventListener("click", (e) => {
      if (e.target.id === "tagOverlay") closeTagModal();
    });
    document.getElementById("tagInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        addTag(e.target.value);
      }
    });
  }

  // ---- what the other modules ask ----
  // js/dashboard-bulk-select.js, aiming the modal at a multi-selection.
  function setBulkTagTarget(ids, targetType) {
    tagTarget = { bulk: true, ids, targetType: targetType || "event" };
  }
  // js/dashboard-starred.js, deriving the starred set from every tag list.
  // Each tag ONCE, like eachCommentList: a tag on a folded event sits in two buckets (#1715).
  function eachTagList(fn) {
    const seen = new Set();
    tagsByTarget.forEach((list) => fn(list.filter((t) => !seen.has(t.id) && seen.add(t.id))));
  }
  // js/dashboard-super-timeline.js, rendering one row's pills.
  // `key` is targetKey(type, id); the row's tagger tags come from its page (#2059).
  function tagsForTarget(key) {
    const k = String(key);
    const at = k.indexOf(":");
    return at < 0 ? tagsByTarget.get(k) || [] : tagsOf(k.slice(0, at), k.slice(at + 1));
  }

  window.initTagModal = initTagModal;
  window.addTag = addTag;
  window.closeTagModal = closeTagModal;
  window.loadTags = loadTags;
  window.openTagModal = openTagModal;
  window.renderTagModal = renderTagModal;
  window.tagAddBtn = tagAddBtn;
  window.tagChip = tagChip;
  window.tagPills = tagPills;
  window.setBulkTagTarget = setBulkTagTarget;
  window.eachTagList = eachTagList;
  window.tagsForTarget = tagsForTarget;
})();
