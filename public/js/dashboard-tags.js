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

  function tagPills(type, id) {
    const list = (tagsByTarget.get(targetKey(type, id)) || []).filter(
      (t) => !(t.label === "starred" && t.targetType === "event"),
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

  function loadTags(caseId) {
    fetch(`/cases/${caseId}/tags`)
      .then((r) => r.json())
      .then((list) => {
        tagsByTarget = new Map();
        (list || []).forEach((t) => {
          const k = targetKey(t.targetType, t.targetId);
          let arr = tagsByTarget.get(k);
          if (!arr) {
            arr = [];
            tagsByTarget.set(k, arr);
          }
          arr.push(t);
        });
        deriveStarred(); // stars are tags — rebuild the star lookup with every tag load
        migrateLocalStars(caseId); // one-time: push legacy localStorage stars up as tags
        if (DfirState.lastState()) render(DfirState.lastState()); // refresh inline pills
        // A tag change alters the super-timeline's Tags filter facet + tag-filtered results (both now
        // server-driven by tags), so reload it rather than a cache re-render — but only when its section
        // has already been loaded, so we don't fire a fetch on the initial case-load loadTags().
        if (DfirState.lastSuperData()) loadSuperTimeline();
        if (tagTarget) renderTagModal(); // refresh an open editor (live collaboration)
      })
      .catch(() => {});
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
    const list =
      tagsByTarget.get(targetKey(tagTarget.type, tagTarget.id)) || [];
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
  function eachTagList(fn) {
    tagsByTarget.forEach(fn);
  }
  // js/dashboard-super-timeline.js, rendering one row's pills.
  function tagsForTarget(key) {
    return tagsByTarget.get(key) || [];
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
