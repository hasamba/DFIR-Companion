// Playbook (#230) — the case's task list, its dependency graph, and the AI-suggested Velociraptor
// hunts that hang off it (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the task list, the open-only filter, which dependency editors
// are expanded, the flattened hunt suggestions and their collapsed state. Nothing outside reads any
// of them — the two that looked like escapes were a mention in a comment and an HTML id attribute.
//
// ITS WIRING IS AN INITIALIZER. Four controls (Add, Sync, the Open-only checkbox and the template
// picker) were wired at the bottom of the inline block. This file is a <head> script, so doing that
// here would query #sec-playbook before it exists and wire nothing, silently.
(function () {
  let playbookTasks = [];
  let pbOpenOnly = false;
  let pbDepsOpen = {}; // task id -> is its "depends on" editor panel expanded?
  let pbHuntFlat = []; // AI-suggested Velociraptor hunts (#70), in severity order; each carries taskId
  let pbHuntCollapsed = {}; // suggestion index -> collapsed? (default false = expanded)
  const PB_STATUS = [
    ["todo", "To do"],
    ["in_progress", "In progress"],
    ["done", "Done"],
    ["skipped", "Skipped"],
  ];
  const pbCaseId = () => document.getElementById("caseId").value.trim();

  function loadPlaybook(caseId) {
    fetch(`/cases/${caseId}/playbook`)
      .then((r) =>
        r.ok ? r.json() : { tasks: [], stats: null, control: null },
      )
      .then((d) => {
        playbookTasks = Array.isArray(d.tasks) ? d.tasks : [];
        const tpl = document.getElementById("pbTemplates");
        if (tpl && d.control) tpl.checked = !!d.control.useTemplates;
        // Restore persisted AI hunt suggestions (#70) so they survive a refresh; the server already
        // dropped any whose task changed. Sorted by severity to match the generate-time ordering.
        pbHuntFlat = Array.isArray(d.huntSuggestions)
          ? [...d.huntSuggestions].sort(
              (a, b) =>
                (VHS_SEV_RANK[a.severity] ?? 9) -
                (VHS_SEV_RANK[b.severity] ?? 9),
            )
          : [];
        renderPlaybook(d.stats);
      })
      .catch(() => {});
  }

  function renderPlaybook(stats) {
    const el = document.getElementById("pbList");
    if (!el) return;
    stats = stats || pbLocalStats(playbookTasks);
    const badge = document.getElementById("pbBadge");
    if (badge)
      badge.textContent = playbookTasks.length
        ? `${stats.done}/${stats.total} done · ${stats.completionPct}%`
        : "";
    const bar = document.getElementById("pbProgressBar");
    if (bar) bar.style.width = (stats.completionPct || 0) + "%";
    let tasks = playbookTasks;
    if (pbOpenOnly)
      tasks = tasks.filter(
        (t) => t.status !== "done" && t.status !== "skipped",
      );
    if (!tasks.length) {
      el.innerHTML = `<div data-safe-style='color:var(--text-muted);font-size:12px'>${playbookTasks.length ? "No open tasks — all done or skipped." : "No tasks yet — run synthesis (or add a custom task below)."}</div>`;
      return;
    }
    const canDrag = !pbOpenOnly; // reordering a filtered subset would be ambiguous
    el.innerHTML = tasks
      .map((t) => {
        const opts = PB_STATUS.map(
          ([v, l]) =>
            `<option value="${v}" ${t.status === v ? "selected" : ""}>${l}</option>`,
        ).join("");
        const src =
          t.source === "custom"
            ? "custom"
            : t.source === "finding"
              ? "from finding"
              : "from next step";
        const findingLink = t.relatedFindingId
          ? `<a href="#" class="pb-finding-link" title="Go to findings" data-act="pbJumpFinding">↳ finding</a>`
          : "";
        const desc = t.description
          ? `<div class="pb-desc">${esc(t.description)}</div>`
          : "";
        const blockedByTitles = (t.blockedBy || []).map((id) => {
          const dep = playbookTasks.find((o) => o.id === id);
          return dep ? dep.shortId || dep.title : id;
        });
        const blockedBadge = t.blocked
          ? `<span class="pb-blocked-badge" title="Blocked by: ${escAttr(blockedByTitles.join(", "))}">⛔ blocked</span>`
          : "";
        // Count only edges that still resolve to a live task. A dependency whose task was
        // deleted stays in `dependsOn` on purpose (an auto-task's id is its stable sourceKey, so
        // the edge reconnects if the seed re-derives), but such a ghost edge is never listed in
        // the picker below — counting it would show "(2)" over a panel with one box ticked, and
        // the analyst would have no way to clear the difference.
        const depCount = (t.dependsOn || []).filter((id) =>
          playbookTasks.some((o) => o.id === id),
        ).length;
        return (
          `<div class="pb-task pb-${escAttr(t.status)}${t.blocked ? " pb-blocked" : ""}" data-id="${escAttr(t.id)}" ${canDrag ? 'draggable="true"' : ""}>` +
          `<div class="pb-row1">` +
          `<span class="pb-drag ${canDrag ? "" : "pb-drag-off"}" title="Drag to reorder">⠿</span>` +
          (t.shortId
            ? `<span class="pb-shortid">${esc(t.shortId)}</span>`
            : "") +
          `<select class="pb-status" data-act="pbPatchStatus" data-act-on="change" data-id="${escAttr(t.id)}">${opts}</select>` +
          `<span class="pb-pri pb-pri-${escAttr(t.priority)}">${esc(t.priority)}</span>` +
          `<span class="pb-title">${esc(t.title)}</span>` +
          blockedBadge +
          `<span class="pb-src">${src}</span>${findingLink}` +
          `<span class="pb-move">` +
          `<button data-act="pbMovePrev" data-id="${escAttr(t.id)}" title="Move up">▲</button>` +
          `<button data-act="pbMoveNext" data-id="${escAttr(t.id)}" title="Move down">▼</button>` +
          `<button class="pb-del" data-act="pbDelete" data-id="${escAttr(t.id)}" title="Delete">✕</button>` +
          `</span>` +
          `</div>` +
          desc +
          `<div class="pb-row2">` +
          `<input class="pb-assignee" placeholder="assignee" value="${escAttr(t.assignee || "")}" data-act="pbPatchAssignee" data-act-on="change" data-id="${escAttr(t.id)}" />` +
          `<input class="pb-due" type="date" value="${escAttr(t.dueDate || "")}" data-act="pbPatchDueDate" data-act-on="change" data-id="${escAttr(t.id)}" title="Due date" />` +
          `<button type="button" class="pb-deps-btn" data-act="pbToggleDeps" data-id="${escAttr(t.id)}" title="Set which tasks must be done before this one can start">🔗 depends on${depCount ? ` (${depCount})` : ""}</button>` +
          `</div>` +
          pbDepsPanel(t) +
          renderTaskHunts(t.id) +
          `</div>`
        );
      })
      .join("");
    if (canDrag) pbWireDrag(el);
    pbWireHuntSuggestions(el);
  }

  // Drag-and-drop reorder (mirrors the section-reorder pattern). On drop, persist the new
  // full id order via PATCH …/order, which re-renders from the server's order.
  function pbWireDrag(container) {
    let dragSrc = null;
    container.querySelectorAll(".pb-task").forEach((row) => {
      row.addEventListener("dragstart", (e) => {
        if (e.target.closest(".pbh-card")) {
          e.preventDefault();
          return;
        } // don't drag the task when interacting with its hunt suggestion
        dragSrc = row;
        e.dataTransfer.effectAllowed = "move";
      });
      row.addEventListener("dragover", (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = "move";
        if (row !== dragSrc) {
          container
            .querySelectorAll(".pb-task")
            .forEach((r) => r.classList.remove("drag-over"));
          row.classList.add("drag-over");
        }
      });
      row.addEventListener("dragleave", () =>
        row.classList.remove("drag-over"),
      );
      row.addEventListener("drop", (e) => {
        e.preventDefault();
        row.classList.remove("drag-over");
        if (dragSrc && dragSrc !== row) {
          container.insertBefore(dragSrc, row);
          const ids = [...container.querySelectorAll(".pb-task")].map(
            (r) => r.dataset.id,
          );
          const caseId = pbCaseId();
          if (caseId)
            fetch(`/cases/${caseId}/playbook/order`, {
              method: "PATCH",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ ids }),
            })
              .then(() => loadPlaybook(caseId))
              .catch(() => {});
        }
      });
      row.addEventListener("dragend", () => {
        dragSrc = null;
        container
          .querySelectorAll(".pb-task")
          .forEach((r) => r.classList.remove("drag-over"));
      });
    });
  }

  function pbPatch(id, patch) {
    const caseId = pbCaseId();
    if (!caseId) return;
    fetch(`/cases/${caseId}/playbook/${id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(patch),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok)
          throw new Error(j && j.error ? j.error : "HTTP request failed");
      })
      .then(() => loadPlaybook(caseId))
      .catch((e) => {
        const m = document.getElementById("pbMsg");
        if (m) m.textContent = "failed: " + e.message;
        loadPlaybook(caseId);
      });
  }

  // The collapsible "depends on" checkbox panel for one task — lists every OTHER task so the
  // analyst can pick which must be "done" before this one is considered ready. Empty string
  // when collapsed. Kept minimal (native checkboxes, no fancy widget) to match the rest of the
  // playbook panel's plain-HTML style.
  function pbDepsPanel(t) {
    if (!pbDepsOpen[t.id]) return "";
    const others = playbookTasks.filter((o) => o.id !== t.id);
    if (!others.length)
      return `<div class="pb-deps-panel"><em data-safe-style="color:var(--text-muted);font-size:11px">No other tasks yet.</em></div>`;
    const cur = new Set(t.dependsOn || []);
    const rows = others
      .map(
        (o) =>
          `<label class="pb-dep-opt"><input type="checkbox" ${cur.has(o.id) ? "checked" : ""} data-act="pbToggleDep" data-act-on="change" data-id="${escAttr(t.id)}" data-dep="${escAttr(o.id)}" /> ` +
          `${o.shortId ? esc(o.shortId) + " — " : ""}${esc(o.title)}</label>`,
      )
      .join("");
    return `<div class="pb-deps-panel">${rows}</div>`;
  }

  function pbToggleDeps(id) {
    pbDepsOpen[id] = !pbDepsOpen[id];
    renderPlaybook();
  }

  // Send only dependencies that still name a LIVE task. A stale edge (the dependency's task was
  // deleted) is retained on the server so an auto-derived task re-derived later reconnects — but it
  // is never listed in this picker, and the server rejects any dependsOn naming an unknown id. So
  // resending it made every toggle fail with "unknown task id(s): ..." against an id the analyst
  // cannot see or untick, permanently freezing that task's dependencies. Filtering to live ids keeps
  // the picker WYSIWYG: what's ticked is what gets saved, and the stale edge is pruned as a side
  // effect of the analyst explicitly restating the list.
  function pbToggleDep(id, depId, checked) {
    const t = playbookTasks.find((x) => x.id === id);
    const live = new Set(playbookTasks.map((x) => x.id));
    const cur = new Set(((t && t.dependsOn) || []).filter((d) => live.has(d)));
    if (checked) cur.add(depId);
    else cur.delete(depId);
    pbPatch(id, { dependsOn: [...cur] });
  }

  function pbDelete(id) {
    const caseId = pbCaseId();
    if (!caseId) return;
    fetch(`/cases/${caseId}/playbook/${id}`, { method: "DELETE" })
      .then(() => loadPlaybook(caseId))
      .catch(() => {});
  }

  function pbMove(id, dir) {
    const ids = playbookTasks.map((t) => t.id);
    const i = ids.indexOf(id);
    if (i < 0) return;
    const j = i + dir;
    if (j < 0 || j >= ids.length) return;
    [ids[i], ids[j]] = [ids[j], ids[i]];
    const caseId = pbCaseId();
    if (!caseId) return;
    fetch(`/cases/${caseId}/playbook/order`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ids }),
    })
      .then(() => loadPlaybook(caseId))
      .catch(() => {});
  }

  function pbJumpFinding() {
    const sec = document.getElementById("sec-findings");
    if (sec) {
      sec.classList.remove("collapsed");
      sec.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  // ── Suggested Velociraptor hunts for the playbook (#70) ───────────────────────────────
  // AI-proposed Velociraptor hunt per ENDPOINT-related playbook task. On-demand (an AI call): the
  // analyst clicks "Suggest Velociraptor hunts" and each suggestion renders INLINE under its own
  // task as a COLLAPSIBLE card showing the deploy mode the server picked (🌐 fleet hunt vs 🎯
  // collection on one host) + the editable VQL. One-click deploys — a fleet hunt via launchHuntInto()
  // (POST /velociraptor/hunt) or a single-endpoint collection via collectHostInto()
  // (POST /velociraptor/collect-host). Ephemeral; the suggestions live in pbHuntFlat and are
  // re-rendered by renderPlaybook() so they survive task-list re-renders.
  function resetPlaybookHuntSuggest() {
    pbHuntFlat = [];
    pbHuntCollapsed = {};
    const msg = document.getElementById("pbHuntMsg");
    if (msg) msg.textContent = "";
  }

  function doSuggestPlaybookHunts() {
    const caseId = pbCaseId();
    if (!caseId) return;
    const btn = document.getElementById("pbHuntBtn");
    const msg = document.getElementById("pbHuntMsg");
    if (btn) btn.disabled = true;
    if (msg) {
      msg.style.color = "var(--text-muted)";
      msg.textContent = "thinking… (only new / changed tasks are sent)";
    }
    fetch(`/cases/${caseId}/playbook/suggest-hunts`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          if (msg) {
            msg.style.color = "var(--sev-high)";
            msg.textContent =
              "error: " +
              (j.error || "could not generate hunts") +
              " — restart the companion server if this 404s";
          }
          return;
        }
        const sugs = j.suggestions || [];
        pbHuntFlat = [...sugs].sort(
          (a, b) =>
            (VHS_SEV_RANK[a.severity] ?? 9) - (VHS_SEV_RANK[b.severity] ?? 9),
        );
        pbHuntCollapsed = {};
        renderPlaybook(); // re-render the task list with the suggestions inlined under their tasks
        if (msg) {
          msg.style.color = "var(--text-muted)";
          const newN = typeof j.generated === "number" ? j.generated : null;
          const more = j.more ? " · press again for more" : "";
          msg.textContent = pbHuntFlat.length
            ? newN === 0
              ? `${pbHuntFlat.length} suggestion(s) — nothing new to generate`
              : `${newN != null ? newN + " new · " : ""}${pbHuntFlat.length} total — shown under their tasks${more}`
            : "no endpoint-related tasks to hunt for (sync the playbook or add evidence)";
        }
      })
      .catch((e) => {
        if (msg) {
          msg.style.color = "var(--sev-high)";
          msg.textContent = "error: " + e.message;
        }
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }

  // The collapsible suggestion card(s) for one playbook task — empty string when the task has none.
  // Keyed by the suggestion's index in pbHuntFlat so ids stay stable across renderPlaybook() calls.
  function renderTaskHunts(taskId) {
    const items = [];
    pbHuntFlat.forEach((s, idx) => {
      if (s.taskId === taskId) items.push({ s, idx });
    });
    if (!items.length) return "";
    // PlaybookHuntSuggestion (playbookHunt.ts) has NO relatedFindingIds field of its own — unlike
    // huntSuggest.ts's HuntSuggestion (the sibling fleet-hunt panel). Every suggestion in THIS call
    // belongs to the same enclosing task, so derive the citation from that task's own (singular)
    // relatedFindingId, set when the task was auto-derived from a Critical/High finding (#222).
    const _pbhTask = playbookTasks.find((t) => t.id === taskId);
    const _pbhFindingIds =
      _pbhTask && _pbhTask.relatedFindingId ? [_pbhTask.relatedFindingId] : [];
    return items
      .map(({ s, idx }) => {
        const sev = s.severity || "Medium";
        const sevColor = VHS_SEV_COLOR[sev] || "#9aa4b2";
        const sevBadge = `<span class="pbh-sev" data-safe-style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}55">${esc(sev)}</span>`;
        const isCollection = s.mode === "collection" && s.targetHost;
        const modeBadge = isCollection
          ? `<span class="pbh-mode pbh-mode-collection">🎯 collection on ${esc(s.targetHost)}</span>`
          : `<span class="pbh-mode pbh-mode-hunt">🌐 fleet hunt</span>`;
        const collapsed = !!pbHuntCollapsed[idx];
        const techs = (s.mitreTechniques || [])
          .map((t) => {
            const u = attackUrl(t);
            return u
              ? `<a href="${escAttr(u)}" target="_blank" rel="noopener" class="pbh-tech">${esc(t)}</a>`
              : `<span class="pbh-tech">${esc(t)}</span>`;
          })
          .join("");
        const rationale = s.rationale
          ? `<div class="pbh-rationale">${esc(s.rationale)}</div>`
          : "";
        const cites = citeFindings(_pbhFindingIds);
        const deployLabel = isCollection
          ? `▶ Collect on ${esc(s.targetHost)}`
          : "▶ Deploy hunt (all clients)";
        const deployTitle = isCollection
          ? `Run this VQL as a collection on ${escAttr(s.targetHost)} only`
          : "Launch this hunt across ALL enrolled Velociraptor clients";
        const deployBtn = veloEnabled
          ? `<button class="pbh-deploy" data-idx="${idx}" title="${deployTitle}">${deployLabel}</button>`
          : `<button class="pbh-deploy" disabled title="Velociraptor API not configured — set the API config path in Settings → Integrations, then restart the server">${deployLabel}</button>`;
        const veloNote = veloEnabled
          ? ""
          : `<div class="pbh-caveat">⚠ Velociraptor API not configured — Deploy is disabled; copy the VQL to run it yourself.</div>`;
        return (
          `<div class="pbh-card" data-idx="${idx}" draggable="false">` +
          `<div class="pbh-head pbh-toggle">` +
          `<span class="pbh-caret">${collapsed ? "▸" : "▾"}</span>` +
          `<span class="pbh-flag">✨ Velociraptor</span>` +
          modeBadge +
          sevBadge +
          `<span class="pbh-title">${esc(s.title)}</span>` +
          `</div>` +
          `<div class="pbh-body" ${collapsed ? 'data-safe-style="display:none"' : ""}>` +
          rationale +
          (cites
            ? `<div class="pbh-rationale" data-safe-style="color:var(--text-muted)">Cites: ${cites}</div>`
            : "") +
          (techs ? `<div class="pbh-techs">${techs}</div>` : "") +
          `<textarea class="pbh-vql" id="pbhQ${idx}" spellcheck="false">${esc(s.vql)}</textarea>` +
          `<div class="pbh-actions"><button class="pbh-copy" data-idx="${idx}">Copy VQL</button>${deployBtn}<button class="pbh-regen" data-idx="${idx}" title="Generate a different VQL for this task approaching from a different angle">🔄 Regenerate</button></div>` +
          veloNote +
          `<div class="pbh-res" id="pbhRes${idx}"></div>` +
          `</div>` +
          `</div>`
        );
      })
      .join("");
  }

  // Wire the inline suggestion cards' collapse toggle + copy/deploy handlers after each renderPlaybook().
  function pbWireHuntSuggestions(container) {
    container.querySelectorAll(".pbh-toggle").forEach(
      (h) =>
        (h.onclick = (e) => {
          e.stopPropagation();
          const card = h.closest(".pbh-card");
          if (!card) return;
          const idx = card.dataset.idx;
          const body = card.querySelector(".pbh-body");
          const caret = h.querySelector(".pbh-caret");
          const nowCollapsed = body.style.display !== "none";
          body.style.display = nowCollapsed ? "none" : "";
          if (caret) caret.textContent = nowCollapsed ? "▸" : "▾";
          pbHuntCollapsed[idx] = nowCollapsed;
        }),
    );
    container.querySelectorAll(".pbh-copy").forEach(
      (b) =>
        (b.onclick = (e) => {
          e.stopPropagation();
          const q = document.getElementById("pbhQ" + b.dataset.idx);
          navigator.clipboard
            .writeText(q ? q.value : "")
            .then(() => {
              b.textContent = "Copied ✓";
              b.classList.add("copied");
              setTimeout(() => {
                b.textContent = "Copy VQL";
                b.classList.remove("copied");
              }, 1500);
            })
            .catch(() => {
              b.textContent = "copy failed";
            });
        }),
    );
    container.querySelectorAll(".pbh-deploy:not([disabled])").forEach(
      (b) =>
        (b.onclick = (e) => {
          e.stopPropagation();
          const idx = b.dataset.idx;
          const s = pbHuntFlat[idx];
          if (!s) return;
          const q = document.getElementById("pbhQ" + idx);
          const vql = q ? q.value : "";
          const desc = s.title || "DFIR playbook hunt";
          const res = document.getElementById("pbhRes" + idx);
          const ctx = {
            caseId: pbCaseId(),
            title: s.title || "DFIR playbook hunt",
            source: "playbook",
            mitre: s.mitreTechniques || [],
          }; // #157 record the deploy
          if (s.mode === "collection" && s.targetHost)
            collectHostInto(s.targetHost, vql, desc, res, b, ctx);
          else launchHuntInto(vql, desc, res, b, ctx);
        }),
    );
    container.querySelectorAll(".pbh-regen").forEach(
      (b) =>
        (b.onclick = (e) => {
          e.stopPropagation();
          const caseId = pbCaseId();
          if (!caseId) return;
          const idx = b.dataset.idx;
          const s = pbHuntFlat[idx];
          if (!s) return;
          const q = document.getElementById("pbhQ" + idx);
          const excludeVql = q ? q.value : s.vql;
          const origText = b.textContent;
          b.textContent = "⏳ thinking…";
          b.disabled = true;
          fetch(`/cases/${caseId}/playbook/suggest-hunts`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ taskId: s.taskId, excludeVql }),
          })
            .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
            .then(({ ok, j }) => {
              if (!ok || j.error) {
                const msg = document.getElementById("pbHuntMsg");
                if (msg) {
                  msg.style.color = "var(--sev-high)";
                  msg.textContent =
                    "regen failed: " + (j.error || "unknown error");
                }
                return;
              }
              const sugs = j.suggestions || [];
              pbHuntFlat = [...sugs].sort(
                (a, b) =>
                  (VHS_SEV_RANK[a.severity] ?? 9) -
                  (VHS_SEV_RANK[b.severity] ?? 9),
              );
              renderPlaybook();
            })
            .catch((err) => {
              const msg = document.getElementById("pbHuntMsg");
              if (msg) {
                msg.style.color = "var(--sev-high)";
                msg.textContent = "regen failed: " + err.message;
              }
            })
            .finally(() => {
              b.disabled = false;
              b.textContent = origText;
            });
        }),
    );
  }

  // The four controls the old block wired at the bottom of the inline script. Order unchanged.
  function initPlaybook() {
    document.getElementById("pbAddBtn").onclick = function () {
      const caseId = pbCaseId();
      const title = document.getElementById("pbTitle").value.trim();
      const priority = document.getElementById("pbPriority").value;
      const msg = document.getElementById("pbMsg");
      if (!caseId || !title) {
        if (msg) msg.textContent = "title required";
        return;
      }
      if (msg) msg.textContent = "adding…";
      fetch(`/cases/${caseId}/playbook`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ title, priority }),
      })
        .then((r) => {
          if (!r.ok) throw new Error("HTTP " + r.status);
          return r.json();
        })
        .then(() => {
          document.getElementById("pbTitle").value = "";
          if (msg) msg.textContent = "";
          loadPlaybook(caseId);
        })
        .catch((e) => {
          if (msg) msg.textContent = "failed: " + e.message;
        });
    };

    document.getElementById("pbSyncBtn").onclick = function () {
      const caseId = pbCaseId();
      if (!caseId) return;
      const msg = document.getElementById("pbMsg");
      if (msg) msg.textContent = "syncing…";
      fetch(`/cases/${caseId}/playbook/sync`, { method: "POST" })
        .then((r) => {
          if (!r.ok) throw new Error("HTTP " + r.status);
          return r.json();
        })
        .then(() => {
          if (msg) msg.textContent = "";
          loadPlaybook(caseId);
        })
        .catch((e) => {
          if (msg)
            msg.textContent =
              "sync failed (restart the companion server?): " + e.message;
        });
    };

    document
      .getElementById("pbOpenOnly")
      .addEventListener("change", function () {
        pbOpenOnly = this.checked;
        renderPlaybook();
      });

    document
      .getElementById("pbTemplates")
      .addEventListener("change", function () {
        const caseId = pbCaseId();
        if (!caseId) {
          this.checked = !this.checked;
          return;
        }
        const msg = document.getElementById("pbMsg");
        if (msg) msg.textContent = "applying…";
        fetch(`/cases/${caseId}/playbook/control`, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ useTemplates: this.checked }),
        })
          .then((r) => {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
          })
          .then(() => {
            if (msg) msg.textContent = "";
            loadPlaybook(caseId);
          })
          .catch((e) => {
            this.checked = !this.checked;
            if (msg)
              msg.textContent =
                "failed (restart the companion server?): " + e.message;
          });
      });
  }

  window.loadPlaybook = loadPlaybook;
  window.pbPatch = pbPatch;
  window.pbDelete = pbDelete;
  window.pbMove = pbMove;
  window.pbToggleDep = pbToggleDep;
  window.pbToggleDeps = pbToggleDeps;
  window.pbJumpFinding = pbJumpFinding;
  window.doSuggestPlaybookHunts = doSuggestPlaybookHunts;
  window.resetPlaybookHuntSuggest = resetPlaybookHuntSuggest;
  window.initPlaybook = initPlaybook;
})();
