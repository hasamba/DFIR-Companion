// Pinned findings (#220) — the strip of findings an analyst has pinned, reorderable by drag
// (#415 tier 3).
//
// It sat under the "Finding assignment + workflow status (#87)" banner, which named only the
// feature above it. Nothing here references that one and nothing there references this.
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: whether a drag is in flight, the signature of the
// last-rendered strip, and the message timer.
//
// NO INITIALIZER: the drag handlers are attached by wirePinnedDrag() each time the strip is
// re-rendered, because the rows it binds are recreated every time.
(function () {
  // Resolve pins against the live findings, worst-severity label preserved. A pin whose finding
  // no longer exists (dropped by a later synthesis) is skipped — the raw pin stays on the server
  // so it reappears if the finding comes back, but it isn't rendered as a dangling row.
  let pinDragActive = false; // true while a drag is in flight — don't rebuild the DOM under it
  let _pinnedSig = null; // signature of the last-rendered strip, to skip no-op rebuilds
  function renderPinned() {
    const el = document.getElementById("pinnedList");
    const countEl = document.getElementById("pinnedCount");
    if (!el) return;
    // Never rebuild the strip DOM mid-drag: render() fires often (every state/tags/comments
    // refresh), and replacing innerHTML under an in-progress drag cancels the browser's drag
    // gesture — the #1 cause of "can't reorder". The dragend handler re-renders once settled.
    if (pinDragActive) return;
    const byId = new Map(
      (DfirState.lastState() && DfirState.lastState().findings
        ? DfirState.lastState().findings
        : []
      ).map((f) => [String(f.id), f]),
    );
    const rows = pinnedList
      .map((p) => ({ pin: p, f: byId.get(String(p.findingId)) }))
      .filter((x) => x.f);
    if (countEl)
      countEl.textContent = rows.length
        ? ` (${rows.length} of ${pinLimit})`
        : "";
    // Skip the rebuild when nothing visible changed (same ids/order/severity/title) so frequent
    // render() calls don't needlessly thrash the DOM (and can't clobber a just-started drag).
    const sig = rows
      .map(({ f }) => `${f.id}|${f.severity}|${f.title}`)
      .join("~~");
    if (sig === _pinnedSig && el.querySelector(".pinned-item")) return;
    _pinnedSig = sig;
    if (!rows.length) {
      el.innerHTML = `<div class="pinned-empty">No findings pinned yet — click 📌 on a finding to keep it here.</div>`;
      return;
    }
    el.innerHTML = rows
      .map(
        ({ pin, f }) =>
          `<div class="pinned-item" data-fid="${escAttr(String(f.id))}">` +
          `<span class="pinned-grip" title="Drag to reorder">⠿</span>` +
          `<span class="sev-${esc(f.severity)}">[${esc(f.severity)}]</span>` +
          `<span class="pinned-title" data-jump="${escAttr(String(f.id))}" title="Jump to this finding">` +
          `<span data-safe-style="color:var(--accent)">${esc(f.id)}</span> ${esc(f.title)}</span>` +
          `<button class="pinned-unpin" data-unpin="${escAttr(String(f.id))}" title="Unpin">✕</button></div>`,
      )
      .join("");
    wirePinnedDrag();
  }

  function togglePin(fid) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !fid) return;
    const id = String(fid);
    if (pinnedSet.has(id)) {
      fetch(`/cases/${caseId}/pinned-findings/${encodeURIComponent(id)}`, {
        method: "DELETE",
      })
        .then((r) => r.json())
        .then(applyPinResponse)
        .catch(() => {});
    } else {
      fetch(`/cases/${caseId}/pinned-findings`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ findingId: id, pinnedBy: investigatorName() }),
      })
        .then(async (r) => {
          if (r.status === 409) {
            const b = await r.json().catch(() => ({}));
            flashPinMsg(
              `Pin limit reached (max ${b.limit || pinLimit}) — unpin one first`,
            );
            return null;
          }
          return r.json();
        })
        .then((d) => {
          if (d) applyPinResponse(d);
        })
        .catch(() => {});
    }
  }
  // Briefly show a message in the strip header (e.g. the cap-reached notice), then restore the count.
  let pinMsgTimer = null;
  function flashPinMsg(text) {
    const sec = document.getElementById("sec-findings");
    if (sec) sec.classList.remove("collapsed"); // make sure the strip is visible to read it
    const countEl = document.getElementById("pinnedCount");
    if (!countEl) return;
    countEl.textContent = " — " + text;
    countEl.style.color = "var(--sev-medium)";
    if (pinMsgTimer) clearTimeout(pinMsgTimer);
    pinMsgTimer = setTimeout(() => {
      countEl.style.color = "";
      renderPinned();
    }, 3500);
  }
  // Apply a mutation response ({pins, limit}) locally so the UI updates instantly; the WS
  // pins_changed broadcast will also arrive and reconcile (idempotent).
  function applyPinResponse(data) {
    if (!data) return;
    pinnedList = Array.isArray(data.pins) ? data.pins : pinnedList;
    pinnedSet = new Set(pinnedList.map((p) => String(p.findingId)));
    if (typeof data.limit === "number") pinLimit = data.limit;
    renderPinned();
    if (DfirState.lastState()) render(DfirState.lastState());
  }

  // Drag-to-reorder within the strip — POINTER-based, NOT native HTML5 drag-and-drop. Native DnD
  // proved unreliable to initiate here (the gesture never started for the analyst), so we drive it
  // with pointerdown/move/up which we fully control: press anywhere on a row (except the jump title
  // / unpin ✕, which stay clickable) and drag it up or down; rows shuffle live and the new order is
  // persisted on release. Testable with synthetic pointer events, unlike native DnD.
  function wirePinnedDrag() {
    const el = document.getElementById("pinnedList");
    if (!el) return;
    el.querySelectorAll(".pinned-item").forEach((item) => {
      item.addEventListener("pointerdown", (e) => {
        if (e.button !== 0 && e.pointerType === "mouse") return; // primary mouse button only
        if (
          e.target.closest(".pinned-title") ||
          e.target.closest(".pinned-unpin")
        )
          return; // let jump/unpin click
        e.preventDefault();
        startPinDrag(item, el, e);
      });
    });
  }
  // Live pointer-drag of one row. Moves the row in the DOM as the pointer passes each neighbour's
  // midpoint (so the layout previews the result), then persists the DOM order on release.
  // CRITICAL: the pointermove/up/cancel listeners live on DOCUMENT, not the row. setPointerCapture
  // isn't guaranteed to route moves to the row in every Chromium build (Comet included) — when it
  // doesn't, moves fire on whatever element is under the cursor, so a row-scoped listener never sees
  // them and the row highlights but won't budge. document always sees every pointer move. Capture is
  // kept only as a bonus (lets pointerup land even if the cursor leaves the window).
  function startPinDrag(item, el, downEvt) {
    pinDragActive = true; // freeze renderPinned() so a background refresh can't yank the row
    item.classList.add("dragging");
    const pid = downEvt.pointerId;
    let moved = false;
    try {
      item.setPointerCapture(pid);
    } catch {}
    const onMove = (e) => {
      if (e.pointerId !== pid) return;
      moved = true;
      const rows = [...el.querySelectorAll(".pinned-item")];
      const y = e.clientY;
      let placed = false;
      for (const other of rows) {
        if (other === item) continue;
        const r = other.getBoundingClientRect();
        if (y < r.top + r.height / 2) {
          el.insertBefore(item, other);
          placed = true;
          break;
        }
      }
      if (!placed) el.appendChild(item); // past the last midpoint → drop at the end
    };
    const finish = (commit) => {
      document.removeEventListener("pointermove", onMove, true);
      document.removeEventListener("pointerup", onUp, true);
      document.removeEventListener("pointercancel", onCancel, true);
      try {
        item.releasePointerCapture(pid);
      } catch {}
      item.classList.remove("dragging");
      pinDragActive = false;
      if (commit && moved) {
        const order = [...el.querySelectorAll(".pinned-item")].map((i) =>
          i.getAttribute("data-fid"),
        );
        persistPinOrder(order);
      } else {
        _pinnedSig = null;
        renderPinned(); // no move (or cancelled) → restore the clean layout
      }
    };
    const onUp = (e) => {
      if (e.pointerId === pid) finish(true);
    };
    const onCancel = (e) => {
      if (e.pointerId === pid) finish(false);
    };
    document.addEventListener("pointermove", onMove, true);
    document.addEventListener("pointerup", onUp, true);
    document.addEventListener("pointercancel", onCancel, true);
  }
  // Persist a new pinned order. Optimistic: reorder the local list + re-render instantly, then PUT;
  // applyPinResponse reconciles with the server and the pins_changed WS broadcast syncs other clients.
  function persistPinOrder(order) {
    const byId = new Map(pinnedList.map((p) => [String(p.findingId), p]));
    pinnedList = order.map((id) => byId.get(id)).filter(Boolean);
    pinnedSet = new Set(pinnedList.map((p) => String(p.findingId)));
    _pinnedSig = null;
    renderPinned(); // settle: rebuild once against the new order
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    fetch(`/cases/${caseId}/pinned-findings/order`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ order }),
    })
      .then((r) => r.json())
      .then(applyPinResponse)
      .catch(() => {});
  }

  window.renderPinned = renderPinned;
  window.togglePin = togglePin;
})();
