// Inline IOC quick-actions (#221) — extracted from dashboard.html (issue #415, tier 3).
//
// A detected value in an event description becomes a clickable target; the tray offers copy /
// mark-benign / mark-confirmed-malicious / suggest-hunt.
//
// qaAuditMark() is published because the mark is a PROTOCOL, not private state: this module writes it at
// the head of every audit comment, and render() — page core machinery — reads it to pick those
// comments out for the Investigation Log. The reader keeps a literal fallback, deliberately: if this
// module ever fails to load, the quick-action buttons go away, but audit lines already recorded in a
// case must still appear in the log. A stub may replace work; never evidence.
(function () {
  "use strict";

  // A detected value inside an event description — or an IOC value — becomes a clickable target
  // (.qa-val); clicking it opens a small floating tray anchored below it with copy / mark-benign /
  // mark-confirmed-malicious / suggest-hunt. It REUSES the existing false-positive modal + tag /
  // hunt / comment routes (no new backend), and records each outcome to the investigation log via
  // a best-effort comment. Detection is client-side so it also works on values that never became a
  // structured IOC (a SID / path buried in a command line).
  // Matchers are tried most-specific-first so an IP inside a URL, or a path, wins over a looser hit.
  const QA_MATCHERS = [
    ["url", /\bhttps?:\/\/[^\s"'<>|)]+/gi],
    ["path", /\b[A-Za-z]:\\[^\s"'<>|]+|\\\\[^\s"'<>|]+/g],
    ["sid", /\bS-1-\d{1,2}(?:-\d{1,10}){1,15}\b/gi],
    ["hash", /\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi],
    ["ip", /\b\d{1,3}(?:\.\d{1,3}){3}\b/g],
    ["domain", /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi],
  ];
  // A "domain" that is really a filename (evil.exe, report.json) — keep it plain, not clickable.
  const QA_FILE_EXT =
    /\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|jar|sh|bin|conf|log|txt|json|xml|ya?ml|cfg|ini|py|pl|so|gz|tar|zip|7z|rar|tmp|bak|dat|pid|sock|key|pem|crt|docx?|xlsx?|pdf|png|jpe?g|gif)$/i;

  // Escape `rawText`, but wrap detected values in clickable .qa-val spans. Truncated to the same
  // limit as descHtml so a linkified title reads identically to a plain one. Operates on the RAW
  // string (esc()-ing the gaps itself) so an entity like &amp; can never land inside a data-val.
  function qaLinkify(rawText, ctx) {
    const text = truncate(
      String(rawText == null ? "" : rawText),
      DESC_TITLE_LIMIT,
    );
    const claims = [];
    const overlaps = (s, e) => claims.some((c) => s < c.end && e > c.start);
    for (const [type, re] of QA_MATCHERS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const val = m[0];
        if (!val) {
          re.lastIndex++;
          continue;
        }
        const s = m.index,
          e = s + val.length;
        if (overlaps(s, e)) continue;
        if (type === "domain" && QA_FILE_EXT.test(val)) continue; // a filename, not a domain
        claims.push({ start: s, end: e, type, val });
      }
    }
    if (!claims.length) return esc(text);
    claims.sort((a, b) => a.start - b.start);
    let out = "",
      pos = 0;
    for (const c of claims) {
      if (c.start < pos) continue;
      out += esc(text.slice(pos, c.start)) + qaSpan(c.type, c.val, ctx);
      pos = c.end;
    }
    return out + esc(text.slice(pos));
  }

  let qaTrayEl = null; // the floating tray element while open
  let qaCur = null; // { val, vtype, evid, iocid } for the value the tray is acting on
  const qaCaseId = () => document.getElementById("caseId").value.trim();
  function qaCloseTray() {
    if (qaTrayEl) {
      qaTrayEl.remove();
      qaTrayEl = null;
    }
    qaCur = null;
  }

  function qaOpenTray(anchor) {
    qaCloseTray();
    const val = anchor.getAttribute("data-val") || "";
    if (!val) return;
    qaCur = {
      val,
      vtype: anchor.getAttribute("data-vtype") || "other",
      evid: anchor.getAttribute("data-evid"),
      iocid: anchor.getAttribute("data-iocid"),
    };
    const tray = document.createElement("div");
    tray.className = "qa-tray";
    tray.innerHTML =
      `<span class="qa-head" title="${escAttr(qaCur.vtype + ": " + val)}">${esc(qaCur.vtype)}</span>` +
      `<button type="button" data-qa="copy" title="Copy value to clipboard">📋 Copy</button>` +
      `<button type="button" class="qa-ben" data-qa="benign" title="Mark this value a false positive (benign) — opens the reason picker">🚫 Benign</button>` +
      `<button type="button" class="qa-mal" data-qa="malicious" title="Tag this value confirmed-malicious">⚠ Malicious</button>` +
      `<button type="button" data-qa="hunt" title="Generate hunt / pivot queries">🔍 Hunt</button>`;
    tray.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-qa]");
      if (!b) return;
      e.stopPropagation();
      qaAction(b.getAttribute("data-qa"), b);
    });
    document.body.appendChild(tray);
    const r = anchor.getBoundingClientRect();
    const top = r.bottom + window.scrollY + 4;
    const maxLeft =
      window.scrollX +
      document.documentElement.clientWidth -
      tray.offsetWidth -
      8;
    const left = Math.max(
      window.scrollX + 8,
      Math.min(r.left + window.scrollX, maxLeft),
    );
    tray.style.left = left + "px";
    tray.style.top = top + "px";
    qaTrayEl = tray;
  }

  // Resolve a clicked value to its tracked IOC id (so tags/comments key consistently with how the
  // IOC panel renders them); fall back to the raw value when it isn't a tracked IOC.
  function qaResolveIocId(val, iocid) {
    if (iocid) return iocid;
    const m = (
      (DfirState.lastState() && DfirState.lastState().iocs) ||
      []
    ).find((i) => String(i.value).toLowerCase() === String(val).toLowerCase());
    return (m && m.id) || val;
  }

  // A quick-action outcome is recorded as a durable comment (comments survive synthesis, unlike
  // state.timeline which the benign-mark re-synthesis would race). It carries this leading mark so
  // render() can surface it in the Investigation Log panel — where the analyst looks for it.
  const QA_AUDIT_MARK = "⚑";
  // An accessor, not the bare constant: the published surface is callables, and a reader that has to
  // cope with this module being absent can then guard with `typeof ... === "function"`.
  function qaAuditMark() {
    return QA_AUDIT_MARK;
  }
  function qaAudit(caseId, targetType, targetId, text) {
    if (!caseId) return;
    fetch(`/cases/${caseId}/comments`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        targetType,
        targetId,
        text: `${QA_AUDIT_MARK} ${text}`,
        author: investigatorName(),
      }),
    })
      .then((r) => {
        if (r.ok) loadComments(caseId);
      })
      .catch(() => {});
  }

  function qaAction(kind, btn) {
    if (!qaCur) return;
    const { val, evid, iocid } = qaCur;
    const caseId = qaCaseId();
    if (kind === "copy") {
      navigator.clipboard
        .writeText(val)
        .then(() => {
          btn.textContent = "✓ Copied";
          btn.classList.add("qa-copied");
          setTimeout(qaCloseTray, 900);
        })
        .catch(() => {
          btn.textContent = "copy failed";
        });
      return;
    }
    if (!caseId) {
      qaCloseTray();
      return;
    }
    if (kind === "benign") {
      qaCloseTray();
      // Reuse the #227 reason-capture modal (records a reversible marker = the audit trail); on
      // confirm, drop a narrative line into the Investigation Log, keyed to the IOC.
      const rid = qaResolveIocId(val, iocid);
      openFalsePositiveModal("ioc", val, val, [], () =>
        qaAudit(caseId, "ioc", rid, `marked benign (false positive): ${val}`),
      );
      return;
    }
    if (kind === "malicious") {
      // IOC tags render keyed by the IOC *id* (tagPills("ioc", i.id)), NOT the value — so key the
      // tag the same way or the red pill never shows and the action looks like it did nothing.
      // Resolve the clicked value to its tracked IOC id (an IOC-row click already carries it; an
      // event-description value is looked up by value); fall back to the raw value otherwise.
      const iocs = (DfirState.lastState() && DfirState.lastState().iocs) || [];
      const match = iocs.find(
        (i) => String(i.value).toLowerCase() === String(val).toLowerCase(),
      );
      const targetId = iocid || (match && match.id) || val;
      const tracked = !!(iocid || match);
      btn.disabled = true;
      btn.textContent = "…";
      fetch(`/cases/${caseId}/tags`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          targetType: "ioc",
          targetId,
          label: "confirmed-malicious",
          author: investigatorName(),
        }),
      })
        .then((r) => {
          if (!r.ok) throw new Error("HTTP " + r.status);
          return r.json();
        })
        .then(() => {
          btn.textContent = "✓ tagged";
          btn.classList.add("qa-copied");
          loadTags(caseId); // repaints the IOC row with the red confirmed-malicious pill
          qaAudit(
            caseId,
            "ioc",
            targetId,
            `marked confirmed-malicious: ${val}`,
          );
          document.getElementById("status").textContent = tracked
            ? `tagged “${val}” confirmed-malicious — red pill now on its IOC row`
            : `recorded “${val}” confirmed-malicious (not a tracked IOC — logged as a note)`;
          setTimeout(qaCloseTray, 700);
        })
        .catch(() => {
          btn.textContent = "failed";
          document.getElementById("status").textContent =
            "tag failed — restart the companion server.";
        });
      return;
    }
    if (kind === "hunt") {
      qaCloseTray();
      // The hunt builder harvests every indicator from the owning entity; scope to the IOC when the
      // value is an IOC row, else to the event the value was found in.
      if (iocid) openHuntModal("ioc", iocid);
      else if (evid) openHuntModal("event", evid);
      return;
    }
  }

  // Open the tray on a .qa-val click; close it on any outside click / Escape / resize.

  // The tray opens on a .qa-val click and closes on any outside click / Escape / resize. All three
  // bind to document/window, so they are initializer work — in a <head> script they would run before
  // the page has a body to receive the events.
  function initIocQuickActions() {
    document.addEventListener("click", (e) => {
      const anchor = e.target.closest && e.target.closest(".qa-val");
      if (anchor) {
        e.stopPropagation();
        qaOpenTray(anchor);
        return;
      }
      if (qaTrayEl && !(e.target.closest && e.target.closest(".qa-tray")))
        qaCloseTray();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") qaCloseTray();
    });
    window.addEventListener("resize", qaCloseTray);
  }

  window.qaAudit = qaAudit;
  window.qaLinkify = qaLinkify;
  window.qaResolveIocId = qaResolveIocId;
  window.qaAuditMark = qaAuditMark;
  window.initIocQuickActions = initIocQuickActions;
})();
