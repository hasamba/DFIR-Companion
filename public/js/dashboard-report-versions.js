// Report versions: diff & rollback (#77) — the report's version list, its review workflow and the
// side-by-side diff between any two versions (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the review mode, the reviewer list and the released-version
// list. This is a CLASSIC script, so an unwrapped top-level `let` would join the shared global
// lexical environment and be reachable by name from every other script on the page.
//
// ITS WIRING IS AN INITIALIZER, and the block itself contains none — the three controls (Diff,
// Cancel, and the overlay backdrop) were bound in the page's shared modal-wiring block, several
// hundred lines away. Left there, the page would hold two bare references to this file evaluated at
// load, and a 404 would be a ReferenceError before the WebSocket connects rather than one dead
// modal. That is the same trap Health / Diagnostics hit: a block that wires nothing is not the same
// as a feature nothing wires.
(function () {
  // ── Report versions: diff & rollback (#77) ────────────────────────────────
  function openReportVersions() {
    document.getElementById("rvMsg").textContent = "";
    document.getElementById("rvDiffResult").innerHTML = "";
    document.getElementById("reportVersionsOverlay").classList.add("open");
    loadReportVersions();
  }
  function closeReportVersions() {
    document.getElementById("reportVersionsOverlay").classList.remove("open");
  }

  let rvReviewMode = "solo";
  let rvReviewers = [];
  let rvReleased = [];

  function rvVersionActions(version) {
    const workflow = version.workflow || { status: "draft", annotations: [] };
    const restore = `<button data-restore="${escAttr(version.id)}" data-safe-style="font-size:11px">Restore meta</button>`;
    if (workflow.status === "draft" && rvReviewMode === "solo") {
      return `${restore}<button data-rv-self-approve="${escAttr(version.id)}" data-safe-style="font-size:11px">Self-review &amp; approve</button>`;
    }
    if (workflow.status === "draft") {
      const choices = rvReviewers
        .map(
          (r) =>
            `<option value="${escAttr(r.id)}">${esc(r.displayName)} (${esc(r.role)})</option>`,
        )
        .join("");
      return choices
        ? `${restore}<select data-rv-reviewer="${escAttr(version.id)}" data-safe-style="font-size:11px;max-width:170px">${choices}</select><button data-rv-submit="${escAttr(version.id)}" data-safe-style="font-size:11px">Submit</button>`
        : `${restore}<span data-safe-style="color:var(--sev-medium)">No reviewer assigned to this case</span>`;
    }
    if (workflow.status === "peer-review") {
      return `${restore}<button data-rv-note="${escAttr(version.id)}" data-safe-style="font-size:11px">Add review note</button><button data-rv-changes="${escAttr(version.id)}" data-safe-style="font-size:11px">Request changes</button><button data-rv-approve="${escAttr(version.id)}" data-safe-style="font-size:11px">Approve</button>`;
    }
    if (workflow.status === "approved") {
      return `${restore}<button data-rv-release="${escAttr(version.id)}" data-safe-style="font-size:11px">Release frozen snapshot</button>`;
    }
    const releaseId = workflow.releaseId || "";
    return releaseId
      ? `<a href="/cases/${encodeURIComponent(document.getElementById("caseId").value.trim())}/report-releases/${encodeURIComponent(releaseId)}/packs/technical">Technical</a> · <a href="/cases/${encodeURIComponent(document.getElementById("caseId").value.trim())}/report-releases/${encodeURIComponent(releaseId)}/packs/executive">Executive</a> · <a href="/cases/${encodeURIComponent(document.getElementById("caseId").value.trim())}/report-releases/${encodeURIComponent(releaseId)}/packs/legal">Legal/insurance</a> · <a href="/cases/${encodeURIComponent(document.getElementById("caseId").value.trim())}/report-releases/${encodeURIComponent(releaseId)}/packs/ioc">IOCs</a>`
      : restore;
  }

  function rvWireActions() {
    const list = document.getElementById("rvList");
    list
      .querySelectorAll("[data-restore]")
      .forEach(
        (btn) =>
          (btn.onclick = () => doRestoreReportVersion(btn.dataset.restore)),
      );
    list
      .querySelectorAll("[data-rv-self-approve]")
      .forEach(
        (btn) => (btn.onclick = () => rvSelfApprove(btn.dataset.rvSelfApprove)),
      );
    list
      .querySelectorAll("[data-rv-submit]")
      .forEach((btn) => (btn.onclick = () => rvSubmit(btn.dataset.rvSubmit)));
    list
      .querySelectorAll("[data-rv-note]")
      .forEach((btn) => (btn.onclick = () => rvAddNote(btn.dataset.rvNote)));
    list
      .querySelectorAll("[data-rv-changes]")
      .forEach(
        (btn) => (btn.onclick = () => rvRequestChanges(btn.dataset.rvChanges)),
      );
    list
      .querySelectorAll("[data-rv-approve]")
      .forEach((btn) => (btn.onclick = () => rvApprove(btn.dataset.rvApprove)));
    list
      .querySelectorAll("[data-rv-release]")
      .forEach((btn) => (btn.onclick = () => rvRelease(btn.dataset.rvRelease)));
    list
      .querySelectorAll("[data-rv-resolve]")
      .forEach(
        (btn) =>
          (btn.onclick = () =>
            rvResolve(btn.dataset.version, btn.dataset.rvResolve)),
      );
  }

  async function loadReportVersions() {
    const caseId = document.getElementById("caseId").value.trim();
    const list = document.getElementById("rvList");
    const fromSel = document.getElementById("rvFrom");
    const toSel = document.getElementById("rvTo");
    if (!caseId) {
      list.textContent = "no case loaded";
      return;
    }
    list.textContent = "loading…";
    try {
      const c = encodeURIComponent(caseId);
      const [res, reviewersRes, releasesRes, integrityRes] = await Promise.all([
        fetch(`/cases/${c}/report-versions`),
        fetch(`/cases/${c}/report-reviewers`),
        fetch(`/cases/${c}/report-releases`),
        fetch(`/cases/${c}/report-releases/integrity`),
      ]);
      const [versions, reviewers, releases, integrity] = await Promise.all([
        res.json(),
        reviewersRes.json(),
        releasesRes.json(),
        integrityRes.json(),
      ]);
      if (!res.ok) throw new Error(versions.error || "HTTP " + res.status);
      if (!reviewersRes.ok)
        throw new Error(reviewers.error || "HTTP " + reviewersRes.status);
      if (!releasesRes.ok)
        throw new Error(releases.error || "HTTP " + releasesRes.status);
      rvReviewMode = reviewers.mode || "solo";
      rvReviewers = Array.isArray(reviewers.reviewers)
        ? reviewers.reviewers
        : [];
      rvReleased = Array.isArray(releases) ? releases : [];
      const integrityEl = document.getElementById("rvReleaseIntegrity");
      integrityEl.textContent = integrity.ok
        ? `✓ Released-report chain intact — ${integrity.releases} release(s)`
        : `⚠ Released-report integrity FAILED — ${(integrity.problems || []).join("; ")}`;
      integrityEl.style.color = integrity.ok
        ? "var(--sev-low)"
        : "var(--badge-danger-text)";
      const releasesEl = document.getElementById("rvReleases");
      releasesEl.innerHTML = rvReleased.length
        ? rvReleased
            .map((r) => {
              const supersedes = r.supersedesReleaseId
                ? ` · supersedes ${esc(r.supersedesReleaseId)}`
                : "";
              return `<div data-safe-style="padding:3px 0;border-bottom:1px solid var(--border-color)"><strong>${esc(r.id)}</strong> · ${esc(r.reportVersion)} · released ${esc(new Date(r.releasedAt).toLocaleString())} by ${esc(r.releasedBy.displayName)}${supersedes}<br><span data-safe-style="font-family:monospace;color:var(--text-muted)">SHA-256 ${esc(r.manifestHash)}</span></div>`;
            })
            .join("")
        : `<span data-safe-style="color:var(--text-muted)">No formal releases yet.</span>`;
      if (!versions.length) {
        list.textContent = "no versions yet — generate a report to create one";
        fromSel.innerHTML = "";
        toSel.innerHTML = "";
        return;
      }
      list.innerHTML = versions
        .map(
          (v) => `
        <div data-safe-style="padding:6px 0; border-bottom:1px solid var(--border-color);">
          <div data-safe-style="display:flex;justify-content:space-between;gap:8px;align-items:flex-start"><span><strong>${esc(v.version)}</strong>${v.manualVersion ? ` (rev ${esc(v.manualVersion)})` : ""} — ${esc(new Date(v.createdAt).toLocaleString())}
            · ${v.findingsCount} finding(s), ${v.iocsCount} IOC(s), ${v.eventsCount} event(s)<br><span data-safe-style="color:var(--text-muted)">${esc(rvStatusLabel(v.workflow))}${v.workflow?.assignedReviewer ? ` · reviewer ${esc(v.workflow.assignedReviewer.displayName)}` : ""}${v.workflow?.approvals?.length ? ` · ${v.workflow.approvals.some((a) => a.independent) ? "independently reviewed" : "self-reviewed"}` : ""}</span></span>
            <span data-safe-style="display:flex;gap:5px;align-items:center;justify-content:flex-end;flex-wrap:wrap">${rvVersionActions(v)}</span></div>
          ${rvAnnotationRows(v.workflow)}
        </div>`,
        )
        .join("");
      rvWireActions();
      const opts = versions
        .map(
          (v) =>
            `<option value="${escAttr(v.id)}">${esc(v.version)} — ${esc(new Date(v.createdAt).toLocaleString())}</option>`,
        )
        .join("");
      fromSel.innerHTML = opts;
      toSel.innerHTML = opts;
      fromSel.selectedIndex = Math.min(1, versions.length - 1); // default: previous version
      toSel.selectedIndex = 0; // default: most recent
    } catch (err) {
      list.textContent = "failed to load: " + err.message;
    }
  }

  async function rvPost(versionId, suffix, body) {
    const caseId = document.getElementById("caseId").value.trim();
    const msg = document.getElementById("rvMsg");
    msg.textContent = "saving…";
    try {
      const res = await fetch(
        `/cases/${encodeURIComponent(caseId)}/report-versions/${encodeURIComponent(versionId)}/${suffix}`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        },
      );
      const result = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(result.error || "HTTP " + res.status);
      msg.textContent = "saved ✓";
      await loadReportVersions();
      return result;
    } catch (err) {
      msg.textContent = err.message;
      return null;
    }
  }

  function rvSubmit(versionId) {
    const select = document.querySelector(
      `[data-rv-reviewer="${CSS.escape(versionId)}"]`,
    );
    if (select?.value)
      rvPost(versionId, "workflow/submit", { reviewerId: select.value });
  }

  function rvSelfApprove(versionId) {
    const note = prompt(
      "Record what you checked during self-review. This will be labelled self-reviewed, not independently peer-reviewed.",
    );
    if (note?.trim())
      rvPost(versionId, "workflow/self-approve", { note: note.trim() });
  }

  function rvAddNote(versionId) {
    const ref = prompt(
      "Attach the note to a finding/claim/evidence item (for example finding:f3 or evidence:e17):",
    );
    const match = /^(finding|claim|evidence):(.+)$/.exec((ref || "").trim());
    if (!match) {
      document.getElementById("rvMsg").textContent =
        "Use finding:id, claim:id, or evidence:id.";
      return;
    }
    const message = prompt("Review note:");
    if (!message?.trim()) return;
    const blocker = confirm(
      "Is this a HIGH-impact unresolved uncertainty that must block approval?",
    );
    rvPost(versionId, "review/annotations", {
      targetType: match[1],
      targetId: match[2].trim(),
      category: blocker ? "uncertainty" : "comment",
      impact: blocker ? "high" : "medium",
      message: message.trim(),
    });
  }

  function rvResolve(versionId, annotationId) {
    const resolution = prompt("How was this review note resolved?");
    if (resolution?.trim())
      rvPost(
        versionId,
        `workflow/annotations/${encodeURIComponent(annotationId)}/resolve`,
        { resolution: resolution.trim() },
      );
  }

  function rvRequestChanges(versionId) {
    const reason = prompt("What must the investigator change?");
    if (reason?.trim())
      rvPost(versionId, "review/request-changes", { reason: reason.trim() });
  }

  function rvApprove(versionId) {
    const note = prompt("Approval note (what was checked and accepted):");
    if (note?.trim())
      rvPost(versionId, "review/approve", { note: note.trim() });
  }

  function rvRelease(versionId) {
    const latest = rvReleased[0];
    const warning = latest
      ? `This creates a new immutable release that explicitly supersedes ${latest.id}. The prior release will remain preserved and linked.`
      : "This freezes the exact report, evidence, analysis runs and custody state as the formal release.";
    if (!confirm(warning + "\n\nContinue?")) return;
    rvPost(
      versionId,
      "workflow/release",
      latest ? { supersedesReleaseId: latest.id } : {},
    );
  }

  async function doReportVersionsDiff() {
    const caseId = document.getElementById("caseId").value.trim();
    const from = document.getElementById("rvFrom").value;
    const to = document.getElementById("rvTo").value;
    const out = document.getElementById("rvDiffResult");
    if (!caseId || !from || !to) return;
    out.textContent = "diffing…";
    try {
      const q = new URLSearchParams({ from, to }).toString();
      const res = await fetch(
        `/cases/${encodeURIComponent(caseId)}/report-versions/diff?${q}`,
      );
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || "HTTP " + res.status);
      const rows = [];
      if (d.findings.added.length)
        rows.push(
          `<div>+ <strong>Findings added:</strong> ${d.findings.added.map(esc).join(", ")}</div>`,
        );
      if (d.findings.removed.length)
        rows.push(
          `<div>− <strong>Findings removed:</strong> ${d.findings.removed.map(esc).join(", ")}</div>`,
        );
      if (d.findings.severityChanged.length)
        rows.push(
          `<div>~ <strong>Severity changed:</strong> ${d.findings.severityChanged.map((s) => `${esc(s.title)} (${esc(s.from)} → ${esc(s.to)})`).join(", ")}</div>`,
        );
      if (d.iocs.added.length)
        rows.push(
          `<div>+ <strong>IOCs added:</strong> ${d.iocs.added.map((i) => esc(i.value)).join(", ")}</div>`,
        );
      if (d.iocs.removed.length)
        rows.push(
          `<div>− <strong>IOCs removed:</strong> ${d.iocs.removed.map((i) => esc(i.value)).join(", ")}</div>`,
        );
      if (d.timeline.added.length)
        rows.push(
          `<div>+ <strong>Timeline events added:</strong> ${d.timeline.added.length}</div>`,
        );
      if (d.timeline.removed.length)
        rows.push(
          `<div>− <strong>Timeline events removed:</strong> ${d.timeline.removed.length}</div>`,
        );
      out.innerHTML = rows.length
        ? rows.join("")
        : "no differences between these versions";
    } catch (err) {
      out.textContent = "diff failed: " + err.message;
    }
  }

  async function doRestoreReportVersion(id) {
    const caseId = document.getElementById("caseId").value.trim();
    const msg = document.getElementById("rvMsg");
    if (!caseId || !id) return;
    if (
      !confirm(
        "Restore this version's report metadata (title page, distribution, BIA, glossary, recommendations)? This overwrites the CURRENT report-meta. It does not touch findings/IOCs/timeline and does not regenerate the report.",
      )
    )
      return;
    msg.textContent = "restoring…";
    try {
      const res = await fetch(
        `/cases/${encodeURIComponent(caseId)}/report-versions/${encodeURIComponent(id)}/restore`,
        { method: "POST" },
      );
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || "HTTP " + res.status);
      fillReportMeta(body); // refresh the report-meta form in place, if open
      msg.textContent = "restored ✓ — regenerate the report to render it";
    } catch (err) {
      msg.textContent = "restore failed: " + err.message;
    }
  }

  // The three controls the page's shared modal-wiring block used to bind. Order unchanged.
  function initReportVersions() {
    document.getElementById("rvDiff").onclick = doReportVersionsDiff;
    document.getElementById("rvCancel").onclick = closeReportVersions;
    document
      .getElementById("reportVersionsOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "reportVersionsOverlay") closeReportVersions();
      });
  }

  window.openReportVersions = openReportVersions;
  window.closeReportVersions = closeReportVersions;
  window.doReportVersionsDiff = doReportVersionsDiff;
  window.initReportVersions = initReportVersions;
})();
