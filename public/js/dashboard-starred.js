// Starred events (per case, tag-backed) — extracted from dashboard.html (issue #415, tier 3).
//
// Reported five state escapes until the IOC VIEW state was moved out of its banner: hideFpNoIntel,
// hideSystemPaths, showSignalIocsOnly, showFlaggedIocsOnly and starredTagIds are read by
// renderIocs (core machinery), reset by the case-switch path, toggled from two separate places and
// read by two extracted modules. None of that is "starred events" — they shared a banner because
// the noise lenses were written into the starring section. They now sit beside veloEnabled with
// the page's other shared view state.
//
// Eight of the 119 lines under this banner were other features' guard stanzas. The split script
// refuses a range containing one, which is how the boundary was found rather than guessed.
//
// No initializer: nothing here runs at load.
(function () {
  "use strict";

  // A star IS the reserved analyst tag "starred" on ("event", id) — server-side, shared across
  // browsers/analysts (TimeSketch's model: its star is the __ts_star label). starredEvents /
  // starredTagIds are DERIVED from tagsByTarget in loadTags(); legacy localStorage stars are
  // migrated up once per case, then the key is deleted.
  // starredEvents moved to js/dashboard-selection.js as DfirStarred (#415).
  // Transient "show only this set of event ids" filter — set by the Timeline Anomalies
  // "view N events" link (and reusable by any panel that points at a group of events) so the
  // analyst sees EXACTLY the events behind a bucket, not just the first. null = inactive.
  // showStarredOnly / evIdFilter / evIdFilterLabel moved to js/dashboard-timeline-view.js (#415).
  // Noise-reduction defaults for a case with hundreds/thousands of IOCs (every file/process/hash seen
  // anywhere becomes one — see the "too many IOCs" discussion): hide false-positive-marked + no-intel IOCs,
  // and default to a "signal only" view (flagged, corroborated by 2+ tools, or has ANY enrichment data).
  // Both are pure display filters — nothing is deleted; each persists per-browser (default ON) and
  // can be toggled off per case/session, mirroring the corroboration lens's localStorage pattern.
  // Well-known OS system-binary paths (Windows/Linux/macOS) — a "file" IOC under one of these is
  // almost always a benign system process observed by an EDR/telemetry artifact (Amcache, MFT,
  // Pslist…), not attacker-controlled content. Display-only (a display filter, NOT extraction-time
  // exclusion — the importers still capture every path; nothing is dropped from the case data or
  // reports, so a genuinely malicious binary planted at a spoofed system32 path is still there if
  // this checkbox is turned off). Deliberately conservative: full system dirs only, not broad
  // parents like C:\Windows\ or /usr/ that would also hide non-system installed software.
  const SYSTEM_PATH_RE =
    /^[a-z]:\\windows\\(system32|syswow64|winsxs)\\|^\/(usr\/(bin|sbin|lib(?:64)?)|s?bin)\/|^\/system\/library\//i;
  function isSystemPathIoc(i) {
    return (
      i.type === "file" && SYSTEM_PATH_RE.test(String(i.value || "").trim())
    );
  }
  const starredKey = (caseId) => `dfir_starred_${caseId}`;
  const starMigrationDone = new Set(); // caseIds migrated this session (guards re-entry)

  // Rebuild the star lookup from the freshly-loaded tags (called by loadTags()).
  function deriveStarred() {
    const starred = [];
    starredTagIds = new Map();
    // eachTagList() rather than the Map itself — see js/dashboard-tags.js.
    (typeof eachTagList === "function" ? eachTagList : () => {})((list) =>
      list.forEach((t) => {
        if (t.targetType === "event" && t.label === "starred") {
          starred.push(t.targetId);
          starredTagIds.set(t.targetId, t.id);
        }
      }),
    );
    DfirStarred.replace(starred);
  }

  // One-time migration: pre-server-side stars lived in localStorage — push any not already
  // starred up as "starred" tags (SERIALIZED — TagsStore.add() is read-modify-write, concurrent
  // POSTs clobber each other), then delete the key so this never runs again.
  async function migrateLocalStars(caseId) {
    if (starMigrationDone.has(caseId)) return;
    starMigrationDone.add(caseId);
    let legacy = [];
    try {
      legacy = JSON.parse(localStorage.getItem(starredKey(caseId)) || "[]");
    } catch {}
    if (!legacy.length) return;
    const toMigrate = legacy.filter((id) => !DfirStarred.has(id));
    try {
      for (const id of toMigrate) {
        const r = await fetch(`/cases/${caseId}/tags`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            targetType: "event",
            targetId: id,
            author: investigatorName(),
            label: "starred",
          }),
        });
        if (!r.ok) throw new Error("HTTP " + r.status);
      }
      localStorage.removeItem(starredKey(caseId)); // only after every star landed
      if (toMigrate.length) loadTags(caseId);
    } catch {
      starMigrationDone.delete(caseId);
    } // retry on the next loadTags
  }

  function toggleStar(caseId, id) {
    const wasStarred = DfirStarred.has(id);
    // Optimistic flip for instant feedback; loadTags() re-derives the truth after the server call.
    DfirStarred.toggle(id, !wasStarred);
    renderTimelineEvents(DfirState.lastFt());
    refreshSuperRows(); // the star may belong to a super-timeline row (shared ("event", id) key)
    const revert = () => {
      DfirStarred.toggle(id, wasStarred);
      renderTimelineEvents(DfirState.lastFt());
      refreshSuperRows();
    };
    const req = wasStarred
      ? fetch(
          `/cases/${caseId}/tags/${encodeURIComponent(starredTagIds.get(id) || "")}`,
          { method: "DELETE" },
        )
      : fetch(`/cases/${caseId}/tags`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            targetType: "event",
            targetId: id,
            author: investigatorName(),
            label: "starred",
          }),
        });
    req
      .then((r) => {
        if (!r.ok && r.status !== 404) throw new Error("HTTP " + r.status); // 404 delete = already gone
        loadTags(caseId);
      })
      .catch(revert);
  }

  // Multi-select and its bulk actions moved to js/dashboard-bulk-select.js (#415 tier 3).
  // Bulk IOC operations moved to js/dashboard-bulk-ioc.js (#415 tier 3).
  // Bulk finding operations + hunt-query builders live in public/js/dashboard-bulk-findings.js.

  window.deriveStarred = deriveStarred;
  window.isSystemPathIoc = isSystemPathIoc;
  window.migrateLocalStars = migrateLocalStars;
  window.toggleStar = toggleStar;
})();
