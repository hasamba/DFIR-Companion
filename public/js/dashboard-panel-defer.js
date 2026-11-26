// Hidden sections load when they are shown (#2854).
//
// A case open used to fetch every panel, and every live `state` push re-derived ~20 of them, whether
// or not the analyst could see them. The default "Now" view lists two sections, so most of those
// whole-case reads (10-60 s each on a large case) were for panels nobody was looking at. Now a HEAVY
// panel whose section the active view profile or the section-visibility settings hide is skipped,
// remembered as pending, and loaded once when its section is shown again.
//
// "Shown" is the analyst's layout: the stored preference (isSectionVisible) or this page load's
// palette reveal (isSectionRevealed). It is NOT the data gate (data-gate-open): a data-gated panel's
// own loader is what opens its gate, so waiting for the gate would never load it.
//
// FAILS OPEN. If the section-visibility functions are missing or throw, every panel counts as
// shown and loads as before. A missing module may cost the saving, never a panel.
//
// Every reveal path ends in applySectionsVis() (view switch, Settings save, palette reveal, a
// panel's own self-reveal, every render), and that calls flushRevealed() below.
//
// THE PREVIOUS CASE'S CONTENT. A hidden panel keeps whatever it last drew. If that was another case,
// the section is masked (data-panel-stale, styled in dashboard-sections.css) until a load for THIS
// case has answered and painted. The reveal load is tracked request by request — every request its
// loader makes — and the mask comes off only once every panel of the section has succeeded for this
// case, so a panel built from two answers, or a section holding two panels that retry on separate
// timers (sec-d3fend), stays masked until all of them are in. A failed answer keeps the
// mask and says so instead of exposing the old case. The same holds for a panel that is VISIBLE
// when the case changes (#2894): the case-open fan-out masks it and tracks its load in place.
(function () {
  "use strict";

  // Deferred panels: key (as in CASE_PANEL_LOADERS) -> [section id, loader global]. Only heavy
  // reads whose data nothing outside their own section reads. The eager ones and why are listed in
  // the #2854 plan: the cockpit (default view), the asset graph (timeline host facet), the four IOC
  // provenance reads (IOC rows, corroboration, finding details), hypotheses and Second Look (their
  // loaders carry case-switch cleanup), duplicate hosts (its gate forces the section open) and the
  // super-timeline (not a gated heavy read).
  const PANELS = {
    campaignScope: ["sec-campaign-scope", "loadCampaignScope"],
    servedExposure: ["sec-served-exposure", "loadServedExposure"],
    kerberoastChain: ["sec-kerberoast-chain", "loadKerberoastChain"],
    tlsGraph: ["sec-tls-graph", "loadTlsGraph"],
    sensitiveAccess: ["sec-sensitive-access", "loadSensitiveAccess"],
    hostScope: ["sec-host-scope", "loadHostScope"],
    collectionGenerationDiff: ["sec-collection-generation-diff", "loadCollectionGenerationDiff"],
    loginGraph: ["sec-login-graph", "loadLoginGraph"],
    evidenceGraph: ["sec-evidence", "loadEvidenceGraph"],
    phases: ["sec-phases", "loadPhases"],
    timelineGaps: ["sec-gaps", "loadTimelineGaps"],
    evidenceGaps: ["sec-evidence-gaps", "loadEvidenceGaps"],
    cloudCoverage: ["sec-cloud-coverage", "loadCloudCoverage"],
    beacons: ["sec-beacons", "loadBeacons"],
    anomalies: ["sec-anomalies", "loadAnomalies"],
    sessions: ["sec-sessions", "loadSessions"],
    adversaryHints: ["sec-adversary", "loadAdversaryHints"],
    playbookMatch: ["sec-playbook-match", "loadPlaybookMatch"],
    hostRanking: ["sec-hostranking", "loadHostRanking"],
    d3fend: ["sec-d3fend", "loadD3fend"],
    attackMitigations: ["sec-d3fend", "loadAttackMitigations"],
    compliance: ["sec-compliance", "loadCompliance"],
    geoMap: ["sec-geomap", "loadGeoMap"],
    swimlane: ["sec-swimlane", "loadSwimlane"],
    customerExposure: ["sec-exposure", "loadCustomerExposure"],
    relatedCases: ["sec-related-cases", "loadRelatedCases"],
  };
  const LOADING = "Loading this case's data…";
  const FAILED = "This panel could not be loaded for this case. It retries on the next update.";
  // #2900: a cancelled (or failed) case load leaves nothing loading, so the mask must not say it is.
  const STOPPED = "Not loaded — the case load was stopped. Open a case to load this panel.";
  const resetListeners = []; // #2900: panels outside PANELS that keep their own placeholder

  const pending = new Set(); // keys skipped while hidden, loaded on reveal
  const loadedOnPage = new Set(); // sections some load has started for on this page
  // Per PANEL, not per section: sec-d3fend holds two panels, and each one's retries run on their own.
  const owner = new Map(); // key -> the case whose tracked load of this panel last succeeded
  const loadGen = new Map(); // key -> generation; a newer tracked load or a reset moves it on
  let tracking = null; // the key whose tracked load is running right now (its guard must pass)
  // #2937: actionLive's generation. It moves when a different case opens or a load is cancelled —
  // the owner of the page changed — and never when the case already open is opened again.
  let openGen = 0;
  let lastOpen = null;
  let flushQueued = false;

  const sectionEl = (id) =>
    typeof document !== "undefined" && document.getElementById ? document.getElementById(id) : null;
  function caseOnScreen() {
    const el = sectionEl("caseId");
    return el ? String(el.value || "").trim() : "";
  }
  function isShown(id) {
    if (typeof isSectionVisible !== "function" || typeof loadSectionsVis !== "function") return true;
    try {
      if (isSectionVisible(id, loadSectionsVis())) return true;
      return typeof isSectionRevealed === "function" && !!isSectionRevealed(id);
    } catch {
      return true;
    }
  }
  function setMask(id, text) {
    const el = sectionEl(id);
    if (el && el.dataset) el.dataset.panelStale = text;
  }
  function clearMask(id) {
    const el = sectionEl(id);
    if (el && el.dataset) delete el.dataset.panelStale;
  }
  function isMasked(id) {
    const el = sectionEl(id);
    return !!(el && el.dataset && el.dataset.panelStale !== undefined);
  }
  function queueFlush() {
    if (flushQueued) return;
    flushQueued = true;
    Promise.resolve().then(flushRevealed);
  }

  // Hidden: remember it, and mask the section if what it shows may be another case's.
  function defer(key, sec, caseId) {
    pending.add(key);
    if (loadedOnPage.has(sec) && owner.get(key) !== caseId) setMask(sec, LOADING);
  }

  // The first line of a deferred loader (after its case-switch cleanup). True = do not fetch.
  function skip(key, caseId) {
    const entry = PANELS[key];
    if (!entry) return false;
    const sec = entry[0];
    const id = String(caseId || "").trim();
    if (tracking === key) {
      loadedOnPage.add(sec);
      return false;
    }
    if (!isShown(sec)) {
      defer(key, sec, id);
      return true;
    }
    // Shown but masked: only a tracked load may lift the mask, so this call becomes one.
    if (isMasked(sec)) {
      pending.add(key);
      queueFlush();
      return true;
    }
    pending.delete(key); // this load supersedes a queued reveal
    loadedOnPage.add(sec);
    // An untracked load for another case: nobody knows whether it will paint, so the section's
    // owner is unknown from here on.
    if (owner.get(key) !== id) owner.delete(key);
    return false;
  }

  // The case-open fan-out keeps only the panels that will really load, so the strip's "N of M
  // panels loaded" counts real loads. A dropped panel loads when its section is shown.
  //
  // A SHOWN panel whose section holds another case's content (#2894) — it loaded for an earlier
  // case on this page, or was masked while hidden — is masked here, at the switch, and its load
  // stays in the fan-out, tracked in place: same moment, same lanes, same abort signal, same strip
  // count. Its own successful paint for this case lifts the mask; a failure shows the failure line.
  // This runs after the case's saved view is applied, so "shown" is the new case's layout.
  function eagerOnly(entries) {
    const caseId = caseOnScreen();
    const kept = [];
    for (const entry of Array.isArray(entries) ? entries : []) {
      const def = PANELS[entry[0]];
      if (!def) kept.push(entry);
      else if (!isShown(def[0])) defer(entry[0], def[0], caseId);
      else if (!isMasked(def[0]) && !(loadedOnPage.has(def[0]) && owner.get(entry[0]) !== caseId))
        kept.push(entry);
      else {
        setMask(def[0], LOADING);
        pending.delete(entry[0]);
        kept.push([entry[0], trackedRun(entry[0], caseId, entry[1]), ...entry.slice(2)]);
      }
    }
    return kept;
  }
  function trackedRun(key, caseId, run) {
    return () => {
      const rec = newRecord(key, caseId);
      try {
        trackFetches(key, rec, run);
      } catch (err) {
        rec.failed = true;
        seal(rec);
        throw err; // the runner records the panel as failed, as before
      }
      seal(rec);
    };
  }

  // ── tracked reveal loads ──────────────────────────────────────────────────────────────────────
  // One record per panel per tracked load: how many requests are out, whether one failed. The mask
  // comes off only when EVERY panel of the section has succeeded for the case on screen, so a
  // section whose two panels retry on separate timers stays masked while either is failed or out.
  function sectionSettled(sec, caseId) {
    return Object.keys(PANELS).every((k) => PANELS[k][0] !== sec || owner.get(k) === caseId);
  }
  function finish(rec) {
    const done = () => {
      if (loadGen.get(rec.key) !== rec.gen) return; // a newer load or a case switch took over
      if (!rec.failed) owner.set(rec.key, rec.caseId);
      else owner.delete(rec.key);
      if (!isMasked(rec.sec)) return;
      if (rec.failed) setMask(rec.sec, FAILED);
      else if (sectionSettled(rec.sec, rec.caseId)) clearMask(rec.sec);
    };
    // A macrotask, so the loader's own render (microtasks after its body read) has run first.
    if (typeof setTimeout === "function") setTimeout(done, 0);
    else Promise.resolve().then(done);
  }
  function requestDone(rec, failed) {
    if (failed) rec.failed = true;
    rec.left--;
    if (rec.sealed && rec.left === 0) finish(rec);
  }
  const BODY_READERS = ["json", "text", "blob", "arrayBuffer", "formData"];
  // A request is done when its body has been read (or, if the loader never reads it, one macrotask
  // after the answer). A non-OK answer other than 501 ("not configured", which loaders draw as
  // their reason) is a failure: several loaders keep their old content on an error answer.
  function watchAnswer(res, rec) {
    let over = false;
    const end = (failed) => {
      if (over) return;
      over = true;
      requestDone(rec, failed);
    };
    const bad = !!res && res.ok === false && res.status !== 501;
    if (!res || typeof res !== "object") {
      end(true);
      return res;
    }
    let backstop = null;
    if (typeof setTimeout === "function") backstop = setTimeout(() => end(bad), 0);
    for (const name of BODY_READERS) {
      const readBody = typeof res[name] === "function" ? res[name] : null;
      if (!readBody) continue;
      try {
        Object.defineProperty(res, name, {
          configurable: true,
          writable: true,
          value: function (...args) {
            if (backstop !== null) clearTimeout(backstop);
            const out = readBody.apply(this, args);
            if (!out || typeof out.then !== "function") {
              end(bad);
              return out;
            }
            out.then(
              () => end(bad),
              () => end(true),
            );
            return out;
          },
        });
      } catch {
        /* a frozen answer: the backstop still ends it */
      }
    }
    if (backstop === null) end(bad);
    return res;
  }
  function newRecord(key, caseId) {
    const gen = (loadGen.get(key) || 0) + 1;
    loadGen.set(key, gen);
    return { key, sec: PANELS[key][0], gen, caseId, left: 0, failed: false, sealed: false };
  }
  // The loader's synchronous body has run: every request it will make is counted. One with none
  // settles at once, so a loader with nothing to ask for this case never stays masked.
  function seal(rec) {
    rec.sealed = true;
    if (rec.left === 0) finish(rec);
  }
  // Count every request the loader's SYNCHRONOUS body makes. Nested inside runPanelLoaders' own
  // per-loader wrapper when the case-open fan-out or the reloader runs it, so its lanes, abort
  // signal and tally see the same requests.
  function trackFetches(key, rec, run) {
    const before = globalThis.fetch;
    if (typeof before === "function") {
      globalThis.fetch = function (...args) {
        rec.left++;
        let p;
        try {
          p = before.apply(this, args);
        } catch (err) {
          requestDone(rec, true);
          throw err;
        }
        if (!p || typeof p.then !== "function") {
          requestDone(rec, true);
          return p;
        }
        return p.then(
          (res) => watchAnswer(res, rec),
          (err) => {
            requestDone(rec, true);
            throw err;
          },
        );
      };
    }
    tracking = key;
    try {
      run();
    } finally {
      tracking = null;
      globalThis.fetch = before;
    }
  }
  function runTracked(key, rec, run) {
    const inner = () => trackFetches(key, rec, run);
    const clp = typeof window !== "undefined" ? window.DfirCaseLoadProgress : null;
    if (clp && typeof clp.runPanelReload === "function") clp.runPanelReload(key, rec.caseId, inner);
    else inner();
  }

  // Load every pending panel whose section is shown now, for the case on screen. Cheap when nothing
  // is pending, which is what it is on almost every render.
  function flushRevealed() {
    flushQueued = false;
    if (!pending.size) return;
    const caseId = caseOnScreen();
    if (!caseId) {
      pending.clear();
      return;
    }
    const due = [...pending].filter((key) => isShown(PANELS[key][0]));
    const records = [];
    for (const key of due) {
      pending.delete(key);
      const loader = globalThis[PANELS[key][1]];
      if (typeof loader !== "function") continue;
      const rec = newRecord(key, caseId);
      records.push(rec);
      try {
        runTracked(key, rec, () => loader(caseId));
      } catch {
        rec.failed = true;
      }
    }
    records.forEach(seal);
  }

  // A case switch or a cancelled load: nothing pending survives, and no answer still on its way
  // may lift a mask. Masks stay — the content under them is still the old case's.
  //
  // #2900: `caseId` names the case now opening, or none after a cancel or a failed load. With no
  // case nothing is loading, so a "Loading…" mask says the load stopped instead; the next case open
  // turns those back into "Loading…" (eagerOnly tracks a shown one in the fan-out, a hidden one
  // loads on reveal). A failure line is left as it is.
  function reset(caseId) {
    pending.clear();
    tracking = null;
    for (const [key, gen] of loadGen) loadGen.set(key, gen + 1);
    const opening = !!String(caseId || "").trim();
    const id = opening ? String(caseId).trim() : null;
    if (id === null || id !== lastOpen) openGen++;
    lastOpen = id;
    for (const sec of new Set(Object.values(PANELS).map((def) => def[0]))) {
      const text = isMasked(sec) ? sectionEl(sec).dataset.panelStale : null;
      if (!opening && text === LOADING) setMask(sec, STOPPED);
      else if (opening && text === STOPPED) setMask(sec, LOADING);
    }
    for (const fn of resetListeners) {
      try {
        fn(opening ? String(caseId).trim() : null);
      } catch {
        /* one panel's placeholder must not stop the reset */
      }
    }
  }
  function onReset(fn) {
    if (typeof fn === "function" && !resetListeners.includes(fn)) resetListeners.push(fn);
  }
  // #2937: for an action in a module that owns no case (whitelist / NSRL Apply, the false-positive
  // modal, Synthesize, import undo). Its answer still paints while live() — the case it was sent for
  // is on screen and no other case has opened (nor a load been cancelled) since.
  function actionLive(caseId) {
    const gen = openGen;
    return () => gen === openGen && caseOnScreen() === caseId;
  }

  window.DfirPanelDefer = {
    skip,
    eagerOnly,
    flushRevealed,
    reset,
    onReset,
    actionLive,
    stoppedText: STOPPED,
    panels: () => JSON.parse(JSON.stringify(PANELS)),
  };
})();
