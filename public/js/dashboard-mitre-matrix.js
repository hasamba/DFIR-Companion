// MITRE ATT&CK matrix view of the MITRE panel (#1764): one column per tactic, one cell per
// technique, the case's hits colored by worst severity. The List view stays in
// js/dashboard-render.js, byte for byte; this module only takes over #mitre when the analyst's
// switch says Matrix.
//
// THE LAYOUT IS A MIRROR. buildAttackMatrix() and aggregateCell() below are the client copy of
// companion/src/analysis/attackMatrix.ts, and buildMatrixHits() is the client copy of
// companion/src/reports/attackMatrixHits.ts. The browser needs its own copy because it re-derives
// the case's techniques on every render, so a finding marked false positive leaves the matrix at
// once, with no reload. tests/dashboard/dashboardMitreMatrixParity.test.ts runs both copies over
// the real catalogue and demands deep-equal output. Change one, change both.
//
// The hits come from the List view's own rows (deriveMitreRows), so the two views can never show
// different techniques. Only findings and the forensic timeline are read — never the
// super-timeline (CLAUDE.md section 7).
//
// The catalogue is GET /attack/matrix, fetched once per page and kept for the session. It holds
// public ATT&CK data only. An empty catalogue is not an error: every hit then shows in Unmapped.
//
// A feature module: initMitreMatrix() wires the controls and publishes window.DfirMitreMatrix. The
// page calls it once at load; this file must not call it itself.
(function () {
  // ── Layout mirror of analysis/attackMatrix.ts ────────────────────────────────────────────────
  const SEVERITY_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
  const MATRIX_PLATFORMS = ["windows", "linux", "macos", "cloud", "all"];
  const PLATFORM_GROUPS = {
    windows: ["Windows"],
    linux: ["Linux"],
    macos: ["macOS"],
    cloud: ["IaaS", "SaaS", "Office Suite", "Identity Provider", "Containers"],
  };
  const ANY_PLATFORM = "PRE";

  const byName = (a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id);

  function matchesPlatform(t, platform) {
    if (platform === "all") return true;
    const group = PLATFORM_GROUPS[platform];
    return t.platforms.some((p) => p === ANY_PLATFORM || group.includes(p));
  }

  // One hit per id; duplicates merge (worst severity wins, ids union in first-seen order).
  function indexHits(hits) {
    const out = new Map();
    for (const h of hits) {
      const id = String(h.id || "")
        .trim()
        .toUpperCase();
      if (!id) continue;
      const cur = out.get(id);
      if (!cur) {
        out.set(id, { ...h, id, findingIds: [...h.findingIds], eventIds: [...h.eventIds] });
        continue;
      }
      out.set(id, {
        id,
        worst: SEVERITY_RANK[h.worst] < SEVERITY_RANK[cur.worst] ? h.worst : cur.worst,
        findingIds: [...new Set([...cur.findingIds, ...h.findingIds])],
        eventIds: [...new Set([...cur.eventIds, ...h.eventIds])],
        ...(cur.analystAccepted || h.analystAccepted ? { analystAccepted: true } : {}),
      });
    }
    return out;
  }

  function cellFor(parent, kids, hits, opts) {
    const parentHit = hits.get(parent.id);
    const children = [];
    for (const k of kids) {
      const hit = hits.get(k.id);
      const visible = hit ? true : !opts.hitsOnly && matchesPlatform(k, opts.platform);
      if (visible) children.push({ id: k.id, name: k.name, ...(hit ? { hit } : {}), children: [], expanded: false });
    }
    const childHit = children.some((c) => c.hit);
    const visible =
      parentHit || childHit || (!opts.hitsOnly && (matchesPlatform(parent, opts.platform) || children.length > 0));
    if (!visible) return null;
    return {
      id: parent.id,
      name: parent.name,
      ...(parentHit ? { hit: parentHit } : {}),
      children: children.sort(byName),
      expanded: childHit,
    };
  }

  function buildAttackMatrix(data, hits, opts) {
    const hitIndex = indexHits(hits);
    const known = new Map(data.techniques.map((t) => [t.id, t]));
    const kidsOf = new Map();
    for (const t of data.techniques) {
      if (!t.parent || !known.has(t.parent)) continue;
      kidsOf.set(t.parent, [...(kidsOf.get(t.parent) ?? []), t]);
    }
    const placed = new Set();
    const columns = [];
    for (const tactic of data.tactics) {
      const cells = [];
      for (const t of data.techniques) {
        if (t.parent || !t.tactics.includes(tactic.shortname)) continue;
        const cell = cellFor(t, kidsOf.get(t.id) ?? [], hitIndex, opts);
        if (cell) cells.push(cell);
      }
      const hitIds = new Set();
      for (const c of cells) {
        if (c.hit) hitIds.add(c.id);
        for (const k of c.children) if (k.hit) hitIds.add(k.id);
      }
      hitIds.forEach((id) => placed.add(id));
      if (opts.hitsOnly && hitIds.size === 0) continue;
      columns.push({ tactic, hitCount: hitIds.size, cells: cells.sort(byName) });
    }
    const unmapped = [...hitIndex.values()].filter((h) => !placed.has(h.id)).sort((a, b) => a.id.localeCompare(b.id));
    return {
      attackVersion: data.attackVersion,
      catalogueAvailable: data.techniques.length > 0,
      columns,
      unmapped,
    };
  }

  // What a cell SHOWS: its own hit merged with every child hit.
  function aggregateCell(cell) {
    const all = [cell.hit, ...cell.children.map((c) => c.hit)].filter((h) => !!h);
    if (all.length === 0) return undefined;
    let worst = all[0].worst;
    for (const h of all) if (SEVERITY_RANK[h.worst] < SEVERITY_RANK[worst]) worst = h.worst;
    return {
      id: cell.id,
      worst,
      findingIds: [...new Set(all.flatMap((h) => h.findingIds))],
      eventIds: [...new Set(all.flatMap((h) => h.eventIds))],
      ...(all.some((h) => h.analystAccepted) ? { analystAccepted: true } : {}),
    };
  }

  // ── Hit builder, mirror of reports/attackMatrixHits.ts ──────────────────────────────────────
  const norm = (id) =>
    String(id || "")
      .trim()
      .toUpperCase();
  const worstOf = (a, b) => (SEVERITY_RANK[b] < SEVERITY_RANK[a] ? b : a);

  // Worst severity and carrying events per technique id, over the surviving findings and `ft`.
  function supportIndex(findings, ft) {
    const index = new Map();
    const get = (raw) => {
      const id = norm(raw);
      const cur = index.get(id) ?? { events: [] };
      index.set(id, cur);
      return cur;
    };
    const bump = (s, sev) => {
      s.worst = s.worst ? worstOf(s.worst, sev) : sev;
    };
    for (const f of findings || []) for (const t of f.mitreTechniques || []) bump(get(t), f.severity);
    for (const e of ft || []) {
      for (const t of new Set((e.mitreTechniques || []).map(norm))) {
        const s = get(t);
        bump(s, e.severity);
        s.events.push({ id: e.id, timestamp: e.timestamp || "" });
      }
    }
    return index;
  }

  // Epoch ms, or +Infinity for a timestamp that does not parse, so undated rows sort last.
  function epoch(ts) {
    const ms = Date.parse(ts);
    return Number.isNaN(ms) ? Number.POSITIVE_INFINITY : ms;
  }

  // De-duplicated, oldest first, then by id.
  function sortedEventIds(events) {
    const seen = new Map();
    for (const e of events) if (!seen.has(e.id)) seen.set(e.id, epoch(e.timestamp));
    return [...seen.entries()]
      .sort((a, b) => (a[1] === b[1] ? a[0].localeCompare(b[0]) : a[1] < b[1] ? -1 : 1))
      .map(([id]) => id);
  }

  // One hit per List-view row, in row order. `findings` is notFp, `ft` the forensic timeline shown.
  function buildMatrixHits(rows, findings, ft) {
    const support = supportIndex(findings, ft);
    return (rows || []).map((row) => {
      const s = support.get(norm(row.id));
      return {
        id: row.id,
        name: row.name || row.id,
        worst: s?.worst ?? "Info",
        findingIds: [...(row.findingIds || [])],
        eventIds: s ? sortedEventIds(s.events) : [],
        ...(row.analystAccepted ? { analystAccepted: true } : {}),
      };
    });
  }

  // ── Catalogue ────────────────────────────────────────────────────────────────────────────────
  const strings = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);

  // Validate at the boundary, as analysis/attackMatrixData.ts does: keep only well-formed entries.
  function coerceCatalogue(raw) {
    const obj = raw && typeof raw === "object" ? raw : {};
    const tactics = (Array.isArray(obj.tactics) ? obj.tactics : [])
      .filter((t) => t && typeof t.id === "string" && typeof t.shortname === "string" && typeof t.name === "string")
      .map((t) => ({ id: t.id, shortname: t.shortname, name: t.name }));
    const techniques = (Array.isArray(obj.techniques) ? obj.techniques : [])
      .filter((t) => t && typeof t.id === "string" && typeof t.name === "string")
      .map((t) => ({
        id: t.id,
        name: t.name,
        tactics: strings(t.tactics),
        platforms: strings(t.platforms),
        ...(typeof t.parent === "string" ? { parent: t.parent } : {}),
      }));
    const attackVersion = typeof obj.attackVersion === "string" ? obj.attackVersion : "unknown";
    return { attackVersion, tactics, techniques };
  }

  // ── Per-viewer choices (localStorage, every access in try/catch) ────────────────────────────
  const VIEW_KEY = "dfir.mitreView";
  const PLATFORM_KEY = "dfir.mitrePlatform";
  const HITS_ONLY_KEY = "dfir.mitreHitsOnly";

  function readPref(key, allowed, fallback) {
    try {
      const v = localStorage.getItem(key);
      return allowed.includes(v) ? v : fallback;
    } catch {
      return fallback; // storage blocked: the default
    }
  }
  function writePref(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch {
      // storage blocked: the choice lasts until the page reloads
    }
  }
  function prefs() {
    return {
      view: readPref(VIEW_KEY, ["matrix", "list"], "matrix"),
      platform: readPref(PLATFORM_KEY, MATRIX_PLATFORMS, "windows"),
      hitsOnly: readPref(HITS_ONLY_KEY, ["1", "0"], "0") === "1",
    };
  }

  // ── HTML (pure: every string escaped) ───────────────────────────────────────────────────────
  const EVENT_CAP = 50;
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

  function cellLabel(id, name, agg) {
    if (!agg) return `${id} ${name}, not seen in this case`;
    return `${id} ${name}, ${agg.worst}, ${plural(agg.findingIds.length, "finding")}, ${plural(agg.eventIds.length, "event")}`;
  }

  // Hover text for a cell's number and letter; a parent's count includes its sub-techniques.
  function badgeTitle(agg, withSubs) {
    const subs = withSubs ? " (with its sub-techniques)" : "";
    return `${plural(agg.findingIds.length, "finding")}, ${plural(agg.eventIds.length, "event")}${subs}`;
  }

  // One technique button. `agg` is what it shows (parent + children for a parent cell).
  function cellHtml(id, name, agg, extraClass, withSubs) {
    const sev = agg ? ` mm-hit mm-sev-${esc(agg.worst)}` : "";
    const tail = agg
      ? `<span class="mm-badge" aria-hidden="true" title="${escAttr(badgeTitle(agg, withSubs))}">` +
        `${agg.findingIds.length + agg.eventIds.length}</span>` +
        `<span class="mm-sevl" aria-hidden="true" title="${escAttr(`Worst severity: ${agg.worst}`)}">` +
        `${esc(agg.worst.charAt(0))}</span>`
      : "";
    return (
      `<button type="button" class="mm-cell mm-nav${sev}${extraClass}" data-tid="${escAttr(id)}" tabindex="-1" ` +
      `aria-label="${escAttr(cellLabel(id, name, agg))}"><span class="mm-name">${esc(name)}</span>${tail}</button>`
    );
  }

  function toggleHtml(cell, open) {
    const n = cell.children.length;
    const label = `${open ? "Hide" : "Show"} ${plural(n, "sub-technique")} of ${cell.id} ${cell.name}`;
    return (
      `<button type="button" class="mm-toggle mm-nav" data-toggle="${escAttr(cell.id)}" tabindex="-1" ` +
      `aria-expanded="${open}" aria-label="${escAttr(label)}">${open ? "−" : `+${n}`}</button>`
    );
  }

  function techniqueHtml(cell, expanded) {
    const open = cell.children.length > 0 && (expanded.has(cell.id) ? expanded.get(cell.id) : cell.expanded);
    const head =
      cellHtml(cell.id, cell.name, aggregateCell(cell), "", cell.children.some((k) => k.hit)) +
      (cell.children.length ? toggleHtml(cell, open) : "");
    const subs = open
      ? `<div class="mm-subs">${cell.children.map((k) => cellHtml(k.id, k.name, k.hit, " mm-sub")).join("")}</div>`
      : "";
    return `<div class="mm-tech"><div class="mm-tech-row">${head}</div>${subs}</div>`;
  }

  function columnHtml(title, count, body) {
    return (
      `<div class="mm-col" role="group" aria-label="${escAttr(`${title}, ${plural(count, "technique")} seen`)}">` +
      `<div class="mm-col-head"><span class="mm-tactic">${esc(title)}</span>` +
      `<span class="mm-col-count" aria-hidden="true" title="${escAttr(`${plural(count, "technique")} seen in this tactic`)}">` +
      `${count}</span></div>${body}</div>`
    );
  }

  function legendHtml(hits) {
    const present = SEVERITIES.filter((s) => hits.some((h) => h.worst === s));
    if (!present.length) return "";
    return (
      `<span class="mm-legend">` +
      present
        .map((s) => `<span class="mm-legend-item"><span class="mm-swatch mm-sev-${s}">${s.charAt(0)}</span>${s}</span>`)
        .join("") +
      `<span class="mm-key">Cell number = findings + events · letter = worst severity · column number = techniques seen</span>` +
      `</span>`
    );
  }

  // The whole matrix: columns, Unmapped, then legend and version stamp. `expanded` holds the
  // analyst's +N choices for this session; a parent not in it uses the model's default.
  function matrixHtml(model, hits, expanded) {
    const exp = expanded || new Map();
    const cols = model.columns.map((c) =>
      columnHtml(c.tactic.name, c.hitCount, c.cells.map((cell) => techniqueHtml(cell, exp)).join("")),
    );
    if (model.unmapped.length || !model.catalogueAvailable) {
      const body = model.unmapped
        .map((h) => `<div class="mm-tech"><div class="mm-tech-row">${cellHtml(h.id, h.name || h.id, h, "")}</div></div>`)
        .join("");
      cols.push(columnHtml("Unmapped", model.unmapped.length, body));
    }
    const note = model.catalogueAvailable
      ? ""
      : `<p class="mm-note">ATT&amp;CK catalogue not available — showing case techniques only</p>`;
    const stamp = model.catalogueAvailable
      ? `<span class="mm-stamp">ATT&amp;CK Enterprise v${esc(model.attackVersion)}</span>`
      : "";
    return (
      `${note}<div class="mm-scroll"><div class="mm-grid">${cols.join("")}</div></div>` +
      `<div class="mm-foot">${legendHtml(hits)}${stamp}</div>`
    );
  }

  // ── Popover ─────────────────────────────────────────────────────────────────────────────────
  const TECHNIQUE_RE = /^T\d{4}(?:\.\d{3})?$/;
  const attackUrl = (id) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;

  // Tactic names for a technique, in column order. A sub-technique sits in its parent's columns.
  function tacticNames(catalogue, id) {
    const byId = new Map(catalogue.techniques.map((t) => [t.id, t]));
    const t = byId.get(id);
    if (!t) return [];
    const home = t.parent && byId.get(t.parent) ? byId.get(t.parent) : t;
    return catalogue.tactics.filter((x) => home.tactics.includes(x.shortname)).map((x) => x.name);
  }

  function findingsHtml(ids, findingsById) {
    if (!ids.length) return "";
    const items = ids.map((id) => {
      const f = findingsById.get(id);
      const text = f ? `${f.title || id} (${f.severity || "?"})` : id;
      return `<li><button type="button" class="mm-link" data-jump-finding="${escAttr(id)}">${esc(text)}</button></li>`;
    });
    return `<h4>${plural(ids.length, "finding")}</h4><ul class="mm-pop-list">${items.join("")}</ul>`;
  }

  function eventsHtml(ids, eventsById) {
    if (!ids.length) return "";
    const items = ids.slice(0, EVENT_CAP).map((id) => {
      const e = eventsById.get(id);
      const text = e ? `${e.timestamp || ""} ${String(e.description || id).slice(0, 140)}` : id;
      return `<li><button type="button" class="mm-link" data-jump-event="${escAttr(id)}">${esc(text.trim())}</button></li>`;
    });
    const more = ids.length > EVENT_CAP ? `<p class="mm-more">and ${ids.length - EVENT_CAP} more</p>` : "";
    return `<h4>${plural(ids.length, "forensic event")}</h4><ul class="mm-pop-list">${items.join("")}</ul>${more}`;
  }

  // `entry` is { id, name, agg }; ctx carries the catalogue and the id -> finding / event maps.
  function popoverHtml(entry, ctx) {
    const { id, name, agg } = entry;
    const tactics = tacticNames(ctx.catalogue, id);
    const link = TECHNIQUE_RE.test(id)
      ? `<a href="${escAttr(attackUrl(id))}" target="_blank" rel="noopener noreferrer">View on attack.mitre.org</a>`
      : "";
    const accepted = agg && agg.analystAccepted ? `<p class="mm-accepted">Accepted by analyst</p>` : "";
    return (
      `<div class="mm-pop-head"><strong>${esc(id)} ${esc(name)}</strong>` +
      `<button type="button" class="mm-pop-close" data-mm-close="1" aria-label="Close">×</button></div>` +
      `<p class="mm-pop-meta">${link}</p>` +
      `<p class="mm-pop-meta">Tactics: ${esc(tactics.length ? tactics.join(", ") : "not in the bundled catalogue")}</p>` +
      `<p class="mm-pop-meta">Worst severity: ${esc(agg ? agg.worst : "not seen in this case")}</p>` +
      accepted +
      (agg ? findingsHtml(agg.findingIds, ctx.findingsById) + eventsHtml(agg.eventIds, ctx.eventsById) : "")
    );
  }

  // ── Live state ──────────────────────────────────────────────────────────────────────────────
  let mmCatalogue = null; // the coerced catalogue once fetched (empty when the fetch failed)
  let mmLoading = false;
  let mmLast = null; // { rows, findings, ft, renderList } from the latest render()
  let mmEntries = new Map(); // technique id -> { id, name, agg } for the painted matrix
  const mmExpanded = new Map(); // parent id -> open, the analyst's +N choices this session
  let mmParents = []; // ids of the painted parents that have sub-techniques
  let mmPopoverId = null;
  let mmReturnFocus = null;
  let mmWired = false;

  function loadCatalogue() {
    if (mmCatalogue || mmLoading) return;
    mmLoading = true;
    fetch("/attack/matrix")
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => coerceCatalogue(j))
      .catch(() => coerceCatalogue(null))
      .then((cat) => {
        mmCatalogue = cat; // kept for the session, as the server's answer never changes
        mmLoading = false;
        if (mmLast && prefs().view === "matrix") paintMatrix();
      });
  }

  // The id -> entry map the popover and aria labels read, one entry per distinct id.
  function entriesOf(model) {
    const out = new Map();
    for (const col of model.columns) {
      for (const cell of col.cells) {
        out.set(cell.id, { id: cell.id, name: cell.name, agg: aggregateCell(cell) });
        for (const k of cell.children) out.set(k.id, { id: k.id, name: k.name, agg: k.hit });
      }
    }
    for (const h of model.unmapped) out.set(h.id, { id: h.id, name: h.name || h.id, agg: h });
    return out;
  }

  function paintMatrix(focusSelector) {
    const host = document.getElementById("mitre");
    if (!host || !mmLast) return;
    if (!mmCatalogue) {
      host.textContent = "Loading the ATT&CK catalogue…";
      loadCatalogue();
      return;
    }
    const p = prefs();
    const hits = buildMatrixHits(mmLast.rows, mmLast.findings, mmLast.ft);
    const model = buildAttackMatrix(mmCatalogue, hits, { platform: p.platform, hitsOnly: p.hitsOnly });
    mmEntries = entriesOf(model);
    mmParents = model.columns.flatMap((c) => c.cells.filter((cell) => cell.children.length).map((cell) => cell.id));
    // render() hands over its empty-case line (#1767): with no techniques the grid alone reads as
    // "nothing matched" rather than "nothing imported yet".
    host.innerHTML = (mmLast.emptyHtml || "") + matrixHtml(model, hits, mmExpanded);
    const first = host.querySelector(focusSelector || ".mm-cell.mm-hit") || host.querySelector(".mm-nav");
    if (first) first.tabIndex = 0;
    if (focusSelector && first) first.focus();
    if (mmPopoverId && mmEntries.has(mmPopoverId)) fillPopover(mmPopoverId);
    else closePopover(false);
  }

  // Expand all / Collapse all: one explicit choice per painted parent, overriding the automatic
  // "open when a sub-technique is a hit" default until the analyst changes it again.
  function setAllExpanded(open) {
    for (const id of mmParents) mmExpanded.set(id, open);
    paintMatrix();
  }

  function popoverContext() {
    return {
      catalogue: mmCatalogue || coerceCatalogue(null),
      findingsById: new Map((mmLast.findings || []).map((f) => [f.id, f])),
      eventsById: new Map((mmLast.ft || []).map((e) => [String(e.id), e])),
    };
  }

  function fillPopover(id) {
    const pop = document.getElementById("mitrePopover");
    const entry = mmEntries.get(id);
    if (!pop || !entry) return false;
    pop.innerHTML = popoverHtml(entry, popoverContext());
    pop.hidden = false;
    mmPopoverId = id;
    return true;
  }

  function openPopover(button) {
    if (!fillPopover(button.getAttribute("data-tid"))) return;
    mmReturnFocus = button;
    const pop = document.getElementById("mitrePopover");
    const section = document.getElementById("sec-mitre");
    if (section && pop) {
      const b = button.getBoundingClientRect();
      const s = section.getBoundingClientRect();
      const left = Math.max(0, Math.min(b.left - s.left, s.width - 340));
      pop.style.top = `${Math.round(b.bottom - s.top + 4)}px`;
      pop.style.left = `${Math.round(left)}px`;
    }
    const close = pop && pop.querySelector(".mm-pop-close");
    if (close) close.focus();
  }

  function closePopover(restoreFocus) {
    const pop = document.getElementById("mitrePopover");
    mmPopoverId = null;
    if (!pop || pop.hidden) return;
    pop.hidden = true;
    pop.innerHTML = "";
    if (restoreFocus && mmReturnFocus && mmReturnFocus.isConnected) mmReturnFocus.focus();
  }

  // ── Keyboard: arrows move over the visible cells, within and across columns ─────────────────
  function navTarget(from, key) {
    const col = from.closest(".mm-col");
    if (!col) return null;
    const inCol = [...col.querySelectorAll(".mm-nav")];
    const i = inCol.indexOf(from);
    if (key === "ArrowDown") return inCol[i + 1] || null;
    if (key === "ArrowUp") return inCol[i - 1] || null;
    const cols = [...col.parentElement.querySelectorAll(".mm-col")];
    const next = cols[cols.indexOf(col) + (key === "ArrowRight" ? 1 : -1)];
    if (!next) return null;
    const cells = [...next.querySelectorAll(".mm-nav")];
    return cells[Math.min(i, cells.length - 1)] || null;
  }

  function onMatrixKey(e) {
    if (!["ArrowDown", "ArrowUp", "ArrowLeft", "ArrowRight"].includes(e.key)) return;
    const from = e.target.closest && e.target.closest(".mm-nav");
    const to = from && navTarget(from, e.key);
    if (!to) return;
    e.preventDefault();
    from.tabIndex = -1;
    to.tabIndex = 0;
    to.focus();
  }

  function onMatrixClick(e) {
    const toggle = e.target.closest && e.target.closest(".mm-toggle");
    if (toggle) {
      const id = toggle.getAttribute("data-toggle");
      mmExpanded.set(id, toggle.getAttribute("aria-expanded") !== "true");
      paintMatrix(`.mm-toggle[data-toggle="${CSS.escape(id)}"]`);
      return;
    }
    const cell = e.target.closest && e.target.closest(".mm-cell");
    if (cell) openPopover(cell);
  }

  function onPopoverClick(e) {
    const t = e.target.closest ? e.target.closest("button") : null;
    if (!t) return;
    if (t.hasAttribute("data-mm-close")) return closePopover(true);
    const fid = t.getAttribute("data-jump-finding");
    const evid = t.getAttribute("data-jump-event");
    if (fid) {
      if (typeof revealSection === "function") revealSection("sec-findings");
      if (typeof jumpToFinding === "function") jumpToFinding(fid);
    } else if (evid && typeof jumpToEvent === "function") {
      jumpToEvent(evid); // reveals sec-timeline itself, so the Executive and Report views work
    }
  }

  function onDocumentKey(e) {
    if (e.key === "Escape" && mmPopoverId) closePopover(true);
  }
  function onDocumentPointer(e) {
    if (!mmPopoverId) return;
    const pop = document.getElementById("mitrePopover");
    if (pop && pop.contains(e.target)) return;
    if (e.target.closest && e.target.closest("#mitre .mm-cell")) return;
    closePopover(false);
  }

  // ── Controls (outside #mitre, so the List view's #mitre stays exactly as it was) ────────────
  function syncControls(p) {
    const set = (id, fn) => {
      const el = document.getElementById(id);
      if (el) fn(el);
    };
    set("mitreViewMatrix", (el) => el.setAttribute("aria-pressed", String(p.view === "matrix")));
    set("mitreViewList", (el) => el.setAttribute("aria-pressed", String(p.view === "list")));
    // The platform filter and Hits only act on the matrix alone, so the List view hides them rather
    // than showing two dead controls.
    set("mitrePlatform", (el) => (el.value = p.platform));
    set("mitreHitsOnly", (el) => (el.checked = p.hitsOnly));
    set("mitrePlatformCtl", (el) => (el.hidden = p.view !== "matrix"));
    set("mitreHitsOnlyCtl", (el) => (el.hidden = p.view !== "matrix"));
    set("mitreExpandCtl", (el) => (el.hidden = p.view !== "matrix"));
    set("sec-mitre", (el) => el.classList.toggle("mm-matrix-on", p.view === "matrix"));
  }

  function repaint() {
    if (mmLast) renderPanel(mmLast);
    else syncControls(prefs());
  }

  function wireControls() {
    const on = (id, type, fn) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener(type, fn);
    };
    on("mitreViewMatrix", "click", () => (writePref(VIEW_KEY, "matrix"), repaint()));
    on("mitreViewList", "click", () => (writePref(VIEW_KEY, "list"), repaint()));
    on("mitrePlatform", "change", (e) => (writePref(PLATFORM_KEY, e.target.value), repaint()));
    on("mitreHitsOnly", "change", (e) => (writePref(HITS_ONLY_KEY, e.target.checked ? "1" : "0"), repaint()));
    on("mitreExpandAll", "click", () => setAllExpanded(true));
    on("mitreCollapseAll", "click", () => setAllExpanded(false));
    on("mitre", "click", onMatrixClick);
    on("mitre", "keydown", onMatrixKey);
    on("mitrePopover", "click", onPopoverClick);
    document.addEventListener("keydown", onDocumentKey);
    document.addEventListener("mousedown", onDocumentPointer);
  }

  // Called by render() with the List view's rows. `renderList` paints today's List into #mitre;
  // it runs whenever the switch says List, so that output never depends on this module.
  function renderPanel(args) {
    mmLast = args;
    const p = prefs();
    syncControls(p);
    if (p.view === "list") {
      closePopover(false);
      args.renderList();
      return;
    }
    paintMatrix();
  }

  function initMitreMatrix() {
    window.DfirMitreMatrix = {
      buildAttackMatrix,
      aggregateCell,
      buildMatrixHits,
      coerceCatalogue,
      matrixHtml,
      popoverHtml,
      renderPanel,
      setAllExpanded,
      prefs,
      PLATFORM_GROUPS,
      MATRIX_PLATFORMS,
    };
    if (mmWired) return;
    mmWired = true;
    syncControls(prefs());
    wireControls();
  }

  window.initMitreMatrix = initMitreMatrix;
})();
