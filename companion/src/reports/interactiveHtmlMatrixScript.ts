// The inline renderer for the interactive report's ATT&CK Matrix section (#1764).
//
// It DRAWS, it does not lay out: every column, cell, nesting and expansion comes from the models
// buildMatrixEmbed() (interactiveHtmlMatrix.ts) built on the server with buildAttackMatrix().
// expandModel() only re-attaches the names and hits the compact form stores once; the report tests
// run it in a VM and pin it to deep-equal buildAttackMatrix() for all ten models. What it computes
// is display only, as the spec assigns to every renderer: a parent's shown severity and counts over
// parent + children (the aggregateCell() rule), and the popover's tactic list.
//
// Every case string (technique name, finding title, event text) reaches the page through
// textContent or setAttribute, never markup. It runs after the main report script in the same
// <script> element, so the finding cards and timeline rows it links to already exist.
const DRAW_PART = `
(function () {
  var M = window.__DFIR_MATRIX__;
  var CASE = window.__DFIR_CASE__ || { findings: [], timeline: [] };
  var SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  var TECH_RE = /^T\\d{4}(\\.\\d{3})?$/;
  var MAX_EVENTS = 50;

  function nameOf(id) { return M && Object.prototype.hasOwnProperty.call(M.names, id) ? M.names[id] : id; }

  function expandCell(c) {
    var cell = { id: c.id, name: nameOf(c.id) };
    if (c.h) cell.hit = M.hits[c.id];
    cell.children = (c.k || []).map(expandCell);
    cell.expanded = !!c.x;
    return cell;
  }

  function expandModel(key) {
    var m = M.models[key];
    var tactics = {};
    M.tactics.forEach(function (t) { tactics[t.id] = t; });
    return {
      attackVersion: M.attackVersion,
      catalogueAvailable: M.catalogueAvailable,
      columns: m.columns.map(function (col) {
        return { tactic: tactics[col.t], hitCount: col.n, cells: col.c.map(expandCell) };
      }),
      unmapped: m.unmapped.map(function (id) { return M.hits[id]; }),
    };
  }

  function uniq(list) {
    var seen = {}, out = [];
    list.forEach(function (x) { if (!seen["$" + x]) { seen["$" + x] = true; out.push(x); } });
    return out;
  }

  // What a cell SHOWS: its own hit merged with its children's (attackMatrix.ts aggregateCell()).
  function aggregate(cell) {
    var all = [cell.hit].concat(cell.children.map(function (c) { return c.hit; })).filter(Boolean);
    if (!all.length) return null;
    var worst = all[0].worst;
    all.forEach(function (h) { if (SEV_RANK[h.worst] < SEV_RANK[worst]) worst = h.worst; });
    return {
      id: cell.id,
      worst: worst,
      findingIds: uniq([].concat.apply([], all.map(function (h) { return h.findingIds; }))),
      eventIds: uniq([].concat.apply([], all.map(function (h) { return h.eventIds; }))),
      analystAccepted: all.some(function (h) { return h.analystAccepted; }),
    };
  }

  window.DfirReportMatrix = { expandModel: expandModel, aggregate: aggregate };

  var grid = document.getElementById("atm-grid");
  if (!M || !grid) return;
  var platformSel = document.getElementById("atm-platform");
  var hitsBox = document.getElementById("atm-hits");
  var legend = document.getElementById("atm-legend");
  var note = document.getElementById("atm-note");
  var pop = document.getElementById("atm-pop");
  var openState = {};
  var lastCell = null;

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (k === "class") n.className = attrs[k];
      else if (k === "text") n.textContent = attrs[k];
      else n.setAttribute(k, attrs[k]);
    }
    (children || []).forEach(function (c) {
      if (c != null) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function sevClass(s) { return SEV_RANK.hasOwnProperty(s) ? "sev-" + s : ""; }

  var tacticIndex = null;
  function tacticsOf(id) {
    if (!tacticIndex) {
      tacticIndex = {};
      expandModel("all|0").columns.forEach(function (col) {
        function add(c) {
          (tacticIndex["$" + c.id] = tacticIndex["$" + c.id] || []).push(col.tactic.name);
          c.children.forEach(add);
        }
        col.cells.forEach(add);
      });
    }
    return uniq(tacticIndex["$" + id] || []);
  }

  function cellLabel(cell, agg) {
    var s = cell.id + " " + cell.name;
    if (!agg) return s;
    return s + ", " + agg.worst + ", " + agg.findingIds.length + " findings, " + agg.eventIds.length + " events";
  }

  // Hover text for a cell's number and letter; a parent's count includes its sub-techniques.
  function badgeTitle(cell, agg) {
    var subs = cell.children.some(function (k) { return k.hit; }) ? " (with its sub-techniques)" : "";
    return agg.findingIds.length + " findings, " + agg.eventIds.length + " events" + subs + " · worst severity " + agg.worst;
  }

  function cellEl(cell) {
    var agg = aggregate(cell);
    var btn = el("button", { type: "button", class: "atm-cell " + (agg ? sevClass(agg.worst) : ""), "aria-label": cellLabel(cell, agg) }, [
      agg ? el("span", { class: "atm-badge", title: badgeTitle(cell, agg), text: (agg.findingIds.length + agg.eventIds.length) + " " + agg.worst.charAt(0) }) : null,
      cell.name,
    ]);
    btn.addEventListener("click", function (e) { e.stopPropagation(); openPopover(cell, agg, btn); });
    var row = el("div", { class: "atm-row" }, [btn]);
    var item = el("div", { class: "atm-item" }, [row]);
    if (cell.children.length) {
      var expanded = openState.hasOwnProperty(cell.id) ? openState[cell.id] : cell.expanded;
      var kids = el("div", { class: "atm-kids" }, cell.children.map(cellEl));
      kids.hidden = !expanded;
      var toggle = el("button", { type: "button", class: "atm-toggle", "aria-expanded": String(expanded),
        "aria-label": "Sub-techniques of " + cell.id, text: expanded ? "\\u2212" : "+" + cell.children.length });
      toggle.addEventListener("click", function () {
        kids.hidden = !kids.hidden;
        openState[cell.id] = !kids.hidden;
        toggle.setAttribute("aria-expanded", String(!kids.hidden));
        toggle.textContent = kids.hidden ? "+" + cell.children.length : "\\u2212";
      });
      row.appendChild(toggle);
      item.appendChild(kids);
    }
    return item;
  }

  function columnEl(title, hitCount, cells) {
    return el("div", { class: "atm-col" }, [
      el("h3", null, [title, el("span", { class: "atm-n", title: "Techniques seen in this tactic", text: hitCount + (hitCount === 1 ? " hit" : " hits") })]),
    ].concat(cells.map(cellEl)));
  }

  // Expand all / Collapse all: one explicit choice per parent that has sub-techniques, overriding
  // the automatic "open when a sub-technique is a hit" default until the reader changes it again.
  function setAllOpen(open) {
    var model = expandModel(platformSel.value + "|" + (hitsBox.checked ? 1 : 0));
    model.columns.forEach(function (col) {
      col.cells.forEach(function (c) { if (c.children.length) openState[c.id] = open; });
    });
    render();
  }

  function render() {
    closePopover();
    var model = expandModel(platformSel.value + "|" + (hitsBox.checked ? 1 : 0));
    clear(grid);
    model.columns.forEach(function (col) { grid.appendChild(columnEl(col.tactic.name, col.hitCount, col.cells)); });
    if (model.unmapped.length) {
      grid.appendChild(columnEl("Unmapped", model.unmapped.length, model.unmapped.map(function (h) {
        return { id: h.id, name: nameOf(h.id), hit: h, children: [], expanded: false };
      })));
    }
  }

  function renderLegend() {
    clear(legend);
    M.severities.forEach(function (s) { legend.appendChild(el("span", { class: sevClass(s), text: s })); });
    legend.appendChild(el("span", { text: "Cell number = findings + events · letter = worst severity · column number = techniques seen" }));
    legend.appendChild(el("span", { text: "ATT&CK Enterprise v" + M.attackVersion }));
    if (!M.catalogueAvailable) {
      note.hidden = false;
      note.textContent = "ATT&CK catalogue not available \\u2014 showing case techniques only.";
    }
  }
`;

// The popover, the jump links into the report's own finding cards and timeline rows, and the
// wiring. The second half of the same IIFE: split only so each half stays readable.
const POPOVER_PART = `
  var findingById = {};
  (CASE.findings || []).forEach(function (f) { findingById["$" + f.id] = f; });
  var eventById = {};
  (CASE.timeline || []).forEach(function (e) { eventById["$" + e.id] = e; });

  function flash(n) {
    if (n.scrollIntoView) n.scrollIntoView({ block: "center" });
    n.classList.add("atm-flash");
    setTimeout(function () { n.classList.remove("atm-flash"); }, 2000);
  }
  function fire(id, value, type) {
    var n = document.getElementById(id);
    if (!n || n.value === value) return;
    n.value = value;
    n.dispatchEvent(new Event(type));
  }
  function gotoFinding(id) {
    closePopover();
    if (!document.getElementById("finding-" + id)) fire("conf-slider", "0", "input");
    var card = document.getElementById("finding-" + id);
    if (card) { card.classList.add("open"); flash(card); }
  }
  function gotoEvent(id) {
    closePopover();
    if (!document.getElementById("event-" + id)) {
      fire("sev-filter", "all", "change"); fire("src-filter", "all", "change");
      fire("host-filter", "all", "change"); fire("search", "", "input");
    }
    var row = document.getElementById("event-" + id);
    if (row) flash(row);
  }
  function jumpLink(prefix, id, text, go) {
    var a = el("a", { href: "#" + prefix + encodeURIComponent(id), text: text });
    a.addEventListener("click", function (e) { e.preventDefault(); go(id); });
    return a;
  }

  function findingItem(id) {
    var f = findingById["$" + id];
    return el("li", null, [f ? jumpLink("finding-", id, id + " \\u2014 " + f.title, gotoFinding) : id]);
  }
  function eventItem(id) {
    var e = eventById["$" + id];
    if (!e) return el("li", { text: id + " (not in this report)" });
    var text = (e.timestamp || "") + " " + String(e.description || "").slice(0, 140);
    return el("li", null, [jumpLink("event-", id, text, gotoEvent)]);
  }

  function popoverBody(cell, agg) {
    var parts = [
      el("button", { type: "button", class: "atm-close", "aria-label": "Close", text: "\\u00d7" }),
      el("h4", { text: cell.id + " " + cell.name }),
    ];
    if (TECH_RE.test(cell.id)) {
      parts.push(el("p", null, [el("a", { href: "https://attack.mitre.org/techniques/" + cell.id.replace(".", "/") + "/",
        target: "_blank", rel: "noopener noreferrer", text: "View on attack.mitre.org" })]));
    }
    var tactics = tacticsOf(cell.id);
    parts.push(el("p", null, [el("b", { text: "Tactics: " }), tactics.length ? tactics.join(", ") : "Unmapped"]));
    if (!agg) { parts.push(el("p", { class: "empty", text: "Not seen in this case." })); return parts; }
    parts.push(el("p", null, [el("b", { text: "Worst severity: " }), el("span", { class: sevClass(agg.worst), text: agg.worst })]));
    if (agg.analystAccepted) parts.push(el("p", { text: "Accepted by analyst." }));
    parts.push(el("b", { text: "Findings (" + agg.findingIds.length + ")" }));
    parts.push(el("ul", null, agg.findingIds.map(findingItem)));
    parts.push(el("b", { text: "Forensic events (" + agg.eventIds.length + ")" }));
    var shown = agg.eventIds.slice(0, MAX_EVENTS).map(eventItem);
    if (agg.eventIds.length > MAX_EVENTS) shown.push(el("li", { text: "and " + (agg.eventIds.length - MAX_EVENTS) + " more" }));
    parts.push(el("ul", null, shown));
    return parts;
  }

  function openPopover(cell, agg, btn) {
    clear(pop);
    popoverBody(cell, agg).forEach(function (n) { pop.appendChild(n); });
    pop.querySelector(".atm-close").addEventListener("click", function () { closePopover(true); });
    pop.setAttribute("aria-label", cell.id + " " + cell.name);
    var r = btn.getBoundingClientRect();
    pop.style.left = Math.max(8, r.left + window.scrollX) + "px";
    pop.style.top = (r.bottom + window.scrollY + 4) + "px";
    pop.hidden = false;
    lastCell = btn;
  }
  function closePopover(refocus) {
    if (pop.hidden) return;
    pop.hidden = true;
    if (refocus && lastCell) lastCell.focus();
  }

  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closePopover(true); });
  document.addEventListener("click", function (e) { if (!pop.contains(e.target)) closePopover(false); });

  // Arrow keys move between cells: up/down within a column, left/right to the same row next door.
  grid.addEventListener("keydown", function (e) {
    var t = e.target;
    if (!t.classList || !t.classList.contains("atm-cell")) return;
    var col = t.closest(".atm-col");
    var cells = Array.prototype.slice.call(col.querySelectorAll(".atm-cell"));
    var i = cells.indexOf(t);
    var next = null;
    if (e.key === "ArrowDown") next = cells[i + 1];
    else if (e.key === "ArrowUp") next = cells[i - 1];
    else if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      var side = e.key === "ArrowLeft" ? col.previousElementSibling : col.nextElementSibling;
      var there = side ? side.querySelectorAll(".atm-cell") : [];
      next = there[Math.min(i, there.length - 1)];
    }
    if (next) { e.preventDefault(); next.focus(); }
  });

  platformSel.addEventListener("change", render);
  hitsBox.addEventListener("change", render);
  document.getElementById("atm-expand").addEventListener("click", function () { setAllOpen(true); });
  document.getElementById("atm-collapse").addEventListener("click", function () { setAllOpen(false); });
  renderLegend();
  render();
})();
`;

export const MATRIX_SCRIPT = DRAW_PART + POPOVER_PART;
