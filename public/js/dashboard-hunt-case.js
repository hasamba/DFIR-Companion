// Threat Hunt panel (#2670): the #sec-hunt-case section of a hunt-mode case.
//
// Shows whether the case is a proactive threat hunt, the coverage its hunts recorded (hosts that
// answered cleanly versus targeted; "coverage unknown" for uploaded exports), the graded hunt items
// (policy / new / rare / download, one entry per program with its hosts), and two analyst actions:
//   - Convert to incident — offered whenever the hunt holds any High or Critical finding; it keeps
//     every piece of evidence and marks the AI conclusions out of date.
//   - Re-grade with current baseline — re-grades this case against the client's current baseline,
//     including rows that were demoted, and says how many rows the raw record no longer holds.
//
// Every server- or evidence-derived string is written with textContent, never innerHTML.
(function () {
  "use strict";

  const byId = (id) => document.getElementById(id);
  let huntCaseRenderGen = 0;

  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  }

  async function call(url, opts) {
    try {
      const res = await fetch(url, opts);
      let body = {};
      try {
        body = await res.json();
      } catch {
        body = {};
      }
      return { ok: res.ok, status: res.status, body };
    } catch (e) {
      return { ok: false, status: 0, body: { error: String((e && e.message) || e) } };
    }
  }

  const post = (url, body) =>
    call(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

  const caseUrl = (caseId, tail) => `/cases/${encodeURIComponent(caseId)}/hunt/${tail}`;

  function coverageText(c) {
    if (!c) return "";
    if (!c.known) return `Coverage: ${c.reason}. No absence can be claimed and no percentage stated.`;
    const of = c.targeted ? ` of ${c.targeted} targeted` : "";
    const gap = c.notAnswered > 0 ? `; ${c.notAnswered} did not answer (coverage gap)` : "";
    const names = Array.isArray(c.partialArtifactNames) ? c.partialArtifactNames : [];
    const notGraded = names.length ? ` (rarity not graded for what they reported: ${names.join(", ")})` : "";
    const partial = c.partialArtifacts > 0 ? `; ${c.partialArtifacts} partial artifact collection(s)${notGraded}` : "";
    return `Coverage: ${c.answered} host(s)${of} answered cleanly${gap}${partial}.`;
  }

  function itemsTable(items) {
    const wrap = el("div", null, "hunt-items");
    if (!items || !items.length) {
      wrap.appendChild(el("p", "No hunt item is graded on this case yet.", "ev-sub"));
      return wrap;
    }
    const table = el("table", null, "hunt-items-table");
    const head = el("tr");
    for (const h of ["Kind", "Item", "Severity", "Hosts", "Why"]) head.appendChild(el("th", h));
    table.appendChild(head);
    for (const i of items) {
      const tr = el("tr");
      tr.appendChild(el("td", i.kind));
      tr.appendChild(el("td", i.label));
      tr.appendChild(el("td", i.severity));
      const more = i.moreHosts > 0 ? ` (+${i.moreHosts} more)` : "";
      tr.appendChild(el("td", `${i.hostCount}: ${(i.hosts || []).join(", ")}${more}`));
      tr.appendChild(el("td", i.reason));
      table.appendChild(tr);
    }
    wrap.appendChild(table);
    return wrap;
  }

  async function convert(caseId, status) {
    const ok = window.confirm(
      "Convert this threat hunt to an incident?\n\nAll evidence and analyst work is kept. The case switches to " +
        "incident framing, and the current AI conclusions are marked out of date until the next synthesis.",
    );
    if (!ok) return;
    status.textContent = "Converting…";
    const r = await post(caseUrl(caseId, "convert-to-incident"), {});
    status.textContent = r.ok ? "Converted to an incident. Run synthesis to re-frame the conclusions." : `Convert failed: ${r.body.error || r.status}`;
    if (r.ok) loadHuntCase(caseId);
  }

  async function regrade(caseId, status) {
    const ok = window.confirm(
      "Re-grade this case with the client's current baseline?\n\nThis is audit-logged. Rows already demoted are " +
        "re-read from the raw record; rows the raw record has evicted cannot be recovered without a re-import.",
    );
    if (!ok) return;
    status.textContent = "Re-grading…";
    const r = await post(caseUrl(caseId, "regrade"), {});
    if (!r.ok) {
      status.textContent = `Re-grade failed: ${r.body.error || r.status}`;
      return;
    }
    const b = r.body;
    const evicted = b.evicted > 0 ? ` ${b.evicted} row(s) are no longer in the raw record — re-import to recover them.` : "";
    status.textContent = `Re-graded against baseline version ${b.baselineVersion}: ${b.changed} row(s) changed, ${b.entries} hunt item(s).${evicted}`;
    loadHuntCase(caseId);
  }

  function actions(caseId, s) {
    const bar = el("div", null, "hunt-actions");
    const status = el("span", "", "ev-sub");
    if (s.convertOffered) {
      const b = el("button", "Convert to incident", "hunt-convert-btn");
      b.type = "button";
      b.title = "The hunt holds a High or Critical finding — convert it to an incident (keeps all evidence)";
      b.addEventListener("click", () => convert(caseId, status));
      bar.appendChild(b);
    }
    if (s.regradeAvailable) {
      const b = el("button", "Re-grade with current baseline", "hunt-regrade-btn");
      b.type = "button";
      b.addEventListener("click", () => regrade(caseId, status));
      bar.appendChild(b);
    }
    bar.appendChild(status);
    return bar;
  }

  async function loadHuntCase(caseId) {
    const box = byId("huntCasePanel");
    if (!box || !caseId) return;
    const gen = ++huntCaseRenderGen;
    const r = await call(caseUrl(caseId, "status"));
    if (gen !== huntCaseRenderGen) return;
    box.replaceChildren();
    if (!r.ok) {
      box.appendChild(el("p", `Threat hunt status unavailable: ${r.body.error || r.status}`, "ev-sub"));
      return;
    }
    const s = r.body;
    if (s.convertedFrom) {
      box.appendChild(el("p", `Converted from a threat hunt to an incident on ${s.convertedAt || "an earlier date"}.`, "ev-sub"));
    }
    if (!s.hunt) {
      if (!s.convertedFrom) box.appendChild(el("p", "This case is not a threat hunt. Pick the “Threat hunt” template to switch it to hunt mode.", "ev-sub"));
      return;
    }
    if (s.clientName) box.appendChild(el("p", `Client: ${s.clientName}${s.baselineVersion ? ` · baseline version ${s.baselineVersion}` : ""}`));
    box.appendChild(el("p", coverageText(s.coverage)));
    box.appendChild(itemsTable(s.items));
    box.appendChild(actions(caseId, s));
  }

  window.loadHuntCase = loadHuntCase;
})();
