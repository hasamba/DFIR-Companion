// Sigma paste card → "Dry-run on this case" (#2211): would the pasted rule have matched anything in
// the events this case already holds? POST /cases/:id/sigma/dry-run reads both timelines,
// deterministically and without AI, and writes nothing.
//
// A CLASSIC SCRIPT with no initializer: the card in js/dashboard-sigma-hunt.js calls
// runSigmaDryRun() when the analyst presses the button. It holds no state. Split out of that file
// to keep it under the 800-line limit.
//
// Every string is rendered with textContent, never innerHTML: event ids come from imported
// evidence and field names from the pasted rule, and both are attacker-shapeable.
//
// The point of the render is that "0 matches" is never silent. A field the stored events do not
// keep is named as not checkable, and a field no event carries is named as such.

function sigmaDryEl(tag, text, cls) {
  const el = document.createElement(tag);
  if (text !== undefined && text !== null) el.textContent = String(text);
  if (cls) el.className = cls;
  return el;
}

function sigmaDryNum(n) {
  return Number(n) || 0;
}

function sigmaDryOpen(id) {
  if (typeof closeHuntModal === "function") closeHuntModal();
  if (typeof jumpToEvent === "function")
    jumpToEvent(id, "This event is in the super-timeline only — search for it there, or promote it first.");
}

function sigmaDryFieldLine(f, eligible) {
  if (!f.checkable)
    return `${f.field}: not checkable here — the stored events do not keep it, so rows that depend on it are left undecided`;
  if (!sigmaDryNum(f.carried) && eligible)
    return `${f.field}: no event in this case keeps it, so a rule that needs it cannot fire here`;
  return `${f.field}: ${sigmaDryNum(f.carried)} of ${eligible} events carry it`;
}

function sigmaDryRefusals(box, refusals) {
  box.appendChild(sigmaDryEl("div", "The dry-run cannot test this rule on this case:"));
  const list = sigmaDryEl("ul");
  for (const r of refusals || []) list.appendChild(sigmaDryEl("li", `${r.path} — ${r.message}`));
  box.appendChild(list);
}

function renderSigmaDryRun(box, body) {
  box.textContent = "";
  const d = body && body.dryRun;
  if (!d) {
    box.appendChild(sigmaDryEl("div", `Dry-run failed: ${(body && body.error) || "no answer"}`));
    return;
  }
  if (!d.ok) {
    sigmaDryRefusals(box, d.refusals);
    return;
  }
  const eligible = sigmaDryNum(d.eligible);
  const where = (d.datasets || []).includes("super") ? "both timelines" : "the forensic timeline only";
  box.appendChild(
    sigmaDryEl("div", `Would match ${sigmaDryNum(d.matched)} of ${eligible} ${d.eventCategory} events in this case`),
  );
  box.appendChild(sigmaDryEl("div", `${sigmaDryNum(d.scanned)} events scanned in ${where}. No AI; nothing was written.`, "hq-help"));
  if (d.truncated)
    box.appendChild(
      sigmaDryEl("div", `The scan stopped at ${sigmaDryNum(d.maxRows)} events; events past that were not read.`),
    );
  if (sigmaDryNum(d.undecided))
    box.appendChild(
      sigmaDryEl("div", `${sigmaDryNum(d.undecided)} events could not be decided: the rule reads a field that is not checkable here.`),
    );
  const fields = sigmaDryEl("ul");
  for (const f of d.fields || []) fields.appendChild(sigmaDryEl("li", sigmaDryFieldLine(f, eligible)));
  box.appendChild(fields);
  if ((d.sampleIds || []).length) {
    const row = sigmaDryEl("div", "First matches: ");
    for (const id of d.sampleIds) {
      const b = sigmaDryEl("button", id, "sigma-compile-go");
      b.type = "button";
      b.title = "Open this event in the forensic timeline";
      b.setAttribute("data-jump-event", String(id));
      row.appendChild(b);
    }
    box.appendChild(row);
  }
  // One delegated handler, bound by reference: a render* function must not reach jumpToEvent,
  // whose filter reset commits to DfirFacets (dashboardFacets.test.ts "no renderer writes a facet").
  box.onclick = sigmaDryOnClick;
}

function sigmaDryOnClick(e) {
  const t = e.target && e.target.closest ? e.target.closest("button[data-jump-event]") : null;
  if (t) sigmaDryOpen(t.getAttribute("data-jump-event"));
}

/* exported runSigmaDryRun */
async function runSigmaDryRun() {
  const box = document.getElementById("sigmaDryRunRes");
  const btn = document.getElementById("sigmaDryRunBtn");
  const yamlEl = document.getElementById("sigmaYamlIn");
  const caseEl = document.getElementById("caseId");
  if (!box) return;
  const caseId = ((caseEl && caseEl.value) || "").trim();
  const yaml = (yamlEl && yamlEl.value) || "";
  if (!caseId) {
    box.textContent = "Connect to a case first.";
    return;
  }
  if (!yaml.trim()) {
    box.textContent = "Paste a Sigma rule first.";
    return;
  }
  if (btn) btn.disabled = true;
  box.textContent = "Dry-running against this case's stored events…";
  try {
    const res = await fetch(`/cases/${encodeURIComponent(caseId)}/sigma/dry-run`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ yaml }),
    });
    let body = {};
    try {
      body = await res.json();
    } catch {
      body = {};
    }
    if (!body.dryRun && !body.error && !res.ok) body = { error: `request failed (${res.status})` };
    renderSigmaDryRun(box, body);
  } catch (e) {
    box.textContent = `Dry-run failed: ${e.message}`;
  } finally {
    if (btn) btn.disabled = false;
  }
}
