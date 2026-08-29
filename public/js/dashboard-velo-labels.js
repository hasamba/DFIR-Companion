// The include/exclude LABEL FILTER on a Velociraptor bundle run.
//
// IT OFFERS WHAT THE FLEET CARRIES, NOT WHAT THE ANALYST CAN SPELL. This was two free text boxes
// whose contents went straight into a hunt's include_labels/exclude_labels. A typo there does not
// fail: Velociraptor matches no client, so the hunt launches, reports success, and collects from
// nobody. Deriving the choices from the cached inventory makes that mistake unspellable.
//
// PURE, AND HOLDS NOTHING. The fleet snapshot lives in js/dashboard-velo-triage.js, which owns the
// load that refreshes it; every function here takes the clients or the form it needs as an
// argument. That is what lets the whole control be tested without a DOM.
//
// A NOTE ON THE SUMMARY WORDING. It says "include: all clients" / "exclude: nothing" rather than
// explaining how several picked labels combine, because that is Velociraptor's rule to state, not
// this control's, and it differs by server version. The picker reports WHAT is selected; the hunt
// conditions decide what that selects.

// Every label the cached fleet actually carries, deduped and sorted.
//
// CASE IS SIGNIFICANT. Velociraptor label matching is case-sensitive, so DMZ and dmz are two
// different filters and both stay offerable; they sort next to each other (lowercased key, raw
// string as the tiebreak) so it is visible that there are two rather than looking like a duplicate.
//
// The dedup uses a Set, not `out.includes()`. Nothing caps the cached inventory — it is the whole
// enrolled fleet — so the scan runs once per client label, and a linear re-scan of the distinct set
// on each one is the picker stalling the toolbar on a large deployment. The array is still what
// gets returned, because the order below is the product.
function veloFleetLabels(clients) {
  const seen = new Set();
  const out = [];
  for (const c of clients || []) {
    for (const raw of (c && c.labels) || []) {
      const label = String(raw == null ? "" : raw).trim();
      if (label && !seen.has(label)) {
        seen.add(label);
        out.push(label);
      }
    }
  }
  return out.sort((a, b) => {
    const la = a.toLowerCase(),
      lb = b.toLowerCase();
    if (la !== lb) return la < lb ? -1 : 1;
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

// What the collapsed picker reads when it is shut: the label itself when one is picked, a count
// beyond that, and what NOT picking anything means when none is.
function veloLabelSummaryText(kind, picked) {
  const verb = kind === "exc" ? "exclude" : "include";
  const n = (picked || []).length;
  if (!n) return verb + (kind === "exc" ? ": nothing" : ": all clients");
  if (n === 1) return verb + ": " + picked[0];
  return verb + ": " + n + " labels";
}

// One picker: a <details> whose summary is the current selection and whose body is one checkbox per
// label, so any number of labels can be picked at once.
//
// THE EMPTY STATE TEACHES. A picker-only filter over an empty cache offers nothing and, without a
// reason, reads as a broken control rather than a snapshot nobody has taken yet — so it names the
// button that fills it. It is a plain note, not an empty dropdown.
function veloLabelPickerHtml(kind, labels) {
  const verb = kind === "exc" ? "exclude" : "include";
  const cls = "velo-lbl velo-lbl-" + kind;
  if (!(labels || []).length)
    return (
      `<span class="${cls}" title="The label picker is filled from the cached client inventory." ` +
      `data-safe-style="font-size:11px;color:var(--text-dim);padding:4px">${verb}: no labels cached — ` +
      `use ↻ Refresh client list on Settings → Velociraptor</span>`
    );
  const boxes = labels
    .map(
      (l) =>
        `<label data-safe-style="display:block;font-size:12px;padding:2px 0;white-space:nowrap;cursor:pointer">` +
        `<input type="checkbox" class="velo-lbl-box" value="${escAttr(l)}" /> ${esc(l)}</label>`,
    )
    .join("");
  return (
    `<details class="${cls}" data-safe-style="position:relative;flex:0 1 auto;min-width:120px">` +
    `<summary data-safe-style="cursor:pointer;font-size:12px;padding:4px;border:1px solid var(--border-color);border-radius:4px;white-space:nowrap">` +
    `${veloLabelSummaryText(kind, [])}</summary>` +
    `<div data-safe-style="position:absolute;z-index:5;max-height:220px;overflow:auto;padding:6px 8px;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:4px">` +
    `${boxes}</div></details>`
  );
}

// The labels checked in one picker. An empty-state note has no boxes, so a run over a fleet whose
// inventory was never refreshed reads as "no filter" instead of throwing.
function veloPickedLabels(form, kind) {
  const root =
    form && form.querySelector ? form.querySelector(".velo-lbl-" + kind) : null;
  if (!root || !root.querySelectorAll) return [];
  const out = [];
  for (const box of root.querySelectorAll(".velo-lbl-box"))
    if (box.checked) out.push(box.value);
  return out;
}

// Keep each collapsed summary in step with what is checked inside it — the picker is shut most of
// the time, so the summary is the only place the current filter is visible before Run.
function veloWireLabelPickers(form) {
  for (const kind of ["inc", "exc"]) {
    const root =
      form && form.querySelector
        ? form.querySelector(".velo-lbl-" + kind)
        : null;
    if (!root || !root.querySelectorAll || !root.querySelector) continue;
    const summary = root.querySelector("summary");
    if (!summary) continue;
    for (const box of root.querySelectorAll(".velo-lbl-box"))
      box.onchange = () => {
        summary.textContent = veloLabelSummaryText(
          kind,
          veloPickedLabels(form, kind),
        );
      };
  }
}

window.veloFleetLabels = veloFleetLabels;
window.veloLabelSummaryText = veloLabelSummaryText;
window.veloLabelPickerHtml = veloLabelPickerHtml;
window.veloPickedLabels = veloPickedLabels;
window.veloWireLabelPickers = veloWireLabelPickers;
