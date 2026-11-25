// What the Velociraptor client lists say about the clients they do NOT show (#2887).
//
// TWO CUTS, BOTH USED TO BE SILENT.
//   1. The server reads at most 100,000 enrolled clients. A list cut there read as the whole fleet.
//      The stored inventory now carries `truncated`, and the triage card and the AI Agent picker
//      print one fixed sentence. No search by id or host exists for those lists, so the sentence
//      must not promise one — it points at a fleet hunt or the Velociraptor GUI instead.
//   2. The AI Agent picker drew only the first 2,000 endpoints, and its filter hid and showed only
//      the rows it had drawn, so an endpoint past the 2,000th could never be found. The filter now
//      runs over the whole list and only the DRAWN rows are capped, with a "showing N of M" note.
//
// PURE, AND HOLDS NOTHING. The callers own the lists and the DOM; every function here takes what it
// needs as an argument, which is what lets it be tested without a DOM.

const VELO_PICKER_CAP = 2000;
const VELO_CLIENTS_CUT_TEXT =
  "Showing the first 100,000 clients the server returned — a client past that is not listed here; run a fleet hunt or use the Velociraptor GUI.";

// The notice for an inventory the server cut at its row limit; "" for a complete one. Only a literal
// `true` counts, the same rule the server applies when it loads the file.
function veloClientsCutNotice(inv) {
  return inv && inv.truncated === true ? VELO_CLIENTS_CUT_TEXT : "";
}

// How an endpoint is named in the picker: host, then FQDN, then id — with the id beside it.
function veloPickerLabel(c) {
  return `${c.hostname || c.fqdn || c.clientId} (${c.clientId})`;
}

// The rows to draw for a filter text: every match across the WHOLE list, cut to the cap only for
// drawing. `matched` and `total` are what the note reports.
function veloPickerRows(clients, query, cap = VELO_PICKER_CAP) {
  const all = Array.isArray(clients) ? clients : [];
  const q = String(query || "").trim().toLowerCase();
  const matches = q ? all.filter((c) => veloPickerLabel(c).toLowerCase().includes(q) || String(c.fqdn || "").toLowerCase().includes(q)) : all;
  return { rows: matches.slice(0, cap), matched: matches.length, total: all.length };
}

// "Showing N of M endpoints — type to filter" while the cap hides some matches; "" when all are drawn.
function veloPickerNote(view) {
  if (!view || view.rows.length >= view.matched) return "";
  const n = (x) => x.toLocaleString("en-US");
  return `Showing ${n(view.rows.length)} of ${n(view.matched)} endpoints — type to filter`;
}

window.veloClientsCutNotice = veloClientsCutNotice;
window.veloPickerLabel = veloPickerLabel;
window.veloPickerRows = veloPickerRows;
window.veloPickerNote = veloPickerNote;
