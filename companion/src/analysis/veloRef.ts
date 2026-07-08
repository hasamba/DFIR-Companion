// Parse a pasted Velociraptor reference — a hunt id (H.xxx), a client+flow pair (C.xxx / F.xxx), or the
// GUI URL of either — into a typed ref the import route can act on. Pure + tokeniser-based (no VQL): a
// hunt has just a hunt id; a flow needs BOTH a client id and a flow id (Velociraptor can't look up a
// flow without its client), which the collection GUI URL carries. Ambiguous input (both a hunt token
// AND a flow token) returns null so the caller can ask the analyst to clarify.

export type VeloRef =
  | { kind: "hunt"; huntId: string; isNotebookUrl?: true; isUploadsUrl?: true }
  | { kind: "flow"; clientId: string; flowId: string; isNotebookUrl?: true; isUploadsUrl?: true };

// Capture-group form (not \b) so ids embedded in a URL path like /hunts/H.ABC/ or /collected/C.x/F.y
// are still isolated — the leading boundary is start-of-string or any non-[A-Za-z0-9.] char.
const HUNT = /(?:^|[^A-Za-z0-9.])(H\.[A-Za-z0-9]+)/g;
const CLIENT = /(?:^|[^A-Za-z0-9.])(C\.[A-Za-z0-9]+)/g;
// A flow id can carry dotted suffix segments — a hunt-launched collection's flow id is `F.<base>.H`
// — so capture the whole dotted id, not just the part before the first dot (else the ".H" is dropped
// and the flow can't be found).
const FLOW = /(?:^|[^A-Za-z0-9.])(F\.[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)/g;

// A Velociraptor GUI URL pointing at a hunt/flow's NOTEBOOK tab, e.g.
// "…/app/index.html?org_id=root#/collected/C.x/F.y/notebook" or "…#/hunts/H.x/notebook". The notebook
// shows the analyst's OWN ad-hoc VQL query results (e.g. filtered to a time range/severity) — a
// completely different row set than the flow/hunt's raw collected artifacts. There is no supported way
// for this server (a VQL/gRPC client, not a browser holding the GUI's session) to re-run that specific
// notebook cell's query and get back exactly what the analyst is looking at; only the DFIR Companion
// browser extension's "Push rows" button can, because it reads the GUI's own rendered table. So a
// notebook URL is flagged rather than silently resolved to the (much larger, unfiltered) flow/hunt.
const NOTEBOOK_PATH = /\/notebooks?(?:[/?#]|$)/i;

// A Velociraptor GUI URL pointing at a hunt/flow's "Uploaded Files" tab, e.g.
// "…#/collected/C.x/F.y/uploads" or "…#/hunts/H.x/uploads". Distinct from the raw-rows tabs
// (overview/results) — flagged so import-external can import ONLY the uploaded files and skip rows
// entirely when the analyst pastes this specific tab's URL.
const UPLOADS_PATH = /\/uploads(?:[/?#]|$)/i;

function tokens(s: string, re: RegExp): string[] {
  return [...s.matchAll(re)].map((m) => m[1]);
}

export function parseVeloRef(input: string): VeloRef | null {
  const raw = String(input ?? "").trim();
  const s = " " + raw; // leading space so a token at index 0 still has a boundary
  if (s.trim() === "") return null;
  const hunts = tokens(s, HUNT);
  const clients = tokens(s, CLIENT);
  const flows = tokens(s, FLOW);
  const isNotebookUrl = NOTEBOOK_PATH.test(raw) || undefined;
  const isUploadsUrl = UPLOADS_PATH.test(raw) || undefined;

  // A flow needs exactly one client + one flow token and NO hunt token.
  if (clients.length === 1 && flows.length === 1 && hunts.length === 0) {
    return { kind: "flow", clientId: clients[0], flowId: flows[0], ...(isNotebookUrl ? { isNotebookUrl } : {}), ...(isUploadsUrl ? { isUploadsUrl } : {}) };
  }
  // A hunt needs exactly one hunt token and no flow token.
  if (hunts.length === 1 && flows.length === 0) {
    return { kind: "hunt", huntId: hunts[0], ...(isNotebookUrl ? { isNotebookUrl } : {}), ...(isUploadsUrl ? { isUploadsUrl } : {}) };
  }
  return null;
}
