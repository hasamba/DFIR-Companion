// Parse a pasted Velociraptor reference — a hunt id (H.xxx), a client+flow pair (C.xxx / F.xxx), or the
// GUI URL of either — into a typed ref the import route can act on. Pure + tokeniser-based (no VQL): a
// hunt has just a hunt id; a flow needs BOTH a client id and a flow id (Velociraptor can't look up a
// flow without its client), which the collection GUI URL carries. Ambiguous input (both a hunt token
// AND a flow token) returns null so the caller can ask the analyst to clarify.

export type VeloRef =
  | { kind: "hunt"; huntId: string }
  | { kind: "flow"; clientId: string; flowId: string };

// Capture-group form (not \b) so ids embedded in a URL path like /hunts/H.ABC/ or /collected/C.x/F.y
// are still isolated — the leading boundary is start-of-string or any non-[A-Za-z0-9.] char.
const HUNT = /(?:^|[^A-Za-z0-9.])(H\.[A-Za-z0-9]+)/g;
const CLIENT = /(?:^|[^A-Za-z0-9.])(C\.[A-Za-z0-9]+)/g;
// A flow id can carry dotted suffix segments — a hunt-launched collection's flow id is `F.<base>.H`
// — so capture the whole dotted id, not just the part before the first dot (else the ".H" is dropped
// and the flow can't be found).
const FLOW = /(?:^|[^A-Za-z0-9.])(F\.[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)/g;

function tokens(s: string, re: RegExp): string[] {
  return [...s.matchAll(re)].map((m) => m[1]);
}

export function parseVeloRef(input: string): VeloRef | null {
  const s = " " + String(input ?? "").trim(); // leading space so a token at index 0 still has a boundary
  if (s.trim() === "") return null;
  const hunts = tokens(s, HUNT);
  const clients = tokens(s, CLIENT);
  const flows = tokens(s, FLOW);

  // A flow needs exactly one client + one flow token and NO hunt token.
  if (clients.length === 1 && flows.length === 1 && hunts.length === 0) {
    return { kind: "flow", clientId: clients[0], flowId: flows[0] };
  }
  // A hunt needs exactly one hunt token and no flow token.
  if (hunts.length === 1 && flows.length === 0) {
    return { kind: "hunt", huntId: hunts[0] };
  }
  return null;
}
