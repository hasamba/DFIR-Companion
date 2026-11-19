// What the Velociraptor server holds for each artifact of a hunt or flow RIGHT NOW (#2700), so a
// re-import can tell an artifact it already read in full from one that has gained rows since.
//
// The promise is deliberately narrow: the fingerprint changes whenever the server's collection
// metadata for an artifact changes — a host reports it for the first time, a flow's row counter,
// state, start or activity time moves, or its result addresses change. It is NOT a content hash.
// `total_collected_rows` is per flow across all of its artifacts, so a new row in artifact B also
// flips artifact A of the same flow: over-cautious (A is re-read and de-duplicated), never silent.
// An artifact that any still-collecting host has listed is `live` and is always re-read.
//
// Any shape this file does not expect voids the whole read: unknown is never assumed to be
// "unchanged". The callers validate the ids before they reach the VQL literals.

import { createHash } from "node:crypto";
import { CLIENT_RE } from "./clientInventory.js";

const FLOW_ID_RE = /^F\.[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*$/;

/** One flow of a hunt (or the one flow of a flow import), as far as change detection needs it. */
export interface FlowMeta {
  clientId: string;
  flowId: string;
  state: string;
  rows: number;
  created: number;
  started: number;
  active: number;
  /** `artifacts_with_results`: plain names, or `Artifact/Source` for a multi-source artifact. */
  results: string[];
}

export interface ArtifactFingerprint {
  hash: string;
  /** A host that listed this artifact is still collecting: its rows can still grow. */
  live: boolean;
  /** At least one host listed results for this artifact. */
  listed: boolean;
}

const COLUMNS = (p: string): string =>
  `${p}client_id AS ClientId, ${p}session_id AS FlowId, ${p}state AS State, ` +
  `${p}total_collected_rows AS Rows, ${p}create_time AS Created, ${p}start_time AS Started, ` +
  `${p}active_time AS Active, ${p}artifacts_with_results AS Results`;

/** hunt_flows() nests the collection context under `Flow`. */
export function huntFlowMetaVql(huntId: string): string {
  return `SELECT ${COLUMNS("Flow.")} FROM hunt_flows(hunt_id='${huntId}')`;
}

/** flows() emits the collection context's fields at the top level. */
export function flowMetaVql(clientId: string, flowId: string): string {
  return `SELECT ${COLUMNS("")} FROM flows(client_id='${clientId}') WHERE session_id='${flowId}' LIMIT 1`;
}

// Protobuf JSON drops zero values, so a missing counter is 0; 64-bit counters may arrive as strings.
function count(v: unknown): number | undefined {
  if (v === undefined || v === null) return 0;
  const n = typeof v === "number" ? v : typeof v === "string" && /^\d+$/.test(v.trim()) ? Number(v) : NaN;
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

function parseRow(row: unknown): FlowMeta | undefined {
  if (!row || typeof row !== "object" || Array.isArray(row)) return undefined;
  const r = row as Record<string, unknown>;
  const clientId = typeof r.ClientId === "string" ? r.ClientId.trim() : "";
  const flowId = typeof r.FlowId === "string" ? r.FlowId.trim() : "";
  if (!CLIENT_RE.test(clientId) || !FLOW_ID_RE.test(flowId)) return undefined;
  if (r.State != null && typeof r.State !== "string") return undefined;
  if (r.Results != null && !Array.isArray(r.Results)) return undefined;
  const nums = [r.Rows, r.Created, r.Started, r.Active].map(count);
  if (nums.some((n) => n === undefined)) return undefined;
  const [rows, created, started, active] = nums as number[];
  const results = ((r.Results as unknown[] | undefined) ?? []).map((x) => String(x).trim()).filter(Boolean);
  const state = (typeof r.State === "string" ? r.State.trim().toUpperCase() : "") || "UNSET";
  return { clientId, flowId, state, rows, created, started, active, results };
}

/** hunt_flows rows → flows; [] for a hunt with no flows yet; undefined when the shape is unknown. */
export function parseHuntFlowMeta(rows: unknown): FlowMeta[] | undefined {
  if (!Array.isArray(rows)) return undefined;
  const out: FlowMeta[] = [];
  for (const row of rows) {
    const m = parseRow(row);
    if (!m) return undefined;
    out.push(m);
  }
  return out;
}

/** flows() rows → the one flow; undefined when it is not on the server or the shape is unknown. */
export function parseFlowMeta(rows: unknown): FlowMeta[] | undefined {
  const parsed = parseHuntFlowMeta(rows);
  return parsed && parsed.length ? parsed : undefined;
}

const TERMINAL = new Set(["FINISHED", "ERROR"]);

const addressesFor = (artifact: string, results: string[]): string[] =>
  results.filter((r) => r === artifact || r.startsWith(`${artifact}/`)).sort();

function fingerprintOne(flows: FlowMeta[], artifact: string): ArtifactFingerprint {
  const lines: string[] = [];
  let live = false;
  for (const f of flows) {
    const addresses = addressesFor(artifact, f.results);
    if (!addresses.length) continue;
    if (!TERMINAL.has(f.state)) live = true;
    lines.push(
      [f.clientId, f.flowId, f.state, f.rows, f.created, f.started, f.active, addresses.join(",")].join("|"),
    );
  }
  const hash = createHash("sha256").update(lines.sort().join("\n")).digest("hex");
  return { hash, live, listed: lines.length > 0 };
}

/** Per-artifact fingerprints, or undefined when the server state is unknown. */
export function fingerprintArtifacts(
  flows: FlowMeta[] | undefined,
  artifacts: readonly string[],
): Record<string, ArtifactFingerprint> | undefined {
  if (!flows) return undefined;
  return Object.fromEntries(artifacts.map((a) => [a, fingerprintOne(flows, a)]));
}
