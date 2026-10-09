import { AUTO_FINDING_ID_PREFIX } from "./responseSchema.js";
import type { Finding, ForensicEvent, InvestigationState } from "./stateTypes.js";

// ── Dismissed parent-process clusters (#2092) ──────────────────────────────────────────────────
//
// The directory fold in highSeverityFindings.ts explains a tool corpus by its deep install path.
// It cannot explain a process tree: every child of one benign script host (cscript running
// gatherNetworkInfo.vbs, spawning a dozen `cmd.exe /c …`) sits in C:\Windows\System32, far too
// shallow and far too shared to fold on. So the analyst dismissed the cluster, and every sibling the
// dismissal did not cite came back as a fresh open High auto finding.
//
// This fold keys on the PARENT PROCESS instead. A dismissed (non-auto) finding claims a parent when
// it cites the parent row itself, or at least MIN_DISMISSED_CLUSTER_ROWS of its children. An
// uncovered High child of that parent, on the same host, is then linked onto the dismissal instead of
// minting a finding. Never a Critical row, and never a parent a live finding also cites — a disputed
// cluster is not folded.

const MIN_DISMISSED_CLUSTER_ROWS = 3;
const HOST_SUFFIX = /\s+@\s+\S+\s*$/;
const PARENT_GUID = /ParentProcessGuid:\s*(\{[^}]+\})/i;
const SELF_GUID = /(?<!Parent)ProcessGuid:\s*(\{[^}]+\})/i;
const PARENT_IMAGE = /ParentImage=(.+?)(?: - |$)/;
const PARENT_COMMAND = /ParentCommandLine=(.+?)(?: - [A-Z][A-Za-z]*=|$)/;
// The executable at the head of a command line: quoted, or anything up to `.exe`.
const LEADING_EXECUTABLE = /^"[^"]*"\s*|^\S*?\.exe(?=\s|$)\s*/i;

type ClusterRow = Pick<ForensicEvent, "description" | "message" | "asset">;

function hostOf(e: ClusterRow): string {
  return (e.asset ?? "").trim().toLowerCase();
}

function normalize(text: string): string {
  return text.replace(/"/g, "").replace(/\s+/g, " ").trim().toLowerCase();
}

// The parent image + command line a description quotes, only when the parent ran WITH arguments.
// A bare parent (explorer.exe, cmd.exe) is the parent of unrelated activity and is no cluster.
function describedParent(e: ClusterRow): string | undefined {
  const text = e.description.replace(HOST_SUFFIX, "");
  const image = PARENT_IMAGE.exec(text)?.[1];
  const command = PARENT_COMMAND.exec(text)?.[1];
  if (!image || !command) return undefined;
  if (!command.trim().replace(LEADING_EXECUTABLE, "").trim()) return undefined;
  return `img:${normalize(image)}|cmd:${normalize(command)}`;
}

/** The parent process a row belongs to: its logged ParentProcessGuid, else the described parent. */
export function parentKey(e: ClusterRow): string | undefined {
  const guid = e.message ? PARENT_GUID.exec(e.message)?.[1] : undefined;
  const key = guid ? `guid:${guid.toLowerCase()}` : describedParent(e);
  return key ? `${hostOf(e)}|${key}` : undefined;
}

// The key a row's CHILDREN carry, so a dismissal that cites the parent row seeds its cluster.
function selfKey(e: ClusterRow): string | undefined {
  const guid = e.message ? SELF_GUID.exec(e.message)?.[1] : undefined;
  return guid ? `${hostOf(e)}|guid:${guid.toLowerCase()}` : undefined;
}

// Every event a finding cites, from both directions of the link.
function citedRows(state: InvestigationState): Map<string, ForensicEvent[]> {
  const eventById = new Map(state.forensicTimeline.map((e) => [e.id, e] as const));
  const out = new Map<string, Map<string, ForensicEvent>>();
  const add = (fid: string, e: ForensicEvent | undefined): void => {
    if (!e) return;
    const rows = out.get(fid) ?? new Map<string, ForensicEvent>();
    out.set(fid, rows.set(e.id, e));
  };
  for (const e of state.forensicTimeline) for (const fid of e.relatedFindingIds) add(fid, e);
  for (const f of state.findings) for (const eid of f.relatedEventIds ?? []) add(f.id, eventById.get(eid));
  return new Map([...out].map(([fid, rows]) => [fid, [...rows.values()]] as const));
}

// The parent keys one dismissed finding has demonstrated are noise.
function claimedParents(rows: ForensicEvent[]): string[] {
  const counts = new Map<string, number>();
  for (const e of rows) {
    const key = parentKey(e);
    if (key) counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const byCount = [...counts].filter(([, n]) => n >= MIN_DISMISSED_CLUSTER_ROWS).map(([k]) => k);
  const bySelf = rows.map(selfKey).filter((k): k is string => k !== undefined);
  return [...byCount, ...bySelf];
}

function isHumanFinding(f: Finding): boolean {
  return !f.id.startsWith(AUTO_FINDING_ID_PREFIX);
}

/** Parent key -> the dismissed finding that explains that parent's whole cluster. */
export function dismissedClusters(state: InvestigationState): Map<string, string> {
  const cited = citedRows(state);
  const clusters = new Map<string, string>();
  const disputed = new Set<string>();
  for (const f of state.findings.filter(isHumanFinding)) {
    const rows = cited.get(f.id) ?? [];
    if (f.status !== "dismissed") {
      for (const e of rows) for (const k of [parentKey(e), selfKey(e)]) if (k) disputed.add(k);
      continue;
    }
    for (const k of claimedParents(rows)) if (!clusters.has(k)) clusters.set(k, f.id);
  }
  return new Map([...clusters].filter(([k]) => !disputed.has(k)));
}

/** The dismissed finding whose parent-process cluster `e` belongs to, if any. Never a Critical row. */
export function findDismissedCluster(
  e: ForensicEvent,
  clusters: ReadonlyMap<string, string>,
): string | undefined {
  if (e.severity === "Critical" || clusters.size === 0) return undefined;
  const key = parentKey(e);
  return key ? clusters.get(key) : undefined;
}
