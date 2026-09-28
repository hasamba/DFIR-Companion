// Pure layout of the case's ATT&CK techniques onto the Enterprise matrix (#1764) — the model the
// dashboard's MITRE panel (Matrix view) and the interactive HTML report both draw.
//
// No I/O: the catalogue comes from attackMatrixData.ts, the hits from the caller. The dashboard has
// a client mirror of this function (public/js/dashboard-mitre-matrix.js) because it re-derives
// the case's techniques in the browser the moment a finding is marked false positive; the parity
// suite (tests/dashboard/dashboardMitreMatrixParity.test.ts) pins the two to deep-equal output.
// Change one, change both.
//
// Layout rules, each one a decision the issue settled:
//   - One column per tactic, in the catalogue's (MITRE's) order.
//   - A technique in several tactics appears in every one of its columns.
//   - A sub-technique sits under its parent in every column the PARENT appears in.
//   - A case hit always shows, whatever the platform filter. Only gray cells are filtered.
//   - A hit the catalogue cannot place goes to `unmapped`. No hit is ever dropped.
//   - Cells sort by name, as the Navigator does.

import type { Severity } from "./stateTypes.js";
import { SEVERITY_RANK } from "./stateTypes.js";
import type { AttackMatrixData, AttackMatrixTactic, AttackMatrixTechnique } from "./attackMatrixData.js";

export type MatrixPlatform = "windows" | "linux" | "macos" | "cloud" | "all";
export const MATRIX_PLATFORMS: readonly MatrixPlatform[] = ["windows", "linux", "macos", "cloud", "all"];

// ATT&CK platform names per filter choice. "PRE" (Reconnaissance / Resource Development) is
// pre-compromise and platform-agnostic, so it matches every choice. ESXi and Network Devices
// show under "all" only.
export const PLATFORM_GROUPS: Readonly<Record<Exclude<MatrixPlatform, "all">, readonly string[]>> = {
  windows: ["Windows"],
  linux: ["Linux"],
  macos: ["macOS"],
  cloud: ["IaaS", "SaaS", "Office Suite", "Identity Provider", "Containers"],
};
const ANY_PLATFORM = "PRE";

export interface MatrixHit {
  id: string;
  worst: Severity;
  findingIds: string[];
  eventIds: string[];
  analystAccepted?: boolean;
}
export interface MatrixCell {
  id: string;
  name: string;
  hit?: MatrixHit;
  children: MatrixCell[];
  expanded: boolean;
}
export interface MatrixColumn {
  tactic: AttackMatrixTactic;
  hitCount: number;
  cells: MatrixCell[];
}
export interface MatrixModel {
  attackVersion: string;
  catalogueAvailable: boolean;
  columns: MatrixColumn[];
  unmapped: MatrixHit[];
}
export interface MatrixOptions {
  platform: MatrixPlatform;
  hitsOnly: boolean;
}

const byName = (a: { name: string; id: string }, b: { name: string; id: string }): number =>
  a.name.localeCompare(b.name) || a.id.localeCompare(b.id);

function matchesPlatform(t: AttackMatrixTechnique, platform: MatrixPlatform): boolean {
  if (platform === "all") return true;
  const group = PLATFORM_GROUPS[platform];
  return t.platforms.some((p) => p === ANY_PLATFORM || group.includes(p));
}

// One hit per id; duplicates merge (worst severity wins, ids union in first-seen order).
function indexHits(hits: readonly MatrixHit[]): Map<string, MatrixHit> {
  const out = new Map<string, MatrixHit>();
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

function cellFor(
  parent: AttackMatrixTechnique,
  kids: readonly AttackMatrixTechnique[],
  hits: Map<string, MatrixHit>,
  opts: MatrixOptions,
): MatrixCell | null {
  const parentHit = hits.get(parent.id);
  const children: MatrixCell[] = [];
  for (const k of kids) {
    const hit = hits.get(k.id);
    const visible = hit ? true : !opts.hitsOnly && matchesPlatform(k, opts.platform);
    if (visible)
      children.push({ id: k.id, name: k.name, ...(hit ? { hit } : {}), children: [], expanded: false });
  }
  const childHit = children.some((c) => c.hit);
  const visible =
    parentHit ||
    childHit ||
    (!opts.hitsOnly && (matchesPlatform(parent, opts.platform) || children.length > 0));
  if (!visible) return null;
  return {
    id: parent.id,
    name: parent.name,
    ...(parentHit ? { hit: parentHit } : {}),
    children: children.sort(byName),
    expanded: childHit,
  };
}

export function buildAttackMatrix(
  data: AttackMatrixData,
  hits: readonly MatrixHit[],
  opts: MatrixOptions,
): MatrixModel {
  const hitIndex = indexHits(hits);
  const known = new Map(data.techniques.map((t) => [t.id, t]));
  const kidsOf = new Map<string, AttackMatrixTechnique[]>();
  for (const t of data.techniques) {
    if (!t.parent || !known.has(t.parent)) continue;
    kidsOf.set(t.parent, [...(kidsOf.get(t.parent) ?? []), t]);
  }
  const placed = new Set<string>();

  const columns: MatrixColumn[] = [];
  for (const tactic of data.tactics) {
    const cells: MatrixCell[] = [];
    for (const t of data.techniques) {
      if (t.parent || !t.tactics.includes(tactic.shortname)) continue;
      const cell = cellFor(t, kidsOf.get(t.id) ?? [], hitIndex, opts);
      if (cell) cells.push(cell);
    }
    const hitIds = new Set<string>();
    for (const c of cells) {
      if (c.hit) hitIds.add(c.id);
      for (const k of c.children) if (k.hit) hitIds.add(k.id);
    }
    hitIds.forEach((id) => placed.add(id));
    if (opts.hitsOnly && hitIds.size === 0) continue;
    columns.push({ tactic, hitCount: hitIds.size, cells: cells.sort(byName) });
  }

  // Anything a column could not place: an id the catalogue lacks, a technique with no known tactic,
  // or a sub-technique whose parent is missing. A hit is never filtered out of a column, and a column
  // with a hit is never hidden, so "not placed" means exactly "cannot be placed".
  const unmapped = [...hitIndex.values()]
    .filter((h) => !placed.has(h.id))
    .sort((a, b) => a.id.localeCompare(b.id));

  return {
    attackVersion: data.attackVersion,
    catalogueAvailable: data.techniques.length > 0,
    columns,
    unmapped,
  };
}

// What a cell SHOWS: its own hit merged with every child hit (worst severity, union of ids). A
// child cell has no children, so for it this is just its own hit.
export function aggregateCell(cell: MatrixCell): MatrixHit | undefined {
  const all = [cell.hit, ...cell.children.map((c) => c.hit)].filter((h): h is MatrixHit => !!h);
  if (all.length === 0) return undefined;
  let worst: Severity = all[0].worst;
  for (const h of all) if (SEVERITY_RANK[h.worst] < SEVERITY_RANK[worst]) worst = h.worst;
  return {
    id: cell.id,
    worst,
    findingIds: [...new Set(all.flatMap((h) => h.findingIds))],
    eventIds: [...new Set(all.flatMap((h) => h.eventIds))],
    ...(all.some((h) => h.analystAccepted) ? { analystAccepted: true } : {}),
  };
}
