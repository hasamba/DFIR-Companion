/**
 * Which files of a Velociraptor hunt export to import, and which to set aside (#2714). Pure.
 *
 * A hunt export can carry each artifact's rows up to four times — the per-client
 * `<host>-C.<id>/results/<Artifact>.json`, its `.csv` twin, the hunt-wide `results/All <Artifact>.json`
 * (the per-client rows combined) and its `.csv` twin — beside per-client metadata and
 * `hunt_info.json`. Importing every file imports every row up to four times.
 *
 * The rule goes by artifact, not by layout. For each artifact exactly one copy is imported:
 *   1. the hunt-wide `All <Artifact>.json`, when there is one (#2810) — ONE import for every client,
 *      its rows naming their host (`Fqdn`); one file per client meant one full case merge per client;
 *   2. otherwise the per-client `.json` files;
 *   3. a `.csv` only when no `.json` of that artifact exists (hunt-wide first, again).
 * An artifact whose per-client files a run already started (`started`, a resumed zip's ledger) keeps
 * the per-client copy, so a run begun before #2810 never imports the hunt-wide rows on top.
 *
 * Input is a list of `/`-separated paths — a drop-folder listing or a zip's member names — and the
 * output names only hunt MEMBERS. Anything else beside a hunt (a client's `uploads/` tree, an
 * unrelated file) is not a member, so the caller handles it exactly as it did before.
 */
import { clientFolderHost } from "./assetHost.js";

/** Why a hunt member is not imported. */
export type HuntSkipReason = "csv-twin" | "hunt-wide-copy" | "per-client-copy" | "metadata";

export interface HuntImport {
  path: string;
  /** The artifact key: the file stem, `All ` removed, `%2F` kept. */
  artifact: string;
  /** True for the hunt-wide `results/All <Artifact>` copy. */
  huntWide: boolean;
}

export interface HuntSkip {
  path: string;
  reason: HuntSkipReason;
}

export interface HuntPlan {
  /** The hunt's folder ("" when the hunt sits at the top of the listing). */
  root: string;
  imports: HuntImport[];
  skips: HuntSkip[];
  /** Every member path: imports plus skips. */
  members: string[];
}

export const HUNT_INFO_FILE = "hunt_info.json";

/** The files at the top of a client folder that describe the collection, not the endpoint. */
export const HUNT_CLIENT_METADATA = new Set([
  "client_info.json",
  "collection_context.json",
  "log.json",
  "log.csv",
  "requests.json",
  "uploads.json",
  "uploads.csv",
  "uploads.json.index",
]);

const RESULT_EXT = /\.(json|csv)$/i;
const HUNT_WIDE = /^All (.+)$/;

type Slot = "pcJson" | "pcCsv" | "hwJson" | "hwCsv";
type Member = { path: string; slot: Slot; artifact: string } | { path: string; slot: "metadata" };

/**
 * Every hunt in `paths`, each with the members to import and the members to set aside. `started`:
 * members a resumed run already handled; an artifact with a started per-client file stays per-client.
 */
export function planHuntExports(paths: readonly string[], started?: ReadonlySet<string>): HuntPlan[] {
  const roots = huntRoots(paths);
  if (roots.length === 0) return [];
  const byRoot = new Map<string, Member[]>(roots.map((r) => [r, []]));
  for (const path of paths) {
    const root = deepestRoot(path, roots);
    if (root === undefined) continue;
    const member = classify(path, root);
    if (member) byRoot.get(root)!.push(member);
  }
  const plans: HuntPlan[] = [];
  for (const [root, members] of byRoot) {
    if (members.length === 0) continue;
    plans.push(choose(root, members, started));
  }
  return plans;
}

/** The folders that hold a hunt: one with `hunt_info.json`, or one with a client-folder child. */
function huntRoots(paths: readonly string[]): string[] {
  const roots = new Set<string>();
  for (const path of paths) {
    const segs = path.split("/");
    if (segs[segs.length - 1] === HUNT_INFO_FILE) roots.add(segs.slice(0, -1).join("/"));
    for (let i = 0; i < segs.length - 1; i++) {
      if (clientFolderHost(segs[i]) !== null) {
        roots.add(segs.slice(0, i).join("/"));
        break;
      }
    }
  }
  return [...roots];
}

function deepestRoot(path: string, roots: readonly string[]): string | undefined {
  let best: string | undefined;
  for (const r of roots) {
    const inside = r === "" || path.startsWith(`${r}/`);
    if (inside && (best === undefined || r.length > best.length)) best = r;
  }
  return best;
}

function classify(path: string, root: string): Member | null {
  const rel = (root === "" ? path : path.slice(root.length + 1)).split("/");
  if (rel.length === 1 && rel[0] === HUNT_INFO_FILE) return { path, slot: "metadata" };
  if (rel.length === 2 && clientFolderHost(rel[0]) !== null) {
    return HUNT_CLIENT_METADATA.has(rel[1].toLowerCase()) ? { path, slot: "metadata" } : null;
  }
  if (rel.length === 3 && clientFolderHost(rel[0]) !== null && rel[1].toLowerCase() === "results") {
    return result(path, rel[2], false);
  }
  if (rel.length === 2 && rel[0].toLowerCase() === "results") return result(path, rel[1], true);
  return null;
}

function result(path: string, file: string, huntWide: boolean): Member | null {
  const ext = RESULT_EXT.exec(file);
  if (!ext) return null;
  let stem = file.slice(0, -ext[0].length);
  if (huntWide) {
    const m = HUNT_WIDE.exec(stem);
    if (!m) return null; // only `All <Artifact>` is a hunt-wide copy
    stem = m[1];
  }
  const json = ext[1].toLowerCase() === "json";
  const slot: Slot = huntWide ? (json ? "hwJson" : "hwCsv") : json ? "pcJson" : "pcCsv";
  return { path, slot, artifact: stem };
}

function choose(root: string, members: readonly Member[], started?: ReadonlySet<string>): HuntPlan {
  const imports: HuntImport[] = [];
  const skips: HuntSkip[] = [];
  const groups = new Map<string, Record<Slot, string[]>>();
  for (const m of members) {
    if (m.slot === "metadata") {
      skips.push({ path: m.path, reason: "metadata" });
      continue;
    }
    const g = groups.get(m.artifact) ?? { pcJson: [], pcCsv: [], hwJson: [], hwCsv: [] };
    g[m.slot].push(m.path);
    groups.set(m.artifact, g);
  }
  for (const [artifact, g] of groups) {
    const take = (paths: string[], huntWide: boolean): void => {
      for (const path of paths) imports.push({ path, artifact, huntWide });
    };
    const skip = (paths: string[], reason: HuntSkipReason): void => {
      for (const path of paths) skips.push({ path, reason });
    };
    const perClientStarted = !!started && [...g.pcJson, ...g.pcCsv].some((p) => started.has(p));
    if (g.hwJson.length && !perClientStarted) {
      take(g.hwJson, true);
      skip(g.pcJson, "per-client-copy");
      skip([...g.pcCsv, ...g.hwCsv], "csv-twin");
    } else if (g.pcJson.length) {
      take(g.pcJson, false);
      skip(g.pcCsv, "csv-twin");
      skip([...g.hwJson, ...g.hwCsv], "hunt-wide-copy");
    } else if (g.hwCsv.length && !perClientStarted) {
      take(g.hwCsv, true);
      skip(g.pcCsv, "per-client-copy");
    } else if (g.pcCsv.length) {
      take(g.pcCsv, false);
      skip([...g.hwJson, ...g.hwCsv], "hunt-wide-copy");
    } else take(g.hwJson.length ? g.hwJson : g.hwCsv, true);
  }
  imports.sort((a, b) => a.path.localeCompare(b.path));
  skips.sort((a, b) => a.path.localeCompare(b.path));
  return { root, imports, skips, members: [...imports.map((i) => i.path), ...skips.map((s) => s.path)] };
}

const REASON_LABEL: Record<HuntSkipReason, string> = {
  "csv-twin": "CSV twin(s) of an imported JSON",
  "hunt-wide-copy": "hunt-wide copy(ies) of per-client results",
  "per-client-copy": "per-client copy(ies) of an imported hunt-wide result",
  metadata: "collection metadata file(s)",
};

/** "3 CSV twin(s) of an imported JSON, 1 hunt-wide copy(ies) of per-client results, …" */
export function huntSkipSummary(skips: readonly { reason: HuntSkipReason }[]): string {
  const counts = new Map<HuntSkipReason, number>();
  for (const s of skips) counts.set(s.reason, (counts.get(s.reason) ?? 0) + 1);
  return (["csv-twin", "hunt-wide-copy", "per-client-copy", "metadata"] as const)
    .filter((r) => counts.has(r))
    .map((r) => `${counts.get(r)} ${REASON_LABEL[r]}`)
    .join(", ");
}
