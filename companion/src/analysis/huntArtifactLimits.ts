import { assetHostFromDropRelpath } from "./assetHost.js";

/**
 * Size limits for Velociraptor result files (#2746, #2805). A very large result (a 500 MB Hayabusa
 * file) is usually noise the investigator can post-process in Velociraptor into a much smaller file,
 * and importing it costs the server memory it may not have. Every result file is judged ON ITS OWN —
 * sizes are never summed across files or PCs (#2805: 100 PCs with a 40 MB file each hold nothing):
 *
 * - a file with one PC's results over `hostMb` is held;
 * - a file with several PCs' results (the hunt-wide `All <Artifact>` copy) over `totalMb` is held.
 *
 * Held files wait for the analyst (Import anyway / Skip). 0 turns a limit off. Pure.
 */

export const DEFAULT_HUNT_ARTIFACT_HOST_MAX_MB = 50;
export const DEFAULT_HUNT_ARTIFACT_TOTAL_MAX_MB = 200;
const MB = 1024 * 1024;

export interface HuntArtifactLimits {
  /** One result file holding one PC's results; 0 = off. */
  hostMb: number;
  /** One result file holding several PCs' results; 0 = off. */
  totalMb: number;
}

function megabytes(value: string | undefined, fallback: number): number {
  if (value === undefined || value.trim() === "") return fallback;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

export function huntArtifactLimitsFromEnv(env: NodeJS.ProcessEnv = process.env): HuntArtifactLimits {
  return {
    hostMb: megabytes(env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB, DEFAULT_HUNT_ARTIFACT_HOST_MAX_MB),
    totalMb: megabytes(env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB, DEFAULT_HUNT_ARTIFACT_TOTAL_MAX_MB),
  };
}

export interface SizedHuntImport {
  path: string;
  artifact: string;
  /** The hunt-wide `results/All <Artifact>` copy: every client in one file, so no per-PC limit. */
  huntWide: boolean;
  bytes: number;
}

export interface HeldHuntImport {
  path: string;
  artifact: string;
  /** The PC the file belongs to ("" for a hunt-wide copy). */
  host: string;
  bytes: number;
  /** The size that crossed the limit — the file's own size (never a sum, #2805). */
  groupBytes: number;
  /** "host": a one-PC file over `hostMb`; "total": a several-PCs file over `totalMb`. */
  reason: "host" | "total";
  limitMb: number;
}

/** The per-client folder a result file sits in (the segment before `results/`), or "". */
export function clientFolderOf(path: string): string {
  const segs = path.split("/");
  const at = segs.lastIndexOf("results");
  return at > 0 ? segs[at - 1] : "";
}

const hostOf = (path: string, huntWide: boolean): string =>
  huntWide ? "" : assetHostFromDropRelpath(path) || clientFolderOf(path);

/** The imports of ONE hunt plan that are over a limit — each file judged on its own (#2805). */
export function planHolds(imports: readonly SizedHuntImport[], limits: HuntArtifactLimits): HeldHuntImport[] {
  return imports.flatMap((f) => {
    const limitMb = f.huntWide ? limits.totalMb : limits.hostMb;
    if (!(limitMb > 0) || f.bytes <= limitMb * MB) return [];
    return [
      {
        ...{ path: f.path, artifact: f.artifact, host: hostOf(f.path, f.huntWide), bytes: f.bytes },
        ...{ groupBytes: f.bytes, reason: f.huntWide ? ("total" as const) : ("host" as const), limitMb },
      },
    ];
  });
}

export interface HeldArtifactRows {
  artifact: string;
  bytes: number;
  /** The PC(s) over the per-PC limit (at most 20 named), empty for the several-PCs limit. */
  hosts: string[];
  /** The largest one PC's share. */
  hostBytes: number;
  /** The size that crossed the limit: the largest PC's rows, or the rows with no ClientId. */
  overBytes: number;
  reason: "host" | "total";
  limitMb: number;
}

const rowField = (row: unknown, key: string): string => {
  const v = row && typeof row === "object" ? (row as Record<string, unknown>)[key] : undefined;
  return typeof v === "string" ? v : "";
};

/**
 * A bundle hunt's downloaded artifact, all PCs' rows together (#2753). Each PC's rows stand for that
 * PC's result file, so the artifact is held as a whole when one PC's rows pass `hostMb`; rows with no
 * ClientId are not one PC and are measured together against `totalMb`. Never summed across PCs
 * (#2805). Sizes are the rows' UTF-8 JSON bytes.
 */
export function artifactRowHold(
  artifact: string,
  rows: readonly unknown[],
  limits: HuntArtifactLimits,
): HeldArtifactRows | undefined {
  let bytes = 0;
  let unattributed = 0;
  const perClient = new Map<string, number>();
  const names = new Map<string, string>();
  for (const row of rows) {
    const n = Buffer.byteLength(JSON.stringify(row) ?? "", "utf8");
    bytes += n;
    const client = rowField(row, "ClientId");
    if (!client) {
      unattributed += n;
      continue;
    }
    perClient.set(client, (perClient.get(client) ?? 0) + n);
    if (!names.has(client)) names.set(client, rowField(row, "Fqdn") || client);
  }
  const hostBytes = Math.max(0, ...perClient.values());
  if (limits.hostMb > 0 && hostBytes > limits.hostMb * MB) {
    const over = [...perClient].filter(([, n]) => n > limits.hostMb * MB).map(([c]) => names.get(c) ?? c);
    return {
      artifact,
      bytes,
      hosts: over.slice(0, 20),
      hostBytes,
      overBytes: hostBytes,
      reason: "host",
      limitMb: limits.hostMb,
    };
  }
  if (limits.totalMb > 0 && unattributed > limits.totalMb * MB)
    return {
      artifact,
      bytes,
      hosts: [],
      hostBytes,
      overBytes: unattributed,
      reason: "total",
      limitMb: limits.totalMb,
    };
  return undefined;
}
