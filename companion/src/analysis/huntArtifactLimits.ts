import { assetHostFromDropRelpath } from "./assetHost.js";

/**
 * Size limits for one Velociraptor hunt export's artifacts (#2746). A very large artifact (a 500 MB
 * Hayabusa result) is usually noise the investigator can post-process in Velociraptor into a much
 * smaller file, and importing it costs the server memory it may not have. So before a hunt zip imports
 * anything, every result file that would import is measured (unpacked size, from the zip's index):
 *
 * - per PC: one client's files for one artifact over `hostMb` are held;
 * - across PCs: one artifact over `totalMb`, summed over every client (or one hunt-wide copy that
 *   size), is held for every client.
 *
 * Held files wait for the analyst (Import anyway / Skip). 0 turns a limit off. Pure.
 */

export const DEFAULT_HUNT_ARTIFACT_HOST_MAX_MB = 50;
export const DEFAULT_HUNT_ARTIFACT_TOTAL_MAX_MB = 200;
const MB = 1024 * 1024;

export interface HuntArtifactLimits {
  /** One PC's results for one artifact; 0 = off. */
  hostMb: number;
  /** One artifact across every PC of the hunt; 0 = off. */
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
  /** What crossed the limit: the PC's files for this artifact, or the artifact across every PC. */
  groupBytes: number;
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

/** The imports of ONE hunt plan that are over a limit, each with the reason and the size that crossed. */
export function planHolds(imports: readonly SizedHuntImport[], limits: HuntArtifactLimits): HeldHuntImport[] {
  const byArtifact = new Map<string, SizedHuntImport[]>();
  for (const imp of imports) byArtifact.set(imp.artifact, [...(byArtifact.get(imp.artifact) ?? []), imp]);
  const held: HeldHuntImport[] = [];
  for (const [artifact, files] of byArtifact) {
    const total = files.reduce((n, f) => n + f.bytes, 0);
    if (limits.totalMb > 0 && total > limits.totalMb * MB) {
      for (const f of files)
        held.push({
          ...{ path: f.path, artifact, host: hostOf(f.path, f.huntWide), bytes: f.bytes },
          ...{ groupBytes: total, reason: "total", limitMb: limits.totalMb },
        });
      continue;
    }
    if (!(limits.hostMb > 0)) continue;
    const byClient = new Map<string, SizedHuntImport[]>();
    for (const f of files) {
      if (f.huntWide) continue;
      const client = clientFolderOf(f.path);
      byClient.set(client, [...(byClient.get(client) ?? []), f]);
    }
    for (const group of byClient.values()) {
      const sum = group.reduce((n, f) => n + f.bytes, 0);
      if (sum <= limits.hostMb * MB) continue;
      for (const f of group)
        held.push({
          ...{ path: f.path, artifact, host: hostOf(f.path, false), bytes: f.bytes },
          ...{ groupBytes: sum, reason: "host", limitMb: limits.hostMb },
        });
    }
  }
  return held;
}
