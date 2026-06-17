import { statfs } from "node:fs/promises";

export interface DiskStats {
  totalBytes: number;
  freeBytes: number;
  usedPct: number;
}

export type DiskWarningLevel = "none" | "warning" | "danger" | "critical";

export interface DiskWarnThresholds {
  warnPct: number;
  dangerPct: number;
  criticalPct: number;
}

export const DEFAULT_DISK_THRESHOLDS: DiskWarnThresholds = {
  warnPct: 70,
  dangerPct: 85,
  criticalPct: 95,
};

/**
 * Build thresholds from DFIR_DISK_WARN_PCT.
 * When set, that value is the "danger" level; warn is 15 pp below and critical 10 pp above.
 */
export function diskWarnEnvThresholds(): DiskWarnThresholds {
  const pct = Number(process.env.DFIR_DISK_WARN_PCT);
  if (!Number.isFinite(pct) || pct <= 0 || pct >= 100) return DEFAULT_DISK_THRESHOLDS;
  return {
    warnPct: Math.max(1, pct - 15),
    dangerPct: pct,
    criticalPct: Math.min(99, pct + 10),
  };
}

export function getDiskWarningLevel(
  usedPct: number,
  thresholds: DiskWarnThresholds = DEFAULT_DISK_THRESHOLDS,
): DiskWarningLevel {
  if (usedPct >= thresholds.criticalPct) return "critical";
  if (usedPct >= thresholds.dangerPct) return "danger";
  if (usedPct >= thresholds.warnPct) return "warning";
  return "none";
}

export interface DiskStatsDeps {
  statfs?: (path: string) => Promise<{ blocks: number; bfree: number; bsize: number }>;
}

export async function getDiskStats(path: string, deps: DiskStatsDeps = {}): Promise<DiskStats> {
  const s = deps.statfs ? await deps.statfs(path) : await statfs(path);
  const totalBytes = s.blocks * s.bsize;
  const freeBytes = s.bfree * s.bsize;
  const usedPct = totalBytes > 0 ? ((totalBytes - freeBytes) / totalBytes) * 100 : 0;
  return { totalBytes, freeBytes, usedPct };
}
