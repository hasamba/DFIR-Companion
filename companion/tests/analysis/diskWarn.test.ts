import { describe, it, expect } from "vitest";
import {
  getDiskWarningLevel,
  getDiskStats,
  diskWarnEnvThresholds,
  DEFAULT_DISK_THRESHOLDS,
} from "../../src/analysis/diskWarn.js";

describe("getDiskWarningLevel", () => {
  it("returns none when well below all thresholds", () => {
    expect(getDiskWarningLevel(50, DEFAULT_DISK_THRESHOLDS)).toBe("none");
  });

  it("returns none just below the warn threshold", () => {
    expect(getDiskWarningLevel(69.9, DEFAULT_DISK_THRESHOLDS)).toBe("none");
  });

  it("returns warning at the warn threshold", () => {
    expect(getDiskWarningLevel(70, DEFAULT_DISK_THRESHOLDS)).toBe("warning");
  });

  it("returns warning between warn and danger", () => {
    expect(getDiskWarningLevel(80, DEFAULT_DISK_THRESHOLDS)).toBe("warning");
  });

  it("returns danger at the danger threshold", () => {
    expect(getDiskWarningLevel(85, DEFAULT_DISK_THRESHOLDS)).toBe("danger");
  });

  it("returns danger between danger and critical", () => {
    expect(getDiskWarningLevel(90, DEFAULT_DISK_THRESHOLDS)).toBe("danger");
  });

  it("returns critical at the critical threshold", () => {
    expect(getDiskWarningLevel(95, DEFAULT_DISK_THRESHOLDS)).toBe("critical");
  });

  it("returns critical above the critical threshold", () => {
    expect(getDiskWarningLevel(99, DEFAULT_DISK_THRESHOLDS)).toBe("critical");
  });

  it("accepts custom thresholds", () => {
    const t = { warnPct: 50, dangerPct: 60, criticalPct: 70 };
    expect(getDiskWarningLevel(49, t)).toBe("none");
    expect(getDiskWarningLevel(55, t)).toBe("warning");
    expect(getDiskWarningLevel(65, t)).toBe("danger");
    expect(getDiskWarningLevel(75, t)).toBe("critical");
  });
});

describe("getDiskStats", () => {
  it("computes used percentage from a mock statfs", async () => {
    const mockStatfs = async (_p: string) => ({ blocks: 1000, bfree: 300, bsize: 4096 });
    const stats = await getDiskStats("/fake-path", { statfs: mockStatfs });
    expect(stats.totalBytes).toBe(1000 * 4096);
    expect(stats.freeBytes).toBe(300 * 4096);
    expect(stats.usedPct).toBeCloseTo(70, 5);
  });

  it("returns 0% used when the filesystem is empty (full, no used)", async () => {
    const mockStatfs = async (_p: string) => ({ blocks: 1000, bfree: 1000, bsize: 512 });
    const stats = await getDiskStats("/fake-path", { statfs: mockStatfs });
    expect(stats.usedPct).toBe(0);
  });

  it("handles a 100% full filesystem without NaN", async () => {
    const mockStatfs = async (_p: string) => ({ blocks: 100, bfree: 0, bsize: 4096 });
    const stats = await getDiskStats("/fake-path", { statfs: mockStatfs });
    expect(stats.usedPct).toBe(100);
    expect(stats.freeBytes).toBe(0);
  });

  it("returns 0% used when blocks is 0 (no division by zero)", async () => {
    const mockStatfs = async (_p: string) => ({ blocks: 0, bfree: 0, bsize: 4096 });
    const stats = await getDiskStats("/fake-path", { statfs: mockStatfs });
    expect(stats.usedPct).toBe(0);
  });

  it("returns zeros instead of throwing when the path doesn't exist yet (fresh install)", async () => {
    const mockStatfs = async (p: string) => {
      const err = new Error(`ENOENT: no such file or directory, statfs '${p}'`) as NodeJS.ErrnoException;
      err.code = "ENOENT";
      throw err;
    };
    const stats = await getDiskStats("/missing-cases-dir", { statfs: mockStatfs });
    expect(stats).toEqual({ totalBytes: 0, freeBytes: 0, usedPct: 0 });
  });

  it("rethrows non-ENOENT errors", async () => {
    const mockStatfs = async (_p: string) => {
      const err = new Error("EACCES: permission denied") as NodeJS.ErrnoException;
      err.code = "EACCES";
      throw err;
    };
    await expect(getDiskStats("/no-access", { statfs: mockStatfs })).rejects.toThrow("EACCES");
  });
});

describe("diskWarnEnvThresholds", () => {
  it("returns defaults when DFIR_DISK_WARN_PCT is not set", () => {
    delete process.env.DFIR_DISK_WARN_PCT;
    const t = diskWarnEnvThresholds();
    expect(t).toEqual(DEFAULT_DISK_THRESHOLDS);
  });

  it("derives danger from env var and warn/critical around it", () => {
    process.env.DFIR_DISK_WARN_PCT = "80";
    const t = diskWarnEnvThresholds();
    expect(t.dangerPct).toBe(80);
    expect(t.warnPct).toBe(65);      // 80 - 15
    expect(t.criticalPct).toBe(90);  // 80 + 10
    delete process.env.DFIR_DISK_WARN_PCT;
  });

  it("clamps criticalPct to max 99 and warnPct to min 1", () => {
    process.env.DFIR_DISK_WARN_PCT = "95";
    const t = diskWarnEnvThresholds();
    expect(t.criticalPct).toBe(99);  // 95 + 10 = 105 → clamped to 99
    expect(t.warnPct).toBe(80);      // 95 - 15 = 80
    delete process.env.DFIR_DISK_WARN_PCT;
  });

  it("disables the check when env var is 0 (thresholds above 100%)", () => {
    process.env.DFIR_DISK_WARN_PCT = "0";
    const t = diskWarnEnvThresholds();
    expect(t.warnPct).toBeGreaterThan(100);
    expect(t.dangerPct).toBeGreaterThan(100);
    expect(t.criticalPct).toBeGreaterThan(100);
    delete process.env.DFIR_DISK_WARN_PCT;
  });

  it("returns defaults for non-numeric env var", () => {
    process.env.DFIR_DISK_WARN_PCT = "abc";
    expect(diskWarnEnvThresholds()).toEqual(DEFAULT_DISK_THRESHOLDS);
    delete process.env.DFIR_DISK_WARN_PCT;
  });
});
