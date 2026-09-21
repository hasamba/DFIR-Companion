// Correlation cost on the shapes that made the hash and undated-path steps quadratic (#1483): one
// hash or one path with thousands of rows on one host. The bound is the union count, which is
// deterministic; the wall clock is a loose second guard (the cross product took 5–19 s at 20k).
import { describe, it, expect, beforeAll } from "vitest";
import { correlationGroups } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const N = 20000;
const SHA = "a".repeat(64);

function row(i: number, extra: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: `e${i}`,
    timestamp: "",
    description: `row ${i}`,
    severity: "Medium",
    sources: ["sysmon"],
    asset: "host1",
    ...extra,
  } as ForensicEvent;
}

const at = (i: number): string => new Date(Date.UTC(2026, 0, 1, 0, 0, 0, i)).toISOString();

function timed(events: ForensicEvent[]): { groups: number; ms: number } {
  const t0 = performance.now();
  const groups = correlationGroups(events, { windowMs: 5 * 60 * 1000 } as never).length;
  return { groups, ms: performance.now() - t0 };
}

// The cross product took 5–19 s per shape on the machine that measured it; the bucket walk takes
// 0.1–0.3 s. The bound is loose so a slow CI runner never turns it into a flake; the union counts
// are pinned exactly in correlateUnion.test.ts.
const BUDGET_MS = 5000;

describe("correlation stays linear on one hash / one path with thousands of rows (#1483)", () => {
  beforeAll(() => {
    // Warm the JIT and the allocator so the first shape is not billed for them.
    timed(Array.from({ length: 2000 }, (_, i) => row(i, { path: "C:\\warm.exe", sha256: SHA })));
  });

  it("same hash, same path, undated, all merge", () => {
    const evs = Array.from({ length: N }, (_, i) =>
      row(i, { path: "C:\\Windows\\Temp\\x.exe", sha256: SHA }),
    );
    const out = timed(evs);
    expect(out.groups).toBe(1);
    expect(out.ms).toBeLessThan(BUDGET_MS);
  });

  it("same hash, same path, dated, distinct command lines (every pair refused)", () => {
    // 2.5 s apart: outside the path step's 2 s window, so the hash step — which has no time
    // bound — carries the whole shape. Rows packed inside one window still pair in full there
    // (a temporal filter, not a bound); that residual is documented in correlate.ts.
    const evs = Array.from({ length: N }, (_, i) =>
      row(i, {
        timestamp: at(i * 2500),
        path: "C:\\Windows\\Temp\\x.exe",
        sha256: SHA,
        commandLine: `x.exe --run ${i}`,
      }),
    );
    const out = timed(evs);
    expect(out.groups).toBe(N);
    expect(out.ms).toBeLessThan(BUDGET_MS);
  });

  it("same hash, distinct paths (a note dropped in every directory)", () => {
    const evs = Array.from({ length: N }, (_, i) =>
      row(i, { timestamp: at(i * 10), path: `C:\\Users\\u\\dir${i}\\README.txt`, sha256: SHA }),
    );
    const out = timed(evs);
    expect(out.groups).toBe(N);
    expect(out.ms).toBeLessThan(BUDGET_MS);
  });

  it("same path, undated, one tool (nothing corroborates) and two tools (everything bridges)", () => {
    const one = Array.from({ length: N }, (_, i) =>
      row(i, { path: "C:\\Windows\\Temp\\x.dll", sources: ["YARA"] }),
    );
    const a = timed(one);
    expect(a.groups).toBe(N);
    expect(a.ms).toBeLessThan(BUDGET_MS);
    const two = one.map((e, i) => (i % 2 ? { ...e, sources: ["Volatility"] } : e));
    const b = timed(two);
    expect(b.groups).toBe(1);
    expect(b.ms).toBeLessThan(BUDGET_MS);
  });
});
