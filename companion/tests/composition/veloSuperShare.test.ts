import { describe, it, expect } from "vitest";
import {
  createSuperShareLedger,
  superTimelineCap,
  superTimelineShares,
} from "../../src/composition/veloSuperShare.js";

// #1982 — one DFIR_SUPERTIMELINE_MAX is shared by every artifact of a super-only hunt. It used to be
// spent first-come in bundle order, so a full MFT (entry 1) used the whole cap and USN got nothing.

describe("superTimelineShares — water-fill by row count", () => {
  it("the triage example: 38 small artifacts get all their rows, MFT and USN split the rest", () => {
    const small = Array.from({ length: 38 }, (_, i) => (i < 36 ? 200 : 400)); // 36×200 + 2×400 = 8,000
    expect(small.reduce((a, b) => a + b, 0)).toBe(8000);
    const rows = [100_000, ...small.slice(0, 21), 100_000, ...small.slice(21)]; // MFT first, USN at 23
    const shares = superTimelineShares(rows, 100_000);
    expect(shares[0]).toBe(46_000); // MFT
    expect(shares[22]).toBe(46_000); // USN
    rows.forEach((r, i) => {
      if (r < 100_000) expect(shares[i]).toBe(r);
    });
    expect(shares.reduce((a, b) => a + b, 0)).toBe(100_000);
  });

  it("no artifact gets more than its need, and the total never passes the cap", () => {
    const rows = [5, 3_000, 17, 0, 90, 12_345, 1];
    for (const cap of [0, 1, 10, 100, 1_000, 10_000, 1_000_000]) {
      const shares = superTimelineShares(rows, cap);
      shares.forEach((s, i) => {
        expect(s).toBeGreaterThanOrEqual(0);
        expect(s).toBeLessThanOrEqual(rows[i]);
      });
      expect(shares.reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(cap);
    }
  });

  it("everything fits: each artifact gets exactly its rows", () => {
    expect(superTimelineShares([10, 20, 30], 1_000)).toEqual([10, 20, 30]);
  });
});

describe("superTimelineCap", () => {
  it("reads DFIR_SUPERTIMELINE_MAX and defaults to 100,000", () => {
    expect(superTimelineCap({})).toBe(100_000);
    expect(superTimelineCap({ DFIR_SUPERTIMELINE_MAX: "250" })).toBe(250);
    expect(superTimelineCap({ DFIR_SUPERTIMELINE_MAX: "nope" })).toBe(100_000);
  });
});

describe("createSuperShareLedger — the per-artifact limit in loop order", () => {
  it("an artifact read FIRST cannot eat the shares reserved for the artifacts after it", () => {
    const ledger = createSuperShareLedger([100, 100, 10], 100);
    const first = ledger.limit(0);
    expect(first).toBe(45); // 10 for the small one, the rest split in two
    ledger.charge(first);
    const second = ledger.limit(1);
    expect(second).toBe(45);
    ledger.charge(second);
    expect(ledger.limit(2)).toBe(10);
  });

  it("slack an earlier artifact did not use goes to a later one, never past the cap", () => {
    const ledger = createSuperShareLedger([10, 100], 60);
    expect(ledger.limit(0)).toBe(10);
    ledger.charge(4); // the severity floor dropped six
    expect(ledger.limit(1)).toBe(56);
  });
});
