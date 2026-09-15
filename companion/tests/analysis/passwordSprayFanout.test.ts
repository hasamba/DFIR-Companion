import { describe, it, expect } from "vitest";
import {
  passwordSprayPatterns,
  sprayPatternRows,
  sprayPatternToMappedEvent,
  SPRAY_PATTERNS_MAX,
  ACCOUNTS_PER_ROW_MAX,
  type SprayCandidate,
} from "../../src/analysis/passwordSprayFanout.js";

const BASE = Date.parse("2024-05-14T12:00:00.000Z");
const iso = (offsetMs: number) => new Date(BASE + offsetMs).toISOString();

function candidate(overrides: Partial<SprayCandidate>): SprayCandidate {
  return {
    timestamp: iso(0),
    account: "alice",
    sourceIp: "10.0.0.1",
    hostOrTenant: "WEB-BO-01",
    outcome: "failed",
    locator: "record:0",
    ...overrides,
  };
}

describe("passwordSprayPatterns — the three shapes", () => {
  it("one account repeatedly failing is NOT a spray (below distinct-account threshold)", () => {
    const candidates = Array.from({ length: 10 }, (_, i) =>
      candidate({ account: "alice", timestamp: iso(i * 1000), locator: `record:${i}` }),
    );
    expect(passwordSprayPatterns(candidates)).toHaveLength(0);
  });

  it("one source failing 5 distinct accounts inside the burst window IS a spray", () => {
    const accounts = ["alice", "bob", "carol", "dave", "erin"];
    const candidates = accounts.map((a, i) => candidate({ account: a, timestamp: iso(i * 1000) }));
    // Qualifies for both windows at once (5s span fits inside burst AND slow) — both fire.
    const patterns = passwordSprayPatterns(candidates);
    expect(patterns.map((p) => p.windowKind).sort()).toEqual(["burst", "slow"]);
    expect(patterns.every((p) => p.accountsTotal === 5)).toBe(true);
  });

  it("many sources each failing once is noise — no group crosses threshold", () => {
    const candidates = Array.from({ length: 5 }, (_, i) =>
      candidate({ sourceIp: `10.0.0.${i + 1}`, account: `user${i}`, timestamp: iso(i * 1000) }),
    );
    expect(passwordSprayPatterns(candidates)).toHaveLength(0);
  });
});

describe("passwordSprayPatterns — windows", () => {
  it("a low-rate spray spread across most of the 24h window is missed by burst but caught by slow", () => {
    const accounts = ["alice", "bob", "carol", "dave", "erin"];
    const candidates = accounts.map(
      (a, i) => candidate({ account: a, timestamp: iso(i * 4 * 3_600_000) }), // every 4h, spans 16h
    );
    const patterns = passwordSprayPatterns(candidates);
    const kinds = patterns.map((p) => p.windowKind);
    expect(kinds).not.toContain("burst");
    expect(kinds).toContain("slow");
  });

  it("windows are non-overlapping and deterministic (tumbling, not sliding)", () => {
    // 5 accounts inside the first burst window, then 5 more just past it — two episodes, not one.
    const first = ["a", "b", "c", "d", "e"].map((a, i) =>
      candidate({ account: a, timestamp: iso(i * 1000) }),
    );
    const second = ["f", "g", "h", "i", "j"].map((a, i) =>
      candidate({ account: a, timestamp: iso(11 * 60_000 + i * 1000) }),
    );
    const patterns = passwordSprayPatterns([...first, ...second]).filter((p) => p.windowKind === "burst");
    expect(patterns).toHaveLength(2);
  });
});

describe("passwordSprayPatterns — source identity", () => {
  it("a candidate with no source IP is never counted at all", () => {
    const accounts = ["alice", "bob", "carol", "dave", "erin"];
    const candidates = accounts.map((a, i) =>
      candidate({ account: a, sourceIp: "", timestamp: iso(i * 1000) }),
    );
    expect(passwordSprayPatterns(candidates)).toHaveLength(0);
  });
});

describe("passwordSprayPatterns — dedup", () => {
  it("an exact duplicate (same account/source/host/second) counts once, not twice", () => {
    const accounts = ["alice", "bob", "carol", "dave", "erin"];
    const candidates = accounts.flatMap((a, i) => [
      candidate({ account: a, timestamp: iso(i * 1000), locator: `record:${i}` }),
      candidate({ account: a, timestamp: iso(i * 1000), locator: `record:${i}-dup` }), // same second
    ]);
    const patterns = passwordSprayPatterns(candidates);
    expect(patterns.every((p) => p.accountsTotal === 5)).toBe(true); // not inflated by the duplicate
  });

  it("two attempts from two different real IPs are never merged into one group", () => {
    const candidates = [
      candidate({ sourceIp: "10.0.0.1", account: "alice" }),
      candidate({ sourceIp: "10.0.0.2", account: "alice" }),
    ];
    // Neither IP alone reaches the threshold — proves they were never pooled together either.
    expect(passwordSprayPatterns(candidates)).toHaveLength(0);
  });
});

describe("passwordSprayPatterns — followedBySuccess", () => {
  const accounts = ["alice", "bob", "carol", "dave", "erin"];
  function spray() {
    return accounts.map((a, i) => candidate({ account: a, timestamp: iso(i * 1000) }));
  }

  it("fires when a targeted account succeeds strictly after episode close, within the grace window", () => {
    const success = candidate({
      account: "bob",
      outcome: "success",
      timestamp: iso(5 * 60_000), // 5 min after the episode closed (episode ends ~4s in)
    });
    const patterns = passwordSprayPatterns([...spray(), success]).filter((p) => p.windowKind === "burst");
    expect(patterns).toHaveLength(1);
    expect(patterns[0].followedBySuccess).toEqual({ account: "bob", timestamp: success.timestamp });
  });

  it("does NOT fire for a success recorded DURING the episode, before close", () => {
    const midEpisodeSuccess = candidate({ account: "bob", outcome: "success", timestamp: iso(2000) });
    const patterns = passwordSprayPatterns([...spray(), midEpisodeSuccess]).filter(
      (p) => p.windowKind === "burst",
    );
    expect(patterns[0].followedBySuccess).toBeUndefined();
  });

  it("does NOT fire for a success outside the grace window", () => {
    const lateSuccess = candidate({
      account: "bob",
      outcome: "success",
      timestamp: iso(200 * 60_000), // > 120 min default grace
    });
    const patterns = passwordSprayPatterns([...spray(), lateSuccess]).filter((p) => p.windowKind === "burst");
    expect(patterns[0].followedBySuccess).toBeUndefined();
  });

  it("does NOT fire for a success by an account the episode never targeted", () => {
    const untargetedSuccess = candidate({ account: "zoe", outcome: "success", timestamp: iso(5 * 60_000) });
    const patterns = passwordSprayPatterns([...spray(), untargetedSuccess]).filter(
      (p) => p.windowKind === "burst",
    );
    expect(patterns[0].followedBySuccess).toBeUndefined();
  });
});

describe("passwordSprayPatterns — caps and disclosure", () => {
  it("caps the shown account list at ACCOUNTS_PER_ROW_MAX and marks truncation", () => {
    const many = Array.from({ length: ACCOUNTS_PER_ROW_MAX + 10 }, (_, i) =>
      candidate({ account: `user${i}`, timestamp: iso(i) }),
    );
    const patterns = passwordSprayPatterns(many).filter((p) => p.windowKind === "burst");
    expect(patterns[0].accountsShown).toHaveLength(ACCOUNTS_PER_ROW_MAX);
    expect(patterns[0].accountsTruncated).toBe(true);
    expect(patterns[0].accountsTotal).toBe(ACCOUNTS_PER_ROW_MAX + 10);
  });

  it("sprayPatternRows emits an overflow row past SPRAY_PATTERNS_MAX, never silently drops", () => {
    // Build far more distinct groups than SPRAY_PATTERNS_MAX by spacing bursts a day apart per host.
    const candidates: SprayCandidate[] = [];
    for (let g = 0; g < SPRAY_PATTERNS_MAX + 3; g++) {
      for (const a of ["a", "b", "c", "d", "e"]) {
        candidates.push(
          candidate({
            hostOrTenant: `host-${g}`,
            account: a,
            timestamp: new Date(BASE + g * 48 * 3_600_000).toISOString(),
          }),
        );
      }
    }
    const rows = sprayPatternRows(candidates, {
      source: "ECAR",
      importer: "ecar",
      mappingVersion: "ecar-spray-v1",
    });
    // Each group qualifies for both burst and slow windows at once (all 5 accounts share one
    // instant), so there are 2*(SPRAY_PATTERNS_MAX+3) total episodes — far more than the cap.
    expect(rows.length).toBe(SPRAY_PATTERNS_MAX + 1); // capped, + 1 overflow row disclosing the rest
    expect(rows.at(-1)!.description).toContain("further pattern");
  });
});

describe("sprayPatternToMappedEvent — shape", () => {
  it("carries T1110.003, a stable aggKey, and canonical evidence locators", () => {
    const patterns = passwordSprayPatterns(
      ["alice", "bob", "carol", "dave", "erin"].map((a, i) =>
        candidate({ account: a, timestamp: iso(i * 1000) }),
      ),
    );
    const row = sprayPatternToMappedEvent(patterns[0], {
      source: "ECAR",
      importer: "ecar",
      mappingVersion: "ecar-spray-v1",
    });
    expect(row.mitre).toEqual(["T1110.003"]);
    expect(row.aggKey).toContain("spray-pattern|ecar|");
    expect(row.canonical?.evidence.rawRecords.length).toBeGreaterThan(0);
    expect(row.canonical?.producer.importer).toBe("ecar");
  });

  it("bumps severity one rank when followedBySuccess is present", () => {
    const success = candidate({ account: "bob", outcome: "success", timestamp: iso(5 * 60_000) });
    const patterns = passwordSprayPatterns([
      ...["alice", "bob", "carol", "dave", "erin"].map((a, i) =>
        candidate({ account: a, timestamp: iso(i * 1000) }),
      ),
      success,
    ]).filter((p) => p.windowKind === "burst");
    const row = sprayPatternToMappedEvent(patterns[0], {
      source: "ECAR",
      importer: "ecar",
      mappingVersion: "ecar-spray-v1",
    });
    expect(row.severity).toBe("High"); // burst=Medium, bumped once
  });
});
