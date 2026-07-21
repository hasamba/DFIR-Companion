import { describe, it, expect } from "vitest";
import {
  previewFloors, planBatches, DEFAULT_MAX_BATCHES,
  sanitizeObservations, renderObservationDigest, OBSERVATION_CAP_PER_BATCH,
  digestFitsBudget, planCondenseRounds, MAX_CONDENSE_ROUNDS,
} from "../../src/analysis/deepPass.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

function ev(id: string, t: string, sev: Severity, desc = id, asset?: string): ForensicEvent {
  return {
    id, timestamp: t, description: desc, severity: sev,
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    ...(asset ? { asset } : {}),
  };
}

// 40 Critical, 60 High, 100 Medium, 200 Low, 50 Info — all distinct descriptions so nothing groups.
function mixedCase(): ForensicEvent[] {
  const out: ForensicEvent[] = [];
  const add = (n: number, sev: Severity, prefix: string) => {
    for (let i = 0; i < n; i++) {
      out.push(ev(
        `${prefix}${i}`,
        `2026-05-20T${String(i % 24).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}:00Z`,
        sev,
        `${prefix} distinct ${prefix}${i}`,
      ));
    }
  };
  add(40, "Critical", "crit"); add(60, "High", "high"); add(100, "Medium", "med");
  add(200, "Low", "low"); add(50, "Info", "info");
  return out;
}

describe("previewFloors", () => {
  it("reports cumulative volume per floor, never counting Info", () => {
    const rows = previewFloors(mixedCase(), { cap: 100 });
    const byFloor = Object.fromEntries(rows.map((r) => [r.floor, r]));

    expect(byFloor.Critical.events).toBe(40);
    expect(byFloor.High.events).toBe(100);      // Critical + High
    expect(byFloor.Medium.events).toBe(200);
    expect(byFloor.Low.events).toBe(400);       // everything except the 50 Info
    expect(rows.every((r) => r.events <= 400)).toBe(true);
  });

  it("computes batch counts from the rows that survive grouping", () => {
    const rows = previewFloors(mixedCase(), { cap: 100 });
    const low = rows.find((r) => r.floor === "Low")!;
    expect(low.rows).toBe(400);                 // nothing groups: all descriptions distinct
    expect(low.batches).toBe(4);                // ceil(400 / 100)
    const crit = rows.find((r) => r.floor === "Critical")!;
    expect(crit.batches).toBe(1);
  });

  it("estimates tokens from the rendered rows, not from a fixed guess", () => {
    // Select the High floor explicitly — index 0 is Critical, which holds none of these events.
    const at = (rows: ReturnType<typeof previewFloors>) => rows.find((r) => r.floor === "High")!;
    const short = at(previewFloors([ev("a", "2026-05-20T09:00:00Z", "High", "x")], { cap: 100 }));
    const long = at(previewFloors([ev("a", "2026-05-20T09:00:00Z", "High", "x".repeat(400))], { cap: 100 }));
    expect(short.estimatedInputTokens).toBeGreaterThan(0);
    expect(long.estimatedInputTokens).toBeGreaterThan(short.estimatedInputTokens);
  });

  it("returns a zero row for a floor with no events rather than omitting it", () => {
    const rows = previewFloors([ev("m", "2026-05-20T09:00:00Z", "Medium")], { cap: 100 });
    const crit = rows.find((r) => r.floor === "Critical")!;
    expect(crit.events).toBe(0);
    expect(crit.batches).toBe(0);
  });

  it("orders floors most-severe first", () => {
    expect(previewFloors(mixedCase(), { cap: 100 }).map((r) => r.floor))
      .toEqual(["Critical", "High", "Medium", "Low"]);
  });
});

describe("planBatches", () => {
  const rows = Array.from({ length: 250 }, (_, i) =>
    ev(`e${i}`, `2026-05-20T${String(i % 24).padStart(2, "0")}:00:00Z`, "High"));

  it("splits into chronological chunks of at most the cap", () => {
    const batches = planBatches(rows, 100);
    expect(batches).toHaveLength(3);
    expect(batches[0]).toHaveLength(100);
    expect(batches[2]).toHaveLength(50);
    // chronological across the whole plan
    const flat = batches.flat().map((e) => e.timestamp);
    expect(flat).toEqual([...flat].sort());
  });

  it("returns one batch when everything fits", () => {
    expect(planBatches(rows, 1000)).toHaveLength(1);
  });

  it("returns nothing for an empty input", () => {
    expect(planBatches([], 100)).toEqual([]);
  });

  it("never returns a zero-size batch even for a nonsense cap", () => {
    expect(planBatches(rows, 0).every((b) => b.length > 0)).toBe(true);
  });

  it("exposes a batch ceiling default", () => {
    expect(DEFAULT_MAX_BATCHES).toBeGreaterThan(0);
  });
});

describe("sanitizeObservations", () => {
  const valid = new Set(["e1", "e2", "e3"]);

  it("keeps a well-formed observation and its known event ids", () => {
    const out = sanitizeObservations(
      { observations: [{ summary: "archive staged", hosts: ["ws-01"], firstSeen: "2026-05-20T09:00:00Z", lastSeen: "2026-05-20T09:30:00Z", eventIds: ["e1", "e2"], whyItMatters: "precedes an upload" }] },
      valid,
    );
    expect(out).toHaveLength(1);
    expect(out[0].eventIds).toEqual(["e1", "e2"]);
  });

  it("drops event ids the case does not contain, so findings can never cite a ghost", () => {
    const out = sanitizeObservations(
      { observations: [{ summary: "x", eventIds: ["e1", "nope", "e9"], whyItMatters: "y" }] },
      valid,
    );
    expect(out[0].eventIds).toEqual(["e1"]);
  });

  it("drops an observation left with no real evidence", () => {
    expect(sanitizeObservations({ observations: [{ summary: "x", eventIds: ["ghost"], whyItMatters: "y" }] }, valid)).toEqual([]);
  });

  it("ignores a severity or finding field a batch tried to smuggle in", () => {
    const out = sanitizeObservations(
      { observations: [{ summary: "x", eventIds: ["e1"], whyItMatters: "y", severity: "Critical", title: "Ransomware" }] },
      valid,
    );
    expect(out).toHaveLength(1);
    expect(JSON.stringify(out[0])).not.toContain("Critical");
    expect(JSON.stringify(out[0])).not.toContain("Ransomware");
  });

  it("caps how many observations one batch can contribute", () => {
    const many = Array.from({ length: OBSERVATION_CAP_PER_BATCH + 10 }, (_, i) => ({ summary: `s${i}`, eventIds: ["e1"], whyItMatters: "w" }));
    expect(sanitizeObservations({ observations: many }, valid)).toHaveLength(OBSERVATION_CAP_PER_BATCH);
  });

  it("survives junk without throwing", () => {
    expect(sanitizeObservations(null, valid)).toEqual([]);
    expect(sanitizeObservations({}, valid)).toEqual([]);
    expect(sanitizeObservations({ observations: "nope" }, valid)).toEqual([]);
    expect(sanitizeObservations({ observations: [null, 5, "x"] }, valid)).toEqual([]);
  });
});

describe("renderObservationDigest", () => {
  it("renders each observation with its hosts, window and event ids", () => {
    const block = renderObservationDigest([
      { summary: "archive staged", hosts: ["ws-01"], firstSeen: "2026-05-20T09:00:00Z", lastSeen: "2026-05-20T09:30:00Z", eventIds: ["e1"], whyItMatters: "precedes an upload" },
    ]);
    expect(block).toContain("archive staged");
    expect(block).toContain("ws-01");
    expect(block).toContain("e1");
    expect(block).toContain("precedes an upload");
  });

  it("returns an empty string for no observations, so it costs no tokens", () => {
    expect(renderObservationDigest([])).toBe("");
  });

  it("labels the block as evidence from parts of the timeline not shown directly", () => {
    const block = renderObservationDigest([{ summary: "s", eventIds: ["e1"], whyItMatters: "w" }]);
    expect(block).toMatch(/not shown|not included|elsewhere in the timeline/i);
  });
});

describe("condensing", () => {
  const obs = (n: number) => Array.from({ length: n }, (_, i) => ({
    summary: `observation number ${i} with a reasonably long factual summary line`,
    whyItMatters: "it precedes an outbound transfer",
    eventIds: [`e${i}`],
  }));

  it("fits when the digest is under budget", () => {
    expect(digestFitsBudget(obs(5), 100_000)).toBe(true);
  });

  it("does not fit when the digest exceeds budget", () => {
    expect(digestFitsBudget(obs(5000), 500)).toBe(false);
  });

  it("plans condense batches only when needed", () => {
    expect(planCondenseRounds(obs(5), 100_000, 50)).toEqual([]);
    const rounds = planCondenseRounds(obs(500), 500, 50);
    expect(rounds.length).toBeGreaterThan(0);
    expect(rounds.every((b) => b.length <= 50)).toBe(true);
    expect(rounds.flat()).toHaveLength(500);
  });

  it("caps the number of rounds so a pathological case terminates", () => {
    expect(MAX_CONDENSE_ROUNDS).toBeGreaterThan(0);
    expect(MAX_CONDENSE_ROUNDS).toBeLessThanOrEqual(5);
  });
});
