import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { selectSynthesisEventsAnnotated } from "../../src/analysis/synthSelect.js";
import type { CommandSeat } from "../../src/analysis/ai/synthCommandSeats.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

// #2585: the distinct-cloud-operation seats must leave an ENDPOINT case's selection byte-identical.
// The digests below were captured from the selector BEFORE #2585 touched it, over deterministic
// endpoint-shaped cases (normal fill, anchor overflow, just under the overflow threshold, rarity on,
// command seats, and rows carrying a non-audit canonical envelope). A change to any of them means an
// endpoint timeline now sends the model different rows — that is a regression, not a re-baseline.

const BASE = Date.parse("2026-05-20T00:00:00Z");

// A tiny LCG so the fixtures are deterministic without Math.random.
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

const SEVS: Severity[] = ["Low", "Low", "Low", "Medium", "Medium", "High", "Critical"];
const HOSTS = ["ws-01", "ws-02", "srv-db", "dc-01"];
const PROCS = ["powershell.exe", "cmd.exe", "rundll32.exe", undefined, undefined];

function endpointCase(
  seed: number,
  n: number,
  highShare: number,
  nonAuditCanonical = false,
): ForensicEvent[] {
  const r = rng(seed);
  const out: ForensicEvent[] = [];
  for (let i = 0; i < n; i++) {
    const roll = r();
    const severity: Severity =
      roll < highShare ? (r() < 0.2 ? "Critical" : "High") : SEVS[Math.floor(r() * 5)];
    const e: ForensicEvent = {
      id: `e${seed}-${i}`,
      timestamp: new Date(BASE + Math.floor(r() * 86_400_000)).toISOString(),
      description: `activity ${Math.floor(r() * 40)} on ${HOSTS[i % HOSTS.length]}`,
      severity,
      mitreTechniques: r() < 0.15 ? ["T1059.001"] : [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: HOSTS[Math.floor(r() * HOSTS.length)],
      ...(PROCS[i % PROCS.length] ? { processName: PROCS[i % PROCS.length] } : {}),
      ...(r() < 0.1 ? { sources: ["Velociraptor", "THOR"] } : {}),
      ...(nonAuditCanonical && i % 3 === 0
        ? {
            canonical: {
              schemaVersion: 1,
              event: {
                category: "cloud",
                type: "activity-operation",
                action: `Microsoft.Compute/op${i % 7}`,
              },
              evidence: { rawRecords: [{ source: "azure-activity", locator: `record:${i}` }] },
              producer: { importer: "azure-activity", parserVersion: "1", mappingVersion: "x" },
            } as unknown as ForensicEvent["canonical"],
          }
        : {}),
    };
    out.push(e);
  }
  return out;
}

// Rarity by description bucket — the same shape the real prevalence index gives (1/count).
function rarityFor(events: readonly ForensicEvent[]): (e: ForensicEvent) => number {
  const counts = new Map<string, number>();
  for (const e of events) counts.set(e.description, (counts.get(e.description) ?? 0) + 1);
  return (e) => 1 / (counts.get(e.description) ?? 1);
}

function seatsFor(events: readonly ForensicEvent[]): CommandSeat[] {
  return events
    .filter((e) => e.severity === "Low" && e.processName === "cmd.exe")
    .slice(0, 12)
    .map((event, i) => ({ event, shadowedBy: i % 4 === 0 ? [events[0].id] : [] }));
}

function digest(sel: ReturnType<typeof selectSynthesisEventsAnnotated>): string {
  const rows = sel.events.map((e) => `${e.id}:${sel.classOf.get(e.id) ?? "-"}`);
  // Zero tallies are left out, so adding a selection class (with its 0) is not a selection change.
  const counts = Object.entries(sel.counts).filter(([, n]) => n > 0);
  return createHash("sha256")
    .update(JSON.stringify({ rows, counts, omitted: sel.omitted }))
    .digest("hex")
    .slice(0, 16);
}

describe("endpoint selection is unchanged by the cloud-operation seats (#2585)", () => {
  it("normal fill, no rarity", () => {
    const events = endpointCase(1, 400, 0.05);
    expect(digest(selectSynthesisEventsAnnotated(events, 120))).toBe("f9b808da89ecd659");
  });

  it("normal fill with rarity and command seats", () => {
    const events = endpointCase(2, 500, 0.08);
    expect(digest(selectSynthesisEventsAnnotated(events, 150, rarityFor(events), seatsFor(events)))).toBe(
      "4bce89ce4766781c",
    );
  });

  it("anchor overflow with rarity and command seats", () => {
    const events = endpointCase(3, 400, 0.6);
    expect(digest(selectSynthesisEventsAnnotated(events, 100, rarityFor(events), seatsFor(events)))).toBe(
      "11f114aa3fdf8385",
    );
  });

  it("just under the overflow threshold", () => {
    const events = endpointCase(4, 300, 0.31);
    const anchors = events.filter((e) => e.severity === "Critical" || e.severity === "High").length;
    expect(digest(selectSynthesisEventsAnnotated(events, anchors + 5, rarityFor(events)))).toBe(
      "bc636146b666c806",
    );
  });

  it("rows with a non-audit cloud envelope (Azure Activity) are not cloud operations here", () => {
    const events = endpointCase(5, 400, 0.1, true);
    expect(digest(selectSynthesisEventsAnnotated(events, 110, rarityFor(events)))).toBe("9912503e66825ef2");
  });
});
