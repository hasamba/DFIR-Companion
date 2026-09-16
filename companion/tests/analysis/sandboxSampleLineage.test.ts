// #932.8: sandboxImport.ts's mapCape now records a report-scoped sample-association fact for
// each dropped/CAPE.payloads entry, instead of reducing them to bare IOCs. See
// RECOMMENDATION-932.8.md for why this is "listed-during-analysis-of," never parent/child descent.
import { describe, it, expect } from "vitest";
import { parseSandboxReport } from "../../src/analysis/sandboxImport.js";
import type { SiemEvent } from "../../src/analysis/siemImport.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";

const env = (e: SiemEvent) => canonicalEventEnvelopeSchema.parse(e.canonical);

const TARGET_SHA = "a".repeat(64);
const DROPPED_SHA = "c".repeat(64);
const PAYLOAD_SHA = "d".repeat(64);

function baseReport(overrides: Record<string, unknown> = {}) {
  return {
    info: { id: 42, score: 9.2, started: "2023-09-01 10:00:00" },
    target: { category: "file", file: { name: "invoice.exe", sha256: TARGET_SHA } },
    malscore: 9.2,
    signatures: [{ name: "injection_runpe", description: "x", severity: 3 }],
    ...overrides,
  };
}

function lineageEvent(events: SiemEvent[]): SiemEvent | undefined {
  return events.find((e) => e.description.startsWith("CAPE sandbox lineage:"));
}

describe("mapCape sample lineage (#932.8)", () => {
  it("records an association fact for a dropped file, with the target as the analyzed sample", () => {
    const report = baseReport({ dropped: [{ name: "evil.dll", sha256: DROPPED_SHA }] });
    const result = parseSandboxReport(JSON.stringify(report));
    const ev = lineageEvent(result.events);
    expect(ev).toBeTruthy();
    const block = env(ev!).sampleLineage!;
    expect(block.facts).toHaveLength(1);
    expect(block.facts[0]).toMatchObject({
      targetHashes: { sha256: TARGET_SHA },
      objectHashes: { sha256: DROPPED_SHA },
      reportedIn: ["dropped"],
      relationship: "listed-during-analysis-of",
    });
  });

  it("the lineage event is fixed at Medium severity, independent of the sample's own low malscore", () => {
    const report = baseReport({ malscore: 0.1, dropped: [{ name: "x.dll", sha256: DROPPED_SHA }] });
    const result = parseSandboxReport(JSON.stringify(report));
    const ev = lineageEvent(result.events);
    expect(ev!.severity).toBe("Medium");
  });

  it("merges an object listed in BOTH dropped and CAPE.payloads into one fact with both memberships", () => {
    const report = baseReport({
      dropped: [{ name: "x.dll", sha256: DROPPED_SHA }],
      CAPE: { payloads: [{ name: "x.dll", sha256: DROPPED_SHA, cape_type: "Injected image" }] },
    });
    const result = parseSandboxReport(JSON.stringify(report));
    const block = env(lineageEvent(result.events)!).sampleLineage!;
    expect(block.facts).toHaveLength(1);
    expect(block.facts[0].reportedIn.sort()).toEqual(["cape-payloads", "dropped"]);
    expect(block.facts[0].capeType).toBe("Injected image");
  });

  it("never claims a runtime-write/extraction distinction it cannot support — relationship is always the neutral literal", () => {
    const report = baseReport({
      dropped: [{ name: "a.exe", sha256: DROPPED_SHA }],
      CAPE: { payloads: [{ name: "b.exe", sha256: PAYLOAD_SHA }] },
    });
    const result = parseSandboxReport(JSON.stringify(report));
    const block = env(lineageEvent(result.events)!).sampleLineage!;
    expect(block.facts.every((f) => f.relationship === "listed-during-analysis-of")).toBe(true);
  });

  it("handles CAPE's own real array-shaped `name` field (a deduplicated list of basenames)", () => {
    const report = baseReport({ dropped: [{ name: ["a.exe", "b.exe"], sha256: DROPPED_SHA }] });
    const result = parseSandboxReport(JSON.stringify(report));
    const block = env(lineageEvent(result.events)!).sampleLineage!;
    expect(block.facts[0].objectNames).toEqual(["a.exe", "b.exe"]);
  });

  it("keeps guest_paths separate from the analysis-host storage path — never conflated with an endpoint path", () => {
    const report = baseReport({
      dropped: [
        {
          name: "a.exe",
          sha256: DROPPED_SHA,
          path: "/opt/cape/storage/a.exe",
          guest_paths: ["C:\\Users\\a\\a.exe"],
        },
      ],
    });
    const result = parseSandboxReport(JSON.stringify(report));
    const block = env(lineageEvent(result.events)!).sampleLineage!;
    expect(block.facts[0].objectGuestPaths).toEqual(["C:\\Users\\a\\a.exe"]);
    expect(JSON.stringify(block.facts[0])).not.toContain("/opt/cape/storage");
  });

  it("counts an object with no valid hash as malformed, never stored as a fact with an empty identity", () => {
    const report = baseReport({ dropped: [{ name: "a.exe" }, { name: "b.exe", sha256: DROPPED_SHA }] });
    const result = parseSandboxReport(JSON.stringify(report));
    const block = env(lineageEvent(result.events)!).sampleLineage!;
    expect(block.facts).toHaveLength(1);
    expect(block.malformed).toBe(1);
  });

  it("records a fact even when target.file is missing (e.g. a URL-target report) — never dropped", () => {
    const report = {
      ...baseReport({ dropped: [{ name: "a.exe", sha256: DROPPED_SHA }] }),
      target: { category: "url", url: "http://evil.example" },
    };
    const result = parseSandboxReport(JSON.stringify(report));
    const block = env(lineageEvent(result.events)!).sampleLineage!;
    expect(block.facts).toHaveLength(1);
    expect(block.facts[0].targetHashes).toBeUndefined();
  });

  it("two reports sharing a target hash and run id, with different dropped objects, both keep their own facts (H3)", () => {
    const reportA = baseReport({ dropped: [{ name: "a.exe", sha256: DROPPED_SHA }] });
    const reportB = baseReport({ dropped: [{ name: "z.exe", sha256: PAYLOAD_SHA }] });
    const result = parseSandboxReport(JSON.stringify([reportA, reportB]), { aggregate: false });
    const lineageEvents = result.events.filter((e) => e.description.startsWith("CAPE sandbox lineage:"));
    expect(lineageEvents).toHaveLength(2);
    const hashes = lineageEvents.map((e) => env(e).sampleLineage!.facts[0].objectHashes.sha256).sort();
    expect(hashes).toEqual([DROPPED_SHA, PAYLOAD_SHA].sort());
  });

  it("does not emit a lineage event at all when there are no dropped/payload entries", () => {
    const result = parseSandboxReport(JSON.stringify(baseReport()));
    expect(lineageEvent(result.events)).toBeUndefined();
  });

  it("preserves CAPE's own real numeric cape_type_code alongside the verbatim text", () => {
    const report = baseReport({
      dropped: [{ name: "a.exe", sha256: DROPPED_SHA, cape_type: "Unpacked PE image", cape_type_code: 1 }],
    });
    const result = parseSandboxReport(JSON.stringify(report));
    const block = env(lineageEvent(result.events)!).sampleLineage!;
    expect(block.facts[0].capeType).toBe("Unpacked PE image");
    expect(block.facts[0].capeTypeCode).toBe(1);
  });

  // ── Code review round (Codex) ─────────────────────────────────────────────

  it("the lineage carrier survives a default-cap batch dominated by higher-severity signatures (H1)", () => {
    const manySignatures = Array.from({ length: 2100 }, (_, i) => ({
      name: `sig${i}`,
      description: "x",
      severity: 3,
    }));
    const report = baseReport({
      signatures: manySignatures,
      dropped: [{ name: "a.exe", sha256: DROPPED_SHA }],
    });
    const result = parseSandboxReport(JSON.stringify(report));
    expect(lineageEvent(result.events)).toBeTruthy();
  });

  it("the lineage carrier survives a minSeverity floor set above its own fixed Medium severity (H1)", () => {
    const report = baseReport({ dropped: [{ name: "a.exe", sha256: DROPPED_SHA }] });
    const result = parseSandboxReport(JSON.stringify(report), { minSeverity: "High" });
    expect(lineageEvent(result.events)).toBeTruthy();
  });

  it("two reports whose content differs only in an ignored field still get distinct locators — full digest, never truncated (H2)", () => {
    const reportA = baseReport({ dropped: [{ name: "a.exe", sha256: DROPPED_SHA }], junkField: "x" });
    const reportB = baseReport({ dropped: [{ name: "a.exe", sha256: DROPPED_SHA }], junkField: "y" });
    const result = parseSandboxReport(JSON.stringify([reportA, reportB]), { aggregate: true });
    const lineageEvents = result.events.filter((e) => e.description.startsWith("CAPE sandbox lineage:"));
    expect(lineageEvents).toHaveLength(2);
    expect(lineageEvents[0].aggKey).not.toBe(lineageEvents[1].aggKey);
  });

  it("never exposes a malformed/placeholder target hash as the carrier's own event-level hash identity (M1)", () => {
    const report = {
      ...baseReport(),
      target: { category: "file", file: { name: "x.exe", sha256: "not-a-hash" } },
    };
    const overridden = { ...report, dropped: [{ name: "a.exe", sha256: DROPPED_SHA }] };
    const result = parseSandboxReport(JSON.stringify(overridden));
    const ev = lineageEvent(result.events)!;
    expect(ev.sha256).toBeUndefined();
    expect(env(ev).sampleLineage!.facts[0].targetHashes).toBeUndefined();
  });

  it("merges two occurrences of the same object sharing only ONE of two hash algorithms (M2)", () => {
    const report = baseReport({
      dropped: [{ name: "a.exe", sha256: DROPPED_SHA, md5: "e".repeat(32) }],
      CAPE: { payloads: [{ name: "a.exe", md5: "e".repeat(32), cape_type: "Injected image" }] },
    });
    const result = parseSandboxReport(JSON.stringify(report));
    const block = env(lineageEvent(result.events)!).sampleLineage!;
    expect(block.facts).toHaveLength(1);
    expect(block.facts[0].reportedIn.sort()).toEqual(["cape-payloads", "dropped"]);
    expect(block.facts[0].objectHashes.sha256).toBe(DROPPED_SHA);
    expect(block.facts[0].capeType).toBe("Injected image");
  });

  it("still emits a carrier disclosing the malformed count when EVERY dropped/payload entry is malformed (M3)", () => {
    const report = baseReport({ dropped: [{ name: "a.exe" }, { name: "b.exe" }] });
    const result = parseSandboxReport(JSON.stringify(report));
    const ev = lineageEvent(result.events);
    expect(ev).toBeTruthy();
    const block = env(ev!).sampleLineage!;
    expect(block.facts).toHaveLength(0);
    expect(block.malformed).toBe(2);
  });
});
