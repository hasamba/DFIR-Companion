// #2497: the four coverage notes stay on the forensic timeline whatever the severity gate.
//
// They say "nothing found here is not the same as absent" (#908). Graded Medium, a case gated at
// High demoted them on every import, so synthesis lost the warning. They are now exempt from the
// demote step, like a promoted row or a manual event — recognised by the fixed id only the merge
// builds AND the "Coverage" source, never by either alone. Their grade is unchanged.
import { describe, it, expect } from "vitest";
import { demoteBelowSeverity } from "../../src/analysis/forensicGate.js";
import { COVERAGE_NOTE_IDS, COVERAGE_SOURCE, isCoverageNote } from "../../src/analysis/coverageEventTime.js";
import { metadataCoverageEvent, COVERAGE_EVENT_ID } from "../../src/analysis/cloudMetadataAccess.js";
import {
  objectLoggingEvent,
  truncationEvent,
  LOGGING_COVERAGE_ID,
  TRUNCATION_COVERAGE_ID,
} from "../../src/analysis/cloudBulkRead.js";
import {
  attributionCoverageEvent,
  ATTRIBUTION_COVERAGE_ID,
} from "../../src/analysis/serviceAccountBrowsing.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

const ev = (over: Partial<ForensicEvent>): ForensicEvent => ({
  id: "row",
  timestamp: "2026-01-01T10:00:00Z",
  description: "x",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});

/** A cloud object-listing record as an importer that stamps the canonical envelope produces it. */
const listing = (i: number): ForensicEvent =>
  ({
    ...ev({ id: `list-${i}`, description: "AWS ListBucket (s3) by app-role from 10.0.1.5" }),
    canonical: {
      event: { action: "ListBucket" },
      actor: { name: "arn:aws:sts::123456789012:assumed-role/app-role/i-0abc" },
      cloud: { resource: `bucket-${i}` },
      network: { source: { address: "10.0.1.5" } },
    },
  }) as unknown as ForensicEvent;

/** The four notes exactly as the merge builds them. */
function builtNotes(): ForensicEvent[] {
  const notes = [
    metadataCoverageEvent([ev({ id: "ct", description: "AWS GetObject (s3) by a" })]),
    objectLoggingEvent([listing(1), listing(2)]),
    truncationEvent([listing(3)], 5),
    attributionCoverageEvent([
      ev({
        id: "bag",
        description: "Shellbag: C:\\x [user: not recorded by this collection]",
        sources: ["Shellbags"],
      }),
    ]),
  ];
  expect(notes.every(Boolean)).toBe(true);
  return notes as ForensicEvent[];
}

describe("coverage notes and the severity gate (#2497)", () => {
  it("names exactly the four builders' ids", () => {
    expect([...COVERAGE_NOTE_IDS].sort()).toEqual(
      [COVERAGE_EVENT_ID, LOGGING_COVERAGE_ID, TRUNCATION_COVERAGE_ID, ATTRIBUTION_COVERAGE_ID].sort(),
    );
  });

  it("recognises every note the merge builds, and leaves their grade at Medium", () => {
    for (const note of builtNotes()) {
      expect(isCoverageNote(note), note.id).toBe(true);
      expect(note.severity, note.id).toBe("Medium");
      expect(note.sources).toContain(COVERAGE_SOURCE);
    }
  });

  for (const gate of ["High", "Critical"] as Severity[]) {
    it(`keeps all four notes under a ${gate} gate and still demotes ordinary rows`, () => {
      const telemetry = ev({ id: "imported-medium", severity: "Medium" });
      const { kept, demoted } = demoteBelowSeverity([...builtNotes(), telemetry], gate);
      expect(kept.map((e) => e.id).sort()).toEqual([...COVERAGE_NOTE_IDS].sort());
      expect(demoted.map((e) => e.id)).toEqual(["imported-medium"]);
    });
  }

  it("keeps a note that a later grade lowered below the gate", () => {
    const low = { ...builtNotes()[0], severity: "Low" as const };
    expect(demoteBelowSeverity([low], "High").kept).toHaveLength(1);
  });

  it("does not exempt an imported row whose sources merely say 'Coverage'", () => {
    const forged = ev({ id: "ai-row", severity: "Medium", sources: [COVERAGE_SOURCE] });
    expect(isCoverageNote(forged)).toBe(false);
    expect(demoteBelowSeverity([forged], "High").demoted.map((e) => e.id)).toEqual(["ai-row"]);
  });

  it("does not exempt a row that has a coverage id but not the Coverage source", () => {
    const row = ev({ id: COVERAGE_EVENT_ID, severity: "Medium", sources: ["CloudTrail"] });
    expect(isCoverageNote(row)).toBe(false);
    expect(demoteBelowSeverity([row], "High").demoted).toHaveLength(1);
  });
});
