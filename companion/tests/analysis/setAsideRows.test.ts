// #1535 — what makes a row one the super-timeline's cap evicts LAST.
//
// Two halves, and both are load-bearing: the row must read Info (a note alone is not a downgrade —
// veloDetectionNoise appends the collector note to a Critical row it refuses to demote, and
// buildTimeWindow caps at Low), and it must carry a stated reason a named rule wrote. Each named
// pass is exercised FOR REAL below, so rewording its note fails here instead of quietly costing
// that pass's rows their standing.
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  COLLECTOR_NOTE_PREFIX,
  SET_ASIDE_NOTE_MARKERS,
  SET_ASIDE_REGISTRY_VERSION,
  isSetAsideRow,
} from "../../src/analysis/setAsideRows.js";
import { downgradeFirstPartyEgress } from "../../src/analysis/firstPartyEgress.js";
import { SPAWNED_CHILD_NOTE } from "../../src/analysis/collectorChildren.js";
import { SPAWNED_SCRIPT_NOTE } from "../../src/analysis/collectorLineage.js";
import { TOOL_TREE_SCRIPT_NOTE } from "../../src/analysis/veloDetectionNoise.js";
import { BUILD_TIME_MARKER } from "../../src/analysis/buildTimeWindow.js";
import {
  appendDerivedNote,
  DERIVED_NOTE_DOWNGRADES,
  DERIVED_NOTE_NAMES,
} from "../../src/analysis/derivedNote.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ONEDRIVE_SETUP =
  "C:\\Users\\vagrant\\AppData\\Local\\Microsoft\\OneDrive\\StandaloneUpdater\\OneDriveSetup.exe";

function row(p: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-08-30T15:02:40.005Z",
    description: "Process created: net.exe users",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

function oneDriveEgress(description: string): ForensicEvent {
  return {
    id: "1e61",
    timestamp: "2026-08-30T15:02:40.005Z",
    description,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: {
      schemaVersion: "1.0.0",
      event: { category: "network", type: "connection" },
      network: {
        source: { address: "192.0.2.10" },
        destination: { address: "150.171.109.82", port: 443 },
        protocol: "tcp",
      },
      file: { path: ONEDRIVE_SETUP, name: "OneDriveSetup.exe" },
      time: { observed: "2026-08-30 15:02:40.005", normalized: "2026-08-30T15:02:40.005Z" },
    },
  } as unknown as ForensicEvent;
}

describe("isSetAsideRow — the named passes, run for real", () => {
  it("claims the row the first-party egress pass demoted (#1530)", () => {
    const { events, downgraded } = downgradeFirstPartyEgress([
      oneDriveEgress("Velociraptor [Windows.Sigma.Base] Sigma: Net Conn (Sysmon Alert) (EID 3)"),
    ]);
    expect(downgraded).toHaveLength(1);
    expect(events[0].severity).toBe("Info");
    expect(isSetAsideRow(events[0])).toBe(true);
  });

  it("claims a row carrying any collector footprint / deployment note (#1500)", () => {
    for (const note of [SPAWNED_CHILD_NOTE, SPAWNED_SCRIPT_NOTE, TOOL_TREE_SCRIPT_NOTE]) {
      expect(isSetAsideRow(row({ description: `Process created: net.exe users${note}` }))).toBe(true);
    }
  });

  it("claims a row a registered derived-note DOWNGRADE lowered to Info (#1529)", () => {
    const description = appendDerivedNote(
      "Security log cleared (EID 1102)",
      BUILD_TIME_MARKER,
      "2026-01-02/2026-01-02",
    );
    expect(isSetAsideRow(row({ description }))).toBe(true);
  });
});

describe("isSetAsideRow — what it refuses", () => {
  it("refuses ordinary bulk Info telemetry", () => {
    expect(isSetAsideRow(row({ description: "Prefetch: NOTEPAD.EXE-1234ABCD.pf" }))).toBe(false);
  });

  it("refuses a CRITICAL row that carries the collector note but was never demoted", () => {
    // veloDetectionNoise.ts keeps a Critical row's grade and still explains the collector ran it.
    expect(isSetAsideRow(row({ severity: "Critical", description: `x${TOOL_TREE_SCRIPT_NOTE}` }))).toBe(
      false,
    );
  });

  it("refuses a build-time row, which is capped at LOW and stays in the forensic timeline", () => {
    const description = appendDerivedNote(
      "Service install (EID 7045)",
      BUILD_TIME_MARKER,
      "2026-01-02/2026-01-02",
    );
    expect(isSetAsideRow(row({ severity: "Low", description }))).toBe(false);
  });

  it("refuses a row whose note states a RAISE, not a downgrade", () => {
    const description = appendDerivedNote("Outbound transfer", "[confirmed exfiltration:", "staged on h1");
    expect(isSetAsideRow(row({ description }))).toBe(false);
  });

  it("refuses a row with no description", () => {
    expect(isSetAsideRow(row({ description: "" }))).toBe(false);
    expect(isSetAsideRow(undefined)).toBe(false);
  });
});

describe("the registry", () => {
  it("covers every [DFIR collector note literal written under src/analysis", () => {
    const dir = join(__dirname, "../../src/analysis");
    const found = new Set<string>();
    for (const file of readdirSync(dir)) {
      if (!file.endsWith(".ts")) continue;
      for (const m of readFileSync(join(dir, file), "utf8").matchAll(/" \[DFIR collector [^"]*"/g)) {
        found.add(m[0].slice(1, -1));
      }
    }
    expect(found.size).toBeGreaterThan(3);
    for (const note of found) expect(note.startsWith(COLLECTOR_NOTE_PREFIX)).toBe(true);
  });

  it("only classifies names that derivedNote.ts actually registers", () => {
    for (const name of DERIVED_NOTE_DOWNGRADES) expect(DERIVED_NOTE_NAMES).toContain(name);
  });

  it("fingerprints itself, so a new demoter re-derives the relation on cases that already exist", () => {
    expect(SET_ASIDE_REGISTRY_VERSION).toMatch(/^v1:\d+:[0-9a-z]+$/);
    expect(SET_ASIDE_NOTE_MARKERS.length).toBeGreaterThanOrEqual(3);
  });
});

describe("the first-party note survives the description clip", () => {
  it("clips the base, never the stated reason, on a 1,200-character description", () => {
    const long = `Velociraptor Sigma: Net Conn (Sysmon Alert) ${"x".repeat(1400)}`;
    const { events, downgraded } = downgradeFirstPartyEgress([oneDriveEgress(long)]);
    expect(downgraded).toHaveLength(1);
    expect(events[0].description.length).toBeLessThanOrEqual(1200);
    expect(events[0].description).toContain("first-party update traffic");
    expect(events[0].description.endsWith("]")).toBe(true);
    // The whole point: the cap can still tell this row from bulk telemetry.
    expect(isSetAsideRow(events[0])).toBe(true);
  });
});
