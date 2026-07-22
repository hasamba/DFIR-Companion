// #177: an indicator's `value` must be the bare indicator. These cover the two ingest paths that
// used to store whatever they were handed — the AI/importer delta merge, and analyst manual entry —
// plus the backfill for cases already written with an annotation baked in.

import { describe, it, expect } from "vitest";
import { ZodError } from "zod";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { buildManualIoc } from "../../src/analysis/manualEntry.js";
import { repairIocValues } from "../../src/analysis/iocRepair.js";

const baseDelta: AnalysisDelta = {
  findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
  timelineNote: "", summary: "",
};
const ctx = { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] };

describe("mergeDelta IOC value hygiene (#177)", () => {
  it("splits a host label out of an extracted IP into `note`", () => {
    const next = mergeDelta(emptyState("c1"), {
      ...baseDelta,
      iocs: [{ id: "i1", type: "ip", value: "10.10.20.15 (DC01)" }],
    }, ctx);
    expect(next.iocs).toHaveLength(1);
    expect(next.iocs[0].value).toBe("10.10.20.15");
    expect(next.iocs[0].note).toBe("DC01");
  });

  it("folds the annotated form onto an existing bare indicator instead of creating a second row", () => {
    let state = mergeDelta(emptyState("c1"), {
      ...baseDelta,
      iocs: [{ id: "i1", type: "ip", value: "10.10.20.15" }],
    }, ctx);
    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "i9", type: "ip", value: "10.10.20.15 (DC01)" }],
    }, ctx);
    expect(state.iocs).toHaveLength(1);
    expect(state.iocs[0].value).toBe("10.10.20.15");
    // The label the duplicate carried is kept as context on the surviving row.
    expect(state.iocs[0].note).toBe("DC01");
  });

  it("remaps a finding's relatedIocs onto the repaired IOC", () => {
    const next = mergeDelta(emptyState("c1"), {
      ...baseDelta,
      iocs: [{ id: "i1", type: "ip", value: "10.10.20.30 (FS01)" }],
      findings: [{ id: "f1", severity: "High", title: "Lateral movement", description: "",
        relatedIocs: ["i1"], mitreTechniques: [], status: "open" }],
    }, ctx);
    expect(next.findings[0].relatedIocs).toEqual([next.iocs[0].id]);
  });

  it("drops a multi-line text blob mis-typed as an indicator", () => {
    const next = mergeDelta(emptyState("c1"), {
      ...baseDelta,
      iocs: [
        { id: "i1", type: "ip", value: ".PARAMETER Identity\n\nA display name (e.g. 'Test GPO')\n" },
        { id: "i2", type: "ip", value: "185.220.101.47" },
      ],
    }, ctx);
    expect(next.iocs.map((i) => i.value)).toEqual(["185.220.101.47"]);
  });

  it("leaves a clean value (and its absent note) exactly as it was", () => {
    const next = mergeDelta(emptyState("c1"), {
      ...baseDelta,
      iocs: [{ id: "i1", type: "ip", value: "185.220.101.47" }],
    }, ctx);
    expect(next.iocs[0].value).toBe("185.220.101.47");
    expect(next.iocs[0].note).toBeUndefined();
  });
});

describe("buildManualIoc value hygiene (#177)", () => {
  const deps = { now: () => "2026-05-28T10:00:00.000Z", id: () => "fixed" };

  it("splits an annotation the analyst typed into the value field", () => {
    expect(buildManualIoc({ type: "ip", value: "10.10.10.45 (WKSTN-JSMITH)" }, deps)).toEqual({
      id: "manual-fixed", type: "ip", value: "10.10.10.45",
      firstSeen: "2026-05-28T10:00:00.000Z", note: "WKSTN-JSMITH",
    });
  });

  it("keeps an explicit note the analyst supplied separately", () => {
    const ioc = buildManualIoc({ type: "ip", value: "10.10.20.40", note: "WEB01 — DMZ" }, deps);
    expect(ioc.value).toBe("10.10.20.40");
    expect(ioc.note).toBe("WEB01 — DMZ");
  });

  it("prefers the analyst's explicit note over one derived from the value", () => {
    const ioc = buildManualIoc({ type: "ip", value: "10.10.20.40 (WEB01)", note: "staged archive here" }, deps);
    expect(ioc.value).toBe("10.10.20.40");
    expect(ioc.note).toBe("staged archive here");
  });

  it("rejects a value that cannot be an indicator, so the route answers 400 not 500", () => {
    expect(() => buildManualIoc({ type: "ip", value: "line one\nline two" }, deps)).toThrow(ZodError);
  });
});

describe("repairIocValues backfill (#177)", () => {
  it("repairs existing rows and reports what changed", () => {
    const state = {
      ...emptyState("c1"),
      iocs: [
        { id: "i005", type: "ip" as const, value: "10.10.20.15 (DC01)", firstSeen: "2026-05-15T19:51:15.000Z" },
        { id: "ioc001", type: "ip" as const, value: "185.220.101.47", firstSeen: "2026-05-15T09:51:00.000Z" },
      ],
    };
    const { state: repaired, changed } = repairIocValues(state);
    expect(changed).toEqual([{ id: "i005", before: "10.10.20.15 (DC01)", after: "10.10.20.15", note: "DC01" }]);
    expect(repaired.iocs[0]).toMatchObject({ value: "10.10.20.15", note: "DC01" });
    expect(repaired.iocs[1]).toBe(state.iocs[1]);   // untouched row keeps its identity
  });

  it("leaves an unsalvageable value in place rather than deleting evidence", () => {
    const state = {
      ...emptyState("c1"),
      iocs: [{ id: "i1", type: "ip" as const, value: "blob\nacross\nlines", firstSeen: "2026-05-15T00:00:00.000Z" }],
    };
    const { state: repaired, changed } = repairIocValues(state);
    expect(changed).toEqual([]);
    expect(repaired).toBe(state);
  });

  it("does not collapse rows that end up sharing a value (references stay intact)", () => {
    const state = {
      ...emptyState("c1"),
      iocs: [
        { id: "i005", type: "ip" as const, value: "10.10.20.15 (DC01)", firstSeen: "2026-05-15T00:00:00.000Z" },
        { id: "ioc012", type: "ip" as const, value: "10.10.20.15", firstSeen: "2026-05-16T00:00:00.000Z" },
      ],
    };
    const { state: repaired } = repairIocValues(state);
    expect(repaired.iocs.map((i) => i.id)).toEqual(["i005", "ioc012"]);
  });
});
