import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SqliteStateStore } from "../../src/storage/sqliteStateStore.js";
import {
  type InvestigationState,
  type ForensicEvent,
  type IOC,
  type Finding,
  emptyState,
} from "../../src/analysis/stateTypes.js";

let sqliteAvailable = false;
try {
  const getBuiltinModule = (process as unknown as { getBuiltinModule?: (id: string) => unknown }).getBuiltinModule;
  const mod = getBuiltinModule?.("node:sqlite") as { DatabaseSync?: unknown } | undefined;
  sqliteAvailable = !!mod?.DatabaseSync;
} catch {
  sqliteAvailable = false;
}

let root: string;
let cases: CaseStore;
let store: SqliteStateStore;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-sqlite-"));
  cases = new CaseStore(root);
  store = new SqliteStateStore(cases);
});

function sampleState(caseId: string): InvestigationState {
  const events: ForensicEvent[] = [
    {
      id: "e1",
      timestamp: "2026-07-01T10:00:00.000Z",
      description: "powershell.exe launched",
      severity: "High",
      mitreTechniques: ["T1059.001"],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "host-a",
    },
    {
      id: "e2",
      timestamp: "2026-07-01T09:00:00.000Z",
      description: "suspicious file write",
      severity: "Medium",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "host-b",
    },
  ];
  const iocs: IOC[] = [
    { id: "i1", type: "ip", value: "10.0.0.1", firstSeen: "2026-07-01T08:00:00.000Z" },
    { id: "i2", type: "domain", value: "evil.example", firstSeen: "2026-07-01T08:30:00.000Z" },
  ];
  const findings: Finding[] = [
    {
      id: "f1",
      title: "Initial Access via Spearphish",
      severity: "Critical",
      description: "User clicked malicious link",
      mitreTechniques: ["T1566"],
      status: "open",
      relatedIocs: ["i1"],
      sourceScreenshots: [],
      firstSeen: "2026-07-01T08:00:00.000Z",
      lastUpdated: "2026-07-01T12:00:00.000Z",
    },
  ];
  return {
    ...emptyState(caseId),
    forensicTimeline: events,
    iocs,
    findings,
    lastSummary: "Attacker used spearphish",
    updatedAt: "2026-07-01T12:00:00.000Z",
  };
}

describe.skipIf(!sqliteAvailable)("SqliteStateStore", () => {
  it("returns an empty state for a case with no DB", async () => {
    await cases.createCase({ caseId: "c-empty", name: "n", investigator: "i", aiProvider: null });
    const state = await store.load("c-empty");
    expect(state.caseId).toBe("c-empty");
    expect(state.forensicTimeline).toEqual([]);
    expect(state.iocs).toEqual([]);
    expect(state.findings).toEqual([]);
  });

  it("round-trips events, IOCs, and findings through save then load", async () => {
    await cases.createCase({ caseId: "c-rt", name: "n", investigator: "i", aiProvider: null });
    const state = sampleState("c-rt");
    await store.save(state);
    const loaded = await store.load("c-rt");
    expect(loaded.caseId).toBe("c-rt");
    expect(loaded.iocs.map((i) => i.id).sort()).toEqual(["i1", "i2"]);
    expect(loaded.findings.map((f) => f.id)).toEqual(["f1"]);
    expect(loaded.findings[0].mitreTechniques).toEqual(["T1566"]);
    expect(loaded.forensicTimeline.map((e) => e.id).sort()).toEqual(["e1", "e2"]);
  });

  it("orders events by timestamp ascending on load", async () => {
    await cases.createCase({ caseId: "c-order", name: "n", investigator: "i", aiProvider: null });
    await store.save(sampleState("c-order"));
    const loaded = await store.load("c-order");
    expect(loaded.forensicTimeline.map((e) => e.id)).toEqual(["e2", "e1"]);
  });

  it("upserts entities (re-save updates rather than duplicates)", async () => {
    await cases.createCase({ caseId: "c-up", name: "n", investigator: "i", aiProvider: null });
    const state = sampleState("c-up");
    await store.save(state);
    const modified = {
      ...state,
      forensicTimeline: [
        { ...state.forensicTimeline[0], description: "UPDATED powershell", severity: "Critical" as const },
      ],
      iocs: [{ id: "i1", type: "ip" as const, value: "10.0.0.99", firstSeen: "2026-07-01T08:00:00.000Z" }],
    };
    await store.save(modified);
    const loaded = await store.load("c-up");
    const updated = loaded.forensicTimeline.find((e) => e.id === "e1");
    expect(updated?.description).toBe("UPDATED powershell");
    expect(updated?.severity).toBe("Critical");
    expect(loaded.forensicTimeline.filter((e) => e.id === "e1")).toHaveLength(1);
    expect(loaded.iocs.find((i) => i.id === "i1")?.value).toBe("10.0.0.99");
  });

  it("persists meta fields (lastSummary, updatedAt) into the meta table", async () => {
    await cases.createCase({ caseId: "c-meta", name: "n", investigator: "i", aiProvider: null });
    const state = sampleState("c-meta");
    state.lastSummary = "Custom summary text";
    state.attackerPath = "phish -> powershell -> exfil";
    await store.save(state);
    const loaded = await store.load("c-meta");
    expect(loaded.lastSummary).toBe("Custom summary text");
    expect(loaded.attackerPath).toBe("phish -> powershell -> exfil");
  });

  it("preserves mitre_techniques JSON arrays across save/load", async () => {
    await cases.createCase({ caseId: "c-mt", name: "n", investigator: "i", aiProvider: null });
    const state = sampleState("c-mt");
    await store.save(state);
    const loaded = await store.load("c-mt");
    const ps = loaded.forensicTimeline.find((e) => e.id === "e1");
    expect(ps?.mitreTechniques).toEqual(["T1059.001"]);
    const finding = loaded.findings[0];
    expect(finding.mitreTechniques).toEqual(["T1566"]);
  });
});