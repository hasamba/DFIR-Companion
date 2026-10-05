import { describe, it, expect } from "vitest";
import { capBuildTimeRows } from "../../src/analysis/buildTimeWindow.js";
import { capBuildTimeScoped, capLabSetupScoped } from "../../src/routes/importSettleCap.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import type { HostRenameRecord } from "../../src/analysis/hostRenameRecord.js";
import { memoryRowStore } from "../helpers/memoryRowStore.js";

// #1874: the build-time cap over the rows it can change must give exactly what capBuildTimeRows
// gives over the whole case — windows from the chain hosts' rows, the rule applied to rows inside a
// window or carrying a mark, the rest untouched.

const HOST = "DESKTOP-16OJFO6";
const renames: HostRenameRecord[] = [
  { formerName: "WIN-UK1GV882OK6", currentName: HOST, until: "2025-12-05T03:11:54.000Z", basis: "collector" },
];

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: `row ${id}`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: HOST,
    ...extra,
  };
}

function caseState(): InvestigationState {
  return {
    caseId: "c1",
    iocs: [],
    hostRenames: renames,
    forensicTimeline: [
      ev("m1", "2025-12-05T02:43:39Z", {
        path: "c:\\programdata\\chocolatey\\tools\\7z.exe",
        severity: "Low",
      }),
      ev("m2", "2025-12-05T02:50:00Z", { description: "ran C:\\vagrant\\provision.ps1", severity: "Info" }),
      ev("fw", "2025-12-05T02:55:00Z", {
        description: "A firewall rule was deleted (EID 2052)",
        severity: "High",
      }),
      ev("m3", "2025-12-05T03:02:24Z", { description: "choco install git", severity: "Medium" }),
      // Short name of the same host under a different spelling: still on the chain.
      ev("fqdn", "2025-12-05T03:05:00Z", { asset: `${HOST.toLowerCase()}.example.com`, severity: "High" }),
      // Another host at the same time: never in the window.
      ev("other", "2025-12-05T03:00:00Z", { asset: "SRV-01", severity: "High" }),
      // A row far from the build.
      ev("later", "2026-03-01T00:00:00Z", { severity: "High" }),
    ],
  } as unknown as InvestigationState;
}

async function scoped(state: InvestigationState, scanAll: boolean): Promise<ForensicEvent[]> {
  const store = memoryRowStore(state);
  await capBuildTimeScoped(store, "c1", state, { scanAll, extraIds: [] });
  return (await store.load()).forensicTimeline;
}

describe("capBuildTimeScoped (#1874)", () => {
  it("caps exactly the rows capBuildTimeRows caps, reading only the chain hosts", async () => {
    const state = caseState();
    const reference = capBuildTimeRows(state);
    expect(reference.changed).toBeGreaterThan(0); // the fixture really opens a window
    expect(await scoped(state, false)).toEqual(reference.state.forensicTimeline);
    expect(await scoped(state, true)).toEqual(reference.state.forensicTimeline);
  });

  it("un-caps a row whose window is gone, like the full pass", async () => {
    const capped = capBuildTimeRows(caseState()).state;
    // The markers leave the case: the window closes, and the capped rows get their grade back.
    const without = {
      ...capped,
      forensicTimeline: capped.forensicTimeline.filter((e) => !e.id.startsWith("m")),
    };
    const reference = capBuildTimeRows(without);
    expect(reference.changed).toBeGreaterThan(0);
    expect(await scoped(without, false)).toEqual(reference.state.forensicTimeline);
  });

  it("a case with no rename chain touches only the rows it is handed", async () => {
    const state = { ...caseState(), hostRenames: [] } as InvestigationState;
    const store = memoryRowStore(state);
    await capBuildTimeScoped(store, "c1", state, { scanAll: false, extraIds: ["fw"] });
    expect(store.writes.flat()).toEqual([]);
    expect((await store.load()).forensicTimeline).toEqual(capBuildTimeRows(state).state.forensicTimeline);
  });
});

describe("capLabSetupScoped (#1946)", () => {
  const DND = "c:\\users\\lab\\appdata\\local\\temp\\vmware-lab\\vmwarednd\\abc\\x.ps1";
  const labState = (): InvestigationState =>
    ({
      caseId: "c1",
      iocs: [],
      forensicTimeline: [
        ev("dnd", "2026-09-30T13:00:00Z", { path: DND, severity: "High" }),
        ev("docs", "2026-09-30T13:00:00Z", { path: "c:\\users\\lab\\documents\\x.ps1", severity: "High" }),
      ],
    }) as unknown as InvestigationState;

  it("caps the import's own drag-and-drop row and leaves the rest", async () => {
    const state = labState();
    const store = memoryRowStore(state);
    expect(await capLabSetupScoped(store, "c1", { scanAll: false, candidates: state.forensicTimeline })).toBe(
      1,
    );
    const rows = (await store.load()).forensicTimeline;
    expect(rows.find((e) => e.id === "dnd")?.severity).toBe("Medium");
    expect(rows.find((e) => e.id === "docs")?.severity).toBe("High");
  });

  it("finds old rows only on a scan-all settle", async () => {
    const state = labState();
    const store = memoryRowStore(state);
    expect(await capLabSetupScoped(store, "c1", { scanAll: false, candidates: [] })).toBe(0);
    expect(await capLabSetupScoped(store, "c1", { scanAll: true, candidates: [] })).toBe(1);
  });
});
