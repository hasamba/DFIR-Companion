import { describe, it, expect } from "vitest";
import {
  capLabSetupRow,
  labSetupPaths,
  labSetupOf,
  labSetupOnly,
  hasLabSetupMark,
  LAB_SETUP_TAG,
} from "../../src/analysis/labSetupTransfer.js";
import { DERIVED_NOTE_NAMES, DERIVED_NOTE_DOWNGRADES } from "../../src/analysis/derivedNote.js";
import { applyToForensicEvent } from "../../src/analysis/tagger.js";
import type { Finding, ForensicEvent } from "../../src/analysis/stateTypes.js";
import { parseKapeCsv } from "../../src/analysis/kapeImport.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { groundAndScoreFindings } from "../../src/analysis/findingGrounding.js";

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1",
    timestamp: "2026-09-30T13:20:00Z",
    description: p.description ?? "THOR Filescan Warning: SIGNATURE_BASE_Recon_Commands_Windows_Gen1",
    severity: p.severity ?? "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const DND =
  "C:\\Users\\vagrant\\AppData\\Local\\Temp\\vmware-vagrant\\VMwareDnD\\f47a154c\\101-Sim\\recon.ps1";
const VBOX = "C:\\Users\\lab\\AppData\\Local\\Temp\\VirtualBox Dropped Files\\2026-09-30\\tool.ps1";
const NORMAL = "C:\\Users\\vagrant\\Documents\\101-Sim\\recon.ps1";
const defaults = labSetupPaths({});

describe("capLabSetupRow (#1946)", () => {
  it("caps a High file in the VMware drag-and-drop folder at Medium, with a note and the tag", () => {
    const out = capLabSetupRow(ev({ path: DND }), defaults);
    expect(out.severity).toBe("Medium");
    expect(out.description).toMatch(/\[lab-setup: hypervisor drag-and-drop transfer \(\\vmwarednd\\\)/);
    expect(labSetupOf(out)).toEqual({ tag: LAB_SETUP_TAG, folder: "\\vmwarednd\\", cappedFrom: "High" });
  });

  it("caps a Critical file in the VirtualBox dropped-files folder", () => {
    const out = capLabSetupRow(ev({ path: VBOX, severity: "Critical" }), defaults);
    expect(out.severity).toBe("Medium");
    expect(labSetupOf(out)?.cappedFrom).toBe("Critical");
  });

  it("leaves the same file name in a normal user folder unchanged", () => {
    const row = ev({ path: NORMAL });
    expect(capLabSetupRow(row, defaults)).toBe(row);
  });

  it("only lowers: a Low row in the folder stays Low but is tagged", () => {
    const out = capLabSetupRow(ev({ path: DND, severity: "Low" }), defaults);
    expect(out.severity).toBe("Low");
    expect(labSetupOf(out)?.cappedFrom).toBeUndefined();
    expect(hasLabSetupMark(out)).toBe(true);
  });

  it("does not touch an Info row", () => {
    const row = ev({ path: DND, severity: "Info" });
    expect(capLabSetupRow(row, defaults)).toBe(row);
  });

  it("keeps the grade of a run from the folder — executing the copied tool is the scenario", () => {
    const exec = ev({ path: DND, action: "execute" });
    expect(capLabSetupRow(exec, defaults)).toBe(exec);
    const cmd = ev({ path: DND, commandLine: `powershell -File "${DND}"` });
    expect(capLabSetupRow(cmd, defaults)).toBe(cmd);
  });

  it("keeps the grade of an analyst-promoted row", () => {
    const row = ev({ path: DND, promotedAt: "2026-10-01T00:00:00Z" });
    expect(capLabSetupRow(row, defaults)).toBe(row);
  });

  it("is idempotent", () => {
    const once = capLabSetupRow(ev({ path: DND }), defaults);
    expect(capLabSetupRow(once, defaults)).toBe(once);
  });

  it("re-caps a row a merge raised, keeping the worse original grade", () => {
    const once = capLabSetupRow(ev({ path: DND }), defaults);
    const raised = capLabSetupRow({ ...once, severity: "Critical" }, defaults);
    expect(raised.severity).toBe("Medium");
    expect(labSetupOf(raised)?.cappedFrom).toBe("Critical");
  });
});

describe("DFIR_LAB_SETUP_PATHS (#1946)", () => {
  it("adds configured folders to the defaults, case-insensitive, either slash", () => {
    const paths = labSetupPaths({ DFIR_LAB_SETUP_PATHS: " \\LabShare\\ , /Provision/ " });
    expect(paths).toEqual(expect.arrayContaining(["\\vmwarednd\\", "\\labshare\\", "\\provision\\"]));
    const out = capLabSetupRow(ev({ path: "Z:\\labshare\\x.ps1" }), paths);
    expect(out.severity).toBe("Medium");
    expect(out.description).toMatch(/\[lab-setup: configured lab-setup path \(\\labshare\\\)/);
  });

  it("keeps the defaults when the value is empty", () => {
    expect(labSetupPaths({ DFIR_LAB_SETUP_PATHS: "" })).toEqual(defaults);
  });

  it("reverses: a row whose folder is no longer configured gets its grade back and loses the note", () => {
    const paths = labSetupPaths({ DFIR_LAB_SETUP_PATHS: "\\labshare\\" });
    const capped = capLabSetupRow(ev({ path: "Z:\\labshare\\x.ps1", description: "YARA hit" }), paths);
    const lifted = capLabSetupRow(capped, defaults);
    expect(lifted.severity).toBe("High");
    expect(lifted.description).toBe("YARA hit");
    expect(hasLabSetupMark(lifted)).toBe(false);
  });

  it("strips a stray note that arrived without its record", () => {
    const row = ev({ path: NORMAL, description: "x [lab-setup: hypervisor drag-and-drop transfer]" });
    expect(capLabSetupRow(row, defaults).description).toBe("x");
  });
});

describe("lab-setup registration and guards (#1946)", () => {
  it("registers the note as a downgrade", () => {
    expect(DERIVED_NOTE_NAMES).toContain("lab-setup");
    expect(DERIVED_NOTE_DOWNGRADES).toContain("lab-setup");
  });

  it("a manual Run tagger cannot raise a capped row above Medium", () => {
    const capped = capLabSetupRow(ev({ path: DND }), defaults);
    const out = applyToForensicEvent(capped, { severity: "Critical", mitre: [], ruleIds: [] } as never);
    expect(out.severity).toBe("Medium");
  });

  it("labSetupOnly is true only when every cited row is lab setup", () => {
    const a = capLabSetupRow(ev({ id: "a", path: DND }), defaults);
    const b = ev({ id: "b", path: NORMAL });
    expect(labSetupOnly([a])).toBe(true);
    expect(labSetupOnly([a, b])).toBe(false);
    expect(labSetupOnly([])).toBe(false);
  });
});

// Codex review (#1946): the cap read only `action === "execute"` and the row's own command line, so
// an execution ARTIFACT naming a binary in the folder — Prefetch, UserAssist, Amcache, BAM, a process
// start — was capped and labelled operator staging. Running the copied tool is the scenario. These
// rows are built by the real importers, not by hand.
describe("execution evidence from the drag-and-drop folder keeps its grade (#1946 review)", () => {
  const EXE = "C:\\Users\\vagrant\\AppData\\Local\\Temp\\vmware-vagrant\\VMwareDnD\\f47a154c\\mimikatz.exe";
  const VOL_EXE =
    "\\VOLUME{01d0a1b2c3d4e5f6-0123abcd}\\USERS\\VAGRANT\\APPDATA\\LOCAL\\TEMP\\VMWARE-VAGRANT\\VMWAREDND\\F47A154C\\MIMIKATZ.EXE";
  // An importer row as the forensic timeline holds it; `severity` stands in for a later raise
  // (tagger, merge) on artifacts the importer itself leaves at Info.
  const toRow = (e: object, id: string, severity?: ForensicEvent["severity"]): ForensicEvent => {
    const s = e as ForensicEvent;
    return { ...s, id, severity: severity ?? s.severity, relatedFindingIds: [], sourceScreenshots: [] };
  };
  const kapeRow = (csv: string, id: string, severity?: ForensicEvent["severity"]): ForensicEvent => {
    const out = parseKapeCsv(csv, { aggregate: false });
    expect(out.events).toHaveLength(1);
    return toRow(out.events[0], id, severity);
  };
  const veloRow = (artifact: string, row: object, id: string, severity?: ForensicEvent["severity"]) => {
    const out = parseVelociraptorJson(JSON.stringify({ [artifact]: [row] }), { aggregate: false });
    const hit = out.events.filter((e) => (e.path ?? "").toLowerCase().includes("vmwarednd"));
    expect(hit).toHaveLength(1);
    return toRow(hit[0], id, severity);
  };
  const rows = (): ForensicEvent[] => [
    kapeRow(
      [
        "SourceFilename,ExecutableName,RunCount,LastRun,FilesLoaded",
        `C:\\Windows\\Prefetch\\MIMIKATZ.EXE-1A2B3C4D.pf,MIMIKATZ.EXE,2,2026-09-30 13:25:00,"${VOL_EXE}"`,
      ].join("\n"),
      "kape-pf",
    ),
    kapeRow(
      [
        "FullPath,SHA1,FileKeyLastWriteTimestamp",
        `${EXE},0000aabbccddeeff00112233445566778899aabbcc,2026-09-30 13:25:00`,
      ].join("\n"),
      "kape-amcache",
      "High",
    ),
    veloRow(
      "Windows.Forensics.Prefetch",
      { Executable: "mimikatz.exe", ExecutablePath: EXE, RunCount: 2, LastRunTimes: "2026-09-30T13:25:00Z" },
      "velo-pf",
    ),
    veloRow(
      "Windows.Registry.UserAssist",
      { Name: EXE, NumberOfExecutions: 1, LastExecution: "2026-09-30T13:25:00Z" },
      "velo-ua",
      "High",
    ),
    veloRow(
      "Windows.Forensics.Amcache",
      {
        FullPath: EXE,
        SHA1: "aabbccddeeff00112233445566778899aabbccdd",
        OriginalFileName: "mimikatz.exe",
        Timestamp: "2026-09-30T13:25:00Z",
      },
      "velo-amcache",
      "High",
    ),
  ];

  it("the importers put these rows at High on a path inside the folder", () => {
    for (const r of rows()) {
      expect(r.severity, r.id).toBe("High");
      expect((r.path ?? "").toLowerCase(), r.id).toContain("vmwarednd");
    }
  });

  it("caps none of them and records no lab-setup mark", () => {
    for (const r of rows()) {
      const out = capLabSetupRow(r, defaults);
      expect(out.severity, r.id).toBe("High");
      expect(labSetupOf(out), r.id).toBeUndefined();
      expect(hasLabSetupMark(out), r.id).toBe(false);
    }
  });

  it("keeps a process-start row (canonical process start) at its grade", () => {
    const start = ev({
      path: EXE,
      sources: ["Hayabusa"],
      canonical: { event: { category: "process", type: "start" } } as ForensicEvent["canonical"],
    });
    expect(capLabSetupRow(start, defaults)).toBe(start);
  });

  it("lifts a cap an earlier pass wrote onto a Prefetch row", () => {
    const pf = rows()[0];
    const stale = {
      ...pf,
      severity: "Medium",
      labSetup: { tag: LAB_SETUP_TAG, folder: "\\vmwarednd\\", cappedFrom: "High" },
    } as ForensicEvent;
    const out = capLabSetupRow(stale, defaults);
    expect(out.severity).toBe("High");
    expect(labSetupOf(out)).toBeUndefined();
  });

  it("ShimCache keeps its grade only with the execution flag — presence alone is still the copy", () => {
    const shim = (flag: string, id: string) =>
      veloRow(
        "Windows.Registry.AppCompatCache",
        { Path: EXE, ExecutionFlag: flag, ModificationTime: "2026-09-30T13:25:00Z" },
        id,
        "High",
      );
    expect(capLabSetupRow(shim("true", "s1"), defaults).severity).toBe("High");
    expect(capLabSetupRow(shim("false", "s2"), defaults).severity).toBe("Medium");
  });

  it("still caps the copied file itself (a THOR hit on the same path)", () => {
    expect(capLabSetupRow(ev({ path: EXE, sources: ["THOR"] }), defaults).severity).toBe("Medium");
  });

  it("a finding that cites only these execution rows is not capped", () => {
    const supporting = rows().map((r) => capLabSetupRow(r, defaults));
    const finding: Finding = {
      id: "f1",
      severity: "High",
      title: "mimikatz executed",
      description: "",
      relatedIocs: [],
      relatedEventIds: supporting.map((r) => r.id),
      sourceScreenshots: [],
      mitreTechniques: [],
      firstSeen: "",
      lastUpdated: "",
      status: "open",
    };
    const out = groundAndScoreFindings({
      iocs: [],
      graphLinkedEventIds: new Set<string>(),
      findings: [finding],
      scopedEvents: supporting,
    });
    expect(out[0].severity).toBe("High");
    expect((out[0] as Finding & { labSetup?: boolean }).labSetup).toBeUndefined();
    expect(out[0].confidenceReason ?? "").not.toMatch(/lab-setup folder/);
  });
});
