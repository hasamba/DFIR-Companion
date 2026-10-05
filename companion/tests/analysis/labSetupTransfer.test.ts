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
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

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
