import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  linkTransferToolStaging,
  isTransferToolRow,
  TRANSFER_TOOL_NAMES,
  TRANSFER_TOOL_STAGED_MARKER,
  STAGING_WINDOW_MS,
} from "../../src/analysis/transferToolStaging.js";
import { DERIVED_NOTE_NAMES } from "../../src/analysis/derivedNote.js";
import { mergeLoadAlways, mergeTrigger } from "../../src/analysis/mergeIndex.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1955 part 1: a transfer tool and its config written to one folder on one host within ten
// minutes is a staged exfil kit. The pass raises both file rows to Medium and the record that the
// tool ran to High. Only ever raises; its notes are recomputed on every merge.

const T = "2026-05-02T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const DIR = "C:\\Users\\Public\\Music";

function ev(id: string, p: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: T,
    description: `row ${id}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    sources: ["MFT"],
    ...p,
  };
}

const tool = (p: Partial<ForensicEvent> = {}) =>
  ev("tool", { path: `${DIR}\\rclone.exe`, description: "File created: rclone.exe", ...p });
const conf = (p: Partial<ForensicEvent> = {}) =>
  ev("conf", {
    path: `${DIR}\\rclone.conf`,
    timestamp: at(10),
    description: "File created: rclone.conf",
    ...p,
  });
const amcache = (p: Partial<ForensicEvent> = {}) =>
  ev("amc", {
    path: `${DIR}\\rclone.exe`,
    timestamp: at(60),
    sources: ["Amcache"],
    description: "Amcache entry: rclone.exe",
    ...p,
  });

const byId = (rows: ForensicEvent[], id: string) => rows.find((e) => e.id === id)!;

describe("linkTransferToolStaging", () => {
  it("raises the tool and its config to Medium and the Amcache row of the same path to High", () => {
    const out = linkTransferToolStaging([tool(), conf(), amcache()]);
    const t = byId(out, "tool");
    const c = byId(out, "conf");
    const a = byId(out, "amc");
    expect(t.severity).toBe("Medium");
    expect(c.severity).toBe("Medium");
    expect(a.severity).toBe("High");
    expect(out.filter((e) => e.severity === "High")).toHaveLength(1);
    for (const e of [t, c]) expect(e.mitreTechniques).toContain("T1567.002");
    expect(t.description).toContain(TRANSFER_TOOL_STAGED_MARKER);
    // Each note cites the partner rows by id.
    expect(t.description).toMatch(/conf/);
    expect(t.description).toMatch(/amc/);
    expect(c.description).toMatch(/tool/);
    expect(a.description).toMatch(/tool/);
    expect(a.description).toMatch(/conf/);
    expect(a.description.toLowerCase()).toContain("public\\music");
  });

  it("leaves the pair alone when the files sit in different folders", () => {
    const rows = [tool(), conf({ path: "C:\\Users\\Public\\Videos\\rclone.conf" }), amcache()];
    expect(linkTransferToolStaging(rows)).toEqual(rows);
  });

  it("leaves the pair alone outside the window", () => {
    const rows = [tool(), conf({ timestamp: at(7200) }), amcache()];
    expect(STAGING_WINDOW_MS).toBe(10 * 60_000);
    expect(linkTransferToolStaging(rows)).toEqual(rows);
  });

  it("raises the pair to Medium and nothing to High when no execution record names the tool", () => {
    const out = linkTransferToolStaging([tool(), conf()]);
    expect(byId(out, "tool").severity).toBe("Medium");
    expect(byId(out, "conf").severity).toBe("Medium");
    expect(out.some((e) => e.severity === "High")).toBe(false);
  });

  it("leaves the pair alone when the two files are on different hosts", () => {
    const rows = [tool(), conf({ asset: "WS02" }), amcache()];
    expect(linkTransferToolStaging(rows)).toEqual(rows);
  });

  it("matches a Prefetch row that names the tool through an NT device path", () => {
    const pf = ev("pf", {
      path: "\\Device\\HarddiskVolume3\\Users\\Public\\Music\\RCLONE.EXE",
      timestamp: at(120),
      sources: ["Prefetch"],
      severity: "Medium",
      description: "Prefetch: RCLONE.EXE ran 1 time",
    });
    const out = linkTransferToolStaging([tool(), conf(), pf]);
    expect(byId(out, "pf").severity).toBe("High");
    expect(byId(out, "tool").description).toMatch(/Prefetch/);
  });

  it("matches a Velociraptor Prefetch row by its artifact segment", () => {
    const pf = ev("vpf", {
      path: `${DIR}\\rclone.exe`,
      timestamp: at(120),
      sources: ["Velociraptor"],
      description: "Velociraptor [Windows.Forensics.Prefetch]: Prefetch: RCLONE.EXE",
    });
    const out = linkTransferToolStaging([tool(), conf(), pf]);
    expect(byId(out, "vpf").severity).toBe("High");
  });

  it("raises a process start of the staged tool", () => {
    const proc = ev("proc", {
      path: `${DIR}\\rclone.exe`,
      timestamp: at(300),
      sources: ["Sysmon"],
      commandLine: "rclone.exe copy C:\\data mega:x",
      canonical: { event: { category: "process", type: "start" } } as never,
    });
    const out = linkTransferToolStaging([tool(), conf(), proc]);
    expect(byId(out, "proc").severity).toBe("High");
    // The process row is an execution record, not a third staged file.
    expect(byId(out, "tool").severity).toBe("Medium");
  });

  it("ignores an execution record on another host", () => {
    const out = linkTransferToolStaging([tool(), conf(), amcache({ asset: "WS02" })]);
    expect(byId(out, "amc").severity).toBe("Info");
  });

  it("joins the mega tools to their config", () => {
    const out = linkTransferToolStaging([
      ev("m", { path: `${DIR}\\megacmd.exe` }),
      ev("r", { path: `${DIR}\\.megarc`, timestamp: at(30) }),
    ]);
    expect(byId(out, "m").severity).toBe("Medium");
    expect(byId(out, "r").severity).toBe("Medium");
  });

  it("does not pair a config with another tool's binary", () => {
    const rows = [ev("w", { path: `${DIR}\\winscp.exe` }), conf()];
    expect(linkTransferToolStaging(rows)).toEqual(rows);
  });

  it("never lowers a severity", () => {
    const out = linkTransferToolStaging([tool({ severity: "Critical" }), conf()]);
    expect(byId(out, "tool").severity).toBe("Critical");
  });

  it("is idempotent", () => {
    const once = linkTransferToolStaging([tool(), conf(), amcache()]);
    expect(linkTransferToolStaging(once)).toEqual(once);
  });

  it("takes its note off when the partner row has left the case, and keeps the severity", () => {
    const once = linkTransferToolStaging([tool(), conf()]);
    const out = linkTransferToolStaging([byId(once, "tool")]);
    expect(byId(out, "tool").description).not.toContain(TRANSFER_TOOL_STAGED_MARKER);
    expect(byId(out, "tool").severity).toBe("Medium");
  });

  it("returns the input untouched when no row names a transfer tool", () => {
    const rows = [ev("a", { path: "C:\\x\\notepad.exe" }), ev("b")];
    expect(linkTransferToolStaging(rows)).toBe(rows);
  });

  it("registers its marker as a derived note", () => {
    expect(DERIVED_NOTE_NAMES).toContain(TRANSFER_TOOL_STAGED_MARKER.slice(1, -1));
  });
});

// The timeline layer may not import prefetchExecution.ts (analysis/ingest), so the tool names are
// restated. Every bulk-transfer name the Prefetch grader knows must be one this pass knows.
describe("the restated tool names", () => {
  it("cover every T1567.002 name in prefetchExecution.ts", () => {
    const src = readFileSync(join(__dirname, "../../src/analysis/prefetchExecution.ts"), "utf8");
    const names = [...src.matchAll(/"([a-z0-9_.-]+\.exe)":\s*\["T1567\.002"\]/g)].map((m) => m[1]);
    expect(names.length).toBeGreaterThanOrEqual(4);
    for (const n of names) expect(TRANSFER_TOOL_NAMES).toContain(n);
  });
});

describe("the incremental merge reads every row this pass reads", () => {
  it("loads tool, config and execution rows on every merge, and the note is inert", () => {
    expect(mergeLoadAlways(tool())).toBe(true);
    expect(mergeLoadAlways(conf())).toBe(true);
    expect(mergeLoadAlways(amcache())).toBe(true);
    expect(mergeLoadAlways(tool({ asset: undefined }))).toBe(false);
    expect(mergeLoadAlways(ev("x", { path: "C:\\x\\notepad.exe" }))).toBe(false);
    expect(isTransferToolRow(conf())).toBe(true);
    const noted = linkTransferToolStaging([tool(), conf()]);
    expect(mergeTrigger(byId(noted, "tool"))).toBeNull();
  });
});
