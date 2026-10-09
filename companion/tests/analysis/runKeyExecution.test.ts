import { describe, it, expect } from "vitest";
import {
  corroborateRunKeyExecution,
  isRunKeyValueRow,
  RUN_KEY_EXECUTION_MARKER,
  RUN_KEY_EXECUTION_TOLERANCE_MS,
  RUN_KEY_PROXY_HOSTS,
} from "../../src/analysis/runKeyExecution.js";
import { DERIVED_NOTE_NAMES } from "../../src/analysis/derivedNote.js";
import { LOLBINS } from "../../src/analysis/winProcessBaseline.js";
import type { Severity } from "../../src/analysis/stateTypes.js";

// #2082: a process start whose command line is a Run / RunOnce value already in the forensic
// timeline is the persistence firing. Typed input only (canonical.registry.valueData and the
// process command line); exact match after %var% contraction; same host, strictly later.

interface Ev {
  id: string;
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  asset?: string;
  path?: string;
  processName?: string;
  commandLine?: string;
  message?: string;
  canonical?: {
    event?: { category?: string; type?: string };
    process?: { executable?: string; commandLine?: string };
    registry?: { key?: string; valueName?: string; valueData?: string };
  };
}

const T = "2026-06-01T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const RUN_KEY = "HKU\\S-1-5-21-1-2-3-1104\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Webcache";
const LOCK = "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\cache.lock,VoidFunc";
const VALUE = `rundll32.exe ${LOCK}`;
const STARTED = `"C:\\Windows\\system32\\rundll32.exe" ${LOCK}`;

const runRow = (valueData: string, over: Partial<Ev> = {}, key = RUN_KEY): Ev => ({
  id: over.id ?? "run",
  timestamp: T,
  description: "Registry value set",
  severity: "Medium",
  mitreTechniques: [],
  asset: "WS-01",
  canonical: { event: { category: "registry", type: "change" }, registry: { key, valueData } },
  ...over,
});

const start = (id: string, s: number, commandLine: string, over: Partial<Ev> = {}): Ev => ({
  id,
  timestamp: at(s),
  description: "Process created",
  severity: "Low",
  mitreTechniques: [],
  asset: "WS-01",
  commandLine,
  canonical: { event: { category: "process", type: "start" } },
  ...over,
});

const byId = (events: Ev[], id: string): Ev => events.find((e) => e.id === id)!;
const raised = (e: Ev) => e.description.includes(RUN_KEY_EXECUTION_MARKER);

describe("corroborateRunKeyExecution", () => {
  it("raises both later starts of a rundll32 Run value to High with T1547.001 (APT29 shape)", () => {
    const out = corroborateRunKeyExecution([
      runRow(VALUE),
      start("p1", 3600, STARTED),
      start("p2", 7200, STARTED),
    ]);
    for (const id of ["p1", "p2"]) {
      const e = byId(out, id);
      expect(e.severity).toBe("High");
      expect(e.mitreTechniques).toContain("T1547.001");
      expect(e.description).toContain(RUN_KEY_EXECUTION_MARKER);
      expect(e.description).toContain("Webcache");
    }
    // The Run row is not regraded; it carries a back-reference note only.
    const run = byId(out, "run");
    expect(run.severity).toBe("Medium");
    expect(run.description).toContain("2 later starts");
  });

  it("contracts environment variables on both sides", () => {
    const out = corroborateRunKeyExecution([
      runRow("rundll32.exe %APPDATA%\\Microsoft\\cache.lock,VoidFunc"),
      start("p1", 60, STARTED),
    ]);
    expect(byId(out, "p1").severity).toBe("High");
  });

  it("never matches a substring or a prefix", () => {
    const out = corroborateRunKeyExecution([
      runRow(VALUE),
      start("longer", 60, `${STARTED} extra`),
      start(
        "prefix",
        60,
        `"C:\\Windows\\system32\\rundll32.exe" C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\cache.lock`,
      ),
    ]);
    expect(raised(byId(out, "longer"))).toBe(false);
    expect(raised(byId(out, "prefix"))).toBe(false);
  });

  it("compares the full image path when the value names one", () => {
    const value = "C:\\Users\\x\\AppData\\Roaming\\svchost.exe";
    const out = corroborateRunKeyExecution([
      runRow(value),
      start("real", 60, "C:\\Windows\\System32\\svchost.exe", { path: "C:\\Windows\\System32\\svchost.exe" }),
      start("fake", 60, `"${value}"`, { path: value }),
    ]);
    expect(raised(byId(out, "real"))).toBe(false);
    expect(byId(out, "real").severity).toBe("Low");
    expect(byId(out, "fake").severity).toBe("Medium");
    expect(raised(byId(out, "fake"))).toBe(true);
  });

  it("needs a start strictly after the Run write, past the tolerance, on the same host", () => {
    const tol = RUN_KEY_EXECUTION_TOLERANCE_MS / 1000;
    const out = corroborateRunKeyExecution([
      runRow(VALUE),
      start("before", -60, STARTED),
      start("inside", tol, STARTED),
      start("other", 60, STARTED, { asset: "WS-02" }),
      start("after", tol + 1, STARTED),
    ]);
    expect(raised(byId(out, "before"))).toBe(false);
    expect(raised(byId(out, "inside"))).toBe(false);
    expect(raised(byId(out, "other"))).toBe(false);
    expect(raised(byId(out, "after"))).toBe(true);
  });

  it("leaves the stock OneDrive and SecurityHealth values alone, but not OneDrive from elsewhere", () => {
    const oneDrive = '"C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background';
    const health = "%windir%\\system32\\SecurityHealthSystray.exe";
    const oddDrive = "C:\\Users\\Public\\OneDrive\\OneDrive.exe /background";
    const out = corroborateRunKeyExecution([
      runRow(
        oneDrive,
        { id: "r1" },
        "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
      ),
      runRow(health, { id: "r2" }, "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth"),
      runRow(
        oddDrive,
        { id: "r3" },
        "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Sync",
      ),
      start("p1", 60, oneDrive),
      start("p2", 60, "C:\\Windows\\System32\\SecurityHealthSystray.exe", {
        path: "C:\\Windows\\System32\\SecurityHealthSystray.exe",
      }),
      start("p3", 60, oddDrive),
    ]);
    expect(byId(out, "p1")).toEqual(start("p1", 60, oneDrive));
    expect(raised(byId(out, "p2"))).toBe(false);
    expect(byId(out, "p2").severity).toBe("Low");
    expect(raised(byId(out, "p3"))).toBe(true);
    expect(byId(out, "p3").severity).toBe("Medium");
  });

  it("grades a non-LOLBin match Medium, and never lowers a higher grade", () => {
    const value = "%LOCALAPPDATA%\\Vendor\\Update.exe --processStart app.exe";
    const line = '"C:\\Users\\jdoe\\AppData\\Local\\Vendor\\Update.exe" --processStart app.exe';
    const out = corroborateRunKeyExecution([
      runRow(value),
      start("p1", 60, line),
      runRow(VALUE, { id: "run2" }, RUN_KEY.replace("Webcache", "Other")),
      start("p2", 60, STARTED, { severity: "Critical" }),
    ]);
    expect(byId(out, "p1").severity).toBe("Medium");
    expect(byId(out, "p2").severity).toBe("Critical");
    expect(raised(byId(out, "p2"))).toBe(true);
  });

  it("reads typed input only, never a description or message", () => {
    const textOnly: Ev = {
      id: "hay",
      timestamp: T,
      description: `Run key set ${RUN_KEY} Details: ${VALUE}`,
      message: VALUE,
      severity: "Medium",
      mitreTechniques: ["T1547.001"],
      asset: "WS-01",
      path: RUN_KEY,
    };
    const out = corroborateRunKeyExecution([
      textOnly,
      start("p1", 60, STARTED),
      runRow(VALUE, { id: "run2" }),
      start("p2", 60, "rundll32.exe other.dll,Entry", { description: `Process created ${VALUE}` }),
    ]);
    // p1 matches run2 (typed), not the text-only row: the note names only the typed row's time.
    expect(raised(byId(out, "hay"))).toBe(false);
    expect(raised(byId(out, "p2"))).toBe(false);
    expect(corroborateRunKeyExecution([textOnly, start("p1", 60, STARTED)])[1].severity).toBe("Low");
  });

  it("is idempotent and recomputes its notes from the current evidence", () => {
    const events = [runRow(VALUE), start("p1", 60, STARTED)];
    const once = corroborateRunKeyExecution(events);
    const twice = corroborateRunKeyExecution(once);
    expect(twice).toEqual(once);
    expect(twice[1]).toBe(once[1]);
    // The Run row is gone: the note goes; the raise stays (the Defender pass's precedent).
    const without = corroborateRunKeyExecution([once[1]]);
    expect(raised(without[0])).toBe(false);
    expect(without[0].severity).toBe("High");
  });

  it("returns its input untouched when no row is a typed Run value", () => {
    const events = [start("p1", 60, STARTED)];
    expect(corroborateRunKeyExecution(events)[0]).toBe(events[0]);
  });
});

describe("isRunKeyValueRow", () => {
  it("is true only for a Run / RunOnce key with a non-allow-listed value", () => {
    expect(isRunKeyValueRow(runRow(VALUE))).toBe(true);
    expect(isRunKeyValueRow(runRow(VALUE, {}, RUN_KEY.replace("\\Run\\", "\\RunOnce\\")))).toBe(true);
    expect(isRunKeyValueRow(runRow(""))).toBe(false);
    expect(isRunKeyValueRow(runRow(VALUE, {}, "HKLM\\SOFTWARE\\Vendor\\Settings\\Path"))).toBe(false);
    expect(isRunKeyValueRow(runRow("%windir%\\system32\\SecurityHealthSystray.exe"))).toBe(false);
    expect(isRunKeyValueRow({ ...runRow(VALUE), canonical: undefined })).toBe(false);
  });

  it("registers its note name", () => {
    expect(DERIVED_NOTE_NAMES).toContain(RUN_KEY_EXECUTION_MARKER.slice(1, -1));
  });

  it("grades High only on hosts that are in the LOLBINS baseline", () => {
    for (const host of RUN_KEY_PROXY_HOSTS) expect(LOLBINS.has(host)).toBe(true);
  });
});
