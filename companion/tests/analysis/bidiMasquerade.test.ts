import { describe, it, expect } from "vitest";
import {
  FORMAT_CHARS,
  bidiControlsIn,
  bidiVisual,
  escapeBidiControls,
  escapeBidiControlsAs,
  hasBidiControl,
  normalizeBidiMojibake,
} from "../../src/analysis/bidiControl.js";
import { BIDI_MASQUERADE_MARKER, annotateBidiMasquerade } from "../../src/analysis/bidiMasquerade.js";
import { aggregateEvents, parseSiemExport, type MappedEvent } from "../../src/analysis/siemImport.js";
import { splitDerivedNotes } from "../../src/analysis/derivedNote.js";

// Right-to-left override masquerading (T1036.002, #2027). APT29's Day 1 payload in the OTRF Evals
// dataset is `C:\ProgramData\victim\<U+202E>cod.3aka3.scr`, which Explorer shows as
// `…\rcs.3aka3.doc`. The NXLog export carries the character as mojibake: U+202E's UTF-8 bytes
// (E2 80 AE) read as Windows-1252 — "â€®".
const RLO = "\u202e";
const MOJIBAKE_RLO = "\u00e2\u20ac\u00ae"; // "â€®"
const PAYLOAD = `C:\\ProgramData\\victim\\${RLO}cod.3aka3.scr`;
const PAYLOAD_MOJIBAKE = `C:\\ProgramData\\victim\\${MOJIBAKE_RLO}cod.3aka3.scr`;
const RAW_BIDI = /[\u202a-\u202e\u2066-\u2069]/;

function mapped(over: Partial<MappedEvent>): MappedEvent {
  return {
    timestamp: "2020-05-02T02:55:56.157Z",
    description: "Sysmon Process Create (EID 1)",
    severity: "Info",
    mitre: [],
    aggKey: "k",
    ...over,
  };
}

describe("bidiControl helpers", () => {
  it("decodes the Windows-1252 mojibake of every bidi control back to the real character", () => {
    expect(normalizeBidiMojibake(PAYLOAD_MOJIBAKE)).toBe(PAYLOAD);
    expect(normalizeBidiMojibake("a\u00e2\u20ac\u00aab")).toBe("a\u202ab"); // LRE
    expect(normalizeBidiMojibake("a\u00e2\u20ac\u00adb")).toBe("a\u202db"); // LRO (soft-hyphen byte)
    expect(normalizeBidiMojibake("a\u00e2\u0081\u00a7b")).toBe("a\u2067b"); // RLI (0x81 kept as C1)
    expect(normalizeBidiMojibake("a\u00e2\u0080\u00aeb")).toBe("a\u202eb"); // Latin-1 decode of 0x80
  });

  it("leaves ordinary text, including other â€ mojibake, untouched", () => {
    expect(normalizeBidiMojibake("it\u00e2\u20ac\u2122s fine")).toBe("it\u00e2\u20ac\u2122s fine"); // ’
    expect(bidiControlsIn("C:\\Windows\\System32\\cmd.exe")).toEqual([]);
  });

  it("names the controls in either encoding", () => {
    expect(bidiControlsIn(PAYLOAD)).toEqual(["RLO"]);
    expect(bidiControlsIn(PAYLOAD_MOJIBAKE)).toEqual(["RLO"]);
    expect(bidiControlsIn("x\u2066y\u2069")).toEqual(["LRI", "PDI"]);
  });

  it("escapes every control as a visible marker", () => {
    expect(escapeBidiControls(PAYLOAD)).toBe("C:\\ProgramData\\victim\\<RLO>cod.3aka3.scr");
    expect(escapeBidiControls(PAYLOAD_MOJIBAKE)).toBe("C:\\ProgramData\\victim\\<RLO>cod.3aka3.scr");
    expect(escapeBidiControls("a\u202bb\u202c")).toBe("a<RLE>b<PDF>");
  });

  it("renders how an override displays", () => {
    expect(bidiVisual(`${RLO}cod.3aka3.scr`)).toBe("rcs.3aka3.doc");
    expect(bidiVisual(`${MOJIBAKE_RLO}cod.3aka3.scr`)).toBe("rcs.3aka3.doc");
    expect(bidiVisual(`invoice${RLO}fdp\u202c.exe`)).toBe("invoicepdf.exe");
    expect(bidiVisual(`a${RLO}(b)`)).toBe("a(b)"); // brackets mirror under the override
  });

  it("strips the bidi isolates as well as the embeddings (shared FORMAT_CHARS)", () => {
    expect("a\u2066b\u202ec\u200bd\u2069".replace(FORMAT_CHARS, "")).toBe("abcd");
  });
});

describe("annotateBidiMasquerade — the shared aggregation seam", () => {
  it("grades a mojibake RLO process image High / T1036.002 with a visible marker and the rendered name", () => {
    const m = mapped({
      description: `Sysmon Process Create (EID 1) - Image: ${PAYLOAD_MOJIBAKE}`,
      path: PAYLOAD_MOJIBAKE,
      processName: `${MOJIBAKE_RLO}cod.3aka3.scr`,
      severity: "Medium",
    });
    annotateBidiMasquerade(m);
    expect(m.severity).toBe("High");
    expect(m.mitre).toContain("T1036.002");
    expect(m.description).toContain("<RLO>cod.3aka3.scr");
    expect(m.description).toContain(BIDI_MASQUERADE_MARKER);
    expect(m.description).toContain("rcs.3aka3.doc");
    expect(m.description).toMatch(/right-to-left override/i);
    expect(m.description).not.toContain(MOJIBAKE_RLO);
    expect(splitDerivedNotes(m.description).notes).toContain("rcs.3aka3.doc");
  });

  it("fires on a real U+202E in the command line alone and never emits the raw character", () => {
    const m = mapped({
      description: `Process Create - CommandLine: "${PAYLOAD}" /S`,
      commandLine: `"${PAYLOAD}" /S`,
      message: `Process Create:\r\nImage: ${PAYLOAD}`,
    });
    annotateBidiMasquerade(m);
    expect(m.severity).toBe("High");
    expect(m.mitre).toEqual(["T1036.002"]);
    expect(m.description).toContain("rcs.3aka3.doc");
    expect(m.description).not.toMatch(RAW_BIDI);
    expect(m.message).not.toMatch(RAW_BIDI);
    expect(m.message).toContain("<RLO>cod.3aka3.scr");
  });

  it("fires on the parent image and on a created file name", () => {
    const child = mapped({ parentName: `${RLO}cod.3aka3.scr`, processName: "cmd.exe" });
    annotateBidiMasquerade(child);
    expect(child.severity).toBe("High");
    const file = mapped({ path: `C:\\Users\\a\\Downloads\\report${RLO}xcod.exe` });
    annotateBidiMasquerade(file);
    expect(file.severity).toBe("High");
    expect(file.description).toContain("reportexe.docx");
  });

  it("escapes but does not grade later activity of the disguised process (DLL load, handle open)", () => {
    const load = mapped({
      description: `Image loaded - Image=${PAYLOAD_MOJIBAKE}`,
      path: PAYLOAD_MOJIBAKE,
      severity: "Low",
      canonical: { event: { category: "other", type: "image_load" } } as MappedEvent["canonical"],
    });
    annotateBidiMasquerade(load);
    expect(load.severity).toBe("Low");
    expect(load.mitre).toEqual([]);
    expect(load.description).toContain("<RLO>cod.3aka3.scr");
    const launch = mapped({
      path: PAYLOAD,
      canonical: { event: { category: "process", type: "start" } } as MappedEvent["canonical"],
    });
    annotateBidiMasquerade(launch);
    expect(launch.severity).toBe("High");
    const write = mapped({
      path: PAYLOAD,
      canonical: { event: { category: "file", type: "create" } } as MappedEvent["canonical"],
    });
    annotateBidiMasquerade(write);
    expect(write.severity).toBe("High");
  });

  it("keeps Critical, unions MITRE, and is idempotent", () => {
    const m = mapped({ path: PAYLOAD, severity: "Critical", mitre: ["T1204.002"] });
    annotateBidiMasquerade(m);
    const once = { ...m, mitre: [...m.mitre] };
    annotateBidiMasquerade(m);
    expect(m.severity).toBe("Critical");
    expect(m.mitre).toEqual(["T1204.002", "T1036.002"]);
    expect(m.description).toBe(once.description);
  });

  it("leaves an event with no bidi control unchanged", () => {
    const m = mapped({ path: "C:\\Windows\\System32\\cmd.exe", commandLine: "cmd.exe /c dir" });
    const before = JSON.stringify(m);
    annotateBidiMasquerade(m);
    expect(JSON.stringify(m)).toBe(before);
  });

  it("escapes a control that appears only in the description text, without grading it", () => {
    const m = mapped({ description: `Registry value set - Details: ${PAYLOAD}`, path: "HKCU\\Software\\x" });
    annotateBidiMasquerade(m);
    expect(m.severity).toBe("Info");
    expect(m.description).toContain("<RLO>cod.3aka3.scr");
    expect(m.description).not.toMatch(RAW_BIDI);
  });

  it("is applied by the shared aggregator every importer ends in", () => {
    const { events } = aggregateEvents([mapped({ path: PAYLOAD, description: `x ${PAYLOAD}` })]);
    expect(events[0].severity).toBe("High");
    expect(events[0].mitreTechniques).toContain("T1036.002");
    expect(events[0].description).not.toMatch(RAW_BIDI);
  });
});

describe("parseSiemExport — RLO payload end to end (#2027)", () => {
  const base = {
    Hostname: "SCRANTON.lab.local",
    host: "wec.lab.local",
    "@version": "1",
  };
  const sysmon1 = {
    ...base,
    EventTime: "2020-05-01 22:55:57",
    SourceName: "Microsoft-Windows-Sysmon",
    Channel: "Microsoft-Windows-Sysmon/Operational",
    EventID: 1,
    UtcTime: "2020-05-02 02:55:56.157",
    ProcessId: "8524",
    Image: PAYLOAD_MOJIBAKE,
    CommandLine: `"${PAYLOAD_MOJIBAKE}" /S`,
    ParentImage: "C:\\Windows\\explorer.exe",
    User: "LAB\\analyst",
    Message: `Process Create:\r\nImage: ${PAYLOAD_MOJIBAKE}`,
  };
  const sec4688 = {
    ...base,
    EventTime: "2020-05-01 22:55:57",
    SourceName: "Microsoft-Windows-Security-Auditing",
    Channel: "Security",
    EventID: 4688,
    NewProcessId: "0x214c",
    NewProcessName: PAYLOAD,
    CommandLine: `"${PAYLOAD}" /S`,
    ParentProcessName: "C:\\Windows\\explorer.exe",
    SubjectUserName: "analyst",
    Message: `A new process has been created.\r\nNew Process Name: ${PAYLOAD}`,
  };

  const sysmon7 = {
    ...sysmon1,
    EventID: 7,
    ImageLoaded: "C:\\Windows\\System32\\version.dll",
    Message: `Image loaded:\r\nImage: ${PAYLOAD_MOJIBAKE}`,
  };
  const sysmon11 = {
    ...sysmon1,
    EventID: 11,
    Image: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    TargetFilename: PAYLOAD_MOJIBAKE,
    Message: `File created:\r\nTargetFilename: ${PAYLOAD_MOJIBAKE}`,
  };

  it("grades the Sysmon 1, the 4688 and the file write High with T1036.002 and no raw control character", () => {
    const r = parseSiemExport([sysmon1, sec4688, sysmon11].map((x) => JSON.stringify(x)).join("\n"));
    expect(r.events).toHaveLength(3);
    for (const e of r.events) {
      expect(e.severity).toBe("High");
      expect(e.mitreTechniques).toContain("T1036.002");
      expect(e.description).toContain("<RLO>cod.3aka3.scr");
      expect(e.description).toContain("rcs.3aka3.doc");
      expect(e.description).not.toMatch(RAW_BIDI);
      expect(e.description).not.toContain(MOJIBAKE_RLO);
    }
  });

  it("escapes a DLL load by the payload without grading it T1036.002", () => {
    const r = parseSiemExport(JSON.stringify(sysmon7));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].mitreTechniques).not.toContain("T1036.002");
    expect(r.events[0].description).toContain("<RLO>cod.3aka3.scr");
    expect(r.events[0].description).not.toMatch(RAW_BIDI);
  });
});

// The markers are display-only and one-way (#2050): literal `<RLO>` text in evidence renders the
// same as a real control, so nothing may parse a marker back out — the grading signal comes from
// the raw value.
describe("bidi markers are one-way", () => {
  it("renders literal marker text and a real control identically", () => {
    expect(escapeBidiControls("a<RLO>b")).toBe(escapeBidiControls(`a${RLO}b`));
  });

  it("does not read literal marker text as a bidi control", () => {
    expect(hasBidiControl("a<RLO>b")).toBe(false);
    expect(bidiControlsIn("a<RLO>b")).toEqual([]);
    expect(hasBidiControl(`a${RLO}b`)).toBe(true);
  });

  it("refuses a bracket that is itself a bidi control", () => {
    expect(() => escapeBidiControlsAs(`a${RLO}b`, RLO, ">")).toThrow(/bracket/i);
    expect(() => escapeBidiControlsAs(`a${RLO}b`, "<", "\u2066")).toThrow(/bracket/i);
    expect(() => escapeBidiControlsAs(`a${RLO}b`, MOJIBAKE_RLO, ">")).toThrow(/bracket/i);
  });

  it("refuses empty brackets", () => {
    expect(() => escapeBidiControlsAs(`a${RLO}b`, "", "")).toThrow(/bracket/i);
    expect(() => escapeBidiControlsAs(`a${RLO}b`, "<", "")).toThrow(/bracket/i);
  });

  it("checks the brackets even when the value has no control", () => {
    expect(() => escapeBidiControlsAs("plain", "", "")).toThrow(/bracket/i);
  });

  it("still accepts the built-in bracket pairs", () => {
    expect(escapeBidiControlsAs(`a${RLO}b`, "\u2039", "\u203a")).toBe("a\u2039RLO\u203ab");
    expect(escapeBidiControls(`a${RLO}b`)).toBe("a<RLO>b");
  });
});
