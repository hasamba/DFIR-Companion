// A DetectRaptor EVTX detection post-processed in Velociraptor to cut its size: the event is flattened
// into dotted top-level keys ("Detection.Name", "EventData.NewProcessName", …) with no System wrapper
// and no Message. The process must still reach the title and the event key — before, every hit of one
// rule on a host shared an empty subject and collapsed into one row, titled by the rule alone.
import { describe, expect, it } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

const ART = "DetectRaptor.Windows.Detection.Evtx";

const flatRow = (image: string, over: Record<string, unknown> = {}): Record<string, unknown> => ({
  "Detection.Name": "T1218-Example LOLBIN Rule",
  EventTime: "2026-06-01T10:00:00Z",
  Computer: "WS-LAB-01",
  Username: "",
  "EventData.NewProcessName": image,
  "EventData.CommandLine": "",
  "EventData.ParentProcessName": "C:\\Windows\\System32\\services.exe",
  _Source: ART,
  ...over,
});

const parse = (rows: Record<string, unknown>[]) =>
  parseVelociraptorJson(JSON.stringify({ [ART]: rows })).events;

describe("flattened EventData.* detection rows", () => {
  it("names the process in the title and the parent in the details", () => {
    const [e] = parse([flatRow("C:\\Windows\\SysWOW64\\example.exe")]);
    const i = e.description.indexOf(" - ");
    expect(e.description.slice(0, i)).toContain("T1218-Example LOLBIN Rule — example.exe");
    expect(e.processName).toBe("example.exe");
    expect(e.parentName).toBe("services.exe");
  });

  it("keeps two processes hitting one rule apart", () => {
    const events = parse([flatRow("C:\\Windows\\SysWOW64\\a.exe"), flatRow("C:\\Windows\\SysWOW64\\b.exe")]);
    expect(events).toHaveLength(2);
  });

  it("shows the command line when the row has one", () => {
    const [e] = parse([
      flatRow("C:\\Windows\\SysWOW64\\example.exe", { "EventData.CommandLine": "example.exe /run" }),
    ]);
    expect(e.description).toContain("example.exe /run");
  });

  it("dates the row by its EventTime", () => {
    const [e] = parse([flatRow("C:\\Windows\\SysWOW64\\example.exe")]);
    expect(e.timestamp).toContain("2026-06-01T10:00:00");
  });
});
