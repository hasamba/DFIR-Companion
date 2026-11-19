import { describe, it, expect } from "vitest";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

// #2705: a Velociraptor NOTEBOOK export (a hunt's EVTX-hunter notebook downloaded as JSON Lines) has
// no `_Source`/`Artifact` stamp, a NESTED `Detection` object rather than Elasticsearch's dotted
// keys, and EventData beside Channel/EventID instead of a `System` object — so it fell through to
// the SIEM catch-all and lost its verdict. Synthetic rows; placeholders only.

function notebookRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    EventTime: "2026-08-13T22:00:05Z",
    Computer: "HOSTNAME_1.lab.local",
    Detection: {
      Name: "T1567.002-Use of 32-bit LOLBINs",
      EventId: "^(4688)$",
      Regex: "syswow64",
      Ignore: "",
    },
    Channel: "Security",
    EventID: 4688,
    UserSID: null,
    Username: "",
    EventData: {
      SubjectUserSid: "S-1-5-18",
      SubjectUserName: "HOSTNAME_1$",
      SubjectDomainName: "DOMAIN_1",
      NewProcessName: "C:\\Windows\\SysWOW64\\wbem\\WmiPrvSE.exe",
      ParentProcessName: "C:\\Windows\\System32\\svchost.exe",
      CommandLine: "",
    },
    Message: "A new process has been created.",
    OSPath: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    FlowId: "F.EXAMPLEFLOW01.H",
    ClientId: "C.0123456789abcdef",
    Fqdn: "HOSTNAME_1.lab.local",
    ...over,
  };
}

const ndjson = (rows: object[]): string => rows.map((r) => JSON.stringify(r)).join("\n") + "\n";

describe("detectImportKind — Velociraptor notebook exports (#2705)", () => {
  it("claims a notebook EVTX-hunter row by its client id and flow id", () => {
    const text = ndjson([notebookRow(), notebookRow({ EventTime: "2026-08-14T00:26:47Z" })]);
    expect(detectImportKind("sb_evtx.json", text)).toBe("velociraptor");
  });

  it("claims the row from the client id plus any one corroborating Velociraptor column", () => {
    for (const keep of ["FlowId", "Fqdn", "EventTime", "OSPath"]) {
      const row: Record<string, unknown> = { ClientId: "C.0123456789abcdef", Message: "x", [keep]: "v" };
      if (keep === "FlowId") row.FlowId = "F.EXAMPLEFLOW01.H";
      expect(detectImportKind("export.json", ndjson([row, row])), keep).toBe("velociraptor");
    }
  });

  it("claims a detection row exported without ids by its nested Detection{Name} beside EventData", () => {
    const { ClientId: _c, FlowId: _f, Fqdn: _q, OSPath: _o, EventTime: _t, ...bare } = notebookRow();
    expect(detectImportKind("export.json", ndjson([bare, bare]))).toBe("velociraptor");
  });

  it("maps the notebook row to a Medium Velociraptor detection carrying its MITRE technique", () => {
    const parsed = parseVelociraptorJson(ndjson([notebookRow()]), {});
    const hit = parsed.events.find((e) => /Velociraptor detection: T1567\.002/.test(e.description));
    expect(hit, JSON.stringify(parsed.events.map((e) => e.description))).toBeDefined();
    expect(hit!.severity).toBe("Medium");
    expect(hit!.mitreTechniques).toContain("T1567.002");
  });
});

describe("detectImportKind — what the notebook signature must not claim (#2705)", () => {
  it("leaves a SIEM row whose ClientId is not a Velociraptor client id to the SIEM importer", () => {
    const row = { ClientId: "abc-123", EventTime: "2026-08-13T22:00:05Z", message: "login", host: "h1" };
    expect(detectImportKind("siem.json", ndjson([row, row]))).toBe("siem");
  });

  it("does not claim a Velociraptor-shaped client id with no corroborating column", () => {
    const row = { ClientId: "C.0123456789abcdef", message: "login", host: "h1" };
    expect(detectImportKind("siem.json", ndjson([row, row]))).toBe("siem");
  });

  it("does not claim a Detection object without EventData", () => {
    const row = { Detection: { Name: "rule" }, message: "x", host: "h1" };
    expect(detectImportKind("siem.json", ndjson([row, row]))).toBe("siem");
  });

  it("still sends a Chainsaw flattened Sigma row to Chainsaw", () => {
    const row = {
      Detection: "Suspicious LOLBIN",
      Severity: "high",
      EventID: 4688,
      Channel: "Security",
      ClientId: "C.0123456789abcdef",
      EventTime: "2026-08-13T22:00:05Z",
    };
    expect(detectImportKind("chainsaw.json", ndjson([row, row]))).toBe("chainsaw");
  });

  // A notebook export stamps the hunt's ids on the rows of whatever tool the hunt ran: a Hayabusa or
  // THOR result exported from a notebook must keep its own importer (#1756), not become generic VR.
  it("leaves every later specific detector's rows with that detector when the hunt's ids are added", () => {
    const ids = {
      ClientId: "C.0123456789abcdef",
      FlowId: "F.EXAMPLEFLOW01.H",
      Fqdn: "HOSTNAME_1.lab.local",
    };
    const cases: [string, object][] = [
      ["hayabusa", { Timestamp: "t", RuleTitle: "x", Level: "high" }],
      [
        "hayabusa",
        {
          Timestamp: "t",
          Computer: "W",
          Channel: "Security",
          EID: 1,
          Level: "high",
          Title: "T",
          RecordID: 9,
        },
      ],
      ["network", { event_type: "alert", alert: { signature: "x" } }],
      ["thor", { time: "t", module: "Filescan", level: "Warning", message: "x" }],
      [
        "cybertriage",
        {
          epoch_timestamp: 1769593923,
          hostName: "w",
          message: "/x",
          score: "None",
          timestamp_desc: "File Modified",
        },
      ],
      ["journald", { __REALTIME_TIMESTAMP: "1", PRIORITY: "6", MESSAGE: "m", SYSLOG_IDENTIFIER: "sshd" }],
      ["sysdig", { time: "t", rule: "Terminal shell", priority: "Warning", output: "o", output_fields: {} }],
      [
        "wazuh",
        { timestamp: "t", rule: { level: 7, description: "S", id: "9" }, agent: { id: "2", name: "h" } },
      ],
      ["thehive", { _type: "alert", title: "TOR login", severity: 2 }],
    ];
    for (const [kind, row] of cases) {
      expect(detectImportKind("export.json", ndjson([row, row])), `${kind} baseline`).toBe(kind);
      const withIds = { ...row, ...ids };
      expect(detectImportKind("export.json", ndjson([withIds, withIds])), kind).toBe(kind);
    }
  });
});
