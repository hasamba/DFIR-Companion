import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import { cloudExportCsvKind } from "../../src/analysis/cloudExportDetect.js";
import { readTolerantJsonRecords, jsonRepairNote } from "../../src/analysis/tolerantJson.js";
import { scanConcatenatedJson, parseConcatenatedJson } from "../../src/analysis/concatenatedJson.js";
import { cloudTrailConsoleRow, readCloudRecords } from "../../src/analysis/cloudRecords.js";
import { adaptM365ExportRow, exportCsvTime } from "../../src/analysis/m365ExportAdapters.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";

// #2302: Log Analytics / MES / CloudTrail-console exports route to the importer that reads them,
// and the files that already had a kind keep it. Every value is synthetic (example.com, RFC 5737).

const j = (v: unknown): string => JSON.stringify(v);
const fixture = (p: string): string =>
  readFileSync(new URL(`../fixtures/cloudCompat/${p}`, import.meta.url), "utf8");

const LA_SIGNIN = {
  TenantId: "00000000-0000-4000-8000-000000001300",
  TimeGenerated: "2026-11-01T11:01:05Z",
  ResourceId: "/tenants/00000000-0000-4000-8000-000000000001/providers/Microsoft.aadiam",
  OperationName: "Sign-in activity",
  CorrelationId: "00000000-0000-4000-8000-000000000501",
  ResultType: "50126",
  ResultDescription: "Invalid username or password.",
  AppDisplayName: "Example App",
  IPAddress: "203.0.113.10",
  UserPrincipalName: "user1@example.com",
  Type: "SigninLogs",
};

describe("cloud export detection — positives (#2302)", () => {
  it("a Log Analytics sign-in JSON row is m365, ahead of the Azure Activity catch-all", () => {
    expect(detectImportKind("SigninLogs.json", j([LA_SIGNIN]))).toBe("m365");
  });

  it("a Log Analytics sign-in with a numeric ResultType of 0 (a success) is still m365", () => {
    expect(detectImportKind("SigninLogs.json", j([{ ...LA_SIGNIN, ResultType: 0 }]))).toBe("m365");
  });

  it.each([
    ["resulttype,userprincipalname,appdisplayname", "m365"],
    ["resulttype,userprincipalname,conditionalaccessstatus", "m365"],
    ["activitydisplayname,initiatedby,timegenerated", "m365"],
    ["operation,recordtype,officeworkload", "m365"],
    ["operation,logontype,mailboxownerupn,lastaccessed", "m365"],
    ["operationnamevalue,caller,correlationid", "cloud"],
    ["event name,event source,event time", "aws"],
  ])("CSV header %s → %s", (header, kind) => {
    expect(cloudExportCsvKind(new Set(header.split(",")))).toBe(kind);
  });
});

describe("cloud export detection — negative collisions keep their kind (#2302)", () => {
  it("Azure Activity from the REST API stays cloud", () => {
    const rest = {
      operationName: { value: "Microsoft.Compute/virtualMachines/write", localizedValue: "Create VM" },
      caller: "admin@example.com",
      resourceId: "/subscriptions/00000000-0000-4000-8000-000000000700/resourceGroups/rg1",
      correlationId: "00000000-0000-4000-8000-000000000801",
      eventTimestamp: "2026-11-01T12:00:00Z",
      status: { value: "Succeeded" },
    };
    expect(detectImportKind("activity.json", j({ value: [rest] }))).toBe("cloud");
  });

  it.each(["azure-diagnostic/signinlogs/PT1H.json", "azure-diagnostic/keyvault/PT1H.json"])(
    "%s (diagnostic settings) stays cloud",
    (p) => {
      expect(detectImportKind("PT1H.json", fixture(p))).toBe("cloud");
    },
  );

  it("Log Analytics AzureActivity JSON stays cloud", () => {
    expect(detectImportKind("AzureActivity.json", fixture("log-analytics/AzureActivity.json"))).toBe("cloud");
  });

  it("Sentinel SecurityAlert / SecurityIncident rows are not claimed as M365", () => {
    const base = { TenantId: "t", TimeGenerated: "2026-11-01T10:00:00Z" };
    const alert = { ...base, AlertName: "x", AlertSeverity: "High", CompromisedEntity: "user1@example.com" };
    expect(detectImportKind("a.json", j([{ ...alert, Type: "SecurityAlert" }]))).toBe("siem");
    expect(
      detectImportKind("i.json", j([{ ...base, Title: "t", Status: "New", Type: "SecurityIncident" }])),
    ).toBe("siem");
  });

  it("Sentinel Syslog rows stay sentinellinux", () => {
    const row = {
      TimeGenerated: "2026-11-01T10:00:00Z",
      Facility: "auth",
      HostName: "h1",
      SyslogMessage: "x",
    };
    expect(detectImportKind("syslog.json", j([row]))).toBe("sentinellinux");
  });

  it("Velociraptor rows with _Source stay velociraptor, even with one sign-in-like column", () => {
    const evtx = { _Source: "Windows.EventLogs.Evtx", System: { EventID: 1 }, EventData: {} };
    expect(detectImportKind("vr.json", j([evtx]))).toBe("velociraptor");
    const upn = { _Source: "Custom.Entra.SignIns", UserPrincipalName: "user1@example.com", ResultType: "0" };
    expect(detectImportKind("vr.json", j([upn]))).toBe("velociraptor");
  });

  it("generic SIEM JSON stays siem", () => {
    const row = {
      "@timestamp": "2026-11-01T10:00:00Z",
      message: "login",
      user: { name: "u" },
      ResultType: "0",
    };
    expect(detectImportKind("siem.json", j([row]))).toBe("siem");
  });

  it("a CSV with one of the columns, but not the combination, stays a generic CSV", () => {
    expect(detectImportKind("ops.csv", "Operation,User,Time\nlogin,u1,2026-11-01\n")).toBe("csv");
    expect(detectImportKind("ev.csv", "Event name,Time\nx,2026-11-01\n")).toBe("csv");
    expect(detectImportKind("sign.csv", "UserPrincipalName,ResultType\nuser1@example.com,0\n")).toBe("csv");
  });

  it("the UAL CSV keeps its own signature", () => {
    expect(detectImportKind("UAL-Combined.csv", fixture("mes-4.1.0/UAL-Combined.csv"))).toBe("m365");
  });
});

describe("tolerant JSON reader (#2302)", () => {
  const rec = (n: number) => ({ Operation: `Op${n}`, CreationTime: "2026-11-01T10:00:00" });

  it("a valid document needs no repair", () => {
    expect(readTolerantJsonRecords(j([rec(1)])).repairs).toEqual({
      bomStripped: 0,
      documentsJoined: 0,
      garbageSkipped: 0,
    });
  });

  it("removes and counts a UTF-8 byte-order mark", () => {
    const r = readTolerantJsonRecords(`\uFEFF${j([rec(1)])}`);
    expect(r.records).toHaveLength(1);
    expect(r.repairs.bomStripped).toBe(1);
  });

  it("joins `][` concatenated arrays and counts each seam", () => {
    const text = `${j([rec(1), rec(2)])}${j([rec(3)])}\n${j([rec(4)])}`;
    const r = readTolerantJsonRecords(text);
    expect(r.records.map((x) => x.Operation)).toEqual(["Op1", "Op2", "Op3", "Op4"]);
    expect(r.repairs).toEqual({ bomStripped: 0, documentsJoined: 2, garbageSkipped: 0 });
  });

  it("reads every record of a pretty-printed array with trailing garbage, and counts the garbage", () => {
    // One compact object per line inside an array: the line-by-line fallback alone would keep only
    // the LAST line (the only one without a trailing comma) and silently drop the rest.
    const text = `[\n${j(rec(1))},\n${j(rec(2))},\n${j(rec(3))}\n]\n-- export truncated --`;
    const r = readTolerantJsonRecords(text);
    expect(r.records).toHaveLength(3);
    expect(r.repairs.garbageSkipped).toBe(1);
  });

  it("counts an unparseable line in genuine JSON lines (a truncated tail)", () => {
    const text = `${j(rec(1))}\n${j(rec(2))}\n{"Operation": "Op3", "Crea`;
    const r = readTolerantJsonRecords(text);
    expect(r.records).toHaveLength(2);
    expect(r.repairs.garbageSkipped).toBe(1);
  });

  it("the note names each repair, and says nothing when none was needed", () => {
    expect(jsonRepairNote({ bomStripped: 1, documentsJoined: 1, garbageSkipped: 2 })).toBe(
      "; file repaired on read: a UTF-8 byte-order mark removed, 1 join(s) between concatenated JSON documents, 2 unreadable stretch(es) of text skipped",
    );
    expect(jsonRepairNote({ bomStripped: 0, documentsJoined: 0, garbageSkipped: 0 })).toBe("");
    expect(jsonRepairNote(undefined)).toBe("");
  });

  it("scanConcatenatedJson returns parseConcatenatedJson's values, plus what it skipped", () => {
    const text = '{"a":1} junk {"b":2} [3] tail';
    expect(scanConcatenatedJson(text)).toEqual({ values: parseConcatenatedJson(text), skipped: 2 });
    expect(scanConcatenatedJson('{"a":1},\n{"b":2}\n').skipped).toBe(0);
  });

  it("every cloud importer carries the repairs on its parse result", () => {
    const bom = "\uFEFF";
    expect(parseM365Audit(`${bom}${fixture("mes-4.1.0/UAL-Combined.json")}`).repairs?.bomStripped).toBe(1);
    expect(parseCloudActivity(`${bom}${fixture("mes-4.1.0/ActivityLog.json")}`).repairs?.bomStripped).toBe(1);
    const trail = fixture(
      "aws-cloudtrail/123456789012_CloudTrail_us-east-1_20261101T1005Z_EXAMPLE0000000001.json",
    );
    expect(parseCloudTrail(`${trail}\ngarbage`).repairs?.garbageSkipped).toBe(1);
  });

  it("a BOM-prefixed CSV is read and the BOM is counted", () => {
    const r = readCloudRecords(`\uFEFFa,b\n1,2\n`);
    expect(r.records).toEqual([{ a: "1", b: "2" }]);
    expect(r.repairs.bomStripped).toBe(1);
  });
});

describe("normalizing adapters (#2302)", () => {
  it("exportCsvTime reads en-US AM/PM and unambiguous dates, and refuses a possible month/day swap", () => {
    expect(exportCsvTime("11/1/2026 10:05:00 AM")).toBe("2026-11-01T10:05:00Z");
    expect(exportCsvTime("11/1/2026 12:30:00 AM")).toBe("2026-11-01T00:30:00Z");
    expect(exportCsvTime("11/1/2026 1:05:00 PM")).toBe("2026-11-01T13:05:00Z");
    expect(exportCsvTime("25/11/2026 13:05:00")).toBe("2026-11-25T13:05:00Z");
    expect(exportCsvTime("11/25/2026 13:05")).toBe("2026-11-25T13:05:00Z");
    expect(exportCsvTime("1/2/2026 13:05:00")).toBe("");
    expect(exportCsvTime("2/30/2026 1:00:00 AM")).toBe("");
    expect(exportCsvTime("not a time")).toBe("");
  });

  it("a Log Analytics sign-in takes its outcome from ResultType when Status is absent", () => {
    const row = adaptM365ExportRow(LA_SIGNIN);
    expect(row.status).toEqual({ errorCode: 50126, failureReason: "Invalid username or password." });
    expect(row.createdDateTime).toBe("2026-11-01T11:01:05Z");
    expect(LA_SIGNIN).not.toHaveProperty("status"); // the input is not mutated
  });

  it("a mailbox audit row on a delegate logon names the delegate, not the owner", () => {
    const row = adaptM365ExportRow({
      Operation: "SendAs",
      MailboxOwnerUPN: "user1@example.com",
      LogonType: "Delegate",
      LogonUserDisplayName: "Example User 2",
      LastAccessed: "11/1/2026 10:05:00 AM",
    });
    expect(row.UserId).toBe("Example User 2");
    expect(row.CreationTime).toBe("2026-11-01T10:05:00Z");
  });

  it("a record no adapter claims comes back unchanged", () => {
    const ual = {
      Operation: "New-InboxRule",
      CreationTime: "2026-11-01T10:00:00",
      UserId: "user1@example.com",
    };
    expect(adaptM365ExportRow(ual)).toBe(ual);
  });

  it("a CloudTrail console row with a `CloudTrail event` column uses the full record", () => {
    const full = {
      eventName: "StopLogging",
      eventSource: "cloudtrail.amazonaws.com",
      userIdentity: { type: "Root" },
    };
    expect(cloudTrailConsoleRow({ "Event name": "StopLogging", "CloudTrail event": j(full) })).toEqual(full);
  });

  it("the console CSV grades a logging change and carries user and address", () => {
    const parsed = parseCloudTrail(fixture("aws-cloudtrail/event_history.csv"), { aggregate: false });
    expect(parsed.total).toBe(3);
    const stop = parsed.events.find((e) => e.description.includes("StopLogging"));
    expect(stop?.severity).not.toBe("Info");
    expect(stop?.description).toContain("by user1");
    expect(parsed.iocs.map((i) => i.value)).toContain("203.0.113.50");
  });
});
