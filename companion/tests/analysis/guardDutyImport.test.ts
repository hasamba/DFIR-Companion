import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseGuardDuty, guardDutyNoteDetail } from "../../src/analysis/guardDutyImport.js";
import {
  guardDutyMitre,
  guardDutySeverity,
  isGuardDutyFinding,
  readGuardDutyRecords,
} from "../../src/analysis/guardDutyRecord.js";
import { cloudRecordIdentity } from "../../src/analysis/cloudRecordIdentity.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import { closeTruncatedJsonArray } from "../../src/analysis/extractJson.js";
import { runTagger } from "../../src/analysis/tagger.js";
import { compileText } from "../../src/analysis/taggerStore.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { GD_ACCOUNT, gdExport, gdFinding } from "../helpers/guardDutyFixtures.js";

// #2361 — the GuardDuty findings importer: one row per finding, graded by GuardDuty's own severity.

const parse = (findings: unknown[]) => parseGuardDuty(gdExport(findings), { aggregate: false });

describe("severity bands (#2361)", () => {
  it.each([
    [10, "Critical"],
    [9.0, "Critical"],
    [8.9, "High"],
    [7.0, "High"],
    [6.9, "Medium"],
    [4.0, "Medium"],
    [3.9, "Low"],
    [1, "Low"],
  ])("GuardDuty %s → %s", (score, expected) => {
    expect(guardDutySeverity(score, false)).toBe(expected);
    expect(parse([gdFinding(1, { Severity: score })]).events[0].severity).toBe(expected);
  });

  it("an archived finding stays Info, says so, whatever its score", () => {
    const [e] = parse([gdFinding(1, { Severity: 9.5 }, { Archived: true })]).events;
    expect(e.severity).toBe("Info");
    expect(e.description).toMatch(/, archived$/);
  });

  it.each([[undefined], [null], ["high"], [""], [Number.NaN], ["Infinity"]])(
    "a missing or non-numeric severity (%s) is Low and counted",
    (bad) => {
      const r = parse([gdFinding(1, { Severity: bad })]);
      expect(r.events[0].severity).toBe("Low");
      expect(r.events[0].description).toContain("severity not given");
      expect(r.missingSeverity).toBe(1);
      expect(guardDutyNoteDetail(r)).toMatch(/1 finding\(s\) with no numeric severity, graded Low/);
    },
  );

  it("reads a numeric string severity", () => {
    expect(parse([gdFinding(1, { Severity: "7.5" })]).events[0].severity).toBe("High");
  });
});

describe("MITRE from the finding type (#2361)", () => {
  it.each([
    ["CryptoCurrency:EC2/BitcoinTool.B!DNS", ["T1496"]],
    ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", ["T1552.005"]],
    ["UnauthorizedAccess:EC2/SSHBruteForce", ["T1110"]],
    ["Recon:EC2/Portscan", ["T1046"]],
    ["Stealth:IAMUser/CloudTrailLoggingDisabled", ["T1562.008"]],
    ["Policy:IAMUser/RootCredentialUsage", ["T1078.004"]],
    ["Exfiltration:S3/AnomalousBehavior", ["T1530"]],
    ["Discovery:S3/MaliciousIPCaller", ["T1619"]],
    ["Execution:Runtime/ReverseShell", ["T1059"]],
  ])("%s → %j", (type, ids) => {
    expect(guardDutyMitre(type)).toEqual(ids);
    expect(parse([gdFinding(1, { Type: type })]).events[0].mitreTechniques).toEqual(ids);
  });

  it.each([
    "Execution:Runtime/NewBinaryExecuted",
    "Recon:EC2/PortProbeUnprotectedPort",
    "UnauthorizedAccess:EC2/TorClient",
    "PrivilegeEscalation:Kubernetes/PrivilegedContainer",
    "Backdoor:EC2/C&CActivity.B!DNS",
    "Stealth:IAMUser/PasswordPolicyChange",
  ])("%s maps to no technique (the type does not establish one)", (type) => {
    expect(guardDutyMitre(type)).toEqual([]);
  });
});

describe("one row per finding (#2361)", () => {
  it("names type, title, resource, account, region and severity; IOCs from the action", () => {
    const r = parse([
      gdFinding(1),
      gdFinding(
        2,
        { Type: "Trojan:EC2/DNSDataExfiltration" },
        { Action: { ActionType: "DNS_REQUEST", DnsRequestAction: { Domain: "exfil.example.com" } } },
      ),
    ]);
    expect(r.total).toBe(2);
    expect(r.events).toHaveLength(2);
    const scan = r.events.find((e) => /Portscan/.test(e.description))!;
    expect(scan.description).toBe(
      `GuardDuty finding Recon:EC2/Portscan: Unusual outbound port scan — Instance i-0abc1 (account ${GD_ACCOUNT}, eu-west-1, severity 5)`,
    );
    expect(scan.timestamp).toBe("2026-10-01T00:55:00.000Z"); // EventFirstSeen
    expect(scan.srcIp).toBe("203.0.113.50");
    expect(scan.asset).toBe("Instance i-0abc1");
    expect(scan.sources).toEqual(["AWS GuardDuty"]);
    expect(scan.message).toMatch(/seen 3 time\(s\).*first seen 2026-10-01T00:55:00.000Z/);
    expect(r.iocs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: "ip", value: "203.0.113.50" }),
        expect.objectContaining({ type: "domain", value: "exfil.example.com" }),
      ]),
    );
  });

  it("keeps adversary-controlled text on one bounded line", () => {
    const title = `evil\r\ntitle ${"x".repeat(1000)}`;
    const [e] = parse([gdFinding(1, { Title: title })]).events;
    expect(e.description).not.toMatch(/[\r\n]/);
    expect(e.description.length).toBeLessThanOrEqual(600);
  });

  it("falls back to CreatedAt when EventFirstSeen is missing", () => {
    const f = gdFinding(1);
    delete (f.Service as Record<string, unknown>).EventFirstSeen;
    expect(parse([f]).events[0].timestamp).toBe("2026-10-01T01:00:00.000Z");
  });

  it("two versions of one finding in one export stay two rows, even with aggregation on", () => {
    const v1 = gdFinding(1);
    const v2 = gdFinding(1, { UpdatedAt: "2026-10-01T05:00:00.000Z" }, { Count: 9 });
    const r = parseGuardDuty(gdExport([v1, v2]));
    expect(r.events).toHaveLength(2);
  });
});

describe("export shapes (#2361)", () => {
  const f = gdFinding(1);
  it.each([
    ["the get-findings document", gdExport([f, gdFinding(2)])],
    ["a bare array", JSON.stringify([f, gdFinding(2)])],
    ["JSON lines", `${JSON.stringify(f)}\n${JSON.stringify(gdFinding(2))}\n`],
    ["two concatenated CLI outputs", `${gdExport([f])}\n${gdExport([gdFinding(2)])}`],
  ])("reads %s", (_name, text) => {
    expect(readGuardDutyRecords(text).records).toHaveLength(2);
    expect(parseGuardDuty(text).events).toHaveLength(2);
  });

  it("reads the camelCase spelling EventBridge delivers", () => {
    const camel = {
      accountId: GD_ACCOUNT,
      arn: "arn:aws:guardduty:us-east-1:123456789012:detector/d1/finding/f1",
      id: "f1",
      region: "us-east-1",
      type: "UnauthorizedAccess:EC2/SSHBruteForce",
      severity: 8,
      title: "SSH brute force",
      resource: { resourceType: "Instance", instanceDetails: { instanceId: "i-0cam" } },
      service: { serviceName: "guardduty", archived: false, eventFirstSeen: "2026-10-01T02:00:00Z" },
      createdAt: "2026-10-01T02:00:00Z",
      updatedAt: "2026-10-01T02:00:00Z",
    };
    const [e] = parseGuardDuty(JSON.stringify([camel])).events;
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toEqual(["T1110"]);
    expect(e.asset).toBe("Instance i-0cam");
  });

  it("does not read a Security Hub (ASFF) finding as GuardDuty", () => {
    const asff = {
      SchemaVersion: "2018-10-08",
      Id: "arn:aws:guardduty:us-east-1:123456789012:detector/d1/finding/f1",
      ProductArn: "arn:aws:securityhub:us-east-1::product/aws/guardduty",
      Types: ["TTPs/Discovery/Recon:EC2-Portscan"],
      Type: "Recon:EC2/Portscan",
      Severity: { Label: "MEDIUM", Normalized: 50 },
      Title: "Unusual outbound port scan",
    };
    expect(isGuardDutyFinding(asff)).toBe(false);
    const r = parseGuardDuty(gdExport([asff]));
    expect(r.events).toEqual([]);
    expect(r.unrecognized).toBe(1);
    expect(detectImportKind("findings.json", gdExport([asff]))).not.toBe("guardduty");
  });
});

describe("detection (#2361)", () => {
  it("detects a hand-dropped export, a bare array and JSON lines through the full detector", () => {
    const f = gdFinding(1);
    expect(detectImportKind("gd.json", gdExport([f]))).toBe("guardduty");
    expect(detectImportKind("gd.json", JSON.stringify([f]))).toBe("guardduty");
    expect(detectImportKind("gd.jsonl", `${JSON.stringify(f)}\n${JSON.stringify(gdFinding(2))}`)).toBe(
      "guardduty",
    );
  });

  it("detects a large export from its truncated head", () => {
    const text = gdExport(Array.from({ length: 50 }, (_, i) => gdFinding(i)));
    const head = closeTruncatedJsonArray(text.slice(0, 3000))!;
    expect(head).toBeTruthy();
    expect(detectImportKind("gd.json", head)).toBe("guardduty");
  });

  it("claims no CloudTrail or GCP record", () => {
    const ct = { eventName: "ListFindings", eventSource: "guardduty.amazonaws.com", eventID: "e1" };
    expect(detectImportKind("ct.json", JSON.stringify({ Records: [ct] }))).toBe("aws");
    expect(isGuardDutyFinding(ct)).toBe(false);
    expect(isGuardDutyFinding({ protoPayload: { methodName: "x" }, logName: "cloudaudit" })).toBe(false);
  });
});

describe("record identity (#2361)", () => {
  it("is account + region + id + update time: a re-collect is the same, an update is not", () => {
    const a = cloudRecordIdentity("guardduty", gdFinding(1));
    const same = cloudRecordIdentity("guardduty", gdFinding(1));
    const updated = cloudRecordIdentity("guardduty", gdFinding(1, { UpdatedAt: "2026-10-02T00:00:00Z" }));
    expect(a.key).toBe(`guardduty|${GD_ACCOUNT}|eu-west-1|${gdFinding(1).Id}|2026-10-01T01:30:00.000Z`);
    expect(same).toEqual(a);
    expect(updated.key).not.toBe(a.key);
    expect(a.hashIdentified).toBe(false);
  });
});

describe("the saved page loses nothing (#2361)", () => {
  it("a page body made from the SDK's findings grades exactly like the raw finding", () => {
    const raw = gdFinding(1, { Severity: 9.2, Type: "CryptoCurrency:EC2/BitcoinTool.B!DNS" });
    // The collector writes JSON.stringify({ Findings }) of what the SDK returned.
    const page = JSON.stringify({ Findings: [JSON.parse(JSON.stringify(raw))] });
    const fromPage = parseGuardDuty(page, { aggregate: false }).events[0];
    const fromRaw = parseGuardDuty(JSON.stringify([raw]), { aggregate: false }).events[0];
    expect(fromPage).toEqual(fromRaw);
    expect(fromPage.severity).toBe("Critical");
  });
});

// The detection-overlap rule (#2348) for GuardDuty rows: GuardDuty's own grade is deliberate, so a
// shipped tagger rule that graded a GuardDuty row differently would silently override it.
describe("no shipped tagger rule regrades a GuardDuty row (#2361, #2348)", () => {
  const rules = compileText(
    readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
  );
  const types = [
    "Recon:EC2/Portscan",
    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    "Stealth:IAMUser/CloudTrailLoggingDisabled",
    "Policy:IAMUser/RootCredentialUsage",
    "Execution:Runtime/ReverseShell",
    "Exfiltration:S3/AnomalousBehavior",
    "Persistence:IAMUser/AnomalousBehavior",
    "Impact:S3/MaliciousIPCaller",
    "Trojan:EC2/DNSDataExfiltration",
  ];
  it.each(types)("%s", (type) => {
    for (const [score, archived] of [
      [9.5, false],
      [5, false],
      [2, true],
    ] as const) {
      const [row] = parse([gdFinding(1, { Type: type, Severity: score }, { Archived: archived })]).events;
      const event = {
        ...row,
        id: "e1",
        relatedFindingIds: [],
        sourceScreenshots: [],
      } as unknown as ForensicEvent;
      const hit = runTagger([event], rules).perEvent[0];
      const graded = (hit?.ruleIds ?? [])
        .map((id) => rules.rules.find((r) => r.id === id)!)
        .filter((r) => r.severity && r.severity !== "Info" && r.severity !== row.severity);
      expect(graded.map((r) => r.id)).toEqual([]);
    }
  });
});
