import { describe, expect, it } from "vitest";
import {
  CANONICAL_EVENT_SCHEMA_VERSION,
  canonicalConformanceIssues,
  createCanonicalEvent,
  mergeCanonicalEvents,
  upgradeForensicEvent,
} from "../../src/analysis/canonicalEvent.js";
import { parseAuditdLog } from "../../src/analysis/auditdImport.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { parseEcarJson } from "../../src/analysis/ecarImport.js";
import { parseEmail } from "../../src/analysis/emailImport.js";
import { parseMemory } from "../../src/analysis/memoryImport.js";
import { parseNetworkLogs } from "../../src/analysis/networkImport.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import type { CanonicalEventEnvelope } from "../../src/analysis/canonicalEvent.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function expectConformant(event: { canonical?: CanonicalEventEnvelope }): CanonicalEventEnvelope {
  expect(event.canonical).toBeDefined();
  expect(event.canonical?.schemaVersion).toBe(CANONICAL_EVENT_SCHEMA_VERSION);
  expect(event.canonical?.evidence.sourceArtifactHash).toMatch(/^sha256:[a-f0-9]{64}$/);
  expect(canonicalConformanceIssues(event.canonical)).toEqual([]);
  return event.canonical!;
}

describe("canonical forensic-event envelope", () => {
  it("requires provenance for every normalized leaf field", () => {
    const canonical = createCanonicalEvent({
      event: { category: "authentication", type: "logon", outcome: "success" },
      actor: { kind: "account", name: "CORP\\analyst" },
      target: { kind: "host", name: "SRV-01" },
      authentication: { logonType: 10, protocol: "RDP" },
      time: {
        observed: "2026-07-30 12:34:56 +03:00",
        normalized: "2026-07-30T09:34:56.000Z",
      },
      evidence: { rawRecords: [{ source: "test", locator: "row:0" }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
      rawFieldMap: {
        "actor.name": ["TargetUserName", "TargetDomainName"],
        "target.name": ["Computer"],
        "authentication.logonType": ["LogonType"],
      },
    });

    expect(canonicalConformanceIssues(canonical)).toEqual([]);
    const broken = {
      ...canonical,
      fieldProvenance: Object.fromEntries(
        Object.entries(canonical.fieldProvenance).filter(([path]) => path !== "actor.name"),
      ),
    };
    expect(canonicalConformanceIssues(broken)).toContain("missing field provenance: actor.name");

    const unknownRecord = {
      ...canonical,
      fieldProvenance: {
        ...canonical.fieldProvenance,
        "actor.name": {
          ...canonical.fieldProvenance["actor.name"],
          recordLocators: ["row:missing"],
        },
      },
    };
    expect(canonicalConformanceIssues(unknownRecord)).toContain(
      "field provenance references an unknown record: actor.name -> row:missing",
    );
  });

  it("upgrades a legacy event without changing its display contract or discarding legacy fields", () => {
    const legacy: ForensicEvent = {
      id: "legacy-1",
      timestamp: "2026-07-30T10:00:00Z",
      description:
        "Windows Security Successful logon (EID 4624) - CORP\\jdoe - LogonType=3 - IpAddress=10.0.0.5 @ SRV-01",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: ["evidence.png"],
      asset: "SRV-01",
      sources: ["Windows Event Log"],
    };

    const upgraded = upgradeForensicEvent(legacy);
    expect(upgraded).toMatchObject(legacy);
    expect(upgraded.description).toBe(legacy.description);
    expect(upgraded.canonical).toMatchObject({
      schemaVersion: CANONICAL_EVENT_SCHEMA_VERSION,
      event: { category: "authentication", type: "logon", outcome: "success" },
      actor: { kind: "account", name: "CORP\\jdoe" },
      target: { kind: "host", name: "SRV-01" },
      authentication: { logonType: 3 },
    });
    expect(canonicalConformanceIssues(upgraded.canonical)).toEqual([]);
    expect(upgradeForensicEvent(upgraded)).toBe(upgraded);
  });

  it("preserves an unknown future schema version verbatim for an explicit future migration", () => {
    const future = {
      id: "future-1",
      timestamp: "2026-07-30T10:00:00Z",
      description: "future event",
      severity: "Info" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      canonical: { schemaVersion: "2.0.0", opaqueFutureField: { keep: true } },
    } as unknown as ForensicEvent;

    expect(upgradeForensicEvent(future)).toBe(future);
    expect(
      (upgradeForensicEvent(future).canonical as unknown as Record<string, unknown>).opaqueFutureField,
    ).toEqual({ keep: true });

    const current = createCanonicalEvent({
      event: { category: "other", type: "event" },
      time: { observed: "2026-07-30T10:00:00Z", normalized: "2026-07-30T10:00:00Z" },
      evidence: { rawRecords: [{ source: "test", locator: "row:0" }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    });
    const futureCanonical = future.canonical as unknown as CanonicalEventEnvelope;
    expect(mergeCanonicalEvents(current, futureCanonical)).toBe(futureCanonical);
    expect(mergeCanonicalEvents(futureCanonical, current)).toBe(futureCanonical);
  });
});

describe("representative importer conformance", () => {
  it("maps Windows authentication identity and session context", () => {
    const [event] = parseSiemExport(
      JSON.stringify([
        {
          EventID: 4624,
          Channel: "Security",
          Computer: "SRV-01",
          "@timestamp": "2026-07-30T10:00:00Z",
          EventData: {
            TargetUserName: "jdoe",
            TargetDomainName: "CORP",
            LogonType: "10",
            IpAddress: "203.0.113.10",
            WorkstationName: "WKSTN-01",
            TargetLogonId: "0x123",
          },
        },
      ]),
    ).events;

    expect(expectConformant(event)).toMatchObject({
      event: { category: "authentication", type: "logon", outcome: "success" },
      actor: { kind: "account", name: "CORP\\jdoe" },
      target: { kind: "host", name: "SRV-01" },
      authentication: { logonType: 10, sessionId: "0x123" },
      network: { source: { address: "203.0.113.10" } },
    });
  });

  it("maps Linux audit identity and process context", () => {
    const text = [
      'type=SYSCALL msg=audit(1785405600.123:77): node=linux-1 auid=1000 uid=1000 exe="/usr/bin/bash" comm="bash" success=yes',
      'type=EXECVE msg=audit(1785405600.123:77): argc=2 a0="/usr/bin/bash" a1="-l"',
    ].join("\n");
    const [event] = parseAuditdLog(text).events;

    expect(expectConformant(event)).toMatchObject({
      actor: { kind: "account", id: "1000" },
      target: { kind: "host", name: "linux-1" },
      process: { name: "bash", executable: "/usr/bin/bash", commandLine: "/usr/bin/bash -l" },
      producer: { importer: "auditd" },
    });
  });

  it("maps a cloud principal and API target", () => {
    const [event] = parseCloudTrail(
      JSON.stringify([
        {
          eventTime: "2026-07-30T10:00:00Z",
          eventName: "CreateAccessKey",
          eventSource: "iam.amazonaws.com",
          awsRegion: "us-east-1",
          sourceIPAddress: "203.0.113.11",
          userIdentity: {
            type: "IAMUser",
            userName: "incident-user",
            arn: "arn:aws:iam::123456789012:user/incident-user",
          },
          requestParameters: { userName: "target-user" },
        },
      ]),
    ).events;

    expect(expectConformant(event)).toMatchObject({
      event: { category: "cloud", type: "api", action: "CreateAccessKey" },
      actor: { kind: "cloud_principal", name: "incident-user" },
      cloud: { provider: "aws", region: "us-east-1" },
      producer: { importer: "aws-cloudtrail" },
    });
  });

  it("maps source and destination network entities", () => {
    const [event] = parseNetworkLogs(
      JSON.stringify([
        {
          timestamp: "2026-07-30T10:00:00.000Z",
          event_type: "alert",
          src_ip: "10.0.0.5",
          src_port: 51515,
          dest_ip: "203.0.113.12",
          dest_port: 443,
          proto: "TCP",
          alert: { signature: "Test alert", signature_id: 42, severity: 1 },
        },
      ]),
    ).events;

    expect(expectConformant(event)).toMatchObject({
      event: { category: "network", type: "alert" },
      network: {
        source: { address: "10.0.0.5", port: 51515 },
        destination: { address: "203.0.113.12", port: 443 },
        protocol: "TCP",
      },
      producer: { importer: "network" },
    });
  });

  it("maps mailbox principals and message identity", () => {
    const [event] = parseEmail(
      [
        "From: Sender <sender@example.invalid>",
        "To: Recipient <recipient@example.test>",
        "Date: Thu, 30 Jul 2026 10:00:00 +0000",
        "Message-ID: <message-1@example.invalid>",
        "Subject: Quarterly review",
        "",
        "Please review the attachment.",
      ].join("\r\n"),
    ).events;

    expect(expectConformant(event)).toMatchObject({
      event: { category: "email", type: "message" },
      actor: { kind: "mailbox", name: "sender@example.invalid" },
      target: { kind: "mailbox", name: "recipient@example.test" },
      mailbox: {
        messageId: "message-1@example.invalid",
        sender: "sender@example.invalid",
        recipients: ["recipient@example.test"],
      },
      producer: { importer: "email" },
    });
  });

  it("maps memory process identity", () => {
    const [event] = parseMemory(
      JSON.stringify([
        {
          PID: 4242,
          PPID: 4,
          ImageFileName: "powershell.exe",
          CreateTime: "2026-07-30T10:00:00Z",
          CommandLine: "powershell.exe -NoProfile",
        },
      ]),
      { filename: "windows.pslist.json" },
    ).events;

    expect(expectConformant(event)).toMatchObject({
      event: { category: "process", type: "observation" },
      process: { pid: 4242, name: "powershell.exe" },
      producer: { importer: "memory" },
    });
  });

  it("maps EDR process identity", () => {
    const [event] = parseEcarJson(
      JSON.stringify([
        {
          timestamp_ms: 1785405600000,
          hostname: "EDR-01",
          object: "PROCESS",
          action: "CREATE",
          pid: 4242,
          properties: {
            image_path: "C:\\Windows\\System32\\cmd.exe",
            parent_image_path: "C:\\Windows\\explorer.exe",
            command_line: "cmd.exe /c whoami",
          },
        },
      ]),
    ).events;

    expect(expectConformant(event)).toMatchObject({
      event: { category: "process", type: "start", action: "create" },
      target: { kind: "host", name: "EDR-01" },
      process: { pid: 4242, name: "cmd.exe", parent: { name: "explorer.exe" } },
      producer: { importer: "ecar" },
    });
  });
});
