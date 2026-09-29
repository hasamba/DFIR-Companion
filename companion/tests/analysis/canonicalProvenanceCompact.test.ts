import { describe, expect, it } from "vitest";
import {
  CANONICAL_EVENT_SCHEMA_VERSION,
  canonicalConformanceIssues,
  canonicalEventEnvelopeSchema,
  createCanonicalEvent,
  upgradeForensicEvent,
  type CanonicalEventEnvelope,
} from "../../src/analysis/canonicalEvent.js";
import {
  compactFieldProvenance,
  expandFieldProvenance,
  fieldProvenanceAt,
  migrateCanonicalEnvelope,
  withExpandedFieldProvenance,
  type FieldProvenance,
  type ProvenanceCarrier,
} from "../../src/analysis/canonicalProvenanceCompact.js";
import { fillCanonicalGaps, mergeCanonicalEvents } from "../../src/analysis/canonicalMerge.js";
import { parseAuditdLog } from "../../src/analysis/auditdImport.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { parseEcarJson } from "../../src/analysis/ecarImport.js";
import { parseEmail } from "../../src/analysis/emailImport.js";
import { parseMemory } from "../../src/analysis/memoryImport.js";
import { parseNetworkLogs } from "../../src/analysis/networkImport.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1874: the compact provenance form must never lose or invent a single provenance value.

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** The round-trip property, checked on an envelope in whatever form it was written. */
function expectLosslessRoundTrip(envelope: CanonicalEventEnvelope): void {
  const verbose = withExpandedFieldProvenance(envelope);
  expect(verbose).not.toHaveProperty("fieldProvenanceDefaults");
  const snapshot = clone(verbose);
  const compact = compactFieldProvenance(verbose);
  // expand(compact(x)) deep-equals x, and compacting did not touch x
  expect(expandFieldProvenance(compact)).toEqual(snapshot.fieldProvenance);
  expect(withExpandedFieldProvenance(compact)).toEqual(snapshot);
  expect(verbose).toEqual(snapshot);
  // Byte-identical once expanded: same key order everywhere
  expect(JSON.stringify(withExpandedFieldProvenance(compact))).toBe(JSON.stringify(snapshot));
  // Deterministic and idempotent: compacting the stored form again changes nothing
  expect(compactFieldProvenance(compact)).toBe(compact);
  expect(compact).toEqual(compactFieldProvenance(clone(verbose)));
  // Validation reaches the same verdict on both forms
  expect(canonicalConformanceIssues(compact)).toEqual(canonicalConformanceIssues(verbose));
  // Survives a JSON round trip (what storage does)
  expect(withExpandedFieldProvenance(clone(compact))).toEqual(snapshot);
}

const siemEvents = () =>
  parseSiemExport(
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
      {
        "@timestamp": "2026-07-06T10:00:00.000Z",
        log_name: "System",
        computer_name: "S1-HOST",
        event_id: 7045,
        level: "Information",
        event_data: { ServiceName: "svc-1", ServiceFileName: "C:\\Windows\\Temp\\svc-1.exe" },
      },
    ]),
  ).events;

// Sysmon 22 joined to Sysmon 3 — siemDnsConnJoin.ts writes two entries into the envelope's map
// AFTER createCanonicalEvent compacted it (a mixed-form envelope).
const siemDnsJoinEvents = () =>
  parseSiemExport(
    JSON.stringify(
      [
        {
          "@timestamp": "2026-03-01T10:00:00Z",
          log_name: "Microsoft-Windows-Sysmon/Operational",
          computer_name: "WS-01",
          event_id: 22,
          event_data: {
            Image: "C:\\Windows\\System32\\svchost.exe",
            ProcessId: "1234",
            QueryName: "join.example",
            QueryStatus: "0",
            QueryResults: "::ffff:203.0.113.9;",
          },
        },
        {
          "@timestamp": "2026-03-01T10:00:05Z",
          log_name: "Microsoft-Windows-Sysmon/Operational",
          computer_name: "WS-01",
          event_id: 3,
          event_data: {
            Image: "C:\\Windows\\System32\\svchost.exe",
            Protocol: "tcp",
            Initiated: "true",
            DestinationIp: "203.0.113.9",
            DestinationPort: "443",
          },
        },
      ].map((r) => ({ _source: r })),
    ),
  ).events;

// Two CloudTrail replicas of one cross-account call — awsReplicas.ts adds raw entries pointing at
// the OTHER replica's record.
const awsReplicaEvents = () => {
  const rec = (recipientAccountId: string, eventID: string) => ({
    eventTime: "2023-06-01T10:00:00Z",
    eventName: "GetObject",
    eventSource: "s3.amazonaws.com",
    awsRegion: "us-east-1",
    sourceIPAddress: "203.0.113.10",
    readOnly: true,
    eventType: "AwsApiCall",
    userIdentity: {
      type: "IAMUser",
      userName: "bob",
      arn: "arn:aws:iam::111122223333:user/bob",
      accountId: "111122223333",
    },
    sharedEventID: "shared-both",
    requestParameters: { bucketName: "b", key: "k" },
    recipientAccountId,
    eventID,
  });
  return parseCloudTrail(
    JSON.stringify({ Records: [rec("111122223333", "caller"), rec("444455556666", "owner")] }),
  ).events;
};

// Zeek dns + conn — the network importer's join attributes `dns.leads` to two records (locatorMap).
const zeekJoinEvents = () =>
  parseNetworkLogs(
    [
      {
        ts: 1512115200,
        _path: "dns",
        uid: "D1",
        "id.orig_h": "10.0.0.5",
        "id.resp_h": "10.0.0.1",
        "id.resp_p": 53,
        query: "www.example.com",
        qtype_name: "A",
        rcode_name: "NOERROR",
        AA: false,
        RA: true,
        rejected: false,
        rtt: 0.02,
        answers: ["93.184.216.34"],
        TTLs: [300],
      },
      {
        ts: 1512115203,
        _path: "conn",
        uid: "C1",
        "id.orig_h": "10.0.0.5",
        "id.resp_h": "93.184.216.34",
        "id.resp_p": 443,
        proto: "tcp",
        conn_state: "SF",
        duration: 2,
      },
    ]
      .map((r) => JSON.stringify(r))
      .join("\n"),
  ).events;

const REAL_IMPORTERS: [string, () => { canonical?: CanonicalEventEnvelope }[]][] = [
  ["Windows SIEM (4624 logon, 7045 service)", siemEvents],
  ["SIEM Sysmon 22 → 3 join (entries added after compaction)", siemDnsJoinEvents],
  ["CloudTrail cross-account replicas (entries added after compaction)", awsReplicaEvents],
  ["Zeek dns → conn join (per-field locators differ)", zeekJoinEvents],
  [
    "auditd",
    () =>
      parseAuditdLog(
        [
          'type=SYSCALL msg=audit(1785405600.123:77): node=linux-1 auid=1000 uid=1000 exe="/usr/bin/bash" comm="bash" success=yes',
          'type=EXECVE msg=audit(1785405600.123:77): argc=2 a0="/usr/bin/bash" a1="-l"',
        ].join("\n"),
      ).events,
  ],
  [
    "email",
    () =>
      parseEmail(
        [
          "From: Sender <sender@example.invalid>",
          "To: Recipient <recipient@example.test>",
          "Date: Thu, 30 Jul 2026 10:00:00 +0000",
          "Message-ID: <message-1@example.invalid>",
          "Subject: Quarterly review",
          "",
          "Please review the attachment.",
        ].join("\r\n"),
      ).events,
  ],
  [
    "memory",
    () =>
      parseMemory(
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
      ).events,
  ],
  [
    "ecar",
    () =>
      parseEcarJson(
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
      ).events,
  ],
];

describe("compact field provenance — real importer output (#1874)", () => {
  it.each(REAL_IMPORTERS)("%s: expand(compact(x)) deep-equals x, on every event", (_name, run) => {
    const events = run().filter((e) => e.canonical);
    expect(events.length).toBeGreaterThan(0);
    for (const e of events) {
      expect(e.canonical!.schemaVersion).toBe(CANONICAL_EVENT_SCHEMA_VERSION);
      expect(canonicalConformanceIssues(e.canonical)).toEqual([]);
      expectLosslessRoundTrip(e.canonical!);
    }
  });

  it("an importer's stored envelope IS the compact form, and it is smaller", () => {
    for (const e of siemEvents()) {
      const stored = e.canonical!;
      expect(stored.fieldProvenanceDefaults).toBeDefined();
      expect(compactFieldProvenance(withExpandedFieldProvenance(stored))).toEqual(stored);
      const verboseBytes = JSON.stringify(withExpandedFieldProvenance(stored)).length;
      expect(JSON.stringify(stored).length).toBeLessThan(verboseBytes * 0.6);
    }
  });

  it("the join's added entries keep their own derivation and both records", () => {
    const e = siemDnsJoinEvents().find((ev) => ev.canonical?.dns?.joinState)!;
    expect(fieldProvenanceAt(e.canonical, "dns.joinState")).toMatchObject({
      origin: "derived",
      derivation: expect.stringContaining("siemDnsConnJoin.ts"),
    });
    const zeek = zeekJoinEvents().find((ev) => ev.canonical?.dns?.leads?.length)!;
    expect(fieldProvenanceAt(zeek.canonical, "dns.leads")?.recordLocators).toEqual(["record:0", "record:1"]);
    expect(fieldProvenanceAt(zeek.canonical, "dns.query")?.recordLocators).toEqual(["record:0"]);
  });
});

describe("createCanonicalEvent writes exactly the provenance it always wrote", () => {
  it("expands to the verbose record, default derivation text and locators included", () => {
    const canonical = createCanonicalEvent({
      event: { category: "authentication", type: "logon" },
      actor: { kind: "account", name: "CORP\\analyst" },
      time: { observed: "2026-07-30T09:34:56Z", normalized: "2026-07-30T09:34:56.000Z" },
      evidence: { rawRecords: [{ source: "test", locator: "row:0" }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "map-v1" },
      rawFieldMap: { "actor.name": ["TargetUserName"], "time.observed": ["TimeCreated"] },
      confidenceMap: { "actor.kind": "medium" },
    });
    const DEFAULT = "map-v1: deterministic mapping from referenced raw record";
    const derived = (confidence = "high") => ({
      origin: "derived",
      confidence,
      derivation: DEFAULT,
      recordLocators: ["row:0"],
    });
    expect(JSON.stringify(expandFieldProvenance(canonical))).toBe(
      JSON.stringify({
        "event.category": derived(),
        "event.type": derived(),
        "actor.kind": derived("medium"),
        "actor.name": {
          origin: "raw",
          confidence: "high",
          rawFields: ["TargetUserName"],
          recordLocators: ["row:0"],
        },
        "time.observed": {
          origin: "raw",
          confidence: "high",
          rawFields: ["TimeCreated"],
          recordLocators: ["row:0"],
        },
        "time.normalized": derived(),
        "time.timezone": derived(),
        "time.precision": derived(),
        "time.clockConfidence": derived(),
      }),
    );
  });
});

// A verbose envelope built by hand, the way every stored 1.0.0 envelope looks.
function verboseEnvelope(fieldProvenance: Record<string, unknown>): CanonicalEventEnvelope {
  return {
    schemaVersion: CANONICAL_EVENT_SCHEMA_VERSION,
    event: { category: "other", type: "event" },
    time: {
      observed: "t",
      normalized: "t",
      timezone: "UTC",
      precision: "second",
      clockConfidence: "recorded",
    },
    evidence: {
      rawRecords: [
        { source: "s", locator: "r:0" },
        { source: "s", locator: "r:1" },
      ],
    },
    producer: { importer: "test", parserVersion: "1", mappingVersion: "m" },
    fieldProvenance,
  } as unknown as CanonicalEventEnvelope;
}

const D = "m: deterministic mapping from referenced raw record";

describe("compact field provenance — hand-built edge cases", () => {
  it("per-field locators that differ, raw entries with rawFields, and a raw entry that has a derivation", () => {
    const env = verboseEnvelope({
      a: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
      b: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
      c: { origin: "derived", confidence: "low", derivation: D, recordLocators: ["r:1"] },
      d: { origin: "raw", confidence: "high", rawFields: ["X", "Y"], recordLocators: ["r:0", "r:1"] },
      e: { origin: "raw", confidence: "high", rawFields: ["Z"], derivation: D, recordLocators: ["r:0"] },
      f: { origin: "raw", confidence: "medium", rawFields: ["W"], recordLocators: ["r:1", "r:0"] },
    });
    expectLosslessRoundTrip(env);
    const compact = compactFieldProvenance(env);
    // the raw entry's own derivation is never folded into the default
    expect(compact.fieldProvenance.e).toHaveProperty("derivation", D);
    expect(fieldProvenanceAt(compact, "d")).not.toHaveProperty("derivation");
  });

  it("a derived entry MISSING its derivation stays missing — and is still reported", () => {
    const env = verboseEnvelope({
      a: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
      b: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
      c: { origin: "derived", confidence: "high", recordLocators: ["r:0"] },
    });
    expectLosslessRoundTrip(env);
    const compact = compactFieldProvenance(env);
    expect(fieldProvenanceAt(compact, "c")).not.toHaveProperty("derivation");
    expect(canonicalConformanceIssues(compact)).toContain("derived provenance has no rule: c");
  });

  it("an entry missing confidence or locators fails validation in either form", () => {
    const env = verboseEnvelope({
      a: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
      b: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
      c: { origin: "derived", derivation: D },
    });
    const compact = compactFieldProvenance(env);
    expect(expandFieldProvenance(compact)).toEqual(env.fieldProvenance);
    for (const form of [env, compact]) {
      expect(canonicalEventEnvelopeSchema.safeParse(form).success).toBe(false);
      expect(canonicalConformanceIssues(form)).toEqual(
        expect.arrayContaining([
          "fieldProvenance.c.confidence: Required",
          "fieldProvenance.c.recordLocators: Required",
        ]),
      );
    }
  });

  it("an unknown key on an entry is kept, and an envelope with nothing repeated is left alone", () => {
    const env = verboseEnvelope({
      a: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"], note: "x" },
      b: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
    });
    expectLosslessRoundTrip(env);
    const lone = verboseEnvelope({
      a: { origin: "raw", confidence: "low", rawFields: ["A"], recordLocators: ["r:1"] },
    });
    expect(compactFieldProvenance(lone)).toBe(lone);
  });

  it("defaults never alias: expanding and mutating one entry's locators cannot reach another", () => {
    const compact = compactFieldProvenance(
      verboseEnvelope({
        a: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
        b: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
      }),
    );
    const expanded = expandFieldProvenance(compact);
    expanded.a.recordLocators.push("r:1");
    expect(expanded.b.recordLocators).toEqual(["r:0"]);
    expect(compact.fieldProvenanceDefaults?.recordLocators).toEqual(["r:0"]);
  });

  it("a mixed envelope (compact, then a complete entry written by hand) reads every entry exactly", () => {
    const compact = compactFieldProvenance(
      verboseEnvelope({
        a: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
        b: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
      }),
    );
    const added: FieldProvenance = {
      origin: "derived",
      confidence: "high",
      derivation: "join rule",
      recordLocators: ["r:1"],
    };
    const mixed = { ...compact, fieldProvenance: { ...compact.fieldProvenance, j: added } };
    expect(fieldProvenanceAt(mixed, "j")).toEqual(added);
    expect(fieldProvenanceAt(mixed, "a")).toEqual({
      origin: "derived",
      confidence: "high",
      derivation: D,
      recordLocators: ["r:0"],
    });
    const recompacted = compactFieldProvenance(mixed);
    expect(expandFieldProvenance(recompacted)).toEqual(expandFieldProvenance(mixed));
  });

  it("a merged envelope unions provenance exactly as the verbose merge does, whatever form each side is in", () => {
    const winner = verboseEnvelope({
      a: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
      b: { origin: "raw", confidence: "high", rawFields: ["B"], recordLocators: ["r:0"] },
      c: { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
    });
    const filler = {
      ...verboseEnvelope({
        a: { origin: "derived", confidence: "high", derivation: "other", recordLocators: ["r:1"] },
        z: { origin: "raw", confidence: "medium", rawFields: ["Z"], recordLocators: ["r:1"] },
        y: { origin: "raw", confidence: "medium", rawFields: ["Y"], recordLocators: ["r:1"] },
      }),
      producer: { importer: "other", parserVersion: "1", mappingVersion: "n" },
    } as CanonicalEventEnvelope;
    const reference = fillCanonicalGaps(winner, filler);
    expect(reference.fieldProvenanceDefaults).toBeDefined();
    const expected = expandFieldProvenance(reference);
    expect(expected.a).toEqual({
      origin: "derived",
      confidence: "high",
      derivation: D,
      recordLocators: ["r:0", "r:1"],
    });
    expect(expected.z).toEqual({
      origin: "raw",
      confidence: "medium",
      rawFields: ["Z"],
      recordLocators: ["r:1"],
    });
    for (const w of [winner, compactFieldProvenance(winner)])
      for (const f of [filler, compactFieldProvenance(filler)]) {
        const merged = fillCanonicalGaps(w, f);
        expect(expandFieldProvenance(merged)).toEqual(expected);
        expect(Object.keys(merged)).not.toContain(undefined);
        expectLosslessRoundTrip(merged);
        // idempotent: folding the same filler in again changes nothing
        expect(expandFieldProvenance(fillCanonicalGaps(merged, f))).toEqual(expected);
        // and the state merge (incoming wins) reads the same on either form
        expect(expandFieldProvenance(mergeCanonicalEvents(f, w))).toEqual(expected);
      }
  });
});

describe("1.0.0 envelopes — no migration step, read as they are", () => {
  const stored = (): ForensicEvent => ({
    id: "old-1",
    timestamp: "2026-07-30T10:00:00Z",
    description: "stored before #1874",
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: {
      ...verboseEnvelope({
        "event.category": { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
        "event.type": { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
        "time.observed": { origin: "raw", confidence: "high", rawFields: ["T"], recordLocators: ["r:0"] },
        "time.normalized": { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
        "time.timezone": { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
        "time.precision": { origin: "derived", confidence: "high", derivation: D, recordLocators: ["r:0"] },
        "time.clockConfidence": {
          origin: "derived",
          confidence: "high",
          derivation: D,
          recordLocators: ["r:0"],
        },
      }),
      schemaVersion: "1.0.0",
    } as unknown as CanonicalEventEnvelope,
  });

  it("upgrades on read by relabelling alone; provenance is untouched and validates", () => {
    const old = stored();
    const up = upgradeForensicEvent(old);
    expect(up.canonical?.schemaVersion).toBe(CANONICAL_EVENT_SCHEMA_VERSION);
    expect(up.canonical?.fieldProvenance).toBe(old.canonical?.fieldProvenance);
    expect(up.canonical).not.toHaveProperty("fieldProvenanceDefaults");
    expect(canonicalConformanceIssues(up.canonical)).toEqual([]);
    expect(canonicalConformanceIssues(old.canonical)).toEqual([]);
    expect(upgradeForensicEvent(up)).toBe(up);
    expectLosslessRoundTrip(up.canonical!);
  });

  it("a 1.0.0 envelope carrying a stray defaults block is still read as verbose", () => {
    const old = stored();
    const stray = {
      ...old.canonical,
      fieldProvenanceDefaults: { recordLocators: ["r:1"] },
    } as ProvenanceCarrier;
    const migrated = migrateCanonicalEnvelope(stray);
    expect(migrated).not.toHaveProperty("fieldProvenanceDefaults");
    expect(expandFieldProvenance(migrated)).toBe(old.canonical?.fieldProvenance);
  });

  it("merges with a current envelope instead of being kept opaque", () => {
    const old = stored().canonical!;
    const current = compactFieldProvenance(verboseEnvelope({ ...old.fieldProvenance }));
    const merged = mergeCanonicalEvents(old, current)!;
    expect(merged.schemaVersion).toBe(CANONICAL_EVENT_SCHEMA_VERSION);
    expect(expandFieldProvenance(merged)).toEqual(old.fieldProvenance);
  });
});
