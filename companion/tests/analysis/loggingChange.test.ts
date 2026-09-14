// #931 item 14 (coverage half, record part): a logging-configuration call read for the STATE its
// request establishes after a successful call — never a direction from a prior value the record
// does not carry. Adding logging is not disabling it; a selector set is stated as the resulting
// configuration; an audit-config delta is exact and its effective outcome is not established.
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import {
  canonicalConformanceIssues,
  canonicalEventEnvelopeSchema,
} from "../../src/analysis/canonicalEvent.js";

type Row = Record<string, unknown>;
const ACCT = "111122223333";
const TRAIL = `arn:aws:cloudtrail:us-east-1:${ACCT}:trail/main`;
const ct = (name: string, request: Row = {}, over: Row = {}): Row => ({
  eventVersion: "1.08",
  eventTime: "2024-05-01T09:00:00Z",
  eventSource: "cloudtrail.amazonaws.com",
  eventName: name,
  awsRegion: "us-east-1",
  sourceIPAddress: "203.0.113.5",
  userAgent: "aws-cli/2.15",
  recipientAccountId: ACCT,
  userIdentity: {
    type: "IAMUser",
    principalId: "AIDAEXAMPLE",
    arn: `arn:aws:iam::${ACCT}:user/alice`,
    accountId: ACCT,
    userName: "alice",
  },
  requestParameters: { name: TRAIL, ...request },
  responseElements: null,
  ...over,
});
const aws = (records: Row[]) =>
  parseCloudTrail(JSON.stringify({ Records: records }), { aggregate: false }).events;
const one = (name: string, request: Row = {}, over: Row = {}) => aws([ct(name, request, over)])[0];
const env = (e: { canonical?: unknown }) => canonicalEventEnvelopeSchema.parse(e.canonical);

describe("CloudTrail logging changes — the state the request establishes", () => {
  it("StopLogging is 'logging stopped' (High); StartLogging 'logging started' (Low) and says enabling does not reconstruct the past; DeleteTrail deleted; CreateTrail created with recording state not established", () => {
    const stop = one("StopLogging");
    expect(stop.severity).toBe("High");
    expect(stop.mitreTechniques).toContain("T1562.008");
    expect(stop.description).toContain(`logging stopped for trail ${TRAIL}`);
    expect(stop.description).not.toMatch(/reduces|extends/);
    const e = env(stop);
    expect(e.loggingChange).toMatchObject({
      provider: "aws",
      state: "disabled",
      target: TRAIL,
      targetKind: "trail",
      priorStateInRecord: false,
    });
    expect(canonicalConformanceIssues(e)).toEqual([]);
    const start = one("StartLogging");
    expect(start.severity).toBe("Low");
    expect(start.mitreTechniques).toEqual([]);
    expect(start.description).toContain(`logging started for trail ${TRAIL}`);
    expect(start.description).toContain("enabling a source does not reconstruct its past");
    expect(env(start).loggingChange?.state).toBe("enabled");
    const del = one("DeleteTrail");
    expect(del.severity).toBe("High");
    expect(del.description).toContain(`trail deleted: ${TRAIL}`);
    const create = one("CreateTrail", { s3BucketName: "logs-bucket", isMultiRegionTrail: true });
    expect(create.severity).toBe("Low");
    expect(create.description).toContain(
      "trail created: main — recording state not established (StartLogging is a separate call)",
    );
    expect(create.description).toContain("s3BucketName logs-bucket; isMultiRegionTrail true");
    expect(env(create).loggingChange?.state).toBe("created");
  });

  it("UpdateTrail quotes the fields present; a resulting configuration that narrows coverage is High, a destination change alone is 'prior state not in record' (Medium)", () => {
    const narrow = one("UpdateTrail", {
      isMultiRegionTrail: false,
      includeGlobalServiceEvents: false,
      enableLogFileValidation: false,
    });
    expect(narrow.severity).toBe("High");
    expect(narrow.description).toContain(
      "trail reconfigured: isMultiRegionTrail false; includeGlobalServiceEvents false; enableLogFileValidation false",
    );
    expect(narrow.description).toContain(
      "resulting configuration excludes coverage (multi-region off, global service events off, log-file validation off)",
    );
    expect(narrow.description).toContain("the prior configuration is not in this record");
    expect(env(narrow).loggingChange?.facts).toEqual(
      expect.arrayContaining([{ name: "isMultiRegionTrail", value: "false" }]),
    );
    const widen = one("UpdateTrail", { isMultiRegionTrail: true });
    expect(widen.severity).toBe("Medium");
    expect(widen.description).toContain("trail reconfigured: isMultiRegionTrail true");
    expect(widen.description).not.toContain("excludes coverage");
    const dest = one("UpdateTrail", {
      s3BucketName: "other-bucket",
      kmsKeyId: "arn:aws:kms:us-east-1:111122223333:key/abc",
    });
    expect(dest.severity).toBe("Medium");
    expect(dest.description).toContain(
      "s3BucketName other-bucket; kmsKeyId arn:aws:kms:us-east-1:111122223333:key/abc",
    );
    expect(env(dest).loggingChange?.state).toBe("prior-state-not-in-record");
  });

  it("PutEventSelectors states the RESULTING selector set: management excluded is High; no data events selected is Medium; advanced selectors are quoted; the prior selectors are never claimed", () => {
    const noMgmt = one("PutEventSelectors", {
      trailName: TRAIL,
      eventSelectors: [{ readWriteType: "All", includeManagementEvents: false, dataResources: [] }],
    });
    expect(noMgmt.severity).toBe("High");
    expect(noMgmt.description).toContain(
      "resulting selectors: management events excluded; data events: none selected",
    );
    expect(noMgmt.description).toContain("the prior selectors are not in this record");
    const writeOnly = one("PutEventSelectors", {
      trailName: TRAIL,
      eventSelectors: [
        {
          readWriteType: "WriteOnly",
          includeManagementEvents: true,
          dataResources: [],
          excludeManagementEventSources: ["kms.amazonaws.com"],
        },
      ],
    });
    expect(writeOnly.severity).toBe("Medium");
    expect(writeOnly.description).toContain(
      "resulting selectors: management WriteOnly (excluding kms.amazonaws.com); data events: none selected",
    );
    const data = one("PutEventSelectors", {
      trailName: TRAIL,
      eventSelectors: [
        {
          readWriteType: "All",
          includeManagementEvents: true,
          dataResources: [{ type: "AWS::S3::Object", values: ["arn:aws:s3:::bucket/"] }],
        },
      ],
    });
    expect(data.severity).toBe("Medium");
    expect(data.description).toContain("data events: AWS::S3::Object arn:aws:s3:::bucket/");
    const advanced = one("PutEventSelectors", {
      trailName: TRAIL,
      advancedEventSelectors: [
        { name: "mgmt", fieldSelectors: [{ field: "eventCategory", equals: ["Management"] }] },
        {
          name: "s3",
          fieldSelectors: [
            { field: "eventCategory", equals: ["Data"] },
            { field: "resources.type", equals: ["AWS::S3::Object"] },
          ],
        },
      ],
    });
    expect(advanced.description).toContain(
      "resulting advanced selectors: mgmt (eventCategory equals Management); s3 (eventCategory equals Data, resources.type equals AWS::S3::Object)",
    );
    expect(advanced.severity).toBe("Medium");
    const denied = one(
      "PutEventSelectors",
      { trailName: TRAIL, eventSelectors: [{ includeManagementEvents: false }] },
      { errorCode: "AccessDenied", errorMessage: "no" },
    );
    expect(denied.severity).toBe("Medium");
    expect(denied.description).toContain("attempted, denied");
    expect(denied.description).toContain("requested selectors");
    expect(env(denied).loggingChange?.denied).toBe(true);
  });

  it("insight selectors, event data stores and flow logs; GuardDuty features read one by one and publishing frequency is delivery cadence; bucket access logging", () => {
    expect(one("PutInsightSelectors", { trailName: TRAIL, insightSelectors: [] }).description).toContain(
      "resulting insight selectors: none",
    );
    expect(one("PutInsightSelectors", { trailName: TRAIL, insightSelectors: [] }).severity).toBe("Medium");
    expect(
      one("DeleteEventDataStore", {
        eventDataStore: "arn:aws:cloudtrail:us-east-1:111122223333:eventdatastore/abc",
      }).severity,
    ).toBe("High");
    const flow = aws([
      ct(
        "DeleteFlowLogs",
        { DeleteFlowLogsRequest: { FlowLogId: [{ content: "fl-0a" }] }, flowLogIds: ["fl-0a", "fl-0b"] },
        { eventSource: "ec2.amazonaws.com" },
      ),
    ])[0];
    expect(flow.severity).toBe("High");
    expect(flow.description).toContain("flow logs deleted: fl-0a, fl-0b");
    const createFlow = aws([
      ct(
        "CreateFlowLogs",
        { resourceIds: ["vpc-1"], trafficType: "ALL" },
        { eventSource: "ec2.amazonaws.com" },
      ),
    ])[0];
    expect(createFlow.severity).toBe("Low");
    expect(createFlow.description).toContain("flow logs created for vpc-1 (ALL)");
    const gd = (request: Row) =>
      aws([
        ct("UpdateDetector", { detectorId: "d1", ...request }, { eventSource: "guardduty.amazonaws.com" }),
      ])[0];
    expect(gd({ enable: false }).severity).toBe("High");
    expect(gd({ enable: false }).description).toContain("detector d1 disabled");
    expect(gd({ enable: true }).severity).toBe("Low");
    const sources = gd({
      dataSources: { s3Logs: { enable: false }, kubernetes: { auditLogs: { enable: true } } },
      features: [
        { name: "EBS_MALWARE_PROTECTION", status: "DISABLED" },
        { name: "RDS_LOGIN_EVENTS", status: "ENABLED" },
      ],
    });
    expect(sources.severity).toBe("High");
    expect(sources.description).toContain(
      "detector d1 reconfigured: s3Logs disabled; kubernetes.auditLogs enabled; EBS_MALWARE_PROTECTION DISABLED; RDS_LOGIN_EVENTS ENABLED",
    );
    const cadence = gd({ findingPublishingFrequency: "SIX_HOURS" });
    expect(cadence.severity).toBe("Low");
    expect(cadence.description).toContain(
      "findingPublishingFrequency SIX_HOURS — delivery cadence, no coverage change",
    );
    expect(
      aws([ct("DeleteDetector", { detectorId: "d1" }, { eventSource: "guardduty.amazonaws.com" })])[0]
        .severity,
    ).toBe("High");
    const bucketOff = aws([
      ct(
        "PutBucketLogging",
        { bucketName: "b", BucketLoggingStatus: {} },
        { eventSource: "s3.amazonaws.com" },
      ),
    ])[0];
    expect(bucketOff.severity).toBe("High");
    expect(bucketOff.description).toContain("bucket access logging disabled for bucket b");
    const bucketOn = aws([
      ct(
        "PutBucketLogging",
        {
          bucketName: "b",
          BucketLoggingStatus: { LoggingEnabled: { TargetBucket: "logs", TargetPrefix: "b/" } },
        },
        { eventSource: "s3.amazonaws.com" },
      ),
    ])[0];
    expect(bucketOn.severity).toBe("Low");
    expect(bucketOn.description).toContain("bucket access logging enabled for bucket b → logs/b/");
  });

  it("two selector calls with different resulting sets are two rows; a re-import folds; hostile names are neutralised", () => {
    const a = ct("PutEventSelectors", {
      trailName: TRAIL,
      eventSelectors: [{ includeManagementEvents: false }],
    });
    const b = ct("PutEventSelectors", {
      trailName: TRAIL,
      eventSelectors: [{ includeManagementEvents: true }],
    });
    const r = parseCloudTrail(JSON.stringify({ Records: [a, b, a] }), { aggregate: true }).events;
    expect(r).toHaveLength(2);
    const evil = one("StopLogging", {
      name: "arn:aws:cloudtrail:us-east-1:111122223333:trail/t] [fake: started\u202e|x",
    });
    expect(evil.description).not.toContain("] [");
    expect(evil.description).not.toContain("\u202e");
    expect(evil.description.length).toBeLessThanOrEqual(600);
  });
});

describe("GCP logging changes — sinks, exclusions, buckets and audit-config deltas", () => {
  const gcp = (method: string, over: Row = {}, service = "logging.googleapis.com"): Row => ({
    logName: "projects/acme/logs/cloudaudit.googleapis.com%2Factivity",
    timestamp: "2023-07-01T10:00:00Z",
    resource: { type: "logging_sink", labels: { project_id: "acme" } },
    protoPayload: {
      "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
      serviceName: service,
      methodName: method,
      authenticationInfo: { principalEmail: "alice@corp.example" },
      requestMetadata: { callerIp: "203.0.113.11" },
      resourceName: "projects/acme/sinks/export-all",
      status: {},
      ...over,
    },
  });
  const rows = (records: Row[]) => parseCloudActivity(JSON.stringify(records), { aggregate: false }).events;

  it("DeleteSink High; CreateSink Low with destination and filter; UpdateSink reads disabled by its mask and a filter change is 'prior state not in record'; exclusions", () => {
    const del = rows([
      gcp("google.logging.v2.ConfigServiceV2.DeleteSink", {
        request: { sinkName: "projects/acme/sinks/export-all" },
      }),
    ])[0];
    expect(del.severity).toBe("High");
    expect(del.mitreTechniques).toContain("T1562.008");
    expect(del.description).toContain("sink deleted: projects/acme/sinks/export-all");
    const create = rows([
      gcp("google.logging.v2.ConfigServiceV2.CreateSink", {
        request: {
          sink: {
            name: "export-all",
            destination: "storage.googleapis.com/bucket",
            filter: 'logName:"cloudaudit"',
          },
        },
      }),
    ])[0];
    expect(create.severity).toBe("Low");
    expect(create.description).toContain(
      'sink created: export-all → storage.googleapis.com/bucket; filter logName:"cloudaudit"',
    );
    const disabled = rows([
      gcp("google.logging.v2.ConfigServiceV2.UpdateSink", {
        request: {
          sinkName: "projects/acme/sinks/export-all",
          sink: { disabled: true },
          updateMask: "disabled",
        },
      }),
    ])[0];
    expect(disabled.severity).toBe("High");
    expect(disabled.description).toContain("sink disabled: projects/acme/sinks/export-all");
    const enabled = rows([
      gcp("google.logging.v2.ConfigServiceV2.UpdateSink", {
        request: {
          sinkName: "projects/acme/sinks/export-all",
          sink: { disabled: false },
          updateMask: "disabled",
        },
      }),
    ])[0];
    expect(enabled.severity).toBe("Low");
    const filter = rows([
      gcp("google.logging.v2.ConfigServiceV2.UpdateSink", {
        request: {
          sinkName: "projects/acme/sinks/export-all",
          sink: { filter: "severity>=ERROR", disabled: true },
          updateMask: "filter",
        },
      }),
    ])[0];
    expect(filter.severity).toBe("Medium");
    expect(filter.description).toContain("sink reconfigured: filter severity>=ERROR");
    expect(filter.description).toContain("the prior configuration is not in this record");
    expect(filter.description).not.toContain("disabled");
    const excl = rows([
      gcp("google.logging.v2.ConfigServiceV2.CreateExclusion", {
        request: { exclusion: { name: "drop-audit", filter: 'logName:"cloudaudit"' } },
      }),
    ])[0];
    expect(excl.severity).toBe("High");
    expect(excl.description).toContain('exclusion created: drop-audit; filter logName:"cloudaudit"');
    expect(
      rows([
        gcp("google.logging.v2.ConfigServiceV2.DeleteExclusion", {
          request: { name: "projects/acme/exclusions/drop-audit" },
        }),
      ])[0].severity,
    ).toBe("Low");
    const bucket = rows([
      gcp("google.logging.v2.ConfigServiceV2.UpdateBucket", {
        request: {
          name: "projects/acme/locations/global/buckets/_Default",
          bucket: { retentionDays: 7 },
          updateMask: "retentionDays",
        },
      }),
    ])[0];
    expect(bucket.severity).toBe("Medium");
    expect(bucket.description).toContain("retention set to 7 days; previous retention not in this record");
    const bucketNoMask = rows([
      gcp("google.logging.v2.ConfigServiceV2.UpdateBucket", {
        request: {
          name: "projects/acme/locations/global/buckets/_Default",
          bucket: { retentionDays: 7 },
          updateMask: "description",
        },
      }),
    ])[0];
    expect(bucketNoMask.description).not.toContain("retention set");
  });

  it("an audit-config delta is exact — an exemption added or a log-type entry removed is High, the reverse Low — and effective logging is never established", () => {
    const policy = (deltas: Row[]) =>
      rows([
        gcp(
          "SetIamPolicy",
          {
            resourceName: "projects/acme",
            serviceData: { policyDelta: { auditConfigDeltas: deltas } },
          },
          "cloudresourcemanager.googleapis.com",
        ),
      ]);
    const exempt = policy([
      {
        action: "ADD",
        service: "allServices",
        logType: "DATA_READ",
        exemptedMember: "user:bob@corp.example",
      },
    ])[0];
    expect(exempt.severity).toBe("High");
    expect(exempt.mitreTechniques).toContain("T1562.008");
    expect(exempt.description).toContain(
      "audit-config exemption added for user:bob@corp.example on DATA_READ (allServices)",
    );
    expect(exempt.description).toContain(
      "effective audit logging is the union of configurations — not established by this record",
    );
    expect(env(exempt).loggingChange).toMatchObject({
      provider: "gcp",
      state: "reconfigured",
      effectiveNotEstablished: true,
    });
    const unexempt = policy([
      {
        action: "REMOVE",
        service: "allServices",
        logType: "DATA_READ",
        exemptedMember: "user:bob@corp.example",
      },
    ])[0];
    expect(unexempt.severity).toBe("Low");
    expect(unexempt.description).toContain("audit-config exemption removed for user:bob@corp.example");
    const typeOn = policy([{ action: "ADD", service: "storage.googleapis.com", logType: "DATA_WRITE" }])[0];
    expect(typeOn.severity).toBe("Low");
    expect(typeOn.description).toContain(
      "audit-config log type DATA_WRITE entry added for storage.googleapis.com",
    );
    const typeOff = policy([
      { action: "REMOVE", service: "storage.googleapis.com", logType: "DATA_WRITE" },
    ])[0];
    expect(typeOff.severity).toBe("High");
    expect(typeOff.description).toContain(
      "audit-config log type DATA_WRITE entry removed for storage.googleapis.com",
    );
    const both = rows([
      gcp(
        "SetIamPolicy",
        {
          resourceName: "projects/acme",
          serviceData: {
            policyDelta: {
              bindingDeltas: [{ action: "ADD", role: "roles/viewer", member: "user:bob@corp.example" }],
              auditConfigDeltas: [
                {
                  action: "ADD",
                  service: "allServices",
                  logType: "DATA_READ",
                  exemptedMember: "user:bob@corp.example",
                },
              ],
            },
          },
        },
        "cloudresourcemanager.googleapis.com",
      ),
    ]);
    expect(both).toHaveLength(2);
  });
});

describe("Azure diagnostic settings — logs, metrics and destinations read apart", () => {
  const azure = (op: string, over: Row = {}): Row => ({
    eventTimestamp: "2023-07-01T11:00:00Z",
    operationName: { value: op, localizedValue: op },
    category: { value: "Administrative" },
    status: { value: "Succeeded" },
    caller: "admin@acme.com",
    resourceId:
      "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1/providers/Microsoft.Insights/diagnosticSettings/audit",
    httpRequest: { clientIpAddress: "203.0.113.22" },
    ...over,
  });
  const body = (properties: Row) => ({ properties: { requestbody: JSON.stringify({ properties }) } });
  const rows = (records: Row[]) => parseCloudActivity(JSON.stringify(records), { aggregate: false }).events;

  it("a delete is High; a write with every log category disabled is High; a mix quotes on / off with destinations and is 'prior state not in record'; metrics never bear the technique", () => {
    const del = rows([azure("Microsoft.Insights/diagnosticSettings/delete")])[0];
    expect(del.severity).toBe("High");
    expect(del.mitreTechniques).toContain("T1562.008");
    expect(del.description).toContain("diagnostic setting deleted: audit on vaults/kv1");
    const off = rows([
      azure(
        "Microsoft.Insights/diagnosticSettings/write",
        body({
          logs: [
            { category: "AuditEvent", enabled: false },
            { categoryGroup: "allLogs", enabled: false },
          ],
          metrics: [{ category: "AllMetrics", enabled: true }],
          workspaceId:
            "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law",
        }),
      ),
    ])[0];
    expect(off.severity).toBe("High");
    expect(off.description).toContain(
      "diagnostic setting written: audit on vaults/kv1 — every log category disabled in the resulting setting (AuditEvent, allLogs); metrics on: AllMetrics; destination workspace …/workspaces/law",
    );
    expect(env(off).loggingChange).toMatchObject({ provider: "azure", state: "reconfigured" });
    const mixed = rows([
      azure(
        "Microsoft.Insights/diagnosticSettings/write",
        body({
          logs: [
            { category: "AuditEvent", enabled: true },
            { category: "AzurePolicyEvaluationDetails", enabled: false },
          ],
          storageAccountId:
            "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
        }),
      ),
    ])[0];
    expect(mixed.severity).toBe("Medium");
    expect(mixed.description).toContain(
      "log categories on: AuditEvent; off: AzurePolicyEvaluationDetails; destination storage account …/storageAccounts/sa",
    );
    expect(mixed.description).toContain("the prior setting is not in this record");
    expect(env(mixed).loggingChange?.state).toBe("prior-state-not-in-record");
    const metricsOnly = rows([
      azure(
        "Microsoft.Insights/diagnosticSettings/write",
        body({ metrics: [{ category: "AllMetrics", enabled: false }] }),
      ),
    ])[0];
    expect(metricsOnly.mitreTechniques).not.toContain("T1562.008");
    expect(metricsOnly.description).toContain("metrics off: AllMetrics");
    const noBody = rows([azure("Microsoft.Insights/diagnosticSettings/write")])[0];
    expect(noBody.severity).toBe("Medium");
    expect(noBody.description).toContain("the request body is not in this record");
    expect(
      rows([
        azure("Microsoft.Insights/logProfiles/delete", {
          resourceId: "/subscriptions/abc/providers/Microsoft.Insights/logProfiles/default",
        }),
      ])[0].severity,
    ).toBe("High");
  });
});
