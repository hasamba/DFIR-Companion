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
    expect(writeOnly.severity).toBe("High");
    expect(writeOnly.description).toContain(
      "resulting selectors: management WriteOnly (excluding kms.amazonaws.com); data events: none selected; network activity: none (basic selectors)",
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
    expect(denied.description).toContain("attempted, denied — the resulting state is not established");
    expect(denied.description).toContain("requested (denied): resulting selectors");
    expect(env(denied).loggingChange).toMatchObject({
      denied: true,
      state: "requested",
      requestedState: "reconfigured",
    });
    expect(denied.mitreTechniques).toEqual([]);
  });

  it("insight selectors, event data stores and flow logs; GuardDuty features read one by one and publishing frequency is delivery cadence; bucket access logging", () => {
    expect(one("PutInsightSelectors", { trailName: TRAIL, insightSelectors: [] }).description).toContain(
      "resulting insight selectors: none",
    );
    expect(one("PutInsightSelectors", { trailName: TRAIL, insightSelectors: [] }).severity).toBe("Medium");
    expect(
      one("PutInsightSelectors", {
        trailName: TRAIL,
        insightSelectors: [{ insightType: "ApiCallRateInsight" }],
      }).severity,
    ).toBe("Medium");
    expect(one("PutInsightSelectors", { trailName: TRAIL }).description).toContain(
      "resulting insight selectors: not in the request",
    );
    expect(
      one("DeleteEventDataStore", {
        eventDataStore: "arn:aws:cloudtrail:us-east-1:111122223333:eventdatastore/abc",
      }).severity,
    ).toBe("High");
    const flowShapes: Row[] = [
      { flowLogIds: ["fl-0a", "fl-0b"] },
      { DeleteFlowLogsRequest: { FlowLogId: [{ content: "fl-0a" }, { content: "fl-0b" }] } },
      { flowLogIdSet: { items: [{ flowLogId: "fl-0a" }, { flowLogId: "fl-0b" }] } },
      { FlowLogId: "fl-0a", flowLogId: "fl-0b" },
    ];
    for (const shape of flowShapes) {
      const flow = aws([ct("DeleteFlowLogs", shape, { eventSource: "ec2.amazonaws.com" })])[0];
      expect(flow.severity).toBe("High");
      expect(flow.description).toContain("flow logs deleted: fl-0a, fl-0b");
    }
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
    const mixed = gd({
      enable: true,
      features: [{ name: "EBS_MALWARE_PROTECTION", status: "DISABLED" }],
      findingPublishingFrequency: "ONE_HOUR",
    });
    expect(mixed.severity).toBe("High");
    expect(mixed.description).toContain(
      "detector d1 reconfigured: detector enabled; EBS_MALWARE_PROTECTION DISABLED",
    );
    expect(mixed.description).toContain(
      "findingPublishingFrequency ONE_HOUR — delivery cadence, no coverage change",
    );
    expect(env(mixed).loggingChange?.facts).toEqual(
      expect.arrayContaining([{ name: "findingPublishingFrequency", value: "ONE_HOUR" }]),
    );
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
    expect(env(bucketOn).loggingChange?.facts).toEqual([
      { name: "TargetBucket", value: "logs" },
      { name: "TargetPrefix", value: "b/" },
    ]);
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
    const evil = one(
      "StopLogging",
      { name: "arn:aws:cloudtrail:us-east-1:111122223333:trail/t] [fake: started\u202e|x" },
      {
        userIdentity: {
          type: "IAMUser",
          principalId: "AIDAEXAMPLE",
          arn: `arn:aws:iam::${ACCT}:user/al] [ice`,
          accountId: ACCT,
          userName: "al] [ice\u200b",
        },
        userAgent: "ua] [x",
        errorCode: "Access] [Denied",
      },
    );
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
    expect(unexempt.mitreTechniques).toEqual([]);
    const unknown = policy([{ action: "SET", service: "allServices", logType: "DATA_READ" }])[0];
    expect(unknown.severity).toBe("Medium");
    expect(unknown.description).toContain(
      "audit-config entry changed (action SET) for DATA_READ on allServices",
    );
    expect(unknown.description).not.toContain("removed");
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
      "diagnostic setting written: audit on vaults/kv1 — every log category disabled in the resulting setting (AuditEvent, allLogs); metrics on: AllMetrics; off: none; destination workspace …/workspaces/law",
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
    expect(metricsOnly.description).toContain("metrics on: none; off: AllMetrics");
    const unstated = rows([
      azure(
        "Microsoft.Insights/diagnosticSettings/write",
        body({ logs: [{ category: "AuditEvent" }, { category: "Other", enabled: false }] }),
      ),
    ])[0];
    expect(unstated.severity).toBe("Medium");
    expect(unstated.description).toContain("log categories on: none; off: Other; not stated: AuditEvent");
    const objectBody = rows([
      azure("Microsoft.Insights/diagnosticSettings/write", {
        properties: { requestbody: { properties: { logs: [{ categoryGroup: "allLogs", enabled: false }] } } },
      }),
    ])[0];
    expect(objectBody.severity).toBe("High");
    const pascal = rows([
      azure("Microsoft.Insights/diagnosticSettings/write", {
        Properties: {
          requestbody: JSON.stringify({ properties: { logs: [{ category: "AuditEvent", enabled: false }] } }),
        },
      }),
    ])[0];
    expect(pascal.severity).toBe("High");
    expect(env(off).loggingChange?.facts).toEqual(
      expect.arrayContaining([
        {
          name: "workspace",
          value:
            "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law",
        },
      ]),
    );
    expect(canonicalConformanceIssues(env(off))).toEqual([]);
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

// #1071: AWS Config recorder calls, read for the state they establish. A separate `cfg()` fixture
// builder (not `ct()`) since the CloudTrail default injects a `requestParameters.name: TRAIL`
// field that would misleadingly stand in for `configurationRecorder.name` (Codex design round 1,
// finding #12).
describe("AWS Config recorder calls — the state the request establishes (#1071)", () => {
  const cfg = (name: string, requestParameters: Row = {}, over: Row = {}): Row => ({
    eventVersion: "1.08",
    eventTime: "2024-05-01T09:00:00Z",
    eventSource: "config.amazonaws.com",
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
    requestParameters,
    responseElements: null,
    ...over,
  });
  const put = (recorder: Row, over: Row = {}) =>
    aws([cfg("PutConfigurationRecorder", { configurationRecorder: recorder }, over)])[0];

  it("all-supported, global included, continuous: an explicitly maximal configuration grades Low, state is prior-state-not-in-record (never created/reconfigured)", () => {
    const e = put({
      name: "default",
      roleARN: "arn:aws:iam::111122223333:role/config-role",
      recordingGroup: { allSupported: true, includeGlobalResourceTypes: true },
      recordingMode: { recordingFrequency: "CONTINUOUS" },
    });
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("Config recorder default: all supported resource types");
    const block = env(e).loggingChange!;
    expect(block.state).toBe("prior-state-not-in-record");
    expect(block.targetKind).toBe("config-recorder");
    expect(block.target).toBe("default");
    expect(e.description).toContain("the prior configuration is not in this record");
    expect(canonicalConformanceIssues(env(e))).toEqual([]);
  });

  it("all-supported with global resource types excluded grades High and names the reason", () => {
    const e = put({
      recordingGroup: { allSupported: true, includeGlobalResourceTypes: false },
      recordingMode: { recordingFrequency: "CONTINUOUS" },
    });
    expect(e.severity).toBe("High");
    expect(e.description).toContain("global resource types excluded");
  });

  it("all-supported with a DAILY default frequency grades High", () => {
    const e = put({
      recordingGroup: { allSupported: true, includeGlobalResourceTypes: true },
      recordingMode: { recordingFrequency: "DAILY" },
    });
    expect(e.severity).toBe("High");
    expect(e.description).toContain("daily (not continuous) recording");
  });

  it("all-supported with a per-resource-type DAILY override grades High even though the default is CONTINUOUS", () => {
    const e = put({
      recordingGroup: { allSupported: true, includeGlobalResourceTypes: true },
      recordingMode: {
        recordingFrequency: "CONTINUOUS",
        recordingModeOverrides: [{ resourceTypes: ["AWS::EC2::Instance"], recordingFrequency: "DAILY" }],
      },
    });
    expect(e.severity).toBe("High");
    expect(e.description).toContain("daily (not continuous) recording");
    expect(env(e).loggingChange?.facts).toEqual(
      expect.arrayContaining([{ name: "recordingModeOverride", value: "AWS::EC2::Instance → DAILY" }]),
    );
  });

  it("inclusion-by-resource-types strategy always grades High and names the list", () => {
    const e = put({
      recordingGroup: {
        recordingStrategy: { useOnly: "INCLUSION_BY_RESOURCE_TYPES" },
        resourceTypes: ["AWS::EC2::Instance", "AWS::IAM::Role"],
      },
    });
    expect(e.severity).toBe("High");
    expect(e.description).toContain("inclusion list (AWS::EC2::Instance, AWS::IAM::Role)");
  });

  it("legacy allSupported:false with an explicit resourceTypes list is treated the same as inclusion — High", () => {
    const e = put({ recordingGroup: { allSupported: false, resourceTypes: ["AWS::S3::Bucket"] } });
    expect(e.severity).toBe("High");
    expect(e.description).toContain("inclusion list (AWS::S3::Bucket)");
  });

  it("exclusion-by-resource-types with a non-empty list grades High; includeGlobalResourceTypes has no effect under this strategy", () => {
    const e = put({
      recordingGroup: {
        recordingStrategy: { useOnly: "EXCLUSION_BY_RESOURCE_TYPES" },
        includeGlobalResourceTypes: false,
        exclusionByResourceTypes: { resourceTypes: ["AWS::EC2::Instance"] },
      },
    });
    expect(e.severity).toBe("High");
    expect(e.description).toContain("exclusion list (AWS::EC2::Instance)");
  });

  it("exclusion-by-resource-types with an EMPTY exclusion list is effectively unrestricted — Low", () => {
    const e = put({
      recordingGroup: {
        recordingStrategy: { useOnly: "EXCLUSION_BY_RESOURCE_TYPES" },
        exclusionByResourceTypes: { resourceTypes: [] },
      },
    });
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("exclusion strategy, no resource types excluded");
  });

  it("an unrecognized recordingStrategy value grades Medium and says so, never guessed into a known strategy", () => {
    const e = put({ recordingGroup: { recordingStrategy: { useOnly: "SOMETHING_NEW" } } });
    expect(e.severity).toBe("Medium");
    expect(e.description).toContain("recording strategy not recognized in this record");
  });

  it("recordingGroup absent cites AWS's documented default rather than inventing a fact — Medium", () => {
    const e = put({ recordingMode: { recordingFrequency: "CONTINUOUS" } });
    expect(e.severity).toBe("Medium");
    expect(e.description).toContain(
      "recordingGroup absent; AWS's documented default records all supported resource types except the global IAM types",
    );
  });

  it("recordingMode absent cites AWS's documented default (CONTINUOUS), never invents a frequency", () => {
    const e = put({ recordingGroup: { allSupported: true, includeGlobalResourceTypes: true } });
    expect(e.description).toContain("recordingMode absent; AWS's documented default is CONTINUOUS");
    // No narrowing signal beyond the absence itself -> still Low, since the documented default IS continuous.
    expect(e.severity).toBe("Low");
  });

  it("more than LIST_MAX resource types: the DISPLAYED list is bounded and discloses truncation, but two configurations differing only past the cap remain two distinct aggregated rows", () => {
    const many = Array.from({ length: 12 }, (_, i) => `AWS::Service${i}::Type`);
    const eA = put({
      recordingGroup: {
        recordingStrategy: { useOnly: "INCLUSION_BY_RESOURCE_TYPES" },
        resourceTypes: many,
      },
      // An explicit recordingMode removes the "recordingMode absent" qualifier, keeping the
      // combined qualifier text under renderLoggingDescription's own length bound so the
      // truncation disclosure this test checks for is not itself clipped out.
      recordingMode: { recordingFrequency: "CONTINUOUS" },
    });
    expect(eA.description).toContain("8 of 12 resource types shown");
    const manyDiffering = [...many.slice(0, 8), "AWS::Different::TypeA", "AWS::Different::TypeB", "x", "y"];
    const eB = put({
      recordingGroup: {
        recordingStrategy: { useOnly: "INCLUSION_BY_RESOURCE_TYPES" },
        resourceTypes: manyDiffering,
      },
    });
    const together = aws([
      cfg("PutConfigurationRecorder", {
        configurationRecorder: {
          recordingGroup: {
            recordingStrategy: { useOnly: "INCLUSION_BY_RESOURCE_TYPES" },
            resourceTypes: many,
          },
        },
      }),
      cfg("PutConfigurationRecorder", {
        configurationRecorder: {
          recordingGroup: {
            recordingStrategy: { useOnly: "INCLUSION_BY_RESOURCE_TYPES" },
            resourceTypes: manyDiffering,
          },
        },
      }),
    ]);
    expect(together).toHaveLength(2);
    expect(eA.aggKey).not.toBe(eB.aggKey);
  });

  it("StopConfigurationRecorder is disabled/High, targetKind config-recorder", () => {
    const e = aws([cfg("StopConfigurationRecorder", { configurationRecorderName: "default" })])[0];
    expect(e.severity).toBe("High");
    expect(e.description).toContain("Config recorder stopped: default");
    expect(env(e).loggingChange?.targetKind).toBe("config-recorder");
    expect(env(e).loggingChange?.state).toBe("disabled");
  });

  it("DeleteDeliveryChannel is deleted/High, targetKind config-delivery-channel, and states the recorder had to be stopped first (never 'may still run')", () => {
    const e = aws([cfg("DeleteDeliveryChannel", { deliveryChannelName: "default" })])[0];
    expect(e.severity).toBe("High");
    expect(e.description).toContain(
      "the customer-managed recorder had to be stopped first and cannot restart until a delivery channel exists again",
    );
    expect(e.description).not.toContain("may still run");
    expect(env(e).loggingChange?.targetKind).toBe("config-delivery-channel");
    expect(env(e).loggingChange?.state).toBe("deleted");
  });

  // #1075: StartConfigurationRecorder / DeleteConfigurationRecorder — the recorder lifecycle
  // #1071 doesn't cover.
  it("StartConfigurationRecorder is enabled/Low, names PAST_NOTE, and carries no MITRE technique", () => {
    const e = aws([cfg("StartConfigurationRecorder", { configurationRecorderName: "default" })])[0];
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("Config recorder started: default");
    expect(e.description).toContain("enabling a source does not reconstruct its past");
    expect(e.mitreTechniques).toEqual([]);
    expect(env(e).loggingChange?.targetKind).toBe("config-recorder");
    expect(env(e).loggingChange?.state).toBe("enabled");
  });

  it("DeleteConfigurationRecorder is deleted/High, T1562.008, and states configuration history is not deleted by this operation", () => {
    const e = aws([cfg("DeleteConfigurationRecorder", { configurationRecorderName: "default" })])[0];
    expect(e.severity).toBe("High");
    expect(e.description).toContain("Config recorder deleted: default");
    expect(e.description).toContain(
      "previously recorded configuration history is not deleted by this operation",
    );
    expect(e.mitreTechniques).toContain("T1562.008");
    expect(env(e).loggingChange?.targetKind).toBe("config-recorder");
    expect(env(e).loggingChange?.state).toBe("deleted");
  });

  it("a denied StartConfigurationRecorder / DeleteConfigurationRecorder is an attempt — never establishes the resulting state, and PAST_NOTE never appears when denied", () => {
    const start = aws([
      cfg(
        "StartConfigurationRecorder",
        { configurationRecorderName: "default" },
        { errorCode: "AccessDenied" },
      ),
    ])[0];
    expect(start.severity).toBe("Medium");
    expect(start.mitreTechniques).toEqual([]);
    expect(start.description).not.toContain("enabling a source does not reconstruct its past");
    expect(env(start).loggingChange?.state).toBe("requested");
    expect(env(start).loggingChange?.requestedState).toBe("enabled");

    const del = aws([
      cfg(
        "DeleteConfigurationRecorder",
        { configurationRecorderName: "default" },
        { errorCode: "AccessDenied" },
      ),
    ])[0];
    expect(del.severity).toBe("Medium");
    expect(del.mitreTechniques).toEqual([]);
    expect(env(del).loggingChange?.state).toBe("requested");
    expect(env(del).loggingChange?.requestedState).toBe("deleted");
  });

  it("Start/DeleteConfigurationRecorder calls are canonically conformant", () => {
    const start = aws([cfg("StartConfigurationRecorder", { configurationRecorderName: "default" })])[0];
    const del = aws([cfg("DeleteConfigurationRecorder", { configurationRecorderName: "default" })])[0];
    for (const e of [start, del]) expect(canonicalConformanceIssues(env(e))).toEqual([]);
  });

  it("a denied PutConfigurationRecorder is an attempt — never establishes the resulting state", () => {
    const e = aws([
      cfg(
        "PutConfigurationRecorder",
        {
          configurationRecorder: {
            recordingGroup: { allSupported: false, resourceTypes: ["AWS::EC2::Instance"] },
          },
        },
        { errorCode: "AccessDenied" },
      ),
    ])[0];
    expect(e.description).toContain("requested (denied)");
    expect(env(e).loggingChange?.state).toBe("requested");
    expect(env(e).loggingChange?.requestedState).toBe("prior-state-not-in-record");
  });

  it("a denied StopConfigurationRecorder / DeleteDeliveryChannel is also an attempt", () => {
    const stop = aws([
      cfg(
        "StopConfigurationRecorder",
        { configurationRecorderName: "default" },
        { errorCode: "AccessDenied" },
      ),
    ])[0];
    expect(env(stop).loggingChange?.state).toBe("requested");
    const del = aws([
      cfg(
        "DeleteDeliveryChannel",
        { deliveryChannelName: "default" },
        { errorCode: "NoSuchDeliveryChannel" },
      ),
    ])[0];
    expect(env(del).loggingChange?.state).toBe("requested");
  });

  it("recorder and delivery-channel calls are canonically conformant", () => {
    const put1 = put({ recordingGroup: { allSupported: true, includeGlobalResourceTypes: true } });
    const stop = aws([cfg("StopConfigurationRecorder", { configurationRecorderName: "default" })])[0];
    const del = aws([cfg("DeleteDeliveryChannel", { deliveryChannelName: "default" })])[0];
    for (const e of [put1, stop, del]) expect(canonicalConformanceIssues(env(e))).toEqual([]);
  });

  // Regression tests for Codex code-round-1 findings (RECOMMENDATION-1071.md).
  it("#1/#5 an override's own resourceTypes list beyond LIST_MAX still feeds the aggregation key in full", () => {
    const manyA = Array.from({ length: 10 }, (_, i) => `AWS::OverrideA${i}::Type`);
    const manyB = [...manyA.slice(0, 8), "AWS::Different::X", "AWS::Different::Y"];
    const eA = put({
      recordingGroup: { allSupported: true, includeGlobalResourceTypes: true },
      recordingMode: {
        recordingFrequency: "CONTINUOUS",
        recordingModeOverrides: [{ resourceTypes: manyA, recordingFrequency: "DAILY" }],
      },
    });
    const eB = put({
      recordingGroup: { allSupported: true, includeGlobalResourceTypes: true },
      recordingMode: {
        recordingFrequency: "CONTINUOUS",
        recordingModeOverrides: [{ resourceTypes: manyB, recordingFrequency: "DAILY" }],
      },
    });
    expect(eA.aggKey).not.toBe(eB.aggKey);
    expect(eA.description).toContain("recordingModeOverride: 8 of 10 resource types shown");
  });

  it("#2 roleARN is captured as a fact and distinguishes otherwise-identical configurations in the aggregation key", () => {
    const eA = put({
      roleARN: "arn:aws:iam::111122223333:role/config-role-a",
      recordingGroup: { allSupported: true, includeGlobalResourceTypes: true },
    });
    const eB = put({
      roleARN: "arn:aws:iam::111122223333:role/config-role-b",
      recordingGroup: { allSupported: true, includeGlobalResourceTypes: true },
    });
    expect(env(eA).loggingChange?.facts).toEqual(
      expect.arrayContaining([{ name: "roleARN", value: "arn:aws:iam::111122223333:role/config-role-a" }]),
    );
    expect(eA.aggKey).not.toBe(eB.aggKey);
  });

  it("#3 recordingGroup PRESENT but EMPTY is worded distinctly from recordingGroup ABSENT, and from an unrecognized strategy value", () => {
    const empty = put({ recordingGroup: {}, recordingMode: { recordingFrequency: "CONTINUOUS" } });
    expect(empty.severity).toBe("Medium");
    expect(empty.description).toContain(
      "recordingGroup present but neither recordingStrategy nor allSupported recorded",
    );
    const absent = put({ recordingMode: { recordingFrequency: "CONTINUOUS" } });
    expect(absent.description).toContain(
      "recordingGroup absent; AWS's documented default records all supported resource types",
    );
    expect(absent.description).not.toContain("present but neither");
  });

  it("#4 two different unrecognized recordingStrategy values are distinguishable in evidence and never aggregate together", () => {
    const eA = put({
      recordingGroup: { recordingStrategy: { useOnly: "FUTURE_STRATEGY_A" } },
      recordingMode: { recordingFrequency: "CONTINUOUS" },
    });
    const eB = put({
      recordingGroup: { recordingStrategy: { useOnly: "FUTURE_STRATEGY_B" } },
      recordingMode: { recordingFrequency: "CONTINUOUS" },
    });
    // Canonical facts carry the raw value uncapped, unlike the length-bounded rendered description.
    expect(env(eA).loggingChange?.facts).toEqual(
      expect.arrayContaining([{ name: "recordingStrategy", value: "FUTURE_STRATEGY_A" }]),
    );
    expect(env(eB).loggingChange?.facts).toEqual(
      expect.arrayContaining([{ name: "recordingStrategy", value: "FUTURE_STRATEGY_B" }]),
    );
    expect(eA.description).toContain("recording strategy not recognized in this record: FUTURE_STRATEGY_A");
    expect(eA.aggKey).not.toBe(eB.aggKey);
  });

  it("#5 an explicit ALL_SUPPORTED_RESOURCE_TYPES strategy is read the same as the legacy allSupported:true shape", () => {
    const e = put({
      recordingGroup: {
        recordingStrategy: { useOnly: "ALL_SUPPORTED_RESOURCE_TYPES" },
        includeGlobalResourceTypes: true,
      },
      recordingMode: { recordingFrequency: "CONTINUOUS" },
    });
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("all supported resource types");
  });

  it("#5 recordingStrategy.useOnly takes precedence over a conflicting allSupported field", () => {
    const e = put({
      recordingGroup: {
        recordingStrategy: { useOnly: "INCLUSION_BY_RESOURCE_TYPES" },
        allSupported: true, // contradicts useOnly — the strategy field must win
        resourceTypes: ["AWS::EC2::Instance"],
      },
    });
    expect(e.severity).toBe("High");
    expect(e.description).toContain("inclusion list (AWS::EC2::Instance)");
  });

  it("#5 exclusion-list truncation past LIST_MAX is disclosed and distinguishes the aggregation identity", () => {
    const manyA = Array.from({ length: 10 }, (_, i) => `AWS::ExclA${i}::Type`);
    const manyB = [...manyA.slice(0, 8), "AWS::Different::X", "AWS::Different::Y"];
    const eA = put({
      recordingGroup: {
        recordingStrategy: { useOnly: "EXCLUSION_BY_RESOURCE_TYPES" },
        exclusionByResourceTypes: { resourceTypes: manyA },
      },
      recordingMode: { recordingFrequency: "CONTINUOUS" },
    });
    const eB = put({
      recordingGroup: {
        recordingStrategy: { useOnly: "EXCLUSION_BY_RESOURCE_TYPES" },
        exclusionByResourceTypes: { resourceTypes: manyB },
      },
      recordingMode: { recordingFrequency: "CONTINUOUS" },
    });
    expect(eA.description).toContain("8 of 10 resource types shown");
    expect(eA.aggKey).not.toBe(eB.aggKey);
  });

  it("#5 a hostile recorder/channel name cannot forge a fake field boundary or hide via bidi override", () => {
    // Matches this file's own established hostile-string convention (see the CloudTrail
    // StopLogging test above): "] [" is a field-boundary-injection attempt, ‮ a bidi override.
    const hostile = "default] [fake: started‮|x";
    const put1 = put({ name: hostile, recordingGroup: { allSupported: true } });
    expect(put1.description).not.toContain("] [");
    expect(put1.description).not.toContain("‮");
    const stop = aws([cfg("StopConfigurationRecorder", { configurationRecorderName: hostile })])[0];
    expect(stop.description).not.toContain("] [");
    expect(stop.description).not.toContain("‮");
    const del = aws([cfg("DeleteDeliveryChannel", { deliveryChannelName: hostile })])[0];
    expect(del.description).not.toContain("] [");
    expect(del.description).not.toContain("‮");
  });

  it("#5 Stop/Delete readings never carry the prior-configuration note (only Put's prior-state-not-in-record does)", () => {
    const stop = aws([cfg("StopConfigurationRecorder", { configurationRecorderName: "default" })])[0];
    expect(stop.description).not.toContain("the prior configuration is not in this record");
    const del = aws([cfg("DeleteDeliveryChannel", { deliveryChannelName: "default" })])[0];
    expect(del.description).not.toContain("the prior configuration is not in this record");
  });

  it("#5 a denied Put/Stop/Delete carries no MITRE technique and stays canonically conformant", () => {
    const put1 = aws([
      cfg(
        "PutConfigurationRecorder",
        {
          configurationRecorder: {
            recordingGroup: { allSupported: false, resourceTypes: ["AWS::EC2::Instance"] },
          },
        },
        { errorCode: "AccessDenied" },
      ),
    ])[0];
    const stop = aws([
      cfg(
        "StopConfigurationRecorder",
        { configurationRecorderName: "default" },
        { errorCode: "AccessDenied" },
      ),
    ])[0];
    const del = aws([
      cfg(
        "DeleteDeliveryChannel",
        { deliveryChannelName: "default" },
        { errorCode: "NoSuchDeliveryChannel" },
      ),
    ])[0];
    for (const e of [put1, stop, del]) {
      expect(e.mitreTechniques).toEqual([]);
      expect(canonicalConformanceIssues(env(e))).toEqual([]);
    }
  });

  it("#5 an empty inclusion list under INCLUSION_BY_RESOURCE_TYPES is graded High and named as none", () => {
    const e = put({
      recordingGroup: { recordingStrategy: { useOnly: "INCLUSION_BY_RESOURCE_TYPES" }, resourceTypes: [] },
    });
    expect(e.severity).toBe("High");
    expect(e.description).toContain("inclusion list (none named)");
  });

  it("#5 a missing recorder name reads as not-recorded, never guessed", () => {
    const e = put({ recordingGroup: { allSupported: true } });
    expect(e.description).toContain("Config recorder (name not recorded):");
  });
});

// #1081: the shared "denied" flag conflated authorization denial with any API failure. A failed
// call is now one of three outcomes — denied, not-found, or an honest unclassified "failed" — and
// only the positively-identified not-found case is graded Low; an unclassified failure keeps
// today's conservative Medium, same as denied.
describe("classifyAwsFailure — AWS error-code taxonomy (#1081)", () => {
  it("a NoSuch*/*NotFound* code is not-found, never denied", async () => {
    const { classifyAwsFailure } = await import("../../src/analysis/loggingChange.js");
    expect(classifyAwsFailure("NoSuchDeliveryChannel")).toBe("not-found");
    expect(classifyAwsFailure("NoSuchConfigurationRecorderException")).toBe("not-found");
    expect(classifyAwsFailure("TrailNotFoundException")).toBe("not-found");
    expect(classifyAwsFailure("InvalidFlowLogId.NotFound")).toBe("not-found");
  });
  it("an access/authorization code is denied", async () => {
    const { classifyAwsFailure } = await import("../../src/analysis/loggingChange.js");
    expect(classifyAwsFailure("AccessDenied")).toBe("denied");
    expect(classifyAwsFailure("AccessDeniedException")).toBe("denied");
    expect(classifyAwsFailure("Client.UnauthorizedOperation")).toBe("denied");
    expect(classifyAwsFailure("InsufficientPermissionsException")).toBe("denied");
  });
  it("an ambiguous or unrecognized code is the neutral 'failed' — never guessed as either outcome", async () => {
    const { classifyAwsFailure } = await import("../../src/analysis/loggingChange.js");
    // GuardDuty's real DeleteDetector/UpdateDetector failure code (Codex design review finding #4).
    expect(classifyAwsFailure("BadRequestException")).toBe("failed");
    expect(classifyAwsFailure("ConflictException")).toBe("failed");
    expect(classifyAwsFailure("ThrottlingException")).toBe("failed");
    // S3's ambiguous code (Codex design review finding #4): could mean absent, foreign-owned, or
    // ungranted — none positively provable from the code alone.
    expect(classifyAwsFailure("InvalidTargetBucketForLogging")).toBe("failed");
  });
});

describe("a not-found / failed AWS logging call — three distinct outcomes, never collapsed to one, and the not-found severity is never re-elevated back to Medium by the generic errorCode bump (#1081; the re-elevation risk was self-found during implementation, same class of bug as Codex's GCP head-text finding)", () => {
  const cfg = (name: string, requestParameters: Row = {}, over: Row = {}): Row => ({
    eventVersion: "1.08",
    eventTime: "2024-05-01T09:00:00Z",
    eventSource: "config.amazonaws.com",
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
    requestParameters,
    responseElements: null,
    ...over,
  });
  const delChannel = (over: Row) =>
    aws([cfg("DeleteDeliveryChannel", { deliveryChannelName: "default" }, over)])[0];

  it("NoSuchDeliveryChannel is not-found: Low, 'requested (target not found)', denied is false", () => {
    const e = delChannel({ errorCode: "NoSuchDeliveryChannel" });
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("requested (target not found):");
    const block = env(e).loggingChange;
    expect(block?.denied).toBe(false);
    expect(block?.failure).toBe("not-found");
    expect(block?.state).toBe("requested");
    expect(canonicalConformanceIssues(env(e))).toEqual([]);
  });
  it("AccessDenied stays denied: Medium, 'requested (denied)', denied is true — unchanged from before #1081", () => {
    const e = delChannel({ errorCode: "AccessDenied" });
    expect(e.severity).toBe("Medium");
    expect(e.description).toContain("requested (denied):");
    const block = env(e).loggingChange;
    expect(block?.denied).toBe(true);
    expect(block?.failure).toBe("denied");
  });
  it("a generic/unrecognized code is the neutral 'failed': Medium (unchanged), 'requested (failed)', denied is false", () => {
    const e = delChannel({ errorCode: "InternalFailure" });
    expect(e.severity).toBe("Medium");
    expect(e.description).toContain("requested (failed):");
    const block = env(e).loggingChange;
    expect(block?.denied).toBe(false);
    expect(block?.failure).toBe("failed");
  });
  it("a successful call carries no failure field at all", () => {
    const e = delChannel({});
    const block = env(e).loggingChange;
    expect(block?.denied).toBe(false);
    expect(block?.failure).toBeUndefined();
  });
  it("DeleteConfigurationRecorder against an already-gone recorder is Low, not Medium — the generic errorCode bump never re-elevates a logging row's own severity", () => {
    const e = aws([
      cfg(
        "DeleteConfigurationRecorder",
        { configurationRecorderName: "default" },
        { errorCode: "NoSuchConfigurationRecorderException" },
      ),
    ])[0];
    expect(e.severity).toBe("Low");
    expect(env(e).loggingChange?.failure).toBe("not-found");
  });
});

// #1095: DeleteFlowLogs previously reported every requested id as deleted unconditionally, never
// reading responseElements.unsuccessful — a call naming 3 ids where 1 failed read as "3 flow logs
// deleted" in the case timeline.
describe("DeleteFlowLogs reads responseElements.unsuccessful — only the ids that actually succeeded are 'deleted' (#1095)", () => {
  it("a fully successful call (no unsuccessful items) is unchanged: all requested ids deleted, High", () => {
    const flow = aws([
      ct(
        "DeleteFlowLogs",
        { flowLogIds: ["fl-0a", "fl-0b"] },
        { eventSource: "ec2.amazonaws.com", responseElements: { unsuccessful: [] } },
      ),
    ])[0];
    expect(flow.severity).toBe("High");
    expect(flow.description).toContain("flow logs deleted: fl-0a, fl-0b");
    expect(env(flow).loggingChange?.denied).toBe(false);
    expect(env(flow).loggingChange?.failure).toBeUndefined();
  });

  it("a partial failure: only the succeeded id is reported deleted; the failed one is named separately with its own reason, never silently counted as deleted", () => {
    const flow = aws([
      ct(
        "DeleteFlowLogs",
        { flowLogIds: ["fl-0a", "fl-0b"] },
        {
          eventSource: "ec2.amazonaws.com",
          responseElements: {
            unsuccessful: [{ resourceId: "fl-0b", error: { code: "InvalidFlowLogId.NotFound" } }],
          },
        },
      ),
    ])[0];
    expect(flow.severity).toBe("High");
    expect(flow.description).toContain("flow logs deleted: fl-0a");
    expect(flow.description).not.toContain("flow logs deleted: fl-0a, fl-0b");
    expect(flow.description).not.toContain("fl-0b deleted");
    expect(flow.description).toContain("fl-0b");
    expect(flow.description).toContain("not found");
    expect(env(flow).loggingChange?.state).toBe("deleted");
    expect(env(flow).loggingChange?.denied).toBe(false);
    expect(env(flow).loggingChange?.failure).toBeUndefined();
    expect(canonicalConformanceIssues(env(flow))).toEqual([]);
  });

  it("every requested id fails: the row is an ATTEMPT, never 'deleted' — state is requested, not deleted", () => {
    const flow = aws([
      ct(
        "DeleteFlowLogs",
        { flowLogIds: ["fl-0a", "fl-0b"] },
        {
          eventSource: "ec2.amazonaws.com",
          responseElements: {
            unsuccessful: [
              { resourceId: "fl-0a", error: { code: "AccessDenied" } },
              { resourceId: "fl-0b", error: { code: "AccessDenied" } },
            ],
          },
        },
      ),
    ])[0];
    expect(flow.description).not.toContain("flow logs deleted:");
    expect(env(flow).loggingChange?.state).toBe("requested");
    expect(env(flow).loggingChange?.denied).toBe(true);
    expect(env(flow).loggingChange?.failure).toBe("denied");
  });

  it("every requested id fails for MIXED reasons: the overall outcome is the neutral 'failed' — never asserted as one specific reason a mixed set does not support", () => {
    const flow = aws([
      ct(
        "DeleteFlowLogs",
        { flowLogIds: ["fl-0a", "fl-0b"] },
        {
          eventSource: "ec2.amazonaws.com",
          responseElements: {
            unsuccessful: [
              { resourceId: "fl-0a", error: { code: "AccessDenied" } },
              { resourceId: "fl-0b", error: { code: "InvalidFlowLogId.NotFound" } },
            ],
          },
        },
      ),
    ])[0];
    expect(env(flow).loggingChange?.state).toBe("requested");
    expect(env(flow).loggingChange?.denied).toBe(false);
    expect(env(flow).loggingChange?.failure).toBe("failed");
  });

  it("a whole-call errorCode (the top-level call itself denied) still wins over an absent per-item result", () => {
    const flow = aws([
      ct(
        "DeleteFlowLogs",
        { flowLogIds: ["fl-0a"] },
        { eventSource: "ec2.amazonaws.com", errorCode: "AccessDenied", responseElements: null },
      ),
    ])[0];
    expect(env(flow).loggingChange?.state).toBe("requested");
    expect(env(flow).loggingChange?.failure).toBe("denied");
  });
});
