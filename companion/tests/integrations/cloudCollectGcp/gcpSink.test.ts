import { describe, expect, it } from "vitest";
import {
  SINK_LATE_SHARD_MS,
  chooseSink,
  lastCompleteBatchEnd,
  objectHour,
  sinkFilterMisses,
  sinkVerdict,
  type LogSink,
} from "../../../src/integrations/cloudCollectGcp/gcpSink.js";
import { GCP_AUDIT_LOGS } from "../../../src/integrations/cloudCollectGcp/gcpFilter.js";
import { googleError, mockWire, PROJECT } from "./gcpCollectMocks.js";

// #2314: a GCS log sink is used only after its filter, its history and the bucket permission are
// checked; anything short of that is rejected with a reason and the collector uses the Logging API.

const sink = (over: Partial<LogSink> = {}): LogSink => ({
  name: "audit-to-gcs",
  destination: "storage.googleapis.com/audit-bucket-01",
  filter: 'logName:"cloudaudit.googleapis.com"',
  createTime: "2026-01-01T00:00:00Z",
  ...over,
});

describe("sinkFilterMisses", () => {
  it("accepts an empty filter and a filter naming every audit log", () => {
    expect(sinkFilterMisses("", GCP_AUDIT_LOGS)).toEqual({ missing: [] });
    expect(sinkFilterMisses('logName:"cloudaudit.googleapis.com"', GCP_AUDIT_LOGS)).toEqual({ missing: [] });
    const all = GCP_AUDIT_LOGS.map(
      (l) => `logName="projects/${PROJECT}/logs/cloudaudit.googleapis.com%2F${l}"`,
    );
    expect(sinkFilterMisses(all.join(" OR "), GCP_AUDIT_LOGS)).toEqual({ missing: [] });
  });

  it("names the audit logs a filter misses", () => {
    expect(
      sinkFilterMisses(
        `logName="projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Factivity" OR logName="projects/${PROJECT}/logs/cloudaudit.googleapis.com/policy"`,
        GCP_AUDIT_LOGS,
      ),
    ).toEqual({ missing: ["data_access", "system_event"] });
    expect(sinkFilterMisses('resource.type="gce_instance"', GCP_AUDIT_LOGS).missing).toEqual([
      ...GCP_AUDIT_LOGS,
    ]);
  });

  it("refuses a filter it cannot prove: a negation or a narrowing AND", () => {
    expect(
      sinkFilterMisses('logName:"cloudaudit.googleapis.com" AND severity>=WARNING', GCP_AUDIT_LOGS)
        .unprovable,
    ).toMatch(/AND/);
    expect(
      sinkFilterMisses('NOT logName:"cloudaudit.googleapis.com%2Fdata_access"', GCP_AUDIT_LOGS).unprovable,
    ).toMatch(/negation/);
  });
});

describe("sinkVerdict", () => {
  it("accepts a Cloud Storage sink whose filter covers the audit logs", () => {
    expect(sinkVerdict(sink(), GCP_AUDIT_LOGS)).toEqual({ ok: true, bucket: "audit-bucket-01" });
  });

  it("rejects, with the reason, a sink whose filter misses audit logs", () => {
    const v = sinkVerdict(
      sink({ filter: `logName="projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Factivity"` }),
      GCP_AUDIT_LOGS,
    );
    expect(v).toEqual({
      ok: false,
      reason:
        'sink "audit-to-gcs": its filter does not include the data_access, system_event, policy audit logs',
    });
  });

  it("rejects a disabled sink, one with active exclusions, and one that is not a bucket", () => {
    expect(sinkVerdict(sink({ disabled: true }), GCP_AUDIT_LOGS)).toMatchObject({
      ok: false,
      reason: /disabled/,
    });
    expect(
      sinkVerdict(sink({ exclusions: [{ name: "drop-da", filter: "x" }] }), GCP_AUDIT_LOGS),
    ).toMatchObject({ ok: false, reason: /exclusion/ });
    expect(
      sinkVerdict(sink({ destination: "bigquery.googleapis.com/projects/p/datasets/d" }), GCP_AUDIT_LOGS),
    ).toMatchObject({ ok: false, reason: /not a Cloud Storage bucket/ });
  });
});

describe("objectHour and the late-shard cutoff", () => {
  it("reads the log and the hour from a sink object name (colons, or dashes in a copied folder)", () => {
    const start = Date.parse("2026-11-01T15:00:00Z");
    expect(objectHour("cloudaudit.googleapis.com/activity/2026/11/01/15:00:00_15:59:59_S0.json")).toEqual({
      log: "activity",
      startMs: start,
      endMs: start + 3_600_000,
    });
    expect(
      objectHour("cloudaudit.googleapis.com/data_access/2026/11/01/15-00-00_15-59-59_S1.json")?.log,
    ).toBe("data_access");
    expect(objectHour("cloudaudit.googleapis.com/activity/2026/11/01/readme.txt")).toBeNull();
    expect(objectHour("other/activity/2026/11/01/15:00:00_15:59:59_S0.json")).toBeNull();
  });

  it("settles a sink only up to the last whole hour before the late-shard delay — never 5 minutes", () => {
    const at = Date.parse("2026-11-02T10:20:00Z");
    expect(SINK_LATE_SHARD_MS).toBeGreaterThanOrEqual(3_600_000);
    expect(lastCompleteBatchEnd(at)).toBe(
      new Date(Math.floor((at - SINK_LATE_SHARD_MS) / 3_600_000) * 3_600_000).toISOString(),
    );
    expect(Date.parse(lastCompleteBatchEnd(at))).toBeLessThan(at - 5 * 60_000);
  });
});

/** Sinks + bucket answers for chooseSink. */
function sinkCloud(opts: { sinks: LogSink[]; firstObject?: string | null; bucketStatus?: number }) {
  return mockWire((req) => {
    if (req.url.includes(`/v2/projects/${PROJECT}/sinks`)) return { body: { sinks: opts.sinks } };
    if (req.url.startsWith("https://storage.googleapis.com/storage/v1/b/")) {
      if (opts.bucketStatus && opts.bucketStatus !== 200)
        return {
          status: opts.bucketStatus,
          body: googleError(opts.bucketStatus, "PERMISSION_DENIED", "denied"),
        };
      return {
        body: opts.firstObject ? { items: [{ name: opts.firstObject }] } : { kind: "storage#objects" },
      };
    }
    return { status: 404, body: googleError(404, "NOT_FOUND", "unexpected") };
  });
}

describe("chooseSink", () => {
  const FIRST = "cloudaudit.googleapis.com/activity/2026/06/01/00:00:00_00:59:59_S0.json";

  it("takes a sink that passes the filter, history and permission checks", async () => {
    const { wire, calls } = sinkCloud({ sinks: [sink()], firstObject: FIRST });
    const choice = await chooseSink(wire, PROJECT);
    expect(choice).toMatchObject({ sink: "audit-to-gcs", bucket: "audit-bucket-01" });
    if (!("bucket" in choice)) throw new Error("no sink");
    expect(choice.coveredFrom).toBe("2026-06-01T00:00:00.000Z");
    // Reads only: the sink listing and one object listing.
    expect(calls.map((c) => c.method)).toEqual(["GET", "GET"]);
  });

  it("rejects every sink with its reason when none qualifies", async () => {
    const narrow = sink({ name: "activity-only", filter: 'logName:"cloudaudit.googleapis.com%2Factivity"' });
    const { wire } = sinkCloud({ sinks: [narrow], firstObject: FIRST });
    const choice = await chooseSink(wire, PROJECT);
    expect(choice).toEqual({
      rejected: [
        'sink "activity-only": its filter does not include the data_access, system_event, policy audit logs',
      ],
    });
  });

  it("rejects a sink whose bucket the account cannot list, or that holds no audit logs", async () => {
    const denied = await chooseSink(sinkCloud({ sinks: [sink()], bucketStatus: 403 }).wire, PROJECT);
    expect(denied).toMatchObject({
      rejected: [expect.stringMatching(/roles\/storage\.objectViewer.*HTTP 403/)],
    });
    const empty = await chooseSink(sinkCloud({ sinks: [sink()], firstObject: null }).wire, PROJECT);
    expect(empty).toMatchObject({ rejected: [expect.stringMatching(/holds no audit log objects/)] });
  });

  it("covers from the later of the sink's creation and its oldest object", async () => {
    const late = sink({ createTime: "2026-09-15T12:34:00Z" });
    const choice = await chooseSink(sinkCloud({ sinks: [late], firstObject: FIRST }).wire, PROJECT);
    expect(choice).toMatchObject({ coveredFrom: "2026-09-15T12:34:00.000Z" });
  });

  it("says so when the project has no sink at all", async () => {
    expect(await chooseSink(sinkCloud({ sinks: [] }).wire, PROJECT)).toEqual({
      rejected: ["the project has no log sink"],
    });
  });
});
