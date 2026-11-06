import { describe, expect, it } from "vitest";
import {
  SINK_LATE_SHARD_MS,
  chooseSink,
  lastCompleteBatchEnd,
  objectHour,
  sinkVerdict,
  type LogSink,
} from "../../../src/integrations/cloudCollectGcp/gcpSink.js";
import { sinkFilterMisses } from "../../../src/integrations/cloudCollectGcp/gcpSinkFilter.js";
import { GCP_AUDIT_LOGS } from "../../../src/integrations/cloudCollectGcp/gcpFilter.js";
import { googleError, mockWire, PROJECT } from "./gcpCollectMocks.js";

// #2314: a GCS log sink is used only after its filter, its history and the bucket permission are
// checked; anything short of that is rejected with a reason and the collector uses the Logging API.

const sink = (over: Partial<LogSink> = {}): LogSink => ({
  name: "audit-to-gcs",
  destination: "storage.googleapis.com/audit-bucket-01",
  filter: 'logName:"cloudaudit.googleapis.com"',
  createTime: "2026-01-01T00:00:00Z",
  updateTime: "2026-01-01T00:00:00Z",
  ...over,
});

const UNPROVABLE = "its filter cannot be proven to keep every audit entry";
const misses = (f: string) => sinkFilterMisses(f, PROJECT, GCP_AUDIT_LOGS);
const full = (l: string, sep = "%2F") => `projects/${PROJECT}/logs/cloudaudit.googleapis.com${sep}${l}`;

describe("sinkFilterMisses — a strict allowlist, never a heuristic", () => {
  it("accepts an empty filter, the audit-log 'has' term, and the four exact logName terms", () => {
    expect(misses("")).toEqual({ missing: [] });
    expect(misses('logName:"cloudaudit.googleapis.com"')).toEqual({ missing: [] });
    expect(misses("  logName : cloudaudit.googleapis.com \n")).toEqual({ missing: [] });
    const all = GCP_AUDIT_LOGS.map((l, i) => `logName="${full(l, i % 2 ? "/" : "%2F")}"`);
    expect(misses(all.join(" OR "))).toEqual({ missing: [] });
    expect(misses(`(${all.join("\n  OR ")})`)).toEqual({ missing: [] });
    expect(misses(`logName=(${GCP_AUDIT_LOGS.map((l) => `"${full(l)}"`).join(" OR ")})`)).toEqual({
      missing: [],
    });
  });

  it("names the audit logs a well-formed logName filter misses", () => {
    expect(misses(`logName="${full("activity")}" OR logName="${full("policy", "/")}"`)).toEqual({
      missing: ["data_access", "system_event"],
    });
    // Another project's logs are not this project's.
    expect(
      misses(
        GCP_AUDIT_LOGS.map((l) => `logName="projects/other/logs/cloudaudit.googleapis.com%2F${l}"`).join(
          " OR ",
        ),
      ).missing,
    ).toEqual([...GCP_AUDIT_LOGS]);
  });

  it("refuses an implicit AND: a second term on its own line narrows the sink", () => {
    expect(misses('logName:"cloudaudit.googleapis.com"\nseverity>=ERROR')).toEqual({
      missing: [...GCP_AUDIT_LOGS],
      unprovable: UNPROVABLE,
    });
  });

  it("refuses the audit-log hostname in another field, an explicit AND, and a negation", () => {
    for (const f of [
      'protoPayload.serviceName:"cloudaudit.googleapis.com"',
      '"cloudaudit.googleapis.com"',
      'logName:"cloudaudit.googleapis.com" AND severity>=WARNING',
      `NOT logName:"${full("data_access")}"`,
      '-logName:"cloudaudit.googleapis.com"',
      'logName:"cloudaudit.googleapis.com" OR resource.type="gce_instance"',
      'logName!="x"',
      'resource.type="gce_instance"',
    ])
      expect(misses(f).unprovable, f).toBe(UNPROVABLE);
  });
});

describe("sinkVerdict", () => {
  it("accepts a Cloud Storage sink whose filter covers the audit logs", () => {
    expect(sinkVerdict(sink(), PROJECT, GCP_AUDIT_LOGS)).toEqual({ ok: true, bucket: "audit-bucket-01" });
  });

  it("rejects, with the reason, a sink whose filter misses audit logs", () => {
    const v = sinkVerdict(
      sink({ filter: `logName="projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Factivity"` }),
      PROJECT,
      GCP_AUDIT_LOGS,
    );
    expect(v).toEqual({
      ok: false,
      reason:
        'sink "audit-to-gcs": its filter does not include the data_access, system_event, policy audit logs',
    });
  });

  it("rejects a disabled sink, one with active exclusions, and one that is not a bucket", () => {
    expect(sinkVerdict(sink({ disabled: true }), PROJECT, GCP_AUDIT_LOGS)).toMatchObject({
      ok: false,
      reason: /disabled/,
    });
    expect(
      sinkVerdict(sink({ exclusions: [{ name: "drop-da", filter: "x" }] }), PROJECT, GCP_AUDIT_LOGS),
    ).toMatchObject({ ok: false, reason: /exclusion/ });
    expect(
      sinkVerdict(
        sink({ destination: "bigquery.googleapis.com/projects/p/datasets/d" }),
        PROJECT,
        GCP_AUDIT_LOGS,
      ),
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
    // Addendum shards: late entries for the hour, written after it (A<n>:<epoch seconds>).
    expect(
      objectHour("cloudaudit.googleapis.com/activity/2026/11/01/15:00:00_15:59:59_A0:1762016400.json"),
    ).toEqual({ log: "activity", startMs: start, endMs: start + 3_600_000 });
    expect(
      objectHour("cloudaudit.googleapis.com/policy/2026/11/01/15-00-00_15-59-59_A12-1762016400.json")?.log,
    ).toBe("policy");
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

  it("covers from the latest of the sink's creation, its last update and its oldest object", async () => {
    const late = sink({ createTime: "2026-09-15T12:34:00Z", updateTime: "2026-09-15T12:34:00Z" });
    const choice = await chooseSink(sinkCloud({ sinks: [late], firstObject: FIRST }).wire, PROJECT);
    expect(choice).toMatchObject({ coveredFrom: "2026-09-15T12:34:00.000Z" });
  });

  it("covers a sink widened after creation only from the widening (its update time)", async () => {
    const widened = sink({ createTime: "2026-01-01T00:00:00Z", updateTime: "2026-10-20T08:00:00Z" });
    const choice = await chooseSink(sinkCloud({ sinks: [widened], firstObject: FIRST }).wire, PROJECT);
    expect(choice).toMatchObject({ coveredFrom: "2026-10-20T08:00:00.000Z" });
  });

  it("rejects a sink whose last update time is unknown: its history cannot be verified", async () => {
    const unknown = sink({ updateTime: undefined });
    expect(await chooseSink(sinkCloud({ sinks: [unknown], firstObject: FIRST }).wire, PROJECT)).toEqual({
      rejected: ['sink "audit-to-gcs": its last update time is unknown, so its history cannot be verified'],
    });
  });

  it("says so when the project has no sink at all", async () => {
    expect(await chooseSink(sinkCloud({ sinks: [] }).wire, PROJECT)).toEqual({
      rejected: ["the project has no log sink"],
    });
  });
});
