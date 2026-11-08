import { describe, it, expect } from "vitest";
import {
  AWS_COLLECT_SOURCES,
  createAwsCollectProvider,
  LOOKUP_NOTICE,
  lookupRegions,
} from "../../src/integrations/cloudCollect/aws/awsCollectProvider.js";
import { NO_TRAIL_REASON } from "../../src/integrations/cloudCollect/aws/awsTrailDiscovery.js";
import { deliveredAt, trailDays } from "../../src/integrations/cloudCollect/aws/awsTrailObjects.js";
import {
  adaptLookupEvents,
  LOOKUP_ADAPTATION,
} from "../../src/integrations/cloudCollect/aws/awsLookupEvents.js";
import {
  SkippedItemError,
  type CloudCollectSession,
  type CollectPage,
  type CollectPageRequest,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import { precheckSource } from "../../src/integrations/cloudCollect/collectCoverage.js";
import {
  ACCOUNT,
  awsAccount,
  fakeAwsClients,
  ORG,
  recordJson,
  trailKey,
  trailObject,
  type FakeAwsOptions,
} from "../helpers/awsCollectFakes.js";
import { trailRecord } from "../helpers/cloudCollectFakes.js";

// #2313 — the AWS CloudTrail collector on mocked STS / CloudTrail / S3 (no real AWS is reached).

const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-01T06:00:00Z" };

function session(opts: FakeAwsOptions) {
  const clients = fakeAwsClients(opts);
  const provider = createAwsCollectProvider({
    transport: () => {
      throw new Error("no transport in a mocked test");
    },
    clients: () => clients,
  });
  return { clients, session: provider.open(awsAccount()) };
}

type Outcome = { page: CollectPage } | { skipped: SkippedItemError };

/** Every page (and skip) of one source, the way the engine walks it. */
async function walk(s: CloudCollectSession, source: string, extra: Partial<CollectPageRequest> = {}) {
  const out: Outcome[] = [];
  let token: string | undefined;
  for (let i = 0; i < 200; i++) {
    try {
      const page = await s.fetchPage({
        source,
        subWindowId: `${source}:0`,
        window: WINDOW,
        ...extra,
        ...(token ? { pageToken: token } : {}),
      });
      out.push({ page });
      token = page.nextPageToken;
    } catch (err) {
      if (!(err instanceof SkippedItemError)) throw err;
      out.push({ skipped: err });
      token = err.nextPageToken;
    }
    if (!token) return out;
  }
  throw new Error("walk did not end");
}

const keysOf = (out: Outcome[]) => out.flatMap((o) => ("page" in o ? [o.page.requestParams.key] : []));

describe("S3 trail discovery and paths (#2313)", () => {
  it("finds an organization trail's account folder and never reads another member account", async () => {
    const root = `org-logs/AWSLogs/${ORG}/${ACCOUNT}/`;
    const other = `org-logs/AWSLogs/${ORG}/210987654321/`;
    const k1 = trailKey(root, "us-east-1", "2026-10-01T01:05:00Z");
    const k2 = trailKey(root, "eu-west-1", "2026-10-01T02:10:00Z");
    const { session: s, clients } = session({
      trails: [
        { Name: "org-trail", S3BucketName: "org-bucket", S3KeyPrefix: "org-logs", IsOrganizationTrail: true },
      ],
      buckets: {
        "org-bucket": [
          { key: k1, body: trailObject([trailRecord(1)]) },
          { key: k2, body: trailObject([trailRecord(2)]) },
          { key: trailKey(other, "us-east-1", "2026-10-01T01:05:00Z"), body: trailObject([trailRecord(3)]) },
        ],
      },
    });
    const out = await walk(s, "s3-trail");
    expect(keysOf(out)).toEqual([k2, k1]); // eu-west-1 sorts before us-east-1
    expect(out.every((o) => "page" in o && o.page.requestParams.organizationTrail === "yes")).toBe(true);
    expect(clients.sent.some((c) => String(c.input.Prefix ?? "").includes("210987654321"))).toBe(false);
    expect(await s.partitionValues!("s3-trail")).toEqual(["eu-west-1", "us-east-1"]);
  });

  // #2384: the walk is a fixed list of folders (region × day), so each page says how far through it is.
  it("each page states its folder position in the fixed walk (#2384)", async () => {
    const root = `AWSLogs/${ACCOUNT}/`;
    const k1 = trailKey(root, "us-east-1", "2026-10-01T01:05:00Z");
    const k2 = trailKey(root, "eu-west-1", "2026-10-01T02:10:00Z");
    const { session: s } = session({
      trails: [{ Name: "main", S3BucketName: "b" }],
      buckets: {
        b: [
          { key: k1, body: trailObject([trailRecord(1)]) },
          { key: k2, body: trailObject([trailRecord(2)]) },
        ],
      },
    });
    const out = await walk(s, "s3-trail");
    // Two regions × two days (the window's day plus the delivery horizon), region first.
    expect(out.map((o) => ("page" in o ? o.page.walk : undefined))).toEqual([
      { at: 0, of: 4 },
      { at: 2, of: 4 },
    ]);
  });

  it("an account trail without a prefix, a shadow trail deduped; objects outside the window are left", async () => {
    const root = `AWSLogs/${ACCOUNT}/`;
    const inside = trailKey(root, "us-east-1", "2026-10-01T05:59:00Z");
    const slack = trailKey(root, "us-east-1", "2026-10-01T06:40:00Z"); // delivered after the end, within slack
    const late = trailKey(root, "us-east-1", "2026-10-02T07:30:00Z"); // past the 24 h horizon
    const early = trailKey(root, "us-east-1", "2026-09-30T23:50:00Z");
    const { session: s } = session({
      trails: [
        { Name: "main", S3BucketName: "acct-bucket" },
        { Name: "main", S3BucketName: "acct-bucket" },
      ],
      buckets: {
        "acct-bucket": [early, inside, slack, late].map((key, i) => ({
          key,
          body: trailObject([trailRecord(i)]),
        })),
      },
    });
    expect(keysOf(await walk(s, "s3-trail"))).toEqual([inside, slack]);
  });

  it("asks DescribeTrails in every region: a single-region trail homed elsewhere is found", async () => {
    const root = `AWSLogs/${ACCOUNT}/`;
    const key = trailKey(root, "us-east-1", "2026-10-01T01:00:00Z");
    const { session: s, clients } = session({
      trails: [],
      trailsByRegion: { "us-east-2": "off", "us-east-1": [{ Name: "regional", S3BucketName: "b" }] },
      buckets: { b: [{ key, body: trailObject([trailRecord(1)]) }] },
    });
    expect(keysOf(await walk(s, "s3-trail"))).toEqual([key]);
    const asked = clients.sent.filter((c) => c.op === "DescribeTrails").map((c) => c.region);
    expect(asked[0]).toBe("eu-west-1"); // the account's own region first
    expect(asked).toContain("us-east-2"); // not enabled: passed over, not fatal
  });

  it("a DNS failure during discovery is reported, never read as a disabled region", async () => {
    const { session: s } = session({
      trails: [],
      trailsByRegion: { "us-east-1": "dns", "eu-west-1": [{ Name: "t", S3BucketName: "b" }] },
      buckets: { b: [] },
    });
    await expect(s.fetchPage({ source: "s3-trail", subWindowId: "x", window: WINDOW })).rejects.toThrow(
      /EAI_AGAIN/,
    );
  });

  it("a region that is not enabled is named on the pages, not dropped silently", async () => {
    const root = `AWSLogs/${ACCOUNT}/`;
    const key = trailKey(root, "us-east-1", "2026-10-01T01:00:00Z");
    const { session: s } = session({
      trails: [],
      trailsByRegion: { "us-east-2": "off", "us-east-1": [{ Name: "t", S3BucketName: "b" }] },
      buckets: { b: [{ key, body: trailObject([trailRecord(1)]) }] },
    });
    const page = await s.fetchPage({ source: "s3-trail", subWindowId: "x", window: WINDOW });
    expect(page.requestParams.regionsNotEnabled).toBe("us-east-2");
  });

  it("takes a file delivered 3 h after the window end, and the starting minute of a mid-minute start", async () => {
    const root = `AWSLogs/${ACCOUNT}/`;
    const startMinute = trailKey(root, "us-east-1", "2026-10-01T00:10:00Z", 1);
    const late = trailKey(root, "us-east-1", "2026-10-01T09:00:00Z", 2);
    const beyond = trailKey(root, "us-east-1", "2026-10-02T06:01:00Z", 3); // > 24 h after the end
    const { session: s } = session({
      trails: [{ Name: "main", S3BucketName: "b" }],
      buckets: {
        b: [startMinute, late, beyond].map((key) => ({ key, body: trailObject([trailRecord(1)]) })),
      },
    });
    const window = { start: "2026-10-01T00:10:30Z", end: WINDOW.end };
    expect(keysOf(await walk(s, "s3-trail", { window }))).toEqual([startMinute, late]);
  });

  it("walks a truncated listing with StartAfter and keeps the S3 version id", async () => {
    const root = `AWSLogs/${ACCOUNT}/`;
    const objects = [1, 2, 3, 4, 5].map((n) => ({
      key: trailKey(root, "us-east-1", `2026-10-01T0${n}:00:00Z`, n),
      body: trailObject([trailRecord(n)]),
      versionId: `v${n}-3HL4kqtJlcpXroDTDmJ`,
    }));
    const { session: s } = session({
      trails: [{ Name: "main", S3BucketName: "b" }],
      buckets: { b: objects },
      listPageSize: 2,
    });
    const out = await walk(s, "s3-trail");
    expect(keysOf(out)).toEqual(objects.map((o) => o.key));
    const pages = out.map((o) => ("page" in o ? o.page : null)!);
    expect(pages.map((p) => p.requestParams.versionId)).toEqual(objects.map((o) => o.versionId));
    expect(pages.every((p) => p.extension === "json.gz" && p.recordCount === 1)).toBe(true);
    expect(Buffer.from(pages[2].body).equals(Buffer.from(objects[2].body))).toBe(true); // byte for byte
    expect(pages.at(-1)!.nextPageToken).toBeUndefined();
  });

  it("a token from an earlier session resumes after its key", async () => {
    const root = `AWSLogs/${ACCOUNT}/`;
    const objects = [1, 2, 3].map((n) => ({
      key: trailKey(root, "us-east-1", `2026-10-01T0${n}:00:00Z`, n),
      body: trailObject([trailRecord(n)]),
    }));
    const opts = { trails: [{ Name: "main", S3BucketName: "b" }], buckets: { b: objects } };
    const first = await session(opts).session.fetchPage({
      source: "s3-trail",
      subWindowId: "x",
      window: WINDOW,
    });
    const second = await session(opts).session.fetchPage({
      source: "s3-trail",
      subWindowId: "x",
      window: WINDOW,
      pageToken: first.nextPageToken,
    });
    expect(second.requestParams.key).toBe(objects[1].key);
  });

  it("a KMS-denied object is a skip naming the object and kms:Decrypt; the walk goes on", async () => {
    const root = `AWSLogs/${ACCOUNT}/`;
    const keys = [1, 2, 3].map((n) => trailKey(root, "us-east-1", `2026-10-01T0${n}:00:00Z`, n));
    const { session: s } = session({
      trails: [{ Name: "main", S3BucketName: "b" }],
      buckets: {
        b: keys.map((key, i) => ({ key, body: trailObject([trailRecord(i)]), kmsDenied: i === 1 })),
      },
    });
    const out = await walk(s, "s3-trail");
    expect(keysOf(out)).toEqual([keys[0], keys[2]]);
    const skip = out.find((o) => "skipped" in o) as { skipped: SkippedItemError };
    expect(skip.skipped.item).toBe(`s3://b/${keys[1]}`);
    expect(skip.skipped.reason).toMatch(/AccessDenied \(HTTP 403\).*kms:Decrypt/);
  });

  it("no trail delivering to S3 fails the source with the fallback hint", async () => {
    const { session: s } = session({ trails: [], buckets: {} });
    await expect(s.fetchPage({ source: "s3-trail", subWindowId: "x", window: WINDOW })).rejects.toThrow(
      NO_TRAIL_REASON,
    );
    expect(NO_TRAIL_REASON).toMatch(/90 days, management events only/);
  });

  it("an empty window closes with one 0-record page that records the listing, and no token (#2352)", async () => {
    const root = `AWSLogs/${ACCOUNT}/`;
    const outside = trailKey(root, "us-east-1", "2026-10-05T01:00:00Z"); // the folders exist, not this window
    const { session: s, clients } = session({
      trails: [{ Name: "main", S3BucketName: "b" }],
      buckets: { b: [{ key: outside, body: trailObject([trailRecord(1)]) }] },
    });
    const out = await walk(s, "s3-trail");
    expect(out).toHaveLength(1);
    const page = (out[0] as { page: CollectPage }).page;
    expect(Buffer.from(page.body).toString("utf8")).toBe('{"Records":[]}');
    expect(page.extension).toBe("json");
    expect(page.recordCount).toBe(0);
    expect(page.nextPageToken).toBeUndefined();
    expect(page.requestParams).toMatchObject({ api: "s3:ListObjectsV2", emptyWindow: "yes", bucket: "b" });
    expect(page.requestParams.prefixes).toContain(`${root}CloudTrail/us-east-1/2026/10/01/`);
    expect(page.requestParams.adaptation).toMatch(/not an S3 object/);
    expect(clients.sent.some((c) => c.op === "GetObject")).toBe(false);
  });

  it("a token that finds nothing still fails: only a first page may close empty (#2352)", async () => {
    const root = `AWSLogs/${ACCOUNT}/`;
    const { session: s } = session({
      trails: [{ Name: "main", S3BucketName: "b" }],
      buckets: { b: [{ key: trailKey(root, "us-east-1", "2026-10-05T01:00:00Z"), body: trailObject([]) }] },
    });
    const token = JSON.stringify({ b: "b", p: root, r: "us-east-1", d: "2026/10/01", k: `${root}zzz` });
    await expect(
      s.fetchPage({ source: "s3-trail", subWindowId: "x", window: WINDOW, pageToken: token }),
    ).rejects.toThrow(/no CloudTrail file/);
  });

  it("parses delivery times and the days a window touches", () => {
    expect(deliveredAt(`x/${ACCOUNT}_CloudTrail_us-east-1_20261001T1005Z_abc.json.gz`)).toBe(
      Date.parse("2026-10-01T10:05:00Z"),
    );
    expect(deliveredAt("x/digest.json.gz")).toBeNull();
    expect(trailDays({ start: "2026-10-01T10:00:00Z", end: "2026-10-02T23:30:00Z" })).toEqual([
      "2026/10/01",
      "2026/10/02",
      "2026/10/03",
    ]);
  });
});

describe("LookupEvents fallback (#2313)", () => {
  it("adapts the events' own record strings verbatim into a Records document", () => {
    const raw = recordJson(1);
    const adapted = adaptLookupEvents([{ CloudTrailEvent: raw }, { CloudTrailEvent: "not json" }, {}]);
    expect(adapted.body).toBe(`{"Records":[${raw}]}`);
    expect(adapted).toMatchObject({ kept: 1, dropped: 2 });
  });

  it("walks the regions, skips one that is not enabled and passes empty ones", async () => {
    const regions = lookupRegions(awsAccount().settings as never);
    expect(regions[0]).toBe("eu-west-1");
    expect(new Set(regions).size).toBe(regions.length);
    const lookup: FakeAwsOptions["lookup"] = {
      "eu-west-1": [[recordJson(1), recordJson(2)], [recordJson(3)]],
      "us-east-2": "off",
      "ap-southeast-2": [[recordJson(4)]],
    };
    const { session: s, clients } = session({ trails: [], buckets: {}, lookup });
    const out = await walk(s, "cloudtrail-lookup");
    const pages = out.flatMap((o) => ("page" in o ? [o.page] : []));
    expect(pages.map((p) => [p.requestParams.region, p.recordCount])).toEqual([
      ["eu-west-1", 2],
      ["eu-west-1", 1],
      ["ap-southeast-2", 1],
    ]);
    expect(pages.every((p) => p.requestParams.adaptation === LOOKUP_ADAPTATION)).toBe(true);
    expect(out.filter((o) => "skipped" in o).map((o) => o.skipped.item)).toEqual(["region us-east-2"]);
    expect(pages[2].requestParams.emptyRegions?.split(",")).toContain("us-west-2");
    const asked = clients.sent.filter((c) => c.op === "LookupEvents").map((c) => c.region);
    expect(new Set(asked)).toEqual(new Set(regions));
    expect(
      clients.sent.filter((c) => c.op === "LookupEvents").every((c) => c.input.StartTime instanceof Date),
    ).toBe(true);
  });

  it("only one region when the engine asks for a region partition", async () => {
    const { session: s, clients } = session({
      trails: [],
      buckets: {},
      lookup: { "us-west-2": [[recordJson(1)]] },
    });
    const out = await walk(s, "cloudtrail-lookup", { partition: { region: "us-west-2" } });
    expect(out).toHaveLength(1);
    expect(clients.sent.filter((c) => c.op === "LookupEvents").map((c) => c.region)).toEqual(["us-west-2"]);
  });

  it("declares the #2312 limits and always shows the 90-day notice in the pre-check", () => {
    const lookup = AWS_COLLECT_SOURCES.find((x) => x.id === "cloudtrail-lookup")!;
    expect(lookup).toMatchObject({
      streamKind: "aws",
      minWindowMs: 1000,
      partition: { key: "region" },
      rateLimit: { requests: 2, perMs: 1000, perPartitionKey: "region" },
      overlapMs: 15 * 60_000,
      retention: { minDays: 90 },
    });
    const pre = precheckSource(lookup, WINDOW, Date.parse("2026-10-02T00:00:00Z"));
    expect(pre.warnings).toContain(LOOKUP_NOTICE);
    expect(LOOKUP_NOTICE).toMatch(/90 days of management events only/);
    expect(AWS_COLLECT_SOURCES.map((x) => x.id)).toEqual([
      "s3-trail",
      "cloudtrail-lookup",
      "guardduty-findings",
    ]);
  });
});
