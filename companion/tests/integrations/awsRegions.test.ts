import { describe, expect, it } from "vitest";
import { rm } from "node:fs/promises";
import {
  createAwsCollectProvider,
  lookupRegions,
} from "../../src/integrations/cloudCollect/aws/awsCollectProvider.js";
import {
  fallbackRegions,
  FILTER_NO_LONGER_ENABLED,
  FILTER_REGION_LIST,
  FILTER_REGION_LIST_REASON,
  FILTER_REGIONS,
  FILTER_SKIPPED_BY_CHOICE,
  listEnabledRegions,
  regionScope,
  regionScopeNotes,
} from "../../src/integrations/cloudCollect/aws/awsRegions.js";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import {
  SkippedItemError,
  type CloudCollectSession,
  type CollectPage,
  type CollectRegionListing,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import type { CollectClock } from "../../src/integrations/cloudCollect/collectRateLimit.js";
import {
  ACCOUNT,
  awsAccount,
  fakeAwsClients,
  recordJson,
  trailKey,
  trailObject,
  type FakeAwsOptions,
} from "../helpers/awsCollectFakes.js";
import { faultFs, pipelineImporter, tempCase, trailRecord } from "../helpers/cloudCollectFakes.js";

// #2363 — the regions an AWS collection walks: listed with ec2:DescribeRegions (opt-in regions the
// account enabled included), minus what the analyst unticked; the default list, disclosed, without
// the permission; the scope decided at start and replayed from the manifest header on resume.

const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-01T06:00:00Z" };
const SETTINGS = { authMode: "access-key" as const, region: "eu-west-1" };
const ENABLED = [
  { RegionName: "us-east-1", OptInStatus: "opt-in-not-required" },
  { RegionName: "eu-west-1", OptInStatus: "opt-in-not-required" },
  { RegionName: "af-south-1", OptInStatus: "opted-in" },
  { RegionName: "ap-east-1", OptInStatus: "opted-in" },
  { RegionName: "me-south-1", OptInStatus: "not-opted-in" },
];

function open(opts: FakeAwsOptions) {
  const clients = fakeAwsClients(opts);
  const provider = createAwsCollectProvider({
    transport: () => {
      throw new Error("no transport in a mocked test");
    },
    clients: () => clients,
  });
  return { clients, provider, session: provider.open(awsAccount()) };
}

async function lookupWalk(s: CloudCollectSession) {
  const pages: CollectPage[] = [];
  const skipped: SkippedItemError[] = [];
  let token: string | undefined;
  for (let i = 0; i < 100; i++) {
    try {
      const page = await s.fetchPage({
        source: "cloudtrail-lookup",
        subWindowId: "cloudtrail-lookup:0",
        window: WINDOW,
        ...(token ? { pageToken: token } : {}),
      });
      pages.push(page);
      token = page.nextPageToken;
    } catch (err) {
      if (!(err instanceof SkippedItemError)) throw err;
      skipped.push(err);
      token = err.nextPageToken;
    }
    if (!token) return { pages, skipped };
  }
  throw new Error("walk did not end");
}

const lookupRegionsSent = (sent: { op: string; region?: string }[]) => [
  ...new Set(sent.filter((c) => c.op === "LookupEvents").map((c) => c.region)),
];

describe("listing the enabled regions (#2363)", () => {
  it("lists enabled regions with DescribeRegions — opt-in regions turned on included, account region first", async () => {
    const { clients } = open({ trails: [], buckets: {}, enabledRegions: ENABLED });
    const listing = await listEnabledRegions(clients.ec2, SETTINGS);
    expect(listing).toEqual({
      regions: ["eu-west-1", "af-south-1", "ap-east-1", "us-east-1"],
      home: "eu-west-1",
      source: "ec2:DescribeRegions",
    });
    const call = clients.sent.find((c) => c.op === "DescribeRegions");
    expect(call?.input).toEqual({ AllRegions: false });
  });

  it("without ec2:DescribeRegions falls back to the default list and says why", async () => {
    const { clients } = open({ trails: [], buckets: {}, enabledRegions: "denied" });
    const listing = await listEnabledRegions(clients.ec2, SETTINGS);
    expect(listing.source).toBe("fallback");
    expect(listing.regions).toEqual(fallbackRegions(SETTINGS));
    expect(listing.regions).toEqual(lookupRegions(SETTINGS));
    expect(listing.reason).toBe("UnauthorizedOperation (HTTP 403)");
    expect(listing.note).toMatch(/could not be listed \(UnauthorizedOperation \(HTTP 403\)\)/);
    expect(listing.note).toMatch(/grant ec2:DescribeRegions/);
    expect(listing.note).toMatch(/opt-in region .* may be missing/);
  });

  it("an empty answer is a fallback too, never an empty walk", async () => {
    const { clients } = open({ trails: [], buckets: {}, enabledRegions: [] });
    const listing = await listEnabledRegions(clients.ec2, SETTINGS);
    expect(listing.source).toBe("fallback");
    expect(listing.regions.length).toBeGreaterThan(1);
  });

  it("a cancelled run is not turned into a fallback", async () => {
    const ac = new AbortController();
    ac.abort();
    const ec2 = {
      send: async () => {
        throw Object.assign(new Error("aborted"), { name: "AbortError" });
      },
    };
    await expect(listEnabledRegions(ec2, SETTINGS, ac.signal)).rejects.toThrow(/abort/i);
  });
});

describe("the region scope a start records (#2363)", () => {
  const listed: CollectRegionListing = {
    regions: ["eu-west-1", "af-south-1", "us-east-1"],
    home: "eu-west-1",
    source: "ec2:DescribeRegions",
  };
  const fallback: CollectRegionListing = {
    regions: ["eu-west-1", "us-east-1", "us-west-2"],
    home: "eu-west-1",
    source: "fallback",
    reason: "UnauthorizedOperation (HTTP 403)",
    note: "n",
  };

  it("no choice: every listed region is walked, nothing skipped", () => {
    expect(regionScope(listed, {})).toEqual({
      [FILTER_REGIONS]: "eu-west-1,af-south-1,us-east-1",
      [FILTER_REGION_LIST]: "ec2:DescribeRegions",
    });
  });

  it("only what the analyst unticked is 'skipped by choice'", () => {
    const f = regionScope(listed, { regions: ["eu-west-1", "us-east-1"], excludeRegions: ["af-south-1"] });
    expect(f[FILTER_REGIONS]).toBe("eu-west-1,us-east-1");
    expect(f[FILTER_SKIPPED_BY_CHOICE]).toBe("af-south-1");
  });

  it("picker showed the fallback, start lists more: a newly listed region is walked, not called skipped", () => {
    const f = regionScope(listed, { regions: ["eu-west-1"], excludeRegions: ["us-east-1"] });
    expect(f[FILTER_REGIONS]).toBe("eu-west-1,af-south-1");
    expect(f[FILTER_SKIPPED_BY_CHOICE]).toBe("us-east-1");
  });

  it("picker listed an opt-in region, start falls back: the ticked region is kept, the fallback recorded", () => {
    const f = regionScope(fallback, { regions: ["eu-west-1", "af-south-1"], excludeRegions: ["us-west-2"] });
    expect(f[FILTER_REGIONS]).toBe("eu-west-1,us-east-1,af-south-1");
    expect(f[FILTER_REGION_LIST]).toBe("fallback");
    expect(f[FILTER_REGION_LIST_REASON]).toBe("UnauthorizedOperation (HTTP 403)");
    expect(f[FILTER_SKIPPED_BY_CHOICE]).toBe("us-west-2");
  });

  it("a ticked region a successful listing no longer names is not called, and is named", () => {
    const f = regionScope(listed, { regions: ["eu-west-1", "ap-east-1"] });
    expect(f[FILTER_REGIONS]).toBe("eu-west-1,af-south-1,us-east-1");
    expect(f[FILTER_NO_LONGER_ENABLED]).toBe("ap-east-1");
  });

  it("refuses a scope with no region left", () => {
    expect(() => regionScope(listed, { excludeRegions: ["eu-west-1", "af-south-1", "us-east-1"] })).toThrow(
      /No region is left/,
    );
  });

  it("result sentences name skipped, no-longer-enabled and the fallback", () => {
    const notes = regionScopeNotes({
      [FILTER_REGIONS]: "eu-west-1",
      [FILTER_SKIPPED_BY_CHOICE]: "us-east-1,ap-east-1",
      [FILTER_NO_LONGER_ENABLED]: "me-south-1",
      [FILTER_REGION_LIST]: "fallback",
      [FILTER_REGION_LIST_REASON]: "UnauthorizedOperation (HTTP 403)",
    });
    expect(notes.join("\n")).toMatch(/skipped by choice \(unticked\): us-east-1, ap-east-1/);
    expect(notes.join("\n")).toMatch(/not collected: me-south-1/);
    expect(notes.join("\n")).toMatch(/could not be listed \(UnauthorizedOperation/);
    expect(regionScopeNotes({})).toEqual([]);
  });
});

describe("the AWS session walks the recorded scope (#2363)", () => {
  it("walks an enabled opt-in region, never calls an unticked one, and names it on every page", async () => {
    const { clients, session } = open({
      trails: [],
      buckets: {},
      enabledRegions: ENABLED,
      lookup: { "af-south-1": [[recordJson(1)]], "eu-west-1": [[recordJson(2)]] },
    });
    const filters = await session.prepareFilters!({
      regions: ["eu-west-1", "af-south-1", "ap-east-1"],
      excludeRegions: ["us-east-1"],
    });
    expect(filters[FILTER_REGIONS]).toBe("eu-west-1,af-south-1,ap-east-1");
    const { pages } = await lookupWalk(session);
    expect(lookupRegionsSent(clients.sent)).toEqual(["eu-west-1", "af-south-1", "ap-east-1"]);
    expect(pages.map((p) => p.requestParams.region)).toContain("af-south-1");
    for (const p of pages) expect(p.note).toMatch(/skipped by choice \(unticked\): us-east-1/);
    expect(await session.partitionValues!("cloudtrail-lookup")).toEqual([
      "eu-west-1",
      "af-south-1",
      "ap-east-1",
    ]);
  });

  it("without the permission walks the default list and discloses it on the pages", async () => {
    const { clients, session } = open({ trails: [], buckets: {}, enabledRegions: "denied" });
    await session.prepareFilters!({});
    const { pages } = await lookupWalk(session);
    expect(lookupRegionsSent(clients.sent)).toEqual(lookupRegions(SETTINGS));
    expect(pages[pages.length - 1].note).toMatch(
      /could not be listed \(UnauthorizedOperation \(HTTP 403\)\)/,
    );
  });

  it("a collection without a recorded scope (started before #2363) walks the old list", async () => {
    const { clients, session } = open({ trails: [], buckets: {}, enabledRegions: ENABLED });
    session.applyFilters!({});
    await lookupWalk(session);
    expect(lookupRegionsSent(clients.sent)).toEqual(lookupRegions(SETTINGS));
    expect(clients.sent.some((c) => c.op === "DescribeRegions")).toBe(false);
  });

  it("S3: trails are asked for in the walked regions; an unticked folder is dropped, a not-enabled one kept", async () => {
    const root = `trail-bucket/AWSLogs/${ACCOUNT}/`;
    const at = "2026-10-01T01:00:00Z";
    const keys = ["eu-west-1", "us-east-1", "me-south-1"].map((r) => trailKey(root, r, at));
    const { clients, session } = open({
      trails: [{ Name: "main", S3BucketName: "trail-bucket", S3KeyPrefix: "trail-bucket" }],
      buckets: { "trail-bucket": keys.map((key) => ({ key, body: trailObject([trailRecord(1)]) })) },
      enabledRegions: ENABLED,
    });
    await session.prepareFilters!({ excludeRegions: ["us-east-1"] });
    expect(await session.partitionValues!("s3-trail")).toEqual(["eu-west-1", "me-south-1"]);
    const asked = [...new Set(clients.sent.filter((c) => c.op === "DescribeTrails").map((c) => c.region))];
    expect(asked).toEqual(["eu-west-1", "af-south-1", "ap-east-1"]);
  });

  it("S3: unticking every region the trail holds says so instead of collecting", async () => {
    const root = `trail-bucket/AWSLogs/${ACCOUNT}/`;
    const key = trailKey(root, "us-east-1", "2026-10-01T01:00:00Z");
    const { session } = open({
      trails: [{ Name: "main", S3BucketName: "trail-bucket", S3KeyPrefix: "trail-bucket" }],
      buckets: { "trail-bucket": [{ key, body: trailObject([trailRecord(1)]) }] },
      enabledRegions: ENABLED,
    });
    await session.prepareFilters!({ excludeRegions: ["us-east-1"] });
    await expect(session.partitionValues!("s3-trail")).rejects.toThrow(/skipped by choice: us-east-1/);
  });
});

describe("start and resume keep the chosen regions (#2363)", () => {
  function fakeClock(): CollectClock {
    let t = Date.parse("2026-10-05T00:00:00Z");
    return { now: () => t, sleep: async (ms) => void (t += ms) };
  }
  let tick = 0;
  const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();

  it("the header records the scope and a resumed session walks it without listing again", async () => {
    const t = await tempCase();
    try {
      const opts: FakeAwsOptions = {
        trails: [],
        buckets: {},
        enabledRegions: ENABLED,
        lookup: { "af-south-1": [[recordJson(1)]] },
        lookupDnsFail: { region: "af-south-1", page: 0, times: 1 },
      };
      const first = open(opts);
      const fs = faultFs();
      const filters = await first.session.prepareFilters!({ excludeRegions: ["us-east-1", "ap-east-1"] });
      await createCollection(
        fs,
        first.session,
        {
          dir: t.dir,
          collectionId: "cc-test-abc123",
          caseId: "c1",
          accountId: "a1",
          accountName: "lab",
          provider: "aws",
          sources: ["cloudtrail-lookup"],
          window: WINDOW,
          filters,
          companionVersion: "0.0.0-test",
        },
        now,
      );
      const deps = (s: CloudCollectSession) => ({
        fs,
        session: s,
        importer: pipelineImporter(t),
        sources: first.provider.sources,
        now,
        clock: fakeClock(),
      });
      const cp1 = await runCollection(deps(first.session), t.dir, { resume: false });
      expect(cp1.status).not.toBe("complete"); // af-south-1 failed DNS once: resumable
      expect(lookupRegionsSent(first.clients.sent)).toEqual(["eu-west-1", "af-south-1"]);

      // A resume opens a FRESH session with an account that now lists every region: it must still
      // walk the regions recorded at start, and never list again.
      const second = open({ ...opts, enabledRegions: [...ENABLED, { RegionName: "us-west-2" }] });
      const cp2 = await runCollection(deps(second.session), t.dir, { resume: true });
      expect(cp2.status).toBe("complete");
      expect(second.clients.sent.some((c) => c.op === "DescribeRegions")).toBe(false);
      expect(
        lookupRegionsSent(second.clients.sent).every((r) => ["eu-west-1", "af-south-1"].includes(r!)),
      ).toBe(true);
      const notes = cp2.coverage?.find((c) => c.source === "cloudtrail-lookup")?.notes.join("\n") ?? "";
      expect(notes).toMatch(/skipped by choice \(unticked\): ap-east-1, us-east-1/);
    } finally {
      await rm(t.root, { recursive: true, force: true });
    }
  });
});
