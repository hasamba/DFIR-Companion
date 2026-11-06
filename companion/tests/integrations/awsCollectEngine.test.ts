import { describe, it, expect } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import { collectionPaths, parseManifest } from "../../src/integrations/cloudCollect/collectManifest.js";
import {
  createAwsCollectProvider,
  LOOKUP_NOTICE,
} from "../../src/integrations/cloudCollect/aws/awsCollectProvider.js";
import { NO_TRAIL_REASON } from "../../src/integrations/cloudCollect/aws/awsTrailDiscovery.js";
import type { CollectClock } from "../../src/integrations/cloudCollect/collectRateLimit.js";
import {
  faultFs,
  pipelineImporter,
  tempCase,
  trailRecord,
  type TempCase,
} from "../helpers/cloudCollectFakes.js";
import {
  ACCOUNT,
  awsAccount,
  fakeAwsClients,
  recordJson,
  trailKey,
  trailObject,
  type FakeAwsOptions,
} from "../helpers/awsCollectFakes.js";

// #2313 — the AWS collector end to end on mocks: through the #2311 engine into a temp case, the
// saved objects imported by the existing CloudTrail importer and graded by its existing rules.

const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-01T06:00:00Z" };
let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();

/** A clock that never waits: sleeps advance it and are recorded. */
function fakeClock(): CollectClock & { sleeps: number[] } {
  let t = Date.parse("2026-10-05T00:00:00Z");
  const sleeps: number[] = [];
  return {
    sleeps,
    now: () => t,
    sleep: async (ms) => {
      sleeps.push(ms);
      t += ms;
    },
  };
}

async function collect(t: TempCase, opts: FakeAwsOptions, sources: string[], clock = fakeClock()) {
  const clients = fakeAwsClients(opts);
  const provider = createAwsCollectProvider({
    transport: () => {
      throw new Error("no transport in a mocked test");
    },
    clients: () => clients,
  });
  const session = provider.open(awsAccount());
  const fs = faultFs();
  await createCollection(
    fs,
    session,
    {
      dir: t.dir,
      collectionId: "cc-test-abc123",
      caseId: "c1",
      accountId: "a1",
      accountName: "lab",
      provider: "aws",
      sources,
      window: WINDOW,
      filters: {},
      companionVersion: "0.0.0-test",
    },
    now,
  );
  const cp = await runCollection(
    { fs, session, importer: pipelineImporter(t), sources: provider.sources, now, clock },
    t.dir,
    { resume: false },
  );
  const manifest = parseManifest(await readFile(collectionPaths(t.dir).manifest, "utf8"));
  return { cp, manifest, clients, clock };
}

const ROOT = `AWSLogs/${ACCOUNT}/`;

describe("AWS collection through the engine (#2313)", () => {
  it("saves trail objects byte for byte with version ids, imports and grades them; LookupEvents too", async () => {
    const t = await tempCase();
    const objects = [
      {
        key: trailKey(ROOT, "us-east-1", "2026-10-01T01:00:00Z", 1),
        body: trailObject([trailRecord(3, "StopLogging")]),
        versionId: "v1",
      },
      {
        key: trailKey(ROOT, "us-east-1", "2026-10-01T02:00:00Z", 2),
        body: trailObject([trailRecord(4)]),
        kmsDenied: true,
      },
      {
        key: trailKey(ROOT, "us-east-1", "2026-10-01T03:00:00Z", 3),
        body: trailObject([trailRecord(5)]),
        versionId: "v3",
      },
    ];
    const { cp, manifest, clients } = await collect(
      t,
      {
        trails: [{ Name: "main", S3BucketName: "trail-bucket" }],
        buckets: { "trail-bucket": objects },
        lookup: { "eu-west-1": [[recordJson(9, "DeleteTrail")]] },
      },
      ["s3-trail", "cloudtrail-lookup"],
    );
    expect(cp.status).toBe("complete");
    expect(manifest.header).toMatchObject({
      accountRef: ACCOUNT,
      caller: `arn:aws:iam::${ACCOUNT}:role/collector`,
    });
    const s3Pages = manifest.pages.filter((p) => p.source === "s3-trail");
    expect(s3Pages.map((p) => p.requestParams.versionId)).toEqual(["v1", "v3"]);
    for (const p of manifest.pages) {
      const saved = await readFile(join(collectionPaths(t.dir).pages, p.file));
      expect(createHash("sha256").update(saved).digest("hex")).toBe(p.sha256);
    }
    const firstSaved = await readFile(join(collectionPaths(t.dir).pages, s3Pages[0].file));
    expect(s3Pages[0].file.endsWith(".json.gz")).toBe(true);
    expect(firstSaved.equals(Buffer.from(objects[0].body))).toBe(true);
    // The KMS-denied object: a skip line, and a note on its source in the result.
    const skips = manifest.entries.filter((e) => e.type === "skip");
    expect(skips).toMatchObject([{ source: "s3-trail", item: `s3://trail-bucket/${objects[1].key}` }]);
    const s3Notes = cp.coverage!.find((c) => c.source === "s3-trail")!.notes.join(" ");
    expect(s3Notes).toMatch(/1 item\(s\) could not be read.*kms:Decrypt/);
    expect(cp.coverage!.find((c) => c.source === "cloudtrail-lookup")!.notes).toContain(LOOKUP_NOTICE);
    // Graded by the existing CloudTrail rules, with the page's provenance.
    const state = await t.stateStore.load("c1");
    const stop = state.forensicTimeline.find((e) => /StopLogging/.test(e.description))!;
    expect(["High", "Critical"]).toContain(stop.severity);
    expect(stop.sourceScreenshots.some((s) => s === `evidence/cloud/cc-test-abc123/${s3Pages[0].file}`)).toBe(
      true,
    );
    const del = state.forensicTimeline.find((e) => /DeleteTrail/.test(e.description))!;
    expect(["High", "Critical"]).toContain(del.severity);
    expect(clients.sent.filter((c) => c.op === "GetObject")).toHaveLength(3);
  });

  it("paces LookupEvents at 2 requests a second and backs off on S3 SlowDown", async () => {
    const t = await tempCase();
    const pages = Array.from({ length: 6 }, (_, i) => [recordJson(i + 1)]);
    const { cp, clock } = await collect(
      t,
      {
        trails: [{ Name: "main", S3BucketName: "b" }],
        buckets: {
          b: [
            { key: trailKey(ROOT, "us-east-1", "2026-10-01T01:00:00Z"), body: trailObject([trailRecord(1)]) },
          ],
        },
        lookup: { "eu-west-1": pages },
        slowDowns: 1,
      },
      ["s3-trail", "cloudtrail-lookup"],
    );
    expect(cp.status).toBe("complete");
    expect(clock.sleeps[0]).toBe(1000); // the SlowDown back-off (first retry: 1 s)
    // Six LookupEvents pages in one region at 2 per second: the limiter waited between them.
    expect(clock.sleeps.length).toBeGreaterThanOrEqual(3);
  });

  it("no S3 trail: the S3 source is missing with the fallback reason; LookupEvents still collects", async () => {
    const t = await tempCase();
    const { cp } = await collect(t, { trails: [], buckets: {}, lookup: { "eu-west-1": [[recordJson(1)]] } }, [
      "s3-trail",
      "cloudtrail-lookup",
    ]);
    expect(cp.status).toBe("partial");
    expect(cp.missing).toMatchObject([{ source: "s3-trail" }]);
    expect(cp.missing[0].reason).toContain(NO_TRAIL_REASON);
  });
});

describe("why LookupEvents pages are adapted (#2313)", () => {
  it("the raw LookupEvents envelope grades nothing; the adapted page grades the same record", async () => {
    const t = await tempCase();
    const record = recordJson(3, "StopLogging");
    const raw = join(t.root, "raw-lookup.json");
    await writeFile(
      raw,
      JSON.stringify({ Events: [{ EventId: "e1", EventName: "StopLogging", CloudTrailEvent: record }] }),
    );
    await t.pipeline.importCloudFile("c1", "aws", raw, { label: "raw", idPrefix: "raw", importedAt: now() });
    const before = (await t.stateStore.load("c1")).forensicTimeline.filter((e) =>
      /StopLogging/.test(e.description),
    );
    expect(before.filter((e) => e.severity === "High" || e.severity === "Critical")).toHaveLength(0);
    const adapted = join(t.root, "adapted.json");
    await writeFile(adapted, `{"Records":[${record}]}`);
    await t.pipeline.importCloudFile("c1", "aws", adapted, {
      label: "adapted",
      idPrefix: "ad",
      importedAt: now(),
    });
    const after = (await t.stateStore.load("c1")).forensicTimeline.filter((e) =>
      /StopLogging/.test(e.description),
    );
    expect(after.some((e) => e.severity === "High" || e.severity === "Critical")).toBe(true);
  });
});
