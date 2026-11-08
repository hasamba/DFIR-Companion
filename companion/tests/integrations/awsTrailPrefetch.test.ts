import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { createAwsCollectProvider } from "../../src/integrations/cloudCollect/aws/awsCollectProvider.js";
import type { TrailWalkOptions } from "../../src/integrations/cloudCollect/aws/awsTrailObjects.js";
import {
  MAX_PREFETCH_HELD_BYTES,
  MAX_PREFETCH_OBJECT_BYTES,
  PREFETCH_DEPTH,
  pickPrefetch,
} from "../../src/integrations/cloudCollect/aws/awsTrailPrefetch.js";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import { collectionPaths, parseManifest } from "../../src/integrations/cloudCollect/collectManifest.js";
import {
  RateLimitedError,
  SkippedItemError,
  type CloudCollectSession,
  type CollectPage,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import type { CollectClock } from "../../src/integrations/cloudCollect/collectRateLimit.js";
import { faultFs, pipelineImporter, tempCase, trailRecord } from "../helpers/cloudCollectFakes.js";
import {
  ACCOUNT,
  awsAccount,
  fakeAwsClients,
  trailKey,
  trailObject,
  type FakeAwsOptions,
  type FakeObject,
} from "../helpers/awsCollectFakes.js";

// #2380 — the S3 trail walk reuses its listings and downloads a few objects ahead, while the engine
// still commits one page at a time in order. Everything here runs on the fake S3 (no real AWS).

const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-01T06:00:00Z" };
const ROOT = `AWSLogs/${ACCOUNT}/`;
const OLD: TrailWalkOptions = { prefetchDepth: 0, reuseListings: false };
const NO_PREFETCH: TrailWalkOptions = { prefetchDepth: 0 };

/** `n` trail objects in us-east-1, one a minute from 00:00 on the window's day. */
function objects(n: number, over: (i: number) => Partial<FakeObject> = () => ({})): FakeObject[] {
  return Array.from({ length: n }, (_, i) => ({
    key: trailKey(ROOT, "us-east-1", new Date(Date.parse(WINDOW.start) + i * 60_000).toISOString(), i + 1),
    body: trailObject([trailRecord(i + 1)]),
    versionId: `v${i + 1}`,
    ...over(i),
  }));
}

function session(opts: Omit<FakeAwsOptions, "trails">, trailWalk?: TrailWalkOptions) {
  const clients = fakeAwsClients({ trails: [{ Name: "main", S3BucketName: "b" }], ...opts });
  const provider = createAwsCollectProvider({
    transport: () => {
      throw new Error("no transport in a mocked test");
    },
    clients: () => clients,
    ...(trailWalk ? { trailWalk } : {}),
  });
  return { clients, provider, session: provider.open(awsAccount()) };
}

type Outcome = { page: CollectPage } | { skipped: SkippedItemError };

/** Every page of the S3 source the way the engine asks: one at a time, following the tokens. */
async function walk(s: CloudCollectSession, signal?: AbortSignal, retryThrottle = false): Promise<Outcome[]> {
  const out: Outcome[] = [];
  let token: string | undefined;
  for (let i = 0; i < 500; i++) {
    try {
      const page = await s.fetchPage({
        source: "s3-trail",
        subWindowId: "s3-trail:0",
        window: WINDOW,
        ...(signal ? { signal } : {}),
        ...(token ? { pageToken: token } : {}),
      });
      out.push({ page });
      token = page.nextPageToken;
    } catch (err) {
      if (retryThrottle && err instanceof RateLimitedError) continue; // the engine's retry, simplified
      if (!(err instanceof SkippedItemError)) throw err;
      out.push({ skipped: err });
      token = err.nextPageToken;
    }
    if (!token) return out;
  }
  throw new Error("walk did not end");
}

const pagesOf = (out: Outcome[]) => out.flatMap((o) => ("page" in o ? [o.page] : []));
/** What a page records about its object: key, version, token and the bytes' SHA-256. */
const recordOf = (p: CollectPage) => ({
  key: p.requestParams.key,
  versionId: p.requestParams.versionId,
  token: p.nextPageToken,
  sha256: createHash("sha256").update(p.body).digest("hex"),
});
const walkLists = (sent: { op: string; input: Record<string, unknown> }[]) =>
  sent.filter((c) => c.op === "ListObjectsV2" && !c.input.Delimiter);

describe("listing reuse (#2380)", () => {
  it("lists a folder once per 1,000-key page, not once per object, and returns the same pages", async () => {
    const objs = objects(25);
    const reuse = session({ buckets: { b: objs }, listPageSize: 10 }, NO_PREFETCH);
    const old = session({ buckets: { b: objs }, listPageSize: 10 }, OLD);
    const a = pagesOf(await walk(reuse.session)).map(recordOf);
    const b = pagesOf(await walk(old.session)).map(recordOf);
    expect(a).toEqual(b);
    expect(a.map((r) => r.key)).toEqual(objs.map((o) => o.key));
    // The window's day: three listing pages of 10, 10, 5; the day after (delivery horizon): one.
    expect(walkLists(reuse.clients.sent)).toHaveLength(4);
    expect(walkLists(old.clients.sent).length).toBeGreaterThanOrEqual(25);
  });

  it("an exact page-size multiple and an object outside the window cost no extra listing", async () => {
    const inWindow = objects(20);
    // Delivered past the window end plus the 24 h delivery horizon: listed, never collected.
    const late = { key: trailKey(ROOT, "us-east-1", "2026-10-02T07:00:00Z", 99), body: trailObject([]) };
    const reuse = session({ buckets: { b: [...inWindow, late] }, listPageSize: 10 }, NO_PREFETCH);
    const keys = pagesOf(await walk(reuse.session)).map((p) => p.requestParams.key);
    expect(keys).toEqual(inWindow.map((o) => o.key));
    expect(walkLists(reuse.clients.sent)).toHaveLength(3); // the window's day: 10 + 10; the next day: 1
  });

  it("an old token resumes inside a listing with a cold cache", async () => {
    const objs = objects(12);
    const first = session({ buckets: { b: objs }, listPageSize: 5 });
    const pages = pagesOf(await walk(first.session));
    const second = session({ buckets: { b: objs }, listPageSize: 5 });
    const resumed = await second.session.fetchPage({
      source: "s3-trail",
      subWindowId: "s3-trail:0",
      window: WINDOW,
      pageToken: pages[6].nextPageToken!,
    });
    expect(resumed.requestParams.key).toBe(objs[7].key);
    await first.session.close?.();
    await second.session.close?.();
  });
});

describe("fetch-ahead (#2380)", () => {
  it("gives the same pages, bytes, versions and tokens as sequential collection, each object fetched once", async () => {
    const objs = objects(30);
    const ahead = session({ buckets: { b: objs }, listPageSize: 7 });
    const seq = session({ buckets: { b: objs }, listPageSize: 7 }, OLD);
    expect(pagesOf(await walk(ahead.session)).map(recordOf)).toEqual(
      pagesOf(await walk(seq.session)).map(recordOf),
    );
    const gets = ahead.clients.sent.filter((c) => c.op === "GetObject").map((c) => String(c.input.Key));
    expect(gets.sort()).toEqual(objs.map((o) => o.key).sort());
    expect(ahead.clients.s3Activity.maxActive).toBeLessThanOrEqual(PREFETCH_DEPTH + 1);
    await ahead.session.close?.();
  });

  it("a refused object is still a skip naming it, and the walk goes on", async () => {
    const objs = objects(8, (i) => (i === 3 ? { kmsDenied: true } : {}));
    const s = session({ buckets: { b: objs } });
    const out = await walk(s.session);
    expect(out.filter((o) => "skipped" in o)).toHaveLength(1);
    expect(pagesOf(out).map((p) => p.requestParams.key)).toEqual(
      objs.filter((_, i) => i !== 3).map((o) => o.key),
    );
    await s.session.close?.();
  });

  it("a throttle stops fetching ahead: no object is asked for more than twice", async () => {
    const objs = objects(20);
    const s = session({ buckets: { b: objs }, slowDowns: 1 });
    const pages = pagesOf(await walk(s.session, undefined, true));
    expect(pages.map((p) => p.requestParams.key)).toEqual(objs.map((o) => o.key));
    const gets = s.clients.sent.filter((c) => c.op === "GetObject").map((c) => String(c.input.Key));
    const counts = new Map<string, number>();
    for (const k of gets) counts.set(k, (counts.get(k) ?? 0) + 1);
    expect(Math.max(...counts.values())).toBeLessThanOrEqual(2);
    expect(gets.length).toBeLessThanOrEqual(objs.length + 1);
    await s.session.close?.();
  });

  it("only fetches ahead objects of known, bounded size", () => {
    const has = () => false;
    const c = (key: string, size?: number) => ({ bucket: "b", key, ...(size === undefined ? {} : { size }) });
    expect(
      pickPrefetch(
        [c("unknown"), c("big", MAX_PREFETCH_OBJECT_BYTES + 1), c("ok", 10)],
        { count: 0, bytes: 0, has },
        6,
      ),
    ).toEqual([c("ok", 10)]);
    expect(pickPrefetch([c("a", 10), c("b", 10)], { count: 6, bytes: 0, has }, 6)).toEqual([]);
    expect(pickPrefetch([c("a", 10)], { count: 0, bytes: MAX_PREFETCH_HELD_BYTES - 5, has }, 6)).toEqual([]);
    expect(
      pickPrefetch([c("a", 10), c("b", 10)], { count: 0, bytes: 0, has: (id) => id === "b\na" }, 6),
    ).toEqual([c("b", 10)]);
  });
});

describe("cancel (#2380)", () => {
  const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));

  it("after a cancel no request is running and none starts", async () => {
    const s = session({ buckets: { b: objects(20) }, s3LatencyMs: 30 });
    const ctl = new AbortController();
    const first = await s.session.fetchPage({
      source: "s3-trail",
      subWindowId: "x",
      window: WINDOW,
      signal: ctl.signal,
    });
    ctl.abort();
    await expect(
      s.session.fetchPage({
        source: "s3-trail",
        subWindowId: "x",
        window: WINDOW,
        signal: ctl.signal,
        pageToken: first.nextPageToken!,
      }),
    ).rejects.toThrow();
    await s.session.close?.();
    expect(s.clients.s3Activity.active).toBe(0);
    const sent = s.clients.sent.length;
    await settle(120);
    expect(s.clients.sent.length).toBe(sent);
  });

  it("a cancel while bodies stream ends them; close() waits for every download", async () => {
    const s = session({ buckets: { b: objects(10) }, bodyLatencyMs: 300 });
    const ctl = new AbortController();
    const pending = s.session.fetchPage({
      source: "s3-trail",
      subWindowId: "x",
      window: WINDOW,
      signal: ctl.signal,
    });
    // Wait (bounded) until this object and the ones ahead are streaming — no fixed sleep on slow CI.
    for (let i = 0; i < 100 && s.clients.s3Activity.active <= 1; i++) await settle(10);
    expect(s.clients.s3Activity.active).toBeGreaterThan(1);
    ctl.abort();
    await expect(pending).rejects.toThrow();
    await s.session.close?.();
    expect(s.clients.s3Activity.active).toBe(0);
  });

  it("an already-cancelled request downloads nothing", async () => {
    const s = session({ buckets: { b: objects(5) } });
    await expect(
      s.session.fetchPage({
        source: "s3-trail",
        subWindowId: "x",
        window: WINDOW,
        signal: AbortSignal.abort(),
      }),
    ).rejects.toThrow();
    expect(s.clients.sent.filter((c) => c.op === "GetObject")).toHaveLength(0);
    await s.session.close?.();
  });
});

describe("speed on a fake S3 with latency (#2380)", () => {
  it("is several times faster than the old walk, with far fewer listings", async () => {
    const objs = objects(40);
    const run = async (mode: TrailWalkOptions | undefined) => {
      const s = session({ buckets: { b: objs }, s3LatencyMs: 20 }, mode);
      const t0 = performance.now();
      await walk(s.session);
      const ms = performance.now() - t0;
      await s.session.close?.();
      const lists = walkLists(s.clients.sent).length;
      const gets = s.clients.sent.filter((c) => c.op === "GetObject").length;
      return {
        ms,
        pagesPerSecond: (objs.length / ms) * 1000,
        lists,
        gets,
        maxActive: s.clients.s3Activity.maxActive,
      };
    };
    const old = await run(OLD);
    const reuse = await run(NO_PREFETCH);
    const ahead = await run(undefined);
    console.log("[#2380 benchmark, 40 objects, 20 ms per S3 call]", JSON.stringify({ old, reuse, ahead }));
    expect(reuse.lists).toBeLessThan(old.lists);
    expect(ahead.ms * 3).toBeLessThan(old.ms);
    expect(ahead.maxActive).toBeLessThanOrEqual(PREFETCH_DEPTH + 1);
  });
});

// The acceptance item: a run killed with downloads ahead in flight resumes, with a fresh session,
// to exactly the pages sequential collection saves — no page lost, none twice, same SHA-256s.
describe("kill and resume with fetch-ahead in flight (#2380)", () => {
  let tick = 0;
  const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();
  const clock: CollectClock = { now: () => Date.parse("2026-10-05T00:00:00Z"), sleep: async () => {} };
  const OBJS = objects(23);
  const OPTS: Omit<FakeAwsOptions, "trails"> = { buckets: { b: OBJS }, listPageSize: 7, bodyLatencyMs: 5 };

  async function savedPages(dir: string) {
    const manifest = parseManifest(await readFile(collectionPaths(dir).manifest, "utf8"));
    const pages = manifest.pages.filter((p) => p.source === "s3-trail");
    for (const p of pages) {
      const saved = await readFile(join(collectionPaths(dir).pages, p.file));
      expect(createHash("sha256").update(saved).digest("hex")).toBe(p.sha256);
    }
    return pages.map((p) => ({ key: p.requestParams.key, sha256: p.sha256 }));
  }

  async function start(trailWalk?: TrailWalkOptions) {
    const t = await tempCase();
    const fs = faultFs();
    const first = session(OPTS, trailWalk);
    await createCollection(
      fs,
      first.session,
      {
        dir: t.dir,
        collectionId: "cc-test-2380",
        caseId: "c1",
        accountId: "a1",
        accountName: "lab",
        provider: "aws",
        sources: ["s3-trail"],
        window: WINDOW,
        filters: {},
        companionVersion: "0.0.0-test",
      },
      now,
    );
    return { t, fs, first };
  }

  async function sequential() {
    const { t, fs, first } = await start(OLD);
    await runCollection(
      {
        fs,
        session: first.session,
        importer: pipelineImporter(t),
        sources: first.provider.sources,
        now,
        clock,
      },
      t.dir,
      { resume: false },
    );
    return savedPages(t.dir);
  }

  async function killThenResume(kill: "abort" | "manifest" | "checkpoint" | "page") {
    const { t, fs, first } = await start();
    const ctl = new AbortController();
    let pagesSeen = 0;
    if (kill === "manifest")
      fs.inject(
        "appendSync",
        (p) => p.endsWith("manifest.jsonl") && ++pagesSeen > 6,
        () => new Error("disk gone"),
        true,
      );
    if (kill === "checkpoint")
      fs.inject(
        "rename",
        (p) => /checkpoint/.test(p) && ++pagesSeen > 6,
        () => new Error("disk gone"),
        true,
      );
    if (kill === "page")
      fs.inject(
        "rename",
        (p) => /pages/.test(p) && ++pagesSeen > 6,
        () => new Error("disk gone"),
        true,
      );
    await runCollection(
      {
        fs,
        session: first.session,
        importer: pipelineImporter(t),
        sources: first.provider.sources,
        now,
        clock,
        signal: ctl.signal,
        onProgress: (p) => {
          if (kill === "abort" && p.pages >= 6) ctl.abort();
        },
      },
      t.dir,
      { resume: false },
    ).catch(() => {});
    await first.session.close?.(); // the job's finally
    expect(first.clients.s3Activity.active).toBe(0);
    fs.clear();
    const fresh = session(OPTS);
    await runCollection(
      {
        fs,
        session: fresh.session,
        importer: pipelineImporter(t),
        sources: fresh.provider.sources,
        now,
        clock,
      },
      t.dir,
      { resume: true },
    );
    await fresh.session.close?.();
    return savedPages(t.dir);
  }

  it.each(["abort", "manifest", "checkpoint", "page"] as const)(
    "killed at %s, resumed with a fresh session: the same pages and SHA-256s as sequential",
    async (kill) => {
      const want = await sequential();
      expect(want.map((p) => p.key)).toEqual(OBJS.map((o) => o.key));
      expect(await killThenResume(kill)).toEqual(want);
    },
  );
});
