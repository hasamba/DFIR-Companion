import { describe, it, expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import {
  parseQueryBudget,
  QUOTA_WINDOW_MS,
  QueryUsageStore,
} from "../../src/integrations/cloudCollect/collectBudget.js";
import { precheckSource } from "../../src/integrations/cloudCollect/collectCoverage.js";
import { RETENTION, DEFAULT_OVERLAP_MS } from "../../src/integrations/cloudCollect/collectDefaults.js";
import {
  backoffMs,
  parseRetryAfter,
  rateLimitOf,
} from "../../src/integrations/cloudCollect/collectRateLimit.js";
import {
  RateLimitedError,
  type CloudCollectSession,
  type CollectSourceInfo,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import type { QueryBudget } from "../../src/integrations/cloudCollect/collectBudget.js";
import { collectionJobWarning } from "../../src/routes/cloudCollectJob.js";
import { faultFs, pipelineImporter, tempCase, type TempCase } from "../helpers/cloudCollectFakes.js";
import { denseSession, denseSource, fakeClock, type DenseRecord } from "../helpers/cloudCollectDense.js";

// #2312 — the tenant query budget, 429 back-off, rate limits, cutoff disclosure, retention pre-check.

const WINDOW = { start: "2026-10-01T10:00:00.000Z", end: "2026-10-01T11:00:00.000Z" };
const T0 = Date.parse(WINDOW.start);
const fixedNow = (iso: string) => () => iso;
let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();

const spread = (n: number): DenseRecord[] =>
  Array.from({ length: n }, (_, i) => ({ at: T0 + i * 60_000 + 1000, region: "us-east-1" }));

async function start(
  t: TempCase,
  session: CloudCollectSession,
  opts: { dir?: string; id?: string; overlapMs?: Record<string, number>; window?: typeof WINDOW } = {},
) {
  await createCollection(
    faultFs(),
    session,
    {
      dir: opts.dir ?? t.dir,
      collectionId: opts.id ?? "cc-test-abc123",
      caseId: "c1",
      accountId: "acct1",
      accountName: "lab",
      provider: "microsoft",
      sources: ["ct"],
      window: opts.window ?? WINDOW,
      filters: {},
      companionVersion: "0.0.0-test",
      ...(opts.overlapMs ? { overlapMs: opts.overlapMs } : {}),
    },
    now,
  );
}

function run(
  t: TempCase,
  session: CloudCollectSession,
  source: CollectSourceInfo,
  extra: {
    budget?: QueryBudget;
    retryBudget?: number;
    clock?: ReturnType<typeof fakeClock>;
    dir?: string;
    now?: () => string;
    resume?: boolean;
  } = {},
) {
  return runCollection(
    {
      fs: faultFs(),
      session,
      importer: pipelineImporter(t),
      sources: [source],
      now: extra.now ?? now,
      clock: extra.clock ?? fakeClock(),
      ...(extra.budget ? { budget: extra.budget } : {}),
      ...(extra.retryBudget !== undefined ? { retryBudget: extra.retryBudget } : {}),
    },
    extra.dir ?? t.dir,
    { resume: !!extra.resume },
  );
}

describe("tenant query budget (#2312)", () => {
  it("stops 'partial — budget used', and the count survives a restart and a second account of the tenant", async () => {
    const usageFile = join(await mkdtemp(join(tmpdir(), "dfir-quota-")), "cloud-quota", "query-usage.json");
    let wall = Date.UTC(2026, 9, 5);
    const store = () => new QueryUsageStore(usageFile, { nowMs: () => wall });
    const scope = "microsoft:00000000-0000-4000-a000-000000000001";
    const source = denseSource({ minWindowMs: 60_000, queryCost: 1 });
    // 40 records, a 10-record cap: the hour splits into a tree of many queries.
    const records = spread(40);
    const t = await tempCase();
    const s1 = denseSession({ records, cap: 10 });
    await start(t, s1);
    const cp = await run(t, s1, source, { budget: store().budget(scope, 3) });
    expect(s1.calls.filter((c) => !c.pageToken)).toHaveLength(3);
    expect(cp.status).toBe("partial");
    expect(cp.stopReason).toMatch(/partial — budget used: this companion has used 3 of its 3/);
    expect(cp.stopReason).toMatch(/estimate/);
    expect(cp.stopReason).not.toMatch(/remaining/i);
    expect(cp.missing.length).toBeGreaterThan(0);
    expect(await store().used(scope)).toBe(3);
    expect(JSON.parse(await readFile(usageFile, "utf8")).scopes[scope]).toHaveLength(3);

    // Restart: a new store instance on the same file — the resume sends nothing.
    const s2 = denseSession({ records, cap: 10 });
    const resumed = await run(t, s2, source, { budget: store().budget(scope, 3), resume: true });
    expect(s2.calls).toHaveLength(0);
    expect(resumed.stopReason).toMatch(/budget used/);

    // A second account of the same tenant, another collection: refused before its first query.
    const dir2 = t.dir.replace("cc-test-abc123", "cc-test-def456");
    const s3 = denseSession({ records, cap: 10 });
    await start(t, s3, { dir: dir2, id: "cc-test-def456" });
    const other = await run(t, s3, source, { budget: store().budget(scope, 3), dir: dir2 });
    expect(s3.calls).toHaveLength(0);
    // #2339: no page saved, but a budget stop is still "partial" — resumable, not a failure.
    expect(other.status).toBe("partial");
    expect(other.stopReason).toMatch(/^partial — budget used/);
    expect(other.imported).toEqual([]);
    expect(collectionJobWarning(other)).toBe(other.stopReason); // the job warns; it does not fail
    expect(other.missing[0].reason).toMatch(/budget used/);

    // A rolling 24 h later the count has aged out and the collection finishes.
    wall += QUOTA_WINDOW_MS + 1;
    const s4 = denseSession({ records, cap: 10 });
    const done = await run(t, s4, source, { budget: store().budget(scope, 100), resume: true });
    expect(done.status).toBe("complete");
    expect(collectionJobWarning(done)).toBeUndefined();
  }, 30_000);

  it("parses DFIR_CLOUD_M365_QUERY_BUDGET: 1–200, else 50", () => {
    expect(parseQueryBudget(undefined)).toBe(50);
    expect(parseQueryBudget("20")).toBe(20);
    expect(parseQueryBudget("0")).toBe(50);
    expect(parseQueryBudget("500")).toBe(50);
    expect(parseQueryBudget("abc")).toBe(50);
  });
});

describe("throttling (#2312)", () => {
  it("backs off on 429 with the Retry-After it was given, then succeeds", async () => {
    const t = await tempCase();
    const clock = fakeClock();
    const throwOn = new Map<number, () => Error>([
      [0, () => new RateLimitedError(2000)],
      [
        1,
        () => Object.assign(new Error("Too Many Requests"), { status: 429, headers: { "retry-after": "3" } }),
      ],
    ]);
    const session = denseSession({ records: spread(5), cap: 100, throwOn });
    await start(t, session);
    const cp = await run(t, session, denseSource(), { clock });
    expect(clock.sleeps).toEqual([2000, 3000]);
    expect(session.calls).toHaveLength(3);
    expect(cp.status).toBe("complete");
  });

  it("a used-up retry budget fails the window with the reason", async () => {
    const t = await tempCase();
    const throttle = () => Object.assign(new Error("slow down"), { name: "ThrottlingException" });
    const throwOn = new Map<number, () => Error>([
      [0, throttle],
      [1, throttle],
    ]);
    const session = denseSession({ records: spread(5), cap: 100, throwOn });
    await start(t, session);
    const cp = await run(t, session, denseSource(), { retryBudget: 1 });
    expect(cp.status).toBe("failed");
    expect(cp.missing[0].reason).toMatch(/rate limited: the collection's 1 throttle retries are used up/);
  });

  it("paces requests to the source's rate limit", async () => {
    const t = await tempCase();
    const clock = fakeClock();
    const session = denseSession({ records: spread(12), cap: 100, perPage: 3 });
    await start(t, session);
    const cp = await run(t, session, denseSource({ rateLimit: { requests: 2, perMs: 1000 } }), { clock });
    expect(cp.status).toBe("complete");
    expect(session.calls).toHaveLength(4);
    expect(clock.sleeps).toEqual([1000]);
  });

  it("recognises the SDK throttle shapes and Retry-After forms", () => {
    expect(rateLimitOf({ $metadata: { httpStatusCode: 429 } }, 0)).toEqual({});
    expect(rateLimitOf({ code: 8 }, 0)).toEqual({});
    expect(rateLimitOf(new Error("AccessDenied"), 0)).toBeNull();
    expect(parseRetryAfter("Wed, 21 Oct 2026 07:28:05 GMT", Date.parse("2026-10-21T07:28:00Z"))).toBe(5000);
    expect(backoffMs(0)).toBe(1000);
    expect(backoffMs(10)).toBe(60_000);
  });
});

describe("cutoff disclosure (#2312)", () => {
  const recent = { start: "2026-10-05T00:00:00.000Z", end: "2026-10-05T01:00:00.000Z" };

  it("discloses the cutoff: read time minus the overlap, never past the provider's own", async () => {
    const t = await tempCase();
    const session = denseSession({ records: [], cap: 100 });
    await start(t, session, { window: recent, overlapMs: { ct: DEFAULT_OVERLAP_MS.aws } });
    const cp = await run(t, session, denseSource({ overlapMs: DEFAULT_OVERLAP_MS.microsoft }), {
      now: fixedNow("2026-10-05T01:05:00.000Z"),
    });
    expect(cp.coverage).toEqual([
      expect.objectContaining({
        source: "ct",
        overlapMs: 900_000,
        acquiredCutoff: "2026-10-05T00:50:00.000Z",
      }),
    ]);
    expect(cp.coverage?.[0].notes[0]).toMatch(/Settled up to 2026-10-05T00:50:00.000Z/);

    const t2 = await tempCase();
    const sink = denseSession({ records: [], cap: 100, acquiredUntil: "2026-10-05T00:00:00.000Z" });
    await start(t2, sink, { window: recent });
    const cp2 = await run(t2, sink, denseSource({ overlapMs: 300_000 }), {
      now: fixedNow("2026-10-06T00:00:00.000Z"),
    });
    expect(cp2.coverage?.[0].acquiredCutoff).toBe("2026-10-05T00:00:00.000Z");
  });

  it("an old window is settled to its end with no note", async () => {
    const t = await tempCase();
    const session = denseSession({ records: spread(2), cap: 100 });
    await start(t, session);
    const cp = await run(t, session, denseSource({ overlapMs: 900_000 }));
    expect(cp.coverage?.[0]).toMatchObject({ acquiredCutoff: WINDOW.end, notes: [] });
  });
});

describe("retention pre-check (#2312)", () => {
  const nowMs = Date.parse("2026-11-06T00:00:00Z");
  const day = 86_400_000;
  const win = (fromDays: number, toDays = 0) => ({
    start: new Date(nowMs - fromDays * day).toISOString(),
    end: new Date(nowMs - toDays * day).toISOString(),
  });

  it("Entra 7/30 days: out of retention before 30, maybe before 7", () => {
    const check = precheckSource(denseSource({ retention: RETENTION.entra }), win(40, 1), nowMs);
    expect(check.outOfRetention).toEqual({ start: win(40).start, end: win(30).start });
    expect(check.mayBeOutOfRetention).toEqual({ start: win(30).start, end: win(7).start });
    expect(check.warnings.join(" ")).toMatch(/P1 or P2/);
  });

  it("LookupEvents 90 days, GCP Data Access off by default, the overlap warning", () => {
    expect(
      precheckSource(denseSource({ retention: RETENTION.cloudTrailLookupEvents }), win(30, 1), nowMs)
        .outOfRetention,
    ).toBeUndefined();
    expect(
      precheckSource(denseSource({ retention: RETENTION.cloudTrailLookupEvents }), win(100, 1), nowMs)
        .outOfRetention,
    ).toBeDefined();
    const gcp = precheckSource(
      denseSource({ retention: RETENTION.gcpDataAccess, overlapMs: 300_000 }),
      win(1),
      nowMs,
    );
    expect(gcp.warnings.join(" ")).toMatch(/OFF by default/);
    expect(gcp.warnings.join(" ")).toMatch(/may still be arriving/);
    expect(
      precheckSource(denseSource({ retention: RETENTION.unifiedAuditLog }), win(200, 1), nowMs)
        .mayBeOutOfRetention,
    ).toBeDefined();
    expect(RETENTION.azureActivity.minDays).toBe(90);
  });
});
