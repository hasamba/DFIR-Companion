import { describe, it, expect } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import { collectionPaths, parseManifest } from "../../src/integrations/cloudCollect/collectManifest.js";
import {
  AWS_COLLECT_SOURCES,
  createAwsCollectProvider,
  GUARDDUTY_NOTICE,
} from "../../src/integrations/cloudCollect/aws/awsCollectProvider.js";
import {
  GUARDDUTY_ADAPTATION,
  MAX_DETECTOR_PAGES,
} from "../../src/integrations/cloudCollect/aws/awsGuardDutyFindings.js";
import {
  CursorExpiredError,
  type CloudCollectSession,
  type CollectPage,
  type CollectPageRequest,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import type { CollectPageImporter } from "../../src/integrations/cloudCollect/collectImport.js";
import type { CollectClock } from "../../src/integrations/cloudCollect/collectRateLimit.js";
import { faultFs, kill, pipelineImporter, tempCase, type TempCase } from "../helpers/cloudCollectFakes.js";
import { awsAccount, fakeAwsClients, type FakeAwsOptions, type Sent } from "../helpers/awsCollectFakes.js";
import { GD_DETECTOR, gdFinding } from "../helpers/guardDutyFixtures.js";

// #2361 — the GuardDuty findings source on a recording fake (no real AWS is reached): which regions
// it asks, what it sends, what it saves, and how it resumes and quarantines through the engine.

const SOURCE = "guardduty-findings";
const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-01T06:00:00Z" };

function session(opts: FakeAwsOptions, region = "eu-west-1") {
  const clients = fakeAwsClients(opts);
  const provider = createAwsCollectProvider({
    transport: () => {
      throw new Error("no transport in a mocked test");
    },
    clients: () => clients,
  });
  return { clients, provider, session: provider.open(awsAccount(region)) };
}

/** A session with its region scope decided the way a start decides it (#2363 picker). */
async function scoped(opts: FakeAwsOptions, choice: { excludeRegions?: string[] } = {}) {
  const made = session(opts);
  const filters = await made.session.prepareFilters!(choice);
  return { ...made, filters };
}

/** Every page of the source, the way the engine walks it. */
async function walk(s: CloudCollectSession, extra: Partial<CollectPageRequest> = {}): Promise<CollectPage[]> {
  const out: CollectPage[] = [];
  let token: string | undefined;
  for (let i = 0; i < 100; i++) {
    const page = await s.fetchPage({
      source: SOURCE,
      subWindowId: `${SOURCE}:0`,
      window: WINDOW,
      ...extra,
      ...(token ? { pageToken: token } : {}),
    });
    out.push(page);
    token = page.nextPageToken;
    if (!token) return out;
  }
  throw new Error("walk did not end");
}

const findingsOf = (p: CollectPage) =>
  (JSON.parse(Buffer.from(p.body).toString("utf8")) as { Findings: Array<{ Id: string }> }).Findings;

const EU = [gdFinding(1, { Severity: 9.3 }), gdFinding(2)];
const EU2 = [gdFinding(3, { Severity: 7.5 })];
const ME = [gdFinding(4, { Region: "me-south-1", Severity: 4.5 }, {}, "me-south-1")];

// The regions DescribeRegions lists (#2363): an opt-in one (me-south-1) among them.
const ENABLED = ["eu-west-1", "us-east-1", "us-west-2", "me-south-1", "ap-south-1"].map((RegionName) => ({
  RegionName,
}));

const SCRIPT: FakeAwsOptions = {
  trails: [],
  buckets: {},
  enabledRegions: ENABLED,
  guardduty: {
    "eu-west-1": { detector: GD_DETECTOR, pages: [EU, EU2] },
    "us-east-1": "off",
    "me-south-1": { detector: "d-me", pages: [ME] },
  },
};

describe("the GuardDuty source (#2361)", () => {
  it("is the third AWS source, imported by the GuardDuty importer, with its notice and retention", () => {
    const src = AWS_COLLECT_SOURCES.find((s) => s.id === SOURCE)!;
    expect(src).toMatchObject({
      label: "GuardDuty findings",
      streamKind: "guardduty",
      notice: GUARDDUTY_NOTICE,
      partition: { key: "region" },
      retention: { minDays: 90 },
    });
  });

  it("collects every region with a detector — an opt-in one included — and names the rest", async () => {
    const { session: s, clients } = await scoped(SCRIPT);
    const all = await walk(s);
    // Three pages of findings, then the closing page of the last region asked (no detector there).
    expect(all).toHaveLength(4);
    expect(all[3].nextPageToken).toBeUndefined();
    expect(findingsOf(all[3])).toEqual([]);
    const walked = await s.partitionValues!(SOURCE);
    expect(all[3].requestParams.region).toBe(walked[walked.length - 1]);
    const pages = all.slice(0, 3);
    expect(pages.map((p) => p.requestParams.region)).toEqual(["eu-west-1", "eu-west-1", "me-south-1"]);
    expect(pages.map((p) => findingsOf(p).map((f) => f.Id))).toEqual([
      EU.map((f) => f.Id),
      EU2.map((f) => f.Id),
      ME.map((f) => f.Id),
    ]);
    expect(pages[0].recordCount).toBe(2);
    expect(pages[0].requestParams).toMatchObject({
      api: "guardduty:ListFindings+GetFindings",
      detectorId: GD_DETECTOR,
      listed: "2",
      fetched: "2",
      adaptation: GUARDDUTY_ADAPTATION,
    });
    // Regions passed on the way are named: us-east-1 answered "not enabled", the others no detector.
    const named = (k: string) => all.flatMap((p) => (p.requestParams[k] ?? "").split(",").filter(Boolean));
    expect(named("regionsNotEnabled")).toEqual(["us-east-1"]);
    expect(named("noDetectorRegions").sort()).toEqual(["ap-south-1", "us-west-2"]);
    // The ListFindings request: updatedAt in the window, oldest first, 50 a page, archived included.
    const list = clients.sent.find((c) => c.op === "ListFindings")!;
    expect(list.input).toEqual({
      DetectorId: GD_DETECTOR,
      FindingCriteria: {
        Criterion: {
          updatedAt: { GreaterThanOrEqual: Date.parse(WINDOW.start), LessThan: Date.parse(WINDOW.end) },
        },
      },
      SortCriteria: { AttributeName: "updatedAt", OrderBy: "ASC" },
      MaxResults: 50,
    });
    const get = clients.sent.find((c) => c.op === "GetFindings")!;
    expect(get.input).toEqual({ DetectorId: GD_DETECTOR, FindingIds: EU.map((f) => f.Id) });
    // Read-only: the region listing, then nothing but the three GuardDuty reads.
    expect(new Set(clients.sent.map((c) => c.op))).toEqual(
      new Set(["DescribeRegions", "ListDetectors", "ListFindings", "GetFindings"]),
    );
  });

  it("closes the source with an empty page when no later region has a detector", async () => {
    const { session: s } = session({
      ...SCRIPT,
      guardduty: { "eu-west-1": { detector: GD_DETECTOR, pages: [EU] } },
    });
    const pages = await walk(s);
    const last = pages[pages.length - 1];
    expect(last.nextPageToken).toBeUndefined();
    expect(findingsOf(last)).toEqual([]);
    expect(pages.flatMap(findingsOf)).toHaveLength(2);
  });

  it("walks one region only on the partition fallback", async () => {
    const { session: s, clients } = await scoped(SCRIPT);
    const pages = await walk(s, { partition: { region: "me-south-1" } });
    expect(pages.map((p) => p.requestParams.region)).toEqual(["me-south-1"]);
    expect(
      clients.sent.filter((c) => c.op !== "DescribeRegions").every((c) => c.region === "me-south-1"),
    ).toBe(true);
    expect([...(await s.partitionValues!(SOURCE))].sort()).toEqual(ENABLED.map((r) => r.RegionName).sort());
  });

  it("honours the region picker: an unticked region is never asked", async () => {
    const { session: s, clients } = await scoped(SCRIPT, { excludeRegions: ["me-south-1"] });
    const pages = await walk(s);
    expect(pages.flatMap(findingsOf).map((f) => f.Id)).toEqual([...EU, ...EU2].map((f) => f.Id));
    expect(clients.sent.some((c) => c.region === "me-south-1")).toBe(false);
    expect(pages.some((p) => /me-south-1/.test(p.note ?? ""))).toBe(true); // skipped by choice, said
  });

  it("counts findings expired between list and get, and findings updated after the window end", async () => {
    const later = gdFinding(6, { UpdatedAt: "2026-10-02T00:00:00.000Z" });
    const { session: s } = session({
      trails: [],
      buckets: {},
      guardduty: {
        "eu-west-1": {
          detector: GD_DETECTOR,
          pages: [[gdFinding(5), later]],
          notReturned: [String(gdFinding(5).Id)],
        },
      },
    });
    const [first] = await walk(s, { partition: { region: "eu-west-1" } });
    expect(first.requestParams).toMatchObject({
      listed: "2",
      fetched: "1",
      notReturned: "1",
      updatedAfterWindow: "1",
    });
    expect(findingsOf(first).map((f) => f.Id)).toEqual([later.Id]);
  });

  it("a refused GuardDuty read fails with the policy statement to grant, never an empty success", async () => {
    const { session: s } = session({ ...SCRIPT, guarddutyDenied: true });
    await expect(walk(s)).rejects.toThrow(
      /GuardDuty read refused.*guardduty:ListDetectors, ListFindings, GetFindings/,
    );
  });

  it("an unreadable token or a region no longer listed is an expired cursor", async () => {
    const { session: s } = session(SCRIPT);
    const req = { source: SOURCE, subWindowId: "x", window: WINDOW };
    await expect(s.fetchPage({ ...req, pageToken: "not json" })).rejects.toBeInstanceOf(CursorExpiredError);
    await expect(
      s.fetchPage({ ...req, pageToken: JSON.stringify({ r: "xx-nowhere-1" }) }),
    ).rejects.toBeInstanceOf(CursorExpiredError);
  });
});

// #2372 — ListDetectors is paginated. AWS allows one detector per account and region, so this is
// defensive: every page is read (bounded), and a listing cut at the bound is said, never silent.
describe("GuardDuty detector listing pagination (#2372)", () => {
  const EU_ONLY = { partition: { region: "eu-west-1" } };
  const gdOnly = (plan: FakeAwsOptions["guardduty"]): FakeAwsOptions => ({
    trails: [],
    buckets: {},
    guardduty: plan,
  });
  const detectorCalls = (sent: Sent[], region = "eu-west-1") =>
    sent.filter((c) => c.op === "ListDetectors" && c.region === region);

  it("follows NextToken: detectors on later pages are named in otherDetectors", async () => {
    const { session: s, clients } = session(
      gdOnly({
        "eu-west-1": { detector: GD_DETECTOR, pages: [EU], detectorPages: [[GD_DETECTOR], ["d-2"], ["d-3"]] },
      }),
    );
    const [first] = await walk(s, EU_ONLY);
    const calls = detectorCalls(clients.sent);
    expect(calls.map((c) => c.input.NextToken)).toEqual([undefined, "d1", "d2"]);
    expect(first.requestParams.otherDetectors).toBe("eu-west-1:d-2,eu-west-1:d-3");
    expect(first.requestParams.detectorListTruncated).toBeUndefined();
    expect(findingsOf(first).map((f) => f.Id)).toEqual(EU.map((f) => f.Id));
  });

  it("an empty first page with a NextToken is not 'no detector': the detector on page two is used", async () => {
    const { session: s } = session(
      gdOnly({ "eu-west-1": { detector: GD_DETECTOR, pages: [EU], detectorPages: [[], [GD_DETECTOR]] } }),
    );
    const [first] = await walk(s, EU_ONLY);
    expect(first.requestParams.detectorId).toBe(GD_DETECTOR);
    expect(first.requestParams.noDetectorRegions).toBeUndefined();
    expect(findingsOf(first)).toHaveLength(EU.length);
  });

  it("an id listed on two pages is named once", async () => {
    const { session: s } = session(
      gdOnly({
        "eu-west-1": {
          detector: GD_DETECTOR,
          pages: [EU],
          detectorPages: [
            [GD_DETECTOR, "d-2"],
            ["d-2", GD_DETECTOR],
          ],
        },
      }),
    );
    const [first] = await walk(s, EU_ONLY);
    expect(first.requestParams.otherDetectors).toBe("eu-west-1:d-2");
  });

  it("exactly the bound of pages, the last with no NextToken, is a complete listing", async () => {
    const detectorPages = Array.from({ length: MAX_DETECTOR_PAGES }, (_, i) =>
      i === 0 ? [GD_DETECTOR] : [],
    );
    const { session: s, clients } = session(
      gdOnly({ "eu-west-1": { detector: GD_DETECTOR, pages: [EU], detectorPages } }),
    );
    const [first] = await walk(s, EU_ONLY);
    expect(detectorCalls(clients.sent)).toHaveLength(MAX_DETECTOR_PAGES);
    expect(first.requestParams.detectorListTruncated).toBeUndefined();
  });

  it("a listing that never ends stops at the bound and says so; the first detector is still collected", async () => {
    const { session: s, clients } = session(
      gdOnly({
        "eu-west-1": {
          detector: GD_DETECTOR,
          pages: [EU],
          detectorPages: [[GD_DETECTOR]],
          detectorTokenRepeat: true,
        },
      }),
    );
    const [first] = await walk(s, EU_ONLY);
    expect(detectorCalls(clients.sent)).toHaveLength(MAX_DETECTOR_PAGES);
    expect(first.requestParams.detectorListTruncated).toBe("eu-west-1");
    expect(findingsOf(first)).toHaveLength(EU.length);
  });

  it("a cut listing with no id found is disclosed as cut, not as 'no detector'", async () => {
    const { session: s } = session(
      gdOnly({ "eu-west-1": { detector: null, pages: [], detectorPages: [[]], detectorTokenRepeat: true } }),
    );
    const [only] = await walk(s, EU_ONLY);
    expect(only.requestParams.detectorListTruncated).toBe("eu-west-1");
    expect(only.requestParams.noDetectorRegions).toBeUndefined();
  });

  it("the cut note of a region with no finding in the window is carried onto the next region's page", async () => {
    const { session: s } = await scoped({
      ...gdOnly({
        "eu-west-1": {
          detector: GD_DETECTOR,
          pages: [[]],
          detectorPages: [[GD_DETECTOR]],
          detectorTokenRepeat: true,
        },
        "us-east-1": { detector: "d-us", pages: [EU2] },
      }),
      enabledRegions: [{ RegionName: "eu-west-1" }, { RegionName: "us-east-1" }],
    });
    const pages = await walk(s);
    const us = pages.find((p) => p.requestParams.region === "us-east-1")!;
    expect(findingsOf(us).map((f) => f.Id)).toEqual(EU2.map((f) => f.Id));
    expect(us.requestParams).toMatchObject({ emptyRegions: "eu-west-1", detectorListTruncated: "eu-west-1" });
  });

  it.each(["dns", "token"] as const)(
    "a %s failure on detector page two fails the fetch without expiring the cursor; a retry succeeds",
    async (error) => {
      const { session: s } = session(
        gdOnly({
          "eu-west-1": {
            detector: GD_DETECTOR,
            pages: [EU],
            detectorPages: [[GD_DETECTOR], ["d-2"]],
            detectorFail: { page: 1, error, times: 1 },
          },
        }),
      );
      const req = { source: SOURCE, subWindowId: `${SOURCE}:0`, window: WINDOW, ...EU_ONLY };
      const failed = await s.fetchPage(req).then(
        () => null,
        (err: unknown) => err,
      );
      expect(failed).toBeInstanceOf(Error);
      expect(failed).not.toBeInstanceOf(CursorExpiredError);
      const page = await s.fetchPage(req);
      expect(page.requestParams.otherDetectors).toBe("eu-west-1:d-2");
      expect(findingsOf(page)).toHaveLength(EU.length);
    },
  );
});

// ── through the engine ───────────────────────────────────────────────────────────────────────────

let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();
function fakeClock(): CollectClock {
  let t = Date.parse("2026-10-05T00:00:00Z");
  return { now: () => t, sleep: async (ms) => void (t += ms) };
}

async function collect(t: TempCase, opts: FakeAwsOptions, importer?: CollectPageImporter) {
  const { session: s, provider, clients, filters } = await scoped(opts);
  const fs = faultFs();
  await createCollection(
    fs,
    s,
    {
      dir: t.dir,
      collectionId: "cc-test-abc123",
      caseId: "c1",
      accountId: "a1",
      accountName: "lab",
      provider: "aws",
      sources: [SOURCE],
      window: WINDOW,
      filters,
      companionVersion: "0.0.0-test",
    },
    now,
  );
  const deps = (imp: CollectPageImporter) => ({
    fs,
    session: s,
    importer: imp,
    sources: provider.sources,
    now,
    clock: fakeClock(),
  });
  const first = runCollection(deps(importer ?? pipelineImporter(t)), t.dir, { resume: false });
  const manifest = async () => parseManifest(await readFile(collectionPaths(t.dir).manifest, "utf8"));
  const resume = () => runCollection(deps(pipelineImporter(t)), t.dir, { resume: true });
  return { first, manifest, resume, clients };
}

describe("GuardDuty collection through the engine (#2361)", () => {
  it("saves hash-verified pages, imports them graded by GuardDuty severity, with provenance", async () => {
    const t = await tempCase();
    const { first, manifest } = await collect(t, SCRIPT);
    const cp = await first;
    expect(cp.status).toBe("complete");
    const m = await manifest();
    expect(m.header?.sdkVersions).toBeDefined();
    const pages = m.pages.filter((p) => p.source === SOURCE && p.records > 0);
    expect(pages.map((p) => p.requestParams.region)).toEqual(["eu-west-1", "eu-west-1", "me-south-1"]);
    for (const p of m.pages) {
      const saved = await readFile(join(collectionPaths(t.dir).pages, p.file));
      expect(createHash("sha256").update(saved).digest("hex")).toBe(p.sha256);
    }
    expect(m.entries.filter((e) => e.type === "skip")).toEqual([]);
    expect(cp.coverage!.find((c) => c.source === SOURCE)!.notes).toContain(GUARDDUTY_NOTICE);
    const state = await t.stateStore.load("c1");
    const crit = state.forensicTimeline.find((e) => e.severity === "Critical")!;
    expect(crit.description).toMatch(/^GuardDuty finding Recon:EC2\/Portscan/);
    expect(crit.sourceScreenshots).toContain(`evidence/cloud/cc-test-abc123/${pages[0].file}`);
    const gd = state.forensicTimeline.filter((e) => /^GuardDuty finding/.test(e.description));
    expect(gd.map((e) => e.severity).sort()).toEqual(["Critical", "High", "Medium", "Medium"]);
  });

  it("a DNS failure mid-pagination fails the window keeping its token; Resume carries on from it", async () => {
    const t = await tempCase();
    const { first, resume, clients } = await collect(t, {
      ...SCRIPT,
      guarddutyDnsFail: { region: "eu-west-1", page: 1, times: 1 },
    });
    const cp = await first;
    expect(cp.status).toBe("partial");
    const sw = cp.subWindows[0];
    expect(sw.state).toBe("failed");
    expect(sw.reason).toMatch(/EAI_AGAIN/);
    expect(JSON.parse(sw.pageToken!)).toEqual({ r: "eu-west-1", d: GD_DETECTOR, n: "g1" });
    const again = await resume();
    expect(again.status).toBe("complete");
    const lists = clients.sent.filter((c) => c.op === "ListFindings" && c.region === "eu-west-1");
    expect(lists.map((c) => c.input.NextToken ?? null)).toEqual([null, "g1", "g1"]);
    const state = await t.stateStore.load("c1");
    expect(state.forensicTimeline.filter((e) => /^GuardDuty finding/.test(e.description))).toHaveLength(4);
  });

  it("a saved page whose hash no longer matches is quarantined and its window fetched again", async () => {
    const t = await tempCase();
    const killing = pipelineImporter(t, {
      duringPage: () => {
        throw kill();
      },
      noCleanup: () => true,
    });
    const { first, manifest, resume } = await collect(t, SCRIPT, killing);
    await expect(first).rejects.toThrow("simulated kill");
    const page = (await manifest()).pages[0];
    await writeFile(join(collectionPaths(t.dir).pages, page.file), "tampered");
    const cp = await resume();
    expect(cp.status).toBe("complete");
    expect(cp.quarantined).toEqual([expect.objectContaining({ reason: "corrupt", file: page.file })]);
    const state = await t.stateStore.load("c1");
    const gd = state.forensicTimeline.filter((e) => /^GuardDuty finding/.test(e.description));
    expect(gd).toHaveLength(4); // nothing lost, nothing twice
  });

  it("collecting the same window again imports nothing twice", async () => {
    const t = await tempCase();
    const one = await collect(t, SCRIPT);
    await one.first;
    const t2 = { ...t, dir: join(t.dir, "..", "cc-test-second") };
    const two = await collect(t2, SCRIPT);
    await two.first;
    const state = await t.stateStore.load("c1");
    expect(state.forensicTimeline.filter((e) => /^GuardDuty finding/.test(e.description))).toHaveLength(4);
  });
});
