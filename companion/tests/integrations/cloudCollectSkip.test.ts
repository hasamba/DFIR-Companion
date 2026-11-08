import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import { collectionPaths, parseManifest } from "../../src/integrations/cloudCollect/collectManifest.js";
import { deriveSubWindows } from "../../src/integrations/cloudCollect/collectReplay.js";
import { precheckSource, sourceCoverage } from "../../src/integrations/cloudCollect/collectCoverage.js";
import {
  CursorExpiredError,
  SkippedItemError,
  type CloudCollectSession,
  type CollectPage,
  type CollectSourceInfo,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import {
  faultFs,
  pipelineImporter,
  tempCase,
  trailRecord,
  type TempCase,
} from "../helpers/cloudCollectFakes.js";

// #2313 — the engine's skip hook: a provider can report ONE item it could not read (a KMS-denied
// trail object, a region that refuses the call) without failing the whole sub-window, and the
// result says so per source. Plus the always-shown source notice (LookupEvents: 90 days, management
// events only).

const SOURCES: CollectSourceInfo[] = [{ id: "ct", label: "CloudTrail", streamKind: "aws" }];
const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-02T00:00:00Z" };
let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();

function page(i: number, next?: string): CollectPage {
  const records = [trailRecord(i)];
  return {
    body: Buffer.from(JSON.stringify({ Records: records })),
    extension: "json",
    recordCount: 1,
    ...(next ? { nextPageToken: next } : {}),
    requestParams: { item: `k${i}` },
  };
}

/** Scripted tokens: "k1" ok, "k2" skipped, … `plan` maps the incoming token to an outcome. */
function scripted(plan: Record<string, "ok" | "skip">, order: string[]): CloudCollectSession {
  return {
    identity: async () => ({ accountRef: "123456789012", caller: "arn:test", sdkVersions: {} }),
    fetchPage: async (req) => {
      const at = req.pageToken ? order.indexOf(req.pageToken) + 1 : 0;
      const key = order[at];
      const next = order[at + 1] ? key : undefined;
      if (plan[key] === "skip")
        throw new SkippedItemError(key, "AccessDenied: needs kms:Decrypt on the trail key", next);
      return page(at + 1, next);
    },
  };
}

async function startCollection(t: TempCase, session: CloudCollectSession) {
  await createCollection(
    faultFs(),
    session,
    {
      dir: t.dir,
      collectionId: "cc-test-abc123",
      caseId: "c1",
      accountId: "a1",
      accountName: "lab",
      provider: "aws",
      sources: ["ct"],
      window: WINDOW,
      filters: {},
      companionVersion: "0.0.0-test",
    },
    now,
  );
}

async function runAgain(t: TempCase, session: CloudCollectSession, resume: boolean) {
  const cp = await runCollection(
    { fs: faultFs(), session, importer: pipelineImporter(t), sources: SOURCES, now },
    t.dir,
    { resume },
  );
  const manifest = parseManifest(await readFile(collectionPaths(t.dir).manifest, "utf8"));
  return { cp, manifest };
}

async function runOnce(t: TempCase, session: CloudCollectSession) {
  await startCollection(t, session);
  return runAgain(t, session, false);
}

describe("the skip hook (#2313)", () => {
  it("a skipped item mid-window is a manifest line; the rest is collected; the result is partial", async () => {
    const t = await tempCase();
    const { cp, manifest } = await runOnce(
      t,
      scripted({ k1: "ok", k2: "skip", k3: "ok" }, ["k1", "k2", "k3"]),
    );
    expect(cp.status).toBe("partial");
    expect(manifest.pages.map((p) => p.requestParams.item)).toEqual(["k1", "k3"]);
    const skips = manifest.entries.filter((e) => e.type === "skip");
    expect(skips).toHaveLength(1);
    expect(skips[0]).toMatchObject({ item: "k2", source: "ct", subWindowId: "ct:0" });
    expect(cp.subWindows[0].skipped).toBe(1);
    expect(cp.missing).toHaveLength(1);
    expect(cp.missing[0].reason).toMatch(/1 item\(s\) could not be read.*k2/);
    const cov = cp.coverage![0];
    expect(cov.acquiredCutoff).toBeUndefined(); // never "settled" past an unread item
    expect(cov.notes.join(" ")).toMatch(/1 item\(s\) could not be read.*k2/);
  });

  it("a skipped LAST item still finishes the walk, and the result is partial", async () => {
    const t = await tempCase();
    const { cp } = await runOnce(t, scripted({ k1: "ok", k2: "skip" }, ["k1", "k2"]));
    expect(cp.status).toBe("partial");
    expect(cp.subWindows[0]).toMatchObject({ state: "done", pages: 1, skipped: 1 });
  });

  it("every item refused (a fully KMS-encrypted trail): partial, no acquired cutoff, no read time", async () => {
    const t = await tempCase();
    const { cp } = await runOnce(t, scripted({ k1: "skip", k2: "skip" }, ["k1", "k2"]));
    expect(cp.status).toBe("partial");
    expect(cp.subWindows[0]).toMatchObject({ state: "done", pages: 0, skipped: 2 });
    expect(cp.subWindows[0].firstRetrievedAt).toBeUndefined();
    expect(cp.coverage![0].acquiredCutoff).toBeUndefined();
    expect(cp.coverage![0].notes.join(" ")).toMatch(/2 item\(s\) could not be read.*kms:Decrypt/);
    expect(cp.missing[0].reason).toMatch(/2 item\(s\) could not be read/);
  });

  it("a resume retries the skipped items: complete once the permission is fixed", async () => {
    const t = await tempCase();
    const plan: Record<string, "ok" | "skip"> = { k1: "ok", k2: "skip", k3: "ok" };
    const session = scripted(plan, ["k1", "k2", "k3"]);
    await startCollection(t, session);
    expect((await runAgain(t, session, false)).cp.status).toBe("partial");
    plan.k2 = "ok"; // kms:Decrypt granted
    const { cp, manifest } = await runAgain(t, session, true);
    expect(cp.status).toBe("complete");
    expect(cp.missing).toEqual([]);
    expect(cp.subWindows[0].skipped ?? 0).toBe(0);
    expect(cp.coverage![0].acquiredCutoff).toBeDefined();
    expect(manifest.pages.some((p) => p.requestParams.item === "k2")).toBe(true);
    expect(manifest.entries.filter((e) => e.type === "restart")).toMatchObject([
      { subWindowId: "ct:0", reason: "skipped-retry" },
    ]);
    // Replay of the whole manifest agrees: the retry cleared the skip.
    expect(deriveSubWindows(manifest.header!, manifest.entries)[0].skipped ?? 0).toBe(0);
  });

  it("replay rebuilds the same token and count from the skip line", async () => {
    const t = await tempCase();
    const { cp, manifest } = await runOnce(
      t,
      scripted({ k1: "ok", k2: "skip", k3: "ok" }, ["k1", "k2", "k3"]),
    );
    const derived = deriveSubWindows(manifest.header!, manifest.entries);
    expect(derived[0]).toMatchObject({ state: cp.subWindows[0].state, skipped: 1, pages: 2 });
    // Cut the manifest right after the skip line: the replayed token is the skip's own next token.
    const cut = manifest.entries.slice(0, manifest.entries.findIndex((e) => e.type === "skip") + 1);
    expect(deriveSubWindows(manifest.header!, cut)[0]).toMatchObject({
      state: "pending",
      pageToken: "k2",
      skipped: 1,
    });
  });
});

describe("the always-shown source notice (#2313)", () => {
  const source: CollectSourceInfo = {
    id: "lookup",
    label: "Event history",
    streamKind: "aws",
    notice: "90 days, management events only.",
  };
  it("is in the pre-check and the result whatever the window", () => {
    const pre = precheckSource(source, WINDOW, Date.parse("2026-10-05T00:00:00Z"));
    expect(pre.warnings).toContain("90 days, management events only.");
    const cov = sourceCoverage(
      [
        {
          id: "lookup:0",
          source: "lookup",
          window: WINDOW,
          state: "done",
          pages: 1,
          records: 1,
          restarts: 0,
          firstRetrievedAt: "2026-10-05T00:00:00Z",
        },
      ],
      [source],
      { sources: ["lookup"], window: WINDOW, startedAt: "2026-10-05T00:00:00Z" },
    );
    expect(cov[0].notes).toContain("90 days, management events only.");
  });
});

// #2402: a cursor-expired restart re-reads the whole window and meets the refused item again. The
// live run kept the old skip count and added the new one; replay (on resume) clears it. Both now
// count the unresolved item once.
describe("skip counts across a live cursor restart (#2402)", () => {
  it("counts the re-skipped item once, matching what the manifest replays to", async () => {
    const t = await tempCase();
    const order = ["k1", "k2", "k3"];
    let expired = false;
    const base = scripted({ k1: "ok", k2: "skip", k3: "ok" }, order);
    const session: CloudCollectSession = {
      ...base,
      fetchPage: async (req) => {
        // After the skip, the next token has expired once: the window restarts from the top.
        if (req.pageToken === "k2" && !expired) {
          expired = true;
          throw new CursorExpiredError("page token expired");
        }
        return base.fetchPage(req);
      },
    };
    const { cp, manifest } = await runOnce(t, session);
    expect(manifest.entries.filter((e) => e.type === "restart")).toHaveLength(1);
    expect(manifest.entries.filter((e) => e.type === "skip")).toHaveLength(2); // history kept
    expect(cp.subWindows[0].skipped).toBe(1);
    const replayed = deriveSubWindows(manifest.header!, manifest.entries);
    expect(replayed[0].skipped).toBe(cp.subWindows[0].skipped);
  });
});
