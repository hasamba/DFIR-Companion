import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AuthObservationStore } from "../../src/analysis/authObservationStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";

// One ECAR failed-logon record — same shape ecarImport.test.ts's own spray fixtures use.
function loginRec(principal: string, baseMs: number, offsetMs: number, srcIp = "10.44.30.10") {
  return {
    timestamp_ms: baseMs + offsetMs,
    id: "00000000-0000-0000-0000-000000000000",
    hostname: "WEB-BO-01",
    object: "USER_SESSION",
    action: "LOGIN",
    principal,
    properties: { src_ip: srcIp, outcome: "failure", logon_type: "3", failure_reason: "bad password" },
  };
}
function ndjson(...recs: object[]): string {
  return recs.map((r) => JSON.stringify(r)).join("\n");
}

const BASE_MS = Date.parse("2026-06-01T00:00:00Z");
const MIN = 60_000;

async function makePipeline(caseId = "c1") {
  const root = await mkdtemp(join(tmpdir(), "dfir-crossspray-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const authObservationStore = new AuthObservationStore(cases, 168);
  const pipeline = new AnalysisPipeline({
    stateStore,
    authObservationStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  return { pipeline, authObservationStore };
}

function sprayRows<T extends { mitreTechniques: string[] }>(events: T[]): T[] {
  return events.filter((e) => e.mitreTechniques.includes("T1110.003"));
}

// One Entra sign-in record — same shape m365Import.test.ts's own spray fixtures use.
function signinRec(upn: string, baseMs: number, offsetMs: number) {
  return {
    createdDateTime: new Date(baseMs + offsetMs).toISOString(),
    userPrincipalName: upn,
    appDisplayName: "Azure CLI",
    ipAddress: "198.51.100.9",
    status: { errorCode: 50126 },
    resourceTenantId: "tenant-a",
  };
}

describe("cross-upload password-spray detection (#1104)", () => {
  it("two uploads each below threshold combine to cross it; exactly one cross-upload row appears", async () => {
    const { pipeline } = await makePipeline();

    // Call 1: 4 distinct accounts, below the default threshold of 5 alone. Spaced 20 minutes
    // apart — outside the 10-minute burst window (so no burst episode ever reaches 2 accounts),
    // inside the 24-hour slow window (so all 4 land in one slow episode).
    const first = ["alice", "bob", "carol", "dave"].map((a, i) => loginRec(a, BASE_MS, i * 20 * MIN));
    const s1 = await pipeline.importEcar("c1", ndjson(...first), {
      label: "batch1.ecar.json",
      idPrefix: "e1",
      importedAt: "2026-06-01T01:05:00Z",
    });
    expect(sprayRows(s1.forensicTimeline)).toHaveLength(0);

    // Call 2: 2 NEW distinct accounts, continuing the same 20-minute cadence — combined distinct
    // count is 6, all inside the same slow episode.
    const second = ["erin", "frank"].map((a, i) => loginRec(a, BASE_MS, (4 + i) * 20 * MIN));
    const s2 = await pipeline.importEcar("c1", ndjson(...second), {
      label: "batch2.ecar.json",
      idPrefix: "e2",
      importedAt: "2026-06-01T01:45:00Z",
    });
    const cross = sprayRows(s2.forensicTimeline).filter((e) => e.description.includes("across"));
    expect(cross).toHaveLength(1);
    expect(cross[0].description).toMatch(/across 2 uploads/);
  });

  it("a backdated upload (importedAt far after the events it carries) still finds the prior batch's observations (#1237)", async () => {
    const { pipeline } = await makePipeline("c1b");

    // Call 1: imported the same day its events happened, same shape as the first test above.
    const first = ["alice", "bob", "carol", "dave"].map((a, i) => loginRec(a, BASE_MS, i * 20 * MIN));
    const s1 = await pipeline.importEcar("c1b", ndjson(...first), {
      label: "batch1.ecar.json",
      idPrefix: "b1",
      importedAt: "2026-06-01T01:05:00Z",
    });
    expect(sprayRows(s1.forensicTimeline)).toHaveLength(0);

    // Call 2 carries events from the SAME day (so the combined episode is still one slow episode),
    // but was actually uploaded to the companion 3 days later — a re-upload, a delayed bulk export,
    // exactly the lag DFIR uploads routinely have. `importedAt` is real wall-clock upload time, far
    // outside the default 24h slow-spray window measured from event time. Before the #1237 fix, the
    // window was anchored on `importedAt`, so the query for batch 1's stored observations would miss
    // them entirely and no cross-upload row would appear.
    const second = ["erin", "frank"].map((a, i) => loginRec(a, BASE_MS, (4 + i) * 20 * MIN));
    const s2 = await pipeline.importEcar("c1b", ndjson(...second), {
      label: "batch2.ecar.json",
      idPrefix: "b2",
      importedAt: "2026-06-04T09:00:00Z",
    });
    const cross = sprayRows(s2.forensicTimeline).filter((e) => e.description.includes("across"));
    expect(cross).toHaveLength(1);
    expect(cross[0].description).toMatch(/across 2 uploads/);
  });

  it("dominance: a batch that already crosses the threshold alone suppresses the cross-upload row", async () => {
    const { pipeline } = await makePipeline("c2");

    // Call 1 alone already has 5 distinct accounts (spaced 20 minutes apart — one slow episode,
    // no burst episode, same reasoning as the test above) — the within-upload pass reports it.
    const first = ["alice", "bob", "carol", "dave", "erin"].map((a, i) => loginRec(a, BASE_MS, i * 20 * MIN));
    const s1 = await pipeline.importEcar("c2", ndjson(...first), {
      label: "batch1.ecar.json",
      idPrefix: "d1",
      importedAt: "2026-06-01T01:25:00Z",
    });
    expect(sprayRows(s1.forensicTimeline)).toHaveLength(1);

    // Call 2 adds 2 more distinct accounts — combined batch d1 ALONE still has 5 >= threshold,
    // so the dominance filter must suppress a second, duplicate cross-upload row.
    const second = ["frank", "grace"].map((a, i) => loginRec(a, BASE_MS, (5 + i) * 20 * MIN));
    const s2 = await pipeline.importEcar("c2", ndjson(...second), {
      label: "batch2.ecar.json",
      idPrefix: "d2",
      importedAt: "2026-06-01T02:05:00Z",
    });
    expect(sprayRows(s2.forensicTimeline)).toHaveLength(1);
    expect(sprayRows(s2.forensicTimeline).some((e) => e.description.includes("across"))).toBe(false);
  });

  it("re-importing the same file writes no new observations and no duplicate cross-upload row", async () => {
    const { pipeline, authObservationStore } = await makePipeline("c3");

    const first = ["alice", "bob", "carol", "dave"].map((a, i) => loginRec(a, BASE_MS, i * 20 * MIN));
    const firstText = ndjson(...first);
    await pipeline.importEcar("c3", firstText, {
      label: "batch1.ecar.json",
      idPrefix: "r1",
      importedAt: "2026-06-01T01:05:00Z",
    });
    const second = ["erin", "frank"].map((a, i) => loginRec(a, BASE_MS, (4 + i) * 20 * MIN));
    const s2 = await pipeline.importEcar("c3", ndjson(...second), {
      label: "batch2.ecar.json",
      idPrefix: "r2",
      importedAt: "2026-06-01T01:45:00Z",
    });
    const crossAfterTwo = sprayRows(s2.forensicTimeline).filter((e) => e.description.includes("across"));
    expect(crossAfterTwo).toHaveLength(1);

    const before = await authObservationStore.queryWindow("c3", "2026-01-01T00:00:00Z");
    expect(before.observations).toHaveLength(6); // 4 + 2 distinct observations so far

    // Re-import call 1's exact text under a NEW idPrefix, as a real re-upload would arrive.
    const s3 = await pipeline.importEcar("c3", firstText, {
      label: "batch1-again.ecar.json",
      idPrefix: "r3",
      importedAt: "2026-06-01T02:00:00Z",
    });
    const after = await authObservationStore.queryWindow("c3", "2026-01-01T00:00:00Z");
    expect(after.observations).toHaveLength(6); // no new rows for the duplicate observations

    const crossAfterThree = sprayRows(s3.forensicTimeline).filter((e) => e.description.includes("across"));
    // The recomputed pattern has the identical aggKey, so it collapses onto the existing row
    // rather than adding a second one.
    expect(crossAfterThree).toHaveLength(1);
  });

  it("a burst cross-upload pattern (Medium) survives a minSeverity floor that drops the call's own Low source rows", async () => {
    const { pipeline } = await makePipeline("c4");

    const first = ["alice", "bob", "carol", "dave"].map((a, i) => loginRec(a, BASE_MS, i * 1000));
    await pipeline.importEcar("c4", ndjson(...first), {
      label: "batch1.ecar.json",
      idPrefix: "f1",
      importedAt: "2026-06-01T00:00:00Z",
    });

    // This call's own 2 records are Low-severity failed logons — minSeverity: Medium floors them
    // to zero on their own. The combined burst pattern (Medium) must still survive.
    const second = ["erin", "frank"].map((a, i) => loginRec(a, BASE_MS, (4 + i) * 1000));
    const s2 = await pipeline.importEcar("c4", ndjson(...second), {
      label: "batch2.ecar.json",
      idPrefix: "f2",
      importedAt: "2026-06-01T00:05:00Z",
      minSeverity: "Medium",
    });
    const cross = sprayRows(s2.forensicTimeline).filter((e) => e.description.includes("across"));
    expect(cross).toHaveLength(1);
    expect(cross[0].severity).toBe("Medium");
  });

  it("a batch whose events predate the retention window discloses that later uploads cannot correlate with it (#1286, #1299)", async () => {
    const { pipeline } = await makePipeline("c6");

    // Events dated 30 days before real wall-clock now — well past the store's 168h (7-day)
    // retention window. `pruneIfDue` keys off Date.now(), not this batch's own anchor, so these
    // observations will not survive to be cross-matched by a later upload; the analyst must be
    // told, not left to notice a silent non-match weeks later.
    const staleBaseMs = Date.now() - 30 * 24 * 3_600_000;
    const first = ["alice", "bob"].map((a, i) => loginRec(a, staleBaseMs, i * 20 * MIN));
    const s1 = await pipeline.importEcar("c6", ndjson(...first), {
      label: "stale-batch.ecar.json",
      idPrefix: "st1",
      importedAt: new Date().toISOString(),
    });
    // No cross-upload row from a single batch below threshold — the disclosure is independent of
    // whether any spray pattern was actually detected.
    expect(sprayRows(s1.forensicTimeline).filter((e) => e.description.includes("across"))).toHaveLength(0);

    const note = s1.timeline.find((t) => t.description.includes("ECAR import"));
    expect(note).toBeDefined();
    expect(note?.description).toMatch(/retention window/i);
    // The query DID run for this batch (anchored on its own earliest event, #1237), and it can
    // still match prior observations of the same age — the limit is one-directional: later
    // uploads cannot reach it once the wall-clock prune removes it. The note must not claim more.
    expect(note?.description).toMatch(/later uploads cannot be correlated with it/);
    expect(note?.description).not.toMatch(/could not run/);
  });

  it("the retention disclosure on an EMPTY import is a '; '-joined clause, the same shape as the non-empty note (#1300)", async () => {
    const { pipeline } = await makePipeline("c8");

    // Stale batch (past the 168h retention) whose two Low failed logons are floored out by
    // minSeverity: Medium — zero events, so the importer takes the noteEmptyImport path with the
    // retention disclosure as its `detail`. That path used to parenthesise the detail while the
    // non-empty path joined it with "; ", so the same fact rendered two ways.
    const staleBaseMs = Date.now() - 30 * 24 * 3_600_000;
    const first = ["alice", "bob"].map((a, i) => loginRec(a, staleBaseMs, i * 20 * MIN));
    const s1 = await pipeline.importEcar("c8", ndjson(...first), {
      label: "stale-empty.ecar.json",
      idPrefix: "se1",
      importedAt: new Date().toISOString(),
      minSeverity: "Medium",
    });
    expect(s1.forensicTimeline).toHaveLength(0);

    const note = s1.timeline.find((t) => t.description.includes("ECAR import"));
    expect(note).toBeDefined();
    expect(note?.description).toContain("nothing added to the case; cross-upload spray matching");
    expect(note?.description).not.toContain("(cross-upload");
  });

  it("a fresh batch (recent events) does NOT carry the retention-exceeded disclosure", async () => {
    const { pipeline } = await makePipeline("c7");

    const freshBaseMs = Date.now() - 5 * MIN;
    const first = ["alice", "bob"].map((a, i) => loginRec(a, freshBaseMs, i * MIN));
    const s1 = await pipeline.importEcar("c7", ndjson(...first), {
      label: "fresh-batch.ecar.json",
      idPrefix: "fr1",
      importedAt: new Date().toISOString(),
    });

    const note = s1.timeline.find((t) => t.description.includes("ECAR import"));
    expect(note).toBeDefined();
    expect(note?.description).not.toMatch(/retention window/i);
  });

  it("importM365 detects the same cross-upload pattern over Entra sign-ins", async () => {
    const { pipeline } = await makePipeline("c5");

    const first = ["alice", "bob", "carol", "dave"].map((a, i) =>
      signinRec(`${a}@victim.com`, BASE_MS, i * 20 * MIN),
    );
    const s1 = await pipeline.importM365("c5", JSON.stringify(first), {
      label: "batch1.json",
      idPrefix: "m1",
      importedAt: "2026-06-01T01:05:00Z",
    });
    expect(sprayRows(s1.forensicTimeline)).toHaveLength(0);

    const second = ["erin", "frank"].map((a, i) => signinRec(`${a}@victim.com`, BASE_MS, (4 + i) * 20 * MIN));
    const s2 = await pipeline.importM365("c5", JSON.stringify(second), {
      label: "batch2.json",
      idPrefix: "m2",
      importedAt: "2026-06-01T01:45:00Z",
    });
    const cross = sprayRows(s2.forensicTimeline).filter((e) => e.description.includes("across"));
    expect(cross).toHaveLength(1);
  });
});
