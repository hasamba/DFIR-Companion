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
