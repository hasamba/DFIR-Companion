// #2306 — MFA fatigue end to end through the real import paths: the whole-file M365 import and the
// streamed one, across imports and across batches, with the success row graded Info (it never
// reaches the forensic timeline) still counted, and the finding emitted exactly once.
import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { AuthObservationStore } from "../../src/analysis/authObservationStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";

const TENANT_A = "00000000-0000-4000-8000-00000000000a";
const TENANT_B = "00000000-0000-4000-8000-00000000000b";
const BASE = Date.parse("2026-06-01T10:00:00Z");
const MIN = 60_000;

async function harness(opts: { ledger?: boolean; superStore?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-mfafatigue-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const superTimelineStore = new SuperTimelineStore(cases);
  const authObservationStore = new AuthObservationStore(cases, 168);
  const pipeline = new AnalysisPipeline({
    stateStore: new StateStore(cases),
    authObservationStore,
    ...(opts.ledger ? { cloudRecordStore: new CloudRecordStore(cases) } : {}),
    ...(opts.superStore ? { superTimelineStore } : {}),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const write = async (name: string, body: string) => {
    const p = join(root, name);
    await writeFile(p, body);
    return p;
  };
  return { pipeline, superTimelineStore, authObservationStore, write };
}

let seq = 0;
function signIn(at: number, status: Record<string, unknown>, over: Record<string, unknown> = {}) {
  seq++;
  return {
    id: `00000000-0000-4000-9000-${String(seq).padStart(12, "0")}`,
    createdDateTime: new Date(BASE + at * MIN).toISOString(),
    userPrincipalName: "victim@example.com",
    userId: "00000000-0000-4000-8000-0000000000u1",
    appDisplayName: "Office 365 Exchange Online",
    ipAddress: "203.0.113.20",
    resourceTenantId: TENANT_A,
    homeTenantId: TENANT_A,
    status,
    ...over,
  };
}
const denied = (at: number, over: Record<string, unknown> = {}) =>
  signIn(at, { errorCode: 500121, additionalDetails: "MFA denied; user declined the authentication" }, over);
const timedOut = (at: number, over: Record<string, unknown> = {}) =>
  signIn(
    at,
    { errorCode: 500121, additionalDetails: "MFA denied; user did not respond to mobile app notification" },
    over,
  );
const bare500121 = (at: number) => signIn(at, { errorCode: 500121 });
const required = (at: number) =>
  signIn(at, { errorCode: 50074, additionalDetails: "MFA required in Azure AD" });
const success = (at: number, over: Record<string, unknown> = {}) =>
  signIn(at, { errorCode: 0 }, { ipAddress: "198.51.100.7", ...over });

const fatigue = (events: ForensicEvent[]) =>
  events.filter((e) => e.description.startsWith("Possible MFA fatigue"));
const opts = (idPrefix: string) => ({
  label: `${idPrefix}.json`,
  idPrefix,
  importedAt: "2026-06-02T00:00:00Z",
});

describe("MFA fatigue — whole-file M365 import (#2306)", () => {
  it("fires on denied prompts then a success: one High row with T1621; the Info success stays out of the forensic timeline", async () => {
    const { pipeline } = await harness();
    const s = await pipeline.importM365(
      "c1",
      JSON.stringify([denied(0), timedOut(2), denied(4), success(6)]),
      opts("m1"),
    );
    const rows = fatigue(s.forensicTimeline);
    expect(rows).toHaveLength(1);
    expect(rows[0].severity).toBe("High");
    expect(rows[0].mitreTechniques).toContain("T1621");
    expect(rows[0].description).toContain("3 rejected or timed-out MFA prompts for victim@example.com");
    expect(rows[0].canonical?.evidence.rawRecords.length).toBe(4);
    // merge → tag → demote: the success row is graded Info, so the settle seam's demote moves it to
    // the super-timeline — it was still counted, from the store, before that happened.
    const successRow = s.forensicTimeline.find((e) =>
      e.description.startsWith("Entra sign-in: victim@example.com from 198.51.100.7"),
    );
    expect(successRow?.severity).toBe("Info");
  });

  it("does not fire on 50074 'MFA required' alone, nor on 500121 without a denied/timed-out detail", async () => {
    const { pipeline } = await harness();
    const s1 = await pipeline.importM365(
      "c1",
      JSON.stringify([required(0), required(1), required(2), required(3), success(4)]),
      opts("m1"),
    );
    expect(fatigue(s1.forensicTimeline)).toHaveLength(0);
    const s2 = await pipeline.importM365(
      "c1",
      JSON.stringify([bare500121(10), bare500121(11), bare500121(12), success(13)]),
      opts("m2"),
    );
    expect(fatigue(s2.forensicTimeline)).toHaveLength(0);
  });

  it("does not fire on a cross-tenant mix", async () => {
    const { pipeline } = await harness();
    const s = await pipeline.importM365(
      "c1",
      JSON.stringify([
        denied(0),
        denied(1),
        denied(2, { resourceTenantId: TENANT_B, homeTenantId: TENANT_B }),
        success(3, { resourceTenantId: TENANT_B, homeTenantId: TENANT_B }),
      ]),
      opts("m1"),
    );
    expect(fatigue(s.forensicTimeline)).toHaveLength(0);
  });

  it("across imports: prompts in one upload, the success in the next — one row, and none again on re-import", async () => {
    const { pipeline } = await harness();
    const first = JSON.stringify([denied(0), denied(1), timedOut(2)]);
    const s1 = await pipeline.importM365("c1", first, opts("m1"));
    expect(fatigue(s1.forensicTimeline)).toHaveLength(0);
    const second = JSON.stringify([success(5)]);
    const s2 = await pipeline.importM365("c1", second, opts("m2"));
    const rows = fatigue(s2.forensicTimeline);
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toContain("across 2 uploads");
    // Re-import both files (no record ledger in this wiring, so every record is parsed again).
    await pipeline.importM365("c1", first, opts("m3"));
    const s4 = await pipeline.importM365("c1", second, opts("m4"));
    expect(fatigue(s4.forensicTimeline)).toHaveLength(1);
  });

  it("an overlapping export that adds a prompt to a reported episode adds no second row", async () => {
    const { pipeline } = await harness();
    const s1 = await pipeline.importM365(
      "c1",
      JSON.stringify([denied(0), denied(1), denied(2), success(4)]),
      opts("m1"),
    );
    expect(fatigue(s1.forensicTimeline)).toHaveLength(1);
    const s2 = await pipeline.importM365("c1", JSON.stringify([denied(3)]), opts("m2"));
    expect(fatigue(s2.forensicTimeline)).toHaveLength(1);
  });

  it("with the record ledger, a re-import of the same file parses nothing and adds no row", async () => {
    const { pipeline } = await harness({ ledger: true });
    const text = JSON.stringify([denied(0), denied(1), denied(2), success(3)]);
    expect(fatigue((await pipeline.importM365("c1", text, opts("m1"))).forensicTimeline)).toHaveLength(1);
    expect(fatigue((await pipeline.importM365("c1", text, opts("m2"))).forensicTimeline)).toHaveLength(1);
  });

  // An import whose observations were appended but whose forensic state was never saved (a crash,
  // a failed save): the observations sit in the store under the failed import's batch.
  it("recovers after an import failed between the observation append and the save: the retry emits once", async () => {
    const { pipeline, authObservationStore } = await harness();
    const text = JSON.stringify([denied(0), denied(1), timedOut(2), success(3)]);
    const { signInObservations } = parseM365Audit(text);
    await authObservationStore.append(
      "c1",
      signInObservations.map((o) => ({ ...o, importBatch: "m0" })),
    );
    expect(fatigue((await pipeline.importM365("c1", text, opts("m1"))).forensicTimeline)).toHaveLength(1);
    expect(fatigue((await pipeline.importM365("c1", text, opts("m2"))).forensicTimeline)).toHaveLength(1);
  });

  it("a row a Critical floor filtered out appears once when the file is imported again with a lower floor", async () => {
    const { pipeline } = await harness({ ledger: true });
    const text = JSON.stringify([denied(0), denied(1), denied(2), success(3)]);
    const s1 = await pipeline.importM365("c1", text, { ...opts("m1"), minSeverity: "Critical" as const });
    expect(fatigue(s1.forensicTimeline)).toHaveLength(0);
    expect(fatigue((await pipeline.importM365("c1", text, opts("m2"))).forensicTimeline)).toHaveLength(1);
    expect(fatigue((await pipeline.importM365("c1", text, opts("m3"))).forensicTimeline)).toHaveLength(1);
  });

  // Upgrade: before #2306 the extractor stored a bare 500121 as mfaDetail "denied", with no
  // confirmed-detail mark, and the store keeps that row when the same record is imported again.
  it("legacy observations of bare 500121 records never count after the upgrade", async () => {
    const { pipeline, authObservationStore } = await harness();
    const prompts = [bare500121(0), bare500121(1), bare500121(2)];
    const legacy = parseM365Audit(JSON.stringify(prompts)).signInObservations.map((o) => {
      const { mfaConfirmed: _drop, ...rest } = o as typeof o & { mfaConfirmed?: boolean };
      return { ...rest, mfaDetail: "denied" as const, outcome: "interrupted" as const, importBatch: "old" };
    });
    expect(legacy.every((o) => o.resultCode === "500121")).toBe(true);
    await authObservationStore.append("c1", legacy);
    const s = await pipeline.importM365("c1", JSON.stringify([...prompts, success(3)]), opts("m1"));
    expect(fatigue(s.forensicTimeline)).toHaveLength(0);
  });
});

describe("MFA fatigue — streamed M365 import (#2306)", () => {
  it("prompts and success in different batches still make one row", async () => {
    const { pipeline, write } = await harness({ ledger: true, superStore: true });
    const path = await write(
      "s.jsonl",
      [denied(0), denied(1), timedOut(2), success(3)].map((r) => JSON.stringify(r)).join("\n"),
    );
    const { state } = await pipeline.importCloudFile("c1", "m365", path, { ...opts("s1"), batchRecords: 1 });
    const rows = fatigue(state.forensicTimeline);
    expect(rows).toHaveLength(1);
    expect(rows[0].severity).toBe("High");
  });

  it("a streamed import completes an episode a whole-file import started, then a re-import adds nothing", async () => {
    const { pipeline, write } = await harness({ ledger: true, superStore: true });
    await pipeline.importM365("c1", JSON.stringify([denied(0), denied(1), denied(2)]), opts("m1"));
    const path = await write("s.jsonl", JSON.stringify(success(4)));
    const a = await pipeline.importCloudFile("c1", "m365", path, { ...opts("s1"), batchRecords: 1 });
    expect(fatigue(a.state.forensicTimeline)).toHaveLength(1);
    const b = await pipeline.importCloudFile("c1", "m365", path, { ...opts("s2"), batchRecords: 1 });
    expect(fatigue(b.state.forensicTimeline)).toHaveLength(1);
  });

  it("streamed: a retry after a failed import, and a lower floor after a Critical one, each emit once", async () => {
    const { pipeline, authObservationStore, write } = await harness({ ledger: true, superStore: true });
    const rows = [denied(0), denied(1), timedOut(2), success(3)];
    const { signInObservations } = parseM365Audit(JSON.stringify(rows));
    await authObservationStore.append(
      "c1",
      signInObservations.map((o) => ({ ...o, importBatch: "s0" })),
    );
    const path = await write("r.jsonl", rows.map((r) => JSON.stringify(r)).join("\n"));
    const floored = await pipeline.importCloudFile("c1", "m365", path, {
      ...opts("s1"),
      batchRecords: 1,
      minSeverity: "Critical" as const,
    });
    expect(fatigue(floored.state.forensicTimeline)).toHaveLength(0);
    const a = await pipeline.importCloudFile("c1", "m365", path, { ...opts("s2"), batchRecords: 1 });
    expect(fatigue(a.state.forensicTimeline)).toHaveLength(1);
    const b = await pipeline.importCloudFile("c1", "m365", path, { ...opts("s3"), batchRecords: 1 });
    expect(fatigue(b.state.forensicTimeline)).toHaveLength(1);
  });
});
