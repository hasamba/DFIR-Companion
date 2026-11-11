// #2570: the M365 BEC pairings (#2550) split across streamed batches. A streamed import parses in
// batches (two records each here), so a pair whose halves land in different batches was never seen
// by one parse call. The grades must equal a whole-file import of the same records.
import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { AuthObservationStore } from "../../src/analysis/authObservationStore.js";
import { CloudCoverageStore } from "../../src/analysis/cloudCoverage.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { addUser, deleter, filler, forwardOut, grantAdmin, pairRole } from "./fixtures/m365BecRecords.js";

type Rec = Record<string, unknown>;

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "dfir-bec-stream-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const pipeline = new AnalysisPipeline({
    stateStore: new StateStore(cases),
    superTimelineStore: new SuperTimelineStore(cases),
    cloudRecordStore: new CloudRecordStore(cases),
    cloudCoverageStore: new CloudCoverageStore(cases),
    authObservationStore: new AuthObservationStore(cases, 168),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const write = async (name: string, body: string) => {
    const p = join(root, name);
    await writeFile(p, body);
    return p;
  };
  return { pipeline, write };
}

const grades = (evs: readonly ForensicEvent[]): string[] =>
  evs
    .map((e) => `${pairRole(e.description)}:${e.severity}`)
    .filter((x) => !x.startsWith(":"))
    .sort();

/** Stream `recs` in two-record batches and import them whole; both grade lists, streamed first. */
async function streamVsWhole(recs: Rec[]): Promise<{ stream: string[]; whole: string[] }> {
  const text = JSON.stringify(recs);
  const a = await setup();
  const b = await setup();
  const whole = await a.pipeline.importM365("c1", text, {
    label: "w.json",
    idPrefix: "w1",
    importedAt: "2026-11-11T00:00:00Z",
  });
  const streamed = await b.pipeline.importCloudFile("c1", "m365", await b.write("s.json", text), {
    label: "s.json",
    idPrefix: "s1",
    importedAt: "2026-11-11T00:00:00Z",
    batchRecords: 2,
  });
  return { stream: grades(streamed.state.forensicTimeline), whole: grades(whole.forensicTimeline) };
}

describe("BEC pairings across a streamed batch boundary (#2570)", () => {
  it("forward-out rule in batch 1, hiding rule in batch 2: Critical, as a whole-file import", async () => {
    const { stream, whole } = await streamVsWhole([forwardOut(0), filler(1), deleter(2)]);
    expect(stream).toContain("hide:Critical");
    expect(stream).toEqual(whole);
  });
  it("hiding rule first, forward-out rule in a later batch: Critical", async () => {
    const { stream, whole } = await streamVsWhole([deleter(0), filler(1), forwardOut(3)]);
    expect(stream).toContain("hide:Critical");
    expect(stream).toEqual(whole);
  });
  it("Add user in batch 1, privileged grant in batch 2: the grant is High", async () => {
    const { stream, whole } = await streamVsWhole([addUser(0), filler(1), grantAdmin(2)]);
    expect(stream).toContain("grant:High");
    expect(stream).toContain("created:Medium");
    expect(stream).toEqual(whole);
  });
  it("grant record first in the file, the earlier creation in a later batch: High", async () => {
    const { stream, whole } = await streamVsWhole([grantAdmin(2), filler(1), addUser(0)]);
    expect(stream).toContain("grant:High");
    expect(stream).toEqual(whole);
  });
});
