// #2543 review: a streamed CloudTrail import (every .json.gz upload) keeps the identity IOCs' link
// to the row that produced them. Without `extractedFrom` an `other` IOC is an observation, so the
// IAM principal and the issued key were missing from the signal lens and the report IOC table even
// though they came from High/Critical rows. The link must survive batching: a value first seen in
// one batch and again in a later one links to the rows of both.
import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { iocsLinkedToHighEvent } from "../../src/analysis/iocHighLink.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";
import { ATTACKER_KEY, CREATED_KEY, LAB_ACCOUNT, sans504Upload } from "./fixtures/sans504Lab.js";

const USER_ARN = `arn:aws:iam::${LAB_ACCOUNT}:user/example-user`;
const IDENTITY = [USER_ARN, ATTACKER_KEY, CREATED_KEY, "examplepolicy1"];

async function streamLab(batchRecords: number): Promise<InvestigationState> {
  const root = await mkdtemp(join(tmpdir(), "dfir-streamioclink-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const pipeline = new AnalysisPipeline({
    stateStore: new StateStore(cases),
    superTimelineStore: new SuperTimelineStore(cases),
    cloudRecordStore: new CloudRecordStore(cases),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const path = join(root, "trail.json.gz");
  await writeFile(path, gzipSync(sans504Upload()));
  const { state, disclosure } = await pipeline.importCloudFile("c1", "aws", path, {
    label: "trail.json.gz",
    idPrefix: "g1",
    importedAt: "2026-11-10T00:00:00Z",
    batchRecords,
  });
  expect(disclosure.gzip).toBe(true);
  return state;
}

/** For each identity value: how many High/Critical forensic events it links to. */
function highLinks(state: InvestigationState): Record<string, number> {
  const high = new Set(
    state.forensicTimeline.filter((e) => e.severity === "High" || e.severity === "Critical").map((e) => e.id),
  );
  return Object.fromEntries(
    IDENTITY.map((v) => {
      const ioc = state.iocs.find((i) => i.value === v);
      return [v, (ioc?.extractedFrom ?? []).filter((id) => high.has(id)).length];
    }),
  );
}

describe("streamed CloudTrail import keeps the identity IOCs' event link (#2543)", () => {
  it("links each identity IOC to existing High/Critical forensic events", async () => {
    const state = await streamLab(4);
    const eventIds = new Set(state.forensicTimeline.map((e) => e.id));
    for (const v of IDENTITY) {
      const ioc = state.iocs.find((i) => i.value === v);
      expect(ioc, v).toBeDefined();
      expect(ioc?.extractedFrom?.length, v).toBeGreaterThan(0);
      for (const id of ioc?.extractedFrom ?? []) expect(eventIds.has(id), `${v} → ${id}`).toBe(true);
    }
    for (const [v, n] of Object.entries(highLinks(state))) expect(n, v).toBeGreaterThan(0);
  }, 60_000);

  it("puts the principal and the issued key in the signal set and the report IOC table", async () => {
    const state = await streamLab(4);
    const linked = iocsLinkedToHighEvent(state.iocs, state.forensicTimeline);
    const md = renderMarkdownReport(state);
    const table = md.slice(md.indexOf("### 4.4"), md.indexOf("\n\n", md.indexOf("| ID |")));
    for (const v of [USER_ARN, CREATED_KEY]) {
      const ioc = state.iocs.find((i) => i.value === v);
      expect(linked.has(ioc!.id), v).toBe(true);
      expect(table, v).toContain(v);
    }
  }, 60_000);

  // One record per batch: every link past the first came from a later batch. (The counts are not
  // compared with a one-batch run: the precursor raise grades the later versioning check High only
  // when the CreateAccessKey is in the same batch. Split apart, the check is mapped at Info, yields
  // no IOC, and reaches the forensic timeline later through the cross-upload precursor promotion.)
  it("unions the links across batches: a value seen in several batches links to each row", async () => {
    const state = await streamLab(1);
    const links = highLinks(state);
    expect(links[USER_ARN]).toBeGreaterThan(1);
    expect(links[ATTACKER_KEY]).toBeGreaterThan(1);
    const ioc = state.iocs.find((i) => i.value === USER_ARN);
    const eventIds = new Set(state.forensicTimeline.map((e) => e.id));
    for (const id of ioc?.extractedFrom ?? []) expect(eventIds.has(id), id).toBe(true);
  }, 60_000);
});
