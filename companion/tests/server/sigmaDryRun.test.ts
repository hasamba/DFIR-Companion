// POST /cases/:id/sigma/dry-run (#2211): the compile answer plus "would match N events in this
// case", read from both timelines through the real stores. It must write nothing to the case.
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

const ev = (
  id: string,
  path: string,
  commandLine: string,
  severity: ForensicEvent["severity"],
): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: `process ${id}`,
  severity,
  sources: [],
  asset: "WS-01",
  path,
  commandLine,
  processName: path.split("\\").pop(),
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const RULE = `
title: Certutil download
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains: 'urlcache'
  condition: sel
`;

let cases: CaseStore;
let stateStore: StateStore;
let superStore: SuperTimelineStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-sigma-dryrun-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  const forensic = ev("f1", "C:\\Windows\\System32\\certutil.exe", "certutil -urlcache -f", "High");
  await stateStore.save({ ...emptyState("c1"), forensicTimeline: [forensic] });
  superStore = new SuperTimelineStore(cases);
  await superStore.append("c1", [
    forensic,
    ev("raw1", "C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split", "Info"),
    ev("raw2", "C:\\Windows\\notepad.exe", "notepad", "Info"),
  ]);
});

const post = (app: ReturnType<typeof createApp>, yaml: unknown, caseId = "c1") =>
  request(app).post(`/cases/${caseId}/sigma/dry-run`).send({ yaml });

async function snapshot() {
  const state = await stateStore.load("c1");
  const raw = await superStore.queryIndexed("c1", { limit: 1000 });
  return JSON.stringify({ state, raw: raw.entities });
}

describe("POST /cases/:id/sigma/dry-run", () => {
  it("returns the compile answer and the dry-run over both timelines, deduped", async () => {
    const app = createApp(cases, { stateStore, superTimelineStore: superStore });
    const res = await post(app, RULE);
    expect(res.status, res.text).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.vql).toContain("pslist()");
    expect(res.body.dryRun).toMatchObject({
      ok: true,
      datasets: ["forensic", "super"],
      scanned: 3,
      eligible: 3,
      matched: 2,
      truncated: false,
    });
    expect(res.body.dryRun.sampleIds.sort()).toEqual(["f1", "raw1"]);
  });

  it("changes nothing in the case", async () => {
    const app = createApp(cases, { stateStore, superTimelineStore: superStore });
    const before = await snapshot();
    expect((await post(app, RULE)).status).toBe(200);
    expect(await snapshot()).toBe(before);
  });

  it("scans the forensic timeline alone when no super-timeline store is configured, and says so", async () => {
    const app = createApp(cases, { stateStore });
    const res = await post(app, RULE);
    expect(res.status).toBe(200);
    expect(res.body.dryRun).toMatchObject({ datasets: ["forensic"], scanned: 1, matched: 1 });
  });

  it("still dry-runs a rule the VQL compiler refuses, so both answers show", async () => {
    const app = createApp(cases, { stateStore, superTimelineStore: superStore });
    const res = await post(app, RULE.replace("CommandLine|contains", "SignatureStatus|contains"));
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(false);
    expect(res.body.dryRun.ok).toBe(true);
    expect(res.body.dryRun.fields).toContainEqual({ field: "SignatureStatus", checkable: false, carried: 0 });
  });

  it("answers malformed YAML with 400 and no dry-run", async () => {
    const app = createApp(cases, { stateStore, superTimelineStore: superStore });
    const res = await post(app, "title: [unclosed\n");
    expect(res.status).toBe(400);
    expect(res.body.dryRun).toBeUndefined();
  });

  it("answers 400 without a rule, 404 for an unknown case, 501 without a state store", async () => {
    const app = createApp(cases, { stateStore, superTimelineStore: superStore });
    expect((await post(app, "")).status).toBe(400);
    expect((await post(app, RULE, "nope")).status).toBe(404);
    expect((await post(createApp(cases), RULE)).status).toBe(501);
  });
});
