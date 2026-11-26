// Stored report versions and releases never hand the internal grade mark to a client (#2934).
//
// A version snapshot written on a development build between #2891 and #2909 could hold forensic rows
// with `gradePending` (true or "held") still on them, and a release freezes the version verbatim. The
// served copies drop the mark; the STORED release stays byte-for-byte as frozen, because its manifest
// hash covers the whole record and the server's integrity check re-hashes the stored bytes.
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";
import { ScopeStore } from "../../src/analysis/scope.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { ReportMetaStore } from "../../src/reports/reportMeta.js";
import { ReportReleaseStore } from "../../src/reports/reportReleaseStore.js";
import { ReportVersionStore, type ReportVersionRecord } from "../../src/reports/reportVersionStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const roots: string[] = [];

afterEach(async () => {
  // Windows can still hold a handle for a moment after the app's last write.
  await Promise.all(
    roots.splice(0).map((r) => rm(r, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })),
  );
});

function row(id: string, mark?: true | "held"): ForensicEvent {
  return {
    id,
    timestamp: "2026-07-30T00:00:00.000Z",
    severity: "High",
    description: `Synthetic event ${id}`,
    mitreTechniques: ["T1059"],
    relatedFindingIds: [],
    sourceScreenshots: ["paste-1.txt"],
    ...(mark !== undefined ? { gradePending: mark } : {}),
  };
}

const MARKED_ROWS = [row("e-plain", true), row("e-held", "held"), row("e-unmarked")];

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-rv-mark-"));
  roots.push(root);
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const reportMetaStore = new ReportMetaStore(store);
  const reportVersionStore = new ReportVersionStore(store);
  const analysisRunStore = new AnalysisRunStore(store, { appVersion: "test" });
  const custodyStore = new CustodyStore(store);
  const reportWriter = new ReportWriter(store, stateStore, {
    scope: new ScopeStore(store),
    falsePositives: new FalsePositiveStore(store),
    reportMeta: reportMetaStore,
    reportVersions: reportVersionStore,
    analysisRuns: analysisRunStore,
  });
  const app = createApp(store, {
    stateStore,
    reportWriter,
    reportMetaStore,
    reportVersionStore,
    analysisRunStore,
    custodyStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, reportVersionStore, analysisRunStore, custodyStore };
}

type Harness = Awaited<ReturnType<typeof harness>>;

/** Generate a report, then rewrite its stored version as a pre-#2909 dev build would have left it. */
async function markedVersion(h: Harness): Promise<{ id: string; path: string; raw: string }> {
  await request(h.app).put("/cases/c1/report-meta").send({ organization: "ExampleCorp" });
  expect((await request(h.app).post("/cases/c1/report")).status).toBe(200);
  const id = (await request(h.app).get("/cases/c1/report-versions")).body[0].id as string;
  const path = join(h.store.stateDir("c1"), "report-versions", `${id}.json`);
  const stored = JSON.parse(await readFile(path, "utf8")) as ReportVersionRecord;
  const marked = { ...stored, state: { ...stored.state, forensicTimeline: MARKED_ROWS } };
  const raw = JSON.stringify(marked, null, 2);
  await writeFile(path, raw);
  return { id, path, raw };
}

async function selfApprove(h: Harness, versionId: string): Promise<void> {
  const res = await request(h.app)
    .post(`/cases/c1/report-versions/${versionId}/workflow/self-approve`)
    .send({ note: "Self-reviewed" });
  expect(res.status).toBe(200);
}

/** Freeze a release straight through the release store, mark inside, with a valid manifest hash. */
async function frozenMarkedRelease(h: Harness, versionPath: string, versionId: string) {
  const version = JSON.parse(await readFile(versionPath, "utf8")) as ReportVersionRecord;
  expect(version.state.forensicTimeline.filter((e) => "gradePending" in e)).toHaveLength(2);
  const workflow = await h.reportVersionStore.workflow("c1", versionId);
  const runs = await Promise.all(
    (version.analysisRunIds ?? []).map((id) => h.analysisRunStore.get("c1", id)),
  );
  return new ReportReleaseStore(h.store).create("c1", {
    version,
    workflow: workflow!,
    actor: { id: "solo", displayName: "Solo investigator", kind: "solo" },
    analysisRuns: runs.filter((r): r is NonNullable<typeof r> => r !== null),
    analysisIntegrity: await h.analysisRunStore.verify("c1"),
    custody: { head: await h.custodyStore.chainHead("c1"), chainBreaks: [], mismatches: [] },
  });
}

async function releaseFiles(h: Harness): Promise<Map<string, string>> {
  const dir = join(h.store.stateDir("c1"), "report-releases");
  const names = await readdir(dir);
  return new Map(
    await Promise.all(names.map(async (n) => [n, await readFile(join(dir, n), "utf8")] as const)),
  );
}

const expectRowsUnmarked = (rows: Array<Record<string, unknown>>): void => {
  expect(rows.map((e) => e.id)).toEqual(["e-plain", "e-held", "e-unmarked"]);
  for (const e of rows) {
    expect(e).not.toHaveProperty("gradePending");
    // Every other field survives the strip.
    expect(e).toMatchObject({
      severity: "High",
      description: `Synthetic event ${String(e.id)}`,
      mitreTechniques: ["T1059"],
      sourceScreenshots: ["paste-1.txt"],
    });
  }
};

describe("stored report snapshots never serve the grade mark (#2934)", () => {
  it("a stored version is read without the mark, and its file is left as stored", async () => {
    const h = await harness();
    const v = await markedVersion(h);

    const read = await h.reportVersionStore.get("c1", v.id);
    expectRowsUnmarked(read!.state.forensicTimeline as unknown as Array<Record<string, unknown>>);
    expect(read!.markdown.length).toBeGreaterThan(0);
    expect(read!.meta.organization).toBe("ExampleCorp");
    expect(await readFile(v.path, "utf8")).toBe(v.raw);
  });

  it("a damaged stored version without rows is read as it is, not thrown on", async () => {
    const h = await harness();
    const v = await markedVersion(h);
    const { state: _state, ...withoutState } = JSON.parse(v.raw) as ReportVersionRecord;
    await writeFile(v.path, JSON.stringify(withoutState));

    const read = await h.reportVersionStore.get("c1", v.id);
    expect(read).toEqual(withoutState);
  });

  it("releasing a marked version freezes and returns a snapshot without the mark", async () => {
    const h = await harness();
    const v = await markedVersion(h);
    await selfApprove(h, v.id);

    const released = await request(h.app).post(`/cases/c1/report-versions/${v.id}/workflow/release`).send({});
    expect(released.status).toBe(201);
    expect(released.text).not.toContain("gradePending");
    expectRowsUnmarked(released.body.snapshot.state.forensicTimeline);

    const files = await releaseFiles(h);
    expect([...files.values()].some((text) => text.includes("gradePending"))).toBe(false);
    expect((await request(h.app).get("/cases/c1/report-releases/integrity")).body.ok).toBe(true);
  });

  it("a release frozen with the mark is served without it; the stored record and its hash stay intact", async () => {
    const h = await harness();
    const v = await markedVersion(h);
    await selfApprove(h, v.id);
    const frozen = await frozenMarkedRelease(h, v.path, v.id);
    const before = await releaseFiles(h);
    expect(before.get(`${frozen.id}.json`)).toContain('"gradePending": "held"');

    const got = await request(h.app).get(`/cases/c1/report-releases/${frozen.id}`);
    expect(got.status).toBe(200);
    expect(got.text).not.toContain("gradePending");
    expectRowsUnmarked(got.body.snapshot.state.forensicTimeline);
    // The served copy keeps the STORED record's identity — the hash is never recomputed.
    expect(got.body.manifestHash).toBe(frozen.manifestHash);

    const diff = await request(h.app).get(`/cases/c1/report-releases/diff?from=${frozen.id}&to=${frozen.id}`);
    expect(diff.status).toBe(200);
    expect(diff.text).not.toContain("gradePending");
    for (const pack of ["technical", "executive", "legal", "ioc"]) {
      const res = await request(h.app).get(`/cases/c1/report-releases/${frozen.id}/packs/${pack}`);
      expect(res.status).toBe(200);
      expect(res.text).not.toContain("gradePending");
    }

    expect((await request(h.app).get("/cases/c1/report-releases/integrity")).body.ok).toBe(true);
    expect(await releaseFiles(h)).toEqual(before);
  });

  it("a retried interrupted release returns the stored record without the mark and adds no release", async () => {
    const h = await harness();
    const v = await markedVersion(h);
    await selfApprove(h, v.id);
    // The release record landed but the workflow was never marked released (a crash in between).
    const frozen = await frozenMarkedRelease(h, v.path, v.id);
    const before = await releaseFiles(h);

    const retried = await request(h.app).post(`/cases/c1/report-versions/${v.id}/workflow/release`).send({});
    expect(retried.status).toBe(201);
    expect(retried.body.id).toBe(frozen.id);
    expect(retried.body.manifestHash).toBe(frozen.manifestHash);
    expect(retried.text).not.toContain("gradePending");
    expectRowsUnmarked(retried.body.snapshot.state.forensicTimeline);

    expect((await request(h.app).get("/cases/c1/report-releases")).body).toHaveLength(1);
    const workflow = await request(h.app).get(`/cases/c1/report-versions/${v.id}/workflow`);
    expect(workflow.body.status).toBe("released");
    expect(await releaseFiles(h)).toEqual(before);
    expect((await request(h.app).get("/cases/c1/report-releases/integrity")).body.ok).toBe(true);
  });
});
