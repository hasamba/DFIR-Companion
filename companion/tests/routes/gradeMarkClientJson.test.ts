// #2918: the grade mark (analysis/gradeMark.ts, `gradePending`) is server bookkeeping. No client-facing
// JSON may carry it: every GET route of a case is called on a case holding a marked row, and each body
// is byte-searched for the field name. The case-state route is checked with and without a search.
// #2930: the sweep also covers GET routes with path parameters beyond the case id (each parameter given
// the marked row's id, or a value the route accepts), and the rows carry both marks (true and "held").
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import { buildAppOptions } from "../../src/composition/appWiring.js";
import { createRuntimeStores } from "../../src/composition/runtimeStores.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const CASE = "c1";
const MARK = "gradePending";

const row = (id: string, description: string, gradePending: true | "held" = true): ForensicEvent => ({
  id,
  timestamp: "2026-05-02T10:00:00Z",
  description,
  severity: "High",
  asset: "ws-fake01",
  mitreTechniques: ["T1003"],
  relatedFindingIds: [],
  sourceScreenshots: ["0001_upload.json"],
  sources: ["Sysmon"],
  gradePending,
});

let root: string;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
  vi.spyOn(getServerLogger(), "info").mockImplementation(() => {});
  root = await mkdtemp(join(tmpdir(), "dfir-mark-json-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save({
    ...emptyState(CASE),
    forensicTimeline: [row("m1", "ntdsutil marked row"), row("m2", "lsass marked row", "held")],
  });
  app = createApp(store, {
    importLock: new ImportLock(),
    stateStore,
    stateLock: new StateLock(),
    superTimelineStore: new SuperTimelineStore(store),
    tagsStore: new TagsStore(store),
    forensicGateControlStore: new ForensicGateControlStore(store),
  });
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(root, { recursive: true, force: true });
});

/** Every registered GET path of one case with no parameter beyond the case id. */
function caseGetPaths(a: ReturnType<typeof createApp>): string[] {
  const stack = a as unknown as { _router?: { stack: unknown[] }; router?: { stack: unknown[] } };
  const layers = (stack._router ?? stack.router)?.stack ?? [];
  const out: string[] = [];
  for (const layer of layers as { route?: { path: unknown; methods: Record<string, boolean> } }[]) {
    const r = layer.route;
    if (!r || !r.methods.get || typeof r.path !== "string") continue;
    if (!/^\/cases\/:id(\/[^:*]*)?$/.test(r.path)) continue;
    out.push(r.path.replace(":id", CASE));
  }
  return [...new Set(out)];
}

/** A value for each path parameter: a format the route accepts, else the marked row's id. */
const PARAM_VALUES: Record<string, string> = {
  id: CASE,
  fmt: "json",
  file: "report.md",
  z: "1",
  x: "0",
  y: "0",
};

/** Every registered GET path WITH a parameter beyond the case id (#2930), parameters filled in. */
function parameterisedGetPaths(
  a: ReturnType<typeof createApp>,
  values: Record<string, string> = PARAM_VALUES,
): string[] {
  const stack = a as unknown as { _router?: { stack: unknown[] }; router?: { stack: unknown[] } };
  const layers = (stack._router ?? stack.router)?.stack ?? [];
  const out: string[] = [];
  for (const layer of layers as { route?: { path: unknown; methods: Record<string, boolean> } }[]) {
    const r = layer.route;
    if (!r || !r.methods.get || typeof r.path !== "string") continue;
    const params = r.path.match(/:[A-Za-z]+(\([^)]*\))?/g) ?? [];
    if (!params.some((p) => p !== ":id")) continue;
    out.push(
      r.path.replace(
        /:([A-Za-z]+)(\(([^)|]*)[^)]*\))?/g,
        (_m, name: string, _g, first?: string) => first ?? values[name] ?? PARAM_VALUES[name] ?? "m1",
      ),
    );
  }
  return [...new Set(out)];
}

describe("#2918 — no client-facing JSON carries the grade mark", () => {
  it("the case-state route strips it, with and without a search", async () => {
    for (const path of [`/cases/${CASE}/state`, `/cases/${CASE}/state?q=ntdsutil`]) {
      const res = await request(app).get(path);
      expect(res.status, path).toBe(200);
      expect(res.text).toContain("marked row");
      expect(res.text, path).not.toContain(MARK);
    }
  });

  it("no GET route of the case serves it", { timeout: 60_000 }, async () => {
    const paths = caseGetPaths(app);
    expect(paths.length).toBeGreaterThan(20);
    const offenders: string[] = [];
    for (const path of paths) {
      const res = await request(app)
        .get(path)
        .timeout(5000)
        .catch(() => null);
      if (res && res.text.includes(MARK)) offenders.push(path);
    }
    expect(offenders).toEqual([]);
  });

  it("no GET route with path parameters serves it (#2930)", { timeout: 60_000 }, async () => {
    const paths = parameterisedGetPaths(app);
    expect(paths).toContain(`/cases/${CASE}/analysis-runs/m1`);
    expect(paths).toContain(`/cases/${CASE}/hunt/confirm-list.csv`);
    expect(paths.length).toBeGreaterThan(15);
    expect((await sweep(app, paths)).offenders).toEqual([]);
  });
});

/** The response body as text, whatever its type (a tile is binary, a CSV is text). */
function bodyText(res: { text?: string; body?: unknown }): string {
  if (typeof res.text === "string") return res.text;
  if (Buffer.isBuffer(res.body)) return res.body.toString("utf8");
  return JSON.stringify(res.body ?? "");
}

/** Fetch every path; the paths whose body names the mark, and each path's status. */
async function sweep(a: ReturnType<typeof createApp>, paths: readonly string[]) {
  const offenders: string[] = [];
  const status = new Map<string, number>();
  for (const path of paths) {
    const res = await request(a)
      .get(path)
      .timeout(5000)
      .catch(() => null);
    status.set(path, res?.status ?? 0);
    if (res && bodyText(res).includes(MARK)) offenders.push(path);
  }
  return { offenders, status };
}

// #2930: the production wiring (every store the server builds), with real ids behind the parameterised
// routes that read forensic rows — a report version, a hunt requirement — so the sweep is not passed by
// 404s and 501s. Those routes must answer 200 with the marked rows behind them.
describe("#2930 — the production wiring serves no grade mark on a parameterised route", () => {
  it("sweeps every GET route with real ids", { timeout: 120_000 }, async () => {
    const base = await mkdtemp(join(tmpdir(), "dfir-mark-json-rt-"));
    // #2964: the job manager creates cases/.dfir-companion-jobs.sqlite in the background; cleanup
    // waits for it. Its own initialization error is reported by the manager, not by this teardown.
    let jobsReady: Promise<void> = Promise.resolve();
    try {
      const rt = createRuntimeStores({
        casesRoot: join(base, "cases"),
        host: "127.0.0.1",
        port: 0,
        logDir: join(base, "logs"),
      });
      jobsReady = rt.jobManager.ready().catch(() => undefined);
      const options = buildAppOptions(rt, {} as Parameters<typeof buildAppOptions>[1]);
      const full = createApp(rt.store, options);
      await rt.store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
      await options.stateStore!.save({
        ...emptyState(CASE),
        forensicTimeline: [row("m1", "ntdsutil marked row"), row("m2", "lsass marked row", "held")],
      });
      const report = await request(full).post(`/cases/${CASE}/report`);
      expect(report.status, JSON.stringify(report.body)).toBe(200);
      const versions = await request(full).get(`/cases/${CASE}/report-versions`);
      const versionId = (versions.body.versions ?? versions.body)[0]?.id as string;
      expect(versionId).toBeTruthy();
      const requirement = await options.huntRequirementStore!.create(CASE, {
        decision: "Was the domain controller's credential store copied?",
        audience: "IR lead",
        deadline: "2026-12-01T00:00:00Z",
        subjectScope: { kind: "caseWide" },
        expectedObservableEvidence: "ntdsutil process execution on the controller",
        createdBy: "analyst",
        createdAt: "2026-11-26T00:00:00Z",
      });
      const values = { versionId, reqId: requirement.id };
      const paths = [...caseGetPaths(full), ...parameterisedGetPaths(full, values)];
      const { offenders, status } = await sweep(full, paths);
      const rowServing = [
        `/cases/${CASE}/state`,
        `/cases/${CASE}/report/report.md`,
        `/cases/${CASE}/report-versions/${versionId}/workflow`,
        `/cases/${CASE}/hunt-requirements/${requirement.id}/checklist`,
      ];
      for (const path of rowServing) expect(status.get(path), path).toBe(200);
      expect(offenders).toEqual([]);
    } finally {
      await jobsReady;
      await rm(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
});
