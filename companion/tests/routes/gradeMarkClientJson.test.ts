// #2918: the grade mark (analysis/gradeMark.ts, `gradePending`) is server bookkeeping. No client-facing
// JSON may carry it: every GET route of a case is called on a case holding a marked row, and each body
// is byte-searched for the field name. The case-state route is checked with and without a search.
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
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const CASE = "c1";
const MARK = "gradePending";

const row = (id: string, description: string): ForensicEvent => ({
  id,
  timestamp: "2026-05-02T10:00:00Z",
  description,
  severity: "High",
  asset: "ws-fake01",
  mitreTechniques: ["T1003"],
  relatedFindingIds: [],
  sourceScreenshots: ["0001_upload.json"],
  sources: ["Sysmon"],
  gradePending: true,
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
    forensicTimeline: [row("m1", "ntdsutil marked row"), row("m2", "lsass marked row")],
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
});
