import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { RulePackStore } from "../../src/analysis/rulePackStore.js";
import { resolveRequestPolicy } from "../../src/auth/policy.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { RULES_V1, fakeGitHub, manifestFor } from "../analysis/rulePackFixtures.js";

// The Rule pack routes (#2349): check → review → install, file install, roll back, measure; demo
// refuses; team mode leaves them to the tagger-rule administrators.

const gh = vi.hoisted(() => ({
  current: null as null | ReturnType<typeof import("../analysis/rulePackFixtures.js").fakeGitHub>,
}));
vi.mock("../../src/routes/outboundFetchGuard.js", async (orig) => ({
  ...(await orig<typeof import("../../src/routes/outboundFetchGuard.js")>()),
  fetchOutbound: (url: string, opts: { timeoutMs: number }) => gh.current!.fetchAsset(url, opts.timeoutMs),
}));

const BUNDLED = `bundled_rule:
  description: bundled
  any:
    - { field: message, contains: ['zulu'] }
  tags: ['z']
`;
// The pack keeps nothing of the bundled set, raises "alpha" rows to High and tags them.
const PACK_TAG = "rules-2026.11.05";

const ev = (id: string, message: string): ForensicEvent => ({
  id,
  timestamp: "2026-06-01T00:00:00Z",
  description: "d",
  message,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

let dir: string;
let store: CaseStore;
let stateStore: StateStore;
let taggerStore: TaggerStore;
let rulePackStore: RulePackStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-rulepack-route-"));
  store = new CaseStore(dir);
  setServerLogger(createConsoleLogger("error"));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(store);
  const s = await stateStore.load("c1");
  await stateStore.save({
    ...s,
    forensicTimeline: [ev("e1", "alpha seen"), ev("e2", "zulu seen"), ev("e3", "nothing")],
  });
  const bundled = join(dir, "bundled.yaml");
  await writeFile(bundled, BUNDLED);
  rulePackStore = new RulePackStore(join(dir, "tagger", "pack"), "0.45.0");
  taggerStore = new TaggerStore(join(dir, "tagger", "tags.yaml"), [bundled], {
    pack: rulePackStore,
    appVersion: "0.45.0",
  });
  gh.current = fakeGitHub([{ tag: PACK_TAG, rules: RULES_V1, manifest: manifestFor(RULES_V1, PACK_TAG) }]);
  vi.stubGlobal("fetch", gh.current.fetchFn);
  process.env.TAGGER_SCOPE = "forensic";
});

afterEach(async () => {
  vi.unstubAllGlobals();
  delete process.env.TAGGER_SCOPE;
  await rm(dir, { recursive: true, force: true });
});

const app = (opts: { demoMode?: boolean } = {}) =>
  createApp(store, { stateStore, taggerStore, rulePackStore, ...opts });

describe("rule pack routes", () => {
  it("reports the bundled rules in use before anything is installed", async () => {
    const res = await request(app()).get("/tagger/pack");
    expect(res.status).toBe(200);
    expect(res.body.installed).toBeNull();
    expect(res.body.inUse).toBe("bundled");
    expect(res.body.activeRules).toMatch(/bundled with the app \(0\.45\.0\)/);
    expect(res.body.updateCheck).toBe(false);
  });

  it("check downloads and reviews the pack without installing it; install makes it active", async () => {
    const check = await request(app()).post("/tagger/pack/check");
    expect(check.status).toBe(200);
    expect(check.body.check.status).toBe("update");
    const review = check.body.review;
    expect(review.pack.version).toBe(PACK_TAG);
    expect(review.counts).toEqual({ added: 1, changed: 0, removed: 1 });
    expect(review.added[0].key).toBe("pack_rule_a");
    expect(review.removed[0].key).toBe("bundled_rule");
    expect((await taggerStore.readActive()).source).toBe("default");

    const measure = await request(app())
      .post("/tagger/pack/measure")
      .send({ token: review.token, caseId: "c1" });
    expect(measure.status).toBe(200);
    expect(measure.body).toMatchObject({ scanned: 3, raised: 1, intoForensic: 1, tagsChanged: 2 });
    expect(measure.body.note).toMatch(/only raises grades/);
    expect((await stateStore.load("c1")).forensicTimeline.find((e) => e.id === "e1")?.severity).toBe("Info");

    const install = await request(app()).post("/tagger/pack/install").send({ token: review.token });
    expect(install.status).toBe(200);
    expect((await taggerStore.readActive()).source).toBe("pack");

    const again = await request(app()).post("/tagger/pack/check");
    expect(again.body.check.status).toBe("current");
    expect(again.body.review).toBeNull();
  });

  // #2389: the check said "update"; after Install the status read that stale record and still showed
  // "rules-… is available (installed: the bundled rules)" right above "installed and current".
  it("an install makes the last check read as current, and a roll back makes it an update again", async () => {
    const check = await request(app()).post("/tagger/pack/check");
    await request(app()).post("/tagger/pack/install").send({ token: check.body.review.token }).expect(200);
    const after = await request(app()).get("/tagger/pack");
    expect(after.body.lastCheck.status).toBe("current");
    expect(after.body.lastCheck.message).toBe(`Rule pack ${PACK_TAG} is installed and current.`);
    await request(app()).post("/tagger/pack/rollback").send({ to: "bundled" }).expect(200);
    expect((await request(app()).get("/tagger/pack")).body.lastCheck.status).toBe("update");
  });

  it("a SHA mismatch installs nothing and answers 502 with a sentence", async () => {
    gh.current = fakeGitHub([
      {
        tag: PACK_TAG,
        rules: RULES_V1,
        manifest: manifestFor(RULES_V1, PACK_TAG),
        rulesDigest: "0".repeat(64),
      },
    ]);
    vi.stubGlobal("fetch", gh.current.fetchFn);
    const res = await request(app()).post("/tagger/pack/check");
    expect(res.status).toBe(502);
    expect(res.body.error).toMatch(/does not match GitHub's published SHA-256/);
    expect((await rulePackStore.status()).installed).toBeNull();
  });

  it("a pack that needs a newer app is refused with a clear message", async () => {
    gh.current = fakeGitHub([
      { tag: PACK_TAG, rules: RULES_V1, manifest: manifestFor(RULES_V1, PACK_TAG, "0.46.0") },
    ]);
    vi.stubGlobal("fetch", gh.current.fetchFn);
    const res = await request(app()).post("/tagger/pack/check");
    expect(res.status).toBe(200);
    expect(res.body.check.status).toBe("needs-newer-app");
    expect(res.body.check.message).toMatch(/needs DFIR Companion 0\.46\.0 or newer/);
    expect(res.body.review).toBeNull();
  });

  it("installs from a file, marked not checked against GitHub, and rolls back to bundled", async () => {
    const file = await request(app())
      .post("/tagger/pack/file")
      .send({ name: "tags.yaml", rulesText: RULES_V1, manifestText: manifestFor(RULES_V1, PACK_TAG) });
    expect(file.status).toBe(200);
    expect(file.body.review.pack).toMatchObject({
      origin: "file",
      verifiedByGitHub: false,
      version: PACK_TAG,
    });
    await request(app()).post("/tagger/pack/install").send({ token: file.body.review.token }).expect(200);
    const back = await request(app()).post("/tagger/pack/rollback").send({ to: "bundled" });
    expect(back.status).toBe(200);
    expect(back.body.status.inUse).toBe("bundled");
    expect(back.body.status.previous.version).toBe(PACK_TAG);
  });

  it("refuses a file whose rules do not match its manifest, and a bad body", async () => {
    const res = await request(app())
      .post("/tagger/pack/file")
      .send({
        name: "tags.yaml",
        rulesText: RULES_V1 + "\n# edited\n",
        manifestText: manifestFor(RULES_V1, PACK_TAG),
      });
    expect(res.status).toBe(422);
    expect(res.body.error).toMatch(/does not match the SHA-256/);
    expect((await request(app()).post("/tagger/pack/file").send({})).status).toBe(400);
    expect((await request(app()).post("/tagger/pack/install").send({ token: "nope" })).status).toBe(410);
  });

  it("demo mode refuses every download, install and roll back", async () => {
    for (const [path, body] of [
      ["/tagger/pack/check", {}],
      ["/tagger/pack/file", { name: "x", rulesText: RULES_V1 }],
      ["/tagger/pack/install", { token: "t" }],
      ["/tagger/pack/rollback", { to: "bundled" }],
    ] as const) {
      const res = await request(app({ demoMode: true }))
        .post(path)
        .send(body);
      expect(res.status, path).toBe(403);
    }
    expect(gh.current!.fetched).toEqual([]);
  });

  it("answers 501 without a store", async () => {
    const res = await request(createApp(store, { taggerStore })).get("/tagger/pack");
    expect(res.status).toBe(501);
  });

  it("team mode: every rule pack route is the tagger-rule administrators'", () => {
    for (const [method, path] of [
      ["GET", "/tagger/pack"],
      ["POST", "/tagger/pack/check"],
      ["POST", "/tagger/pack/file"],
      ["POST", "/tagger/pack/install"],
      ["POST", "/tagger/pack/rollback"],
      ["POST", "/tagger/pack/measure"],
    ]) {
      expect(resolveRequestPolicy(method, path), `${method} ${path}`).toEqual({
        kind: "global",
        permission: "admin",
      });
    }
  });
});
