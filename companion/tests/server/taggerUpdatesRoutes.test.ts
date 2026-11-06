import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, readFile, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { parse as parseYaml } from "yaml";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { resolveRequestPolicy } from "../../src/auth/policy.js";

// #2344 routes: the "your rules are older than the built-in set" notice, the review, the apply
// (through the editor's lock + stale-revision check), the export for a TAGGER_RULES_FILE source,
// and dismiss.

const r = (text: string, sev = "Low") =>
  `${text}:\n  description: ${text} rule\n  any:\n    - { field: message, contains: ['${text}'] }\n  tags: ['t']\n  severity: ${sev}\n`;

let dir: string;
let store: CaseStore;
let defaultPath: string;
let userPath: string;
let taggerStore: TaggerStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-tagger-upd-route-"));
  store = new CaseStore(dir);
  setServerLogger(createConsoleLogger("error"));
  defaultPath = join(dir, "default-tags.yaml");
  userPath = join(dir, "tagger", "tags.yaml");
  await writeFile(defaultPath, r("one") + r("two"));
  taggerStore = new TaggerStore(userPath, [defaultPath]);
  delete process.env.TAGGER_RULES_FILE;
});

afterEach(async () => {
  delete process.env.TAGGER_RULES_FILE;
  await rm(dir, { recursive: true, force: true });
});

const app = () => createApp(store, { taggerStore });

/** The three revisions the dashboard sends back with apply and export. */
const reviewed = (body: { revision: string; upstreamId: string; upstreamRevision: string }) => ({
  revision: body.revision,
  upstreamId: body.upstreamId,
  upstreamRevision: body.upstreamRevision,
});

async function upgradeBuiltin(): Promise<void> {
  await writeFile(defaultPath, r("one", "High") + r("two") + r("three", "High"));
}

describe("GET /tagger/rules/updates", () => {
  it("shows no notice for the built-in source", async () => {
    await upgradeBuiltin();
    const res = await request(app()).get("/tagger/rules/updates");
    expect(res.status).toBe(200);
    expect(res.body.source).toBe("default");
    expect(res.body.notice).toBe(false);
  });

  it("shows no notice when the copy already holds every built-in rule", async () => {
    await taggerStore.save(r("one") + r("two") + r("mine"));
    const res = await request(app()).get("/tagger/rules/updates");
    expect(res.body.notice).toBe(false);
    expect(res.body.counts).toMatchObject({ added: 0, changed: 0 });
  });

  it("counts added and changed rules against the copy and lists them with description and grade", async () => {
    await taggerStore.save(r("one") + r("two"));
    await upgradeBuiltin();
    const res = await request(app()).get("/tagger/rules/updates");
    expect(res.body.notice).toBe(true);
    expect(res.body.tracked).toBe(true);
    expect(res.body.counts).toMatchObject({ added: 1, changed: 1, conflicts: 0 });
    expect(res.body.added[0]).toMatchObject({
      key: "three",
      upstream: { description: "three rule", severity: "High" },
    });
    expect(res.body.changed[0]).toMatchObject({
      key: "one",
      upstream: { severity: "High" },
      mine: { severity: "Low" },
    });
    expect(res.body.changed[0].upstream.yaml).toContain("one:");
  });

  it("hides the notice after dismiss until the built-in set changes", async () => {
    await taggerStore.save(r("one"));
    await upgradeBuiltin();
    const first = await request(app()).get("/tagger/rules/updates");
    const d = await request(app())
      .post("/tagger/rules/updates/dismiss")
      .send({ upstreamRevision: first.body.upstreamRevision });
    expect(d.status).toBe(200);
    const after = await request(app()).get("/tagger/rules/updates");
    expect(after.body.dismissed).toBe(true);
    expect(after.body.notice).toBe(false);
    await writeFile(defaultPath, r("one", "Critical") + r("two") + r("three", "High"));
    expect((await request(app()).get("/tagger/rules/updates")).body.notice).toBe(true);
  });

  it("refuses a dismiss with no revision", async () => {
    const res = await request(app()).post("/tagger/rules/updates/dismiss").send({});
    expect(res.status).toBe(400);
  });
});

describe("POST /tagger/rules/updates/apply", () => {
  it("applies the selection and keeps the analyst's rules", async () => {
    await taggerStore.save(r("one") + r("two") + r("mine", "Critical"));
    await upgradeBuiltin();
    const view = await request(app()).get("/tagger/rules/updates");
    const res = await request(app())
      .post("/tagger/rules/updates/apply")
      .send({ ...reviewed(view.body), choices: { three: "upstream", one: "upstream", bogus: "nope" } });
    expect(res.status).toBe(200);
    expect(res.body.applied.sort()).toEqual(["one", "three"]);
    const doc = parseYaml(await readFile(userPath, "utf8"));
    expect(doc.mine.severity).toBe("Critical");
    expect(doc.three.severity).toBe("High");
  });

  it("refuses a stale revision with 409 and writes nothing", async () => {
    await taggerStore.save(r("one") + r("two"));
    await upgradeBuiltin();
    const before = await readFile(userPath, "utf8");
    const view = await request(app()).get("/tagger/rules/updates");
    const res = await request(app())
      .post("/tagger/rules/updates/apply")
      .send({ ...reviewed(view.body), revision: "stale", choices: { three: "upstream" } });
    expect(res.status).toBe(409);
    expect(typeof res.body.revision).toBe("string");
    expect(await readFile(userPath, "utf8")).toBe(before);
  });

  it("requires a revision", async () => {
    await taggerStore.save(r("one"));
    const res = await request(app()).post("/tagger/rules/updates/apply").send({ choices: {} });
    expect(res.status).toBe(400);
  });

  it("requires the upstream the review was made against", async () => {
    await taggerStore.save(r("one"));
    await upgradeBuiltin();
    const view = await request(app()).get("/tagger/rules/updates");
    expect(view.body.upstreamId).toBe("builtin");
    expect(view.body.upstreamRevision).toMatch(/^[0-9a-f]{16}$/);
    const res = await request(app())
      .post("/tagger/rules/updates/apply")
      .send({ revision: view.body.revision, choices: { three: "upstream" } });
    expect(res.status).toBe(400);
    expect(await readFile(userPath, "utf8")).toBe(r("one"));
  });

  it("refuses with 409 when the compared-with rules changed after the review, and writes nothing", async () => {
    await taggerStore.save(r("one") + r("two"));
    await upgradeBuiltin();
    const view = await request(app()).get("/tagger/rules/updates");
    await writeFile(defaultPath, r("one", "High") + r("two") + r("three", "Critical"));
    const before = await readFile(userPath, "utf8");
    const res = await request(app())
      .post("/tagger/rules/updates/apply")
      .send({ ...reviewed(view.body), choices: { three: "upstream" } });
    expect(res.status).toBe(409);
    expect(res.body.reason).toBe("upstream");
    expect(res.body.error).toMatch(/changed since this review/);
    expect(await readFile(userPath, "utf8")).toBe(before);
  });

  it("refuses a TAGGER_RULES_FILE source and never writes it", async () => {
    const envFile = join(dir, "operator.yaml");
    await writeFile(envFile, r("one"));
    process.env.TAGGER_RULES_FILE = envFile;
    await upgradeBuiltin();
    const view = await request(app()).get("/tagger/rules/updates");
    expect(view.body.readOnly).toBe(true);
    expect(view.body.notice).toBe(true);
    const res = await request(app())
      .post("/tagger/rules/updates/apply")
      .send({ revision: view.body.revision, choices: { three: "upstream" } });
    expect(res.status).toBe(400);
    expect(await readFile(envFile, "utf8")).toBe(r("one"));
    await expect(access(userPath)).rejects.toThrow();
  });
});

describe("POST /tagger/rules/updates/export", () => {
  it("downloads the merged YAML for a TAGGER_RULES_FILE source without writing", async () => {
    const envFile = join(dir, "operator.yaml");
    await writeFile(envFile, r("one"));
    process.env.TAGGER_RULES_FILE = envFile;
    await upgradeBuiltin();
    const view = await request(app()).get("/tagger/rules/updates");
    const res = await request(app())
      .post("/tagger/rules/updates/export")
      .send({ ...reviewed(view.body), choices: { three: "upstream" } });
    expect(res.status).toBe(200);
    expect(res.headers["content-disposition"]).toMatch(/attachment; filename="tagger-rules-merged\.yaml"/);
    expect(Object.keys(parseYaml(res.text)).sort()).toEqual(["one", "three"]);
    expect(await readFile(envFile, "utf8")).toBe(r("one"));
  });

  it("requires the reviewed revisions, and refuses with 409 when the built-in set changed since", async () => {
    const envFile = join(dir, "operator.yaml");
    await writeFile(envFile, r("one"));
    process.env.TAGGER_RULES_FILE = envFile;
    await upgradeBuiltin();
    const view = await request(app()).get("/tagger/rules/updates");
    const missing = await request(app())
      .post("/tagger/rules/updates/export")
      .send({ choices: { three: "upstream" } });
    expect(missing.status).toBe(400);
    await writeFile(defaultPath, r("one") + r("three", "Critical"));
    const res = await request(app())
      .post("/tagger/rules/updates/export")
      .send({ ...reviewed(view.body), choices: { three: "upstream" } });
    expect(res.status).toBe(409);
    expect(res.body.reason).toBe("upstream");
  });
});

describe("team mode", () => {
  it("puts every update route behind the instance administrator, like the rules editor", () => {
    for (const [method, path] of [
      ["GET", "/tagger/rules/updates"],
      ["POST", "/tagger/rules/updates/apply"],
      ["POST", "/tagger/rules/updates/export"],
      ["POST", "/tagger/rules/updates/dismiss"],
    ]) {
      expect(resolveRequestPolicy(method, path), `${method} ${path}`).toEqual({
        kind: "global",
        permission: "admin",
      });
    }
    expect(resolveRequestPolicy("PUT", "/tagger/rules")).toEqual({ kind: "global", permission: "admin" });
  });
});
