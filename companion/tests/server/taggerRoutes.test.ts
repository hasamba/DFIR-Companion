import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SuggestOutcome } from "../../src/analysis/taggerRuleSuggest.js";

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const DEFAULT_RULES = `svc:
  description: Windows service installed
  any:
    - { field: message, contains: ['7045'] }
  tags: ['win-service', 'persistence']
  mitre: ['T1543']
  severity: High
  view: Service Installs
`;

let store: CaseStore;
let dir: string;
let stateStore: StateStore;
let tagsStore: TagsStore;
let taggerStore: TaggerStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-tagger-route-"));
  store = new CaseStore(dir);
  setServerLogger(createConsoleLogger("error"));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(store);
  tagsStore = new TagsStore(store);
  const defaultPath = join(dir, "default-tags.yaml");
  await writeFile(defaultPath, DEFAULT_RULES);
  taggerStore = new TaggerStore(join(dir, "user-tags.yaml"), [defaultPath]);

  // Seed the forensic timeline: one matching event, one benign.
  const state = await stateStore.load("c1");
  await stateStore.save({
    ...state,
    forensicTimeline: [
      ev({ id: "e1", message: "A new service was installed 7045", severity: "Low" }),
      ev({ id: "e2", message: "user logged on" }),
    ],
  });
  delete process.env.TAGGER_SCOPE;
  delete process.env.TAGGER_AUTO;
  delete process.env.TAGGER_RULES_FILE;
});

afterEach(async () => {
  delete process.env.TAGGER_SCOPE;
  delete process.env.TAGGER_RULES_FILE;
  await rm(dir, { recursive: true, force: true });
});

function app() {
  return createApp(store, {
    stateStore, tagsStore, taggerStore,
    superTimelineStore: new SuperTimelineStore(store),
  });
}

describe("GET /tagger/rules", () => {
  it("returns the active ruleset text, source, and a per-rule summary", async () => {
    const res = await request(app()).get("/tagger/rules");
    expect(res.status).toBe(200);
    expect(res.body.source).toBe("default");
    expect(res.body.ruleCount).toBe(1);
    expect(res.body.rules[0]).toMatchObject({ id: "svc", severity: "High", view: "Service Installs" });
    expect(res.body.text).toContain("svc:");
  });
});

describe("PUT /tagger/rules", () => {
  it("rejects an invalid ruleset with 400 and does not persist it", async () => {
    const res = await request(app())
      .put("/tagger/rules")
      .send({ text: "bad:\n  any:\n    - { field: key_path, contains: x }\n  tags: ['t']\n" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/key_path/);
    // still the default afterwards
    const get = await request(app()).get("/tagger/rules");
    expect(get.body.source).toBe("default");
  });

  it("accepts a valid ruleset, persists it, and GET then reads it back as source=user", async () => {
    const text = "logon:\n  any:\n    - { field: message, contains: 'logged on' }\n  tags: ['logon']\n";
    const put = await request(app()).put("/tagger/rules").send({ text });
    expect(put.status).toBe(200);
    expect(put.body.ruleCount).toBe(1);
    const get = await request(app()).get("/tagger/rules");
    expect(get.body.source).toBe("user");
    expect(get.body.rules[0].id).toBe("logon");
  });
});

describe("POST /cases/:id/tagger/run", () => {
  it("tags matching events, raises severity, unions MITRE, and reports per-rule counts", async () => {
    const res = await request(app()).post("/cases/c1/tagger/run").send({});
    expect(res.status).toBe(200);
    expect(res.body.totalMatched).toBe(1);
    expect(res.body.tagsWritten).toBe(2); // win-service + persistence on e1
    expect(res.body.mutatedCount).toBe(1);
    expect(res.body.perRule.find((r: { id: string }) => r.id === "svc")).toMatchObject({ matched: 1, view: "Service Installs" });

    // e1 carries two tagger-authored tags; e2 carries none.
    const tags = (await request(app()).get("/cases/c1/tags")).body as Array<{ targetId: string; label: string; author: string }>;
    const e1 = tags.filter((t) => t.targetId === "e1");
    expect(e1.map((t) => t.label).sort()).toEqual(["persistence", "win-service"]);
    expect(e1.every((t) => t.author === "tagger:svc")).toBe(true);
    expect(tags.filter((t) => t.targetId === "e2")).toHaveLength(0);

    // Forensic severity raised Low -> High; MITRE gained T1543.
    const state = await stateStore.load("c1");
    const stored = state.forensicTimeline.find((e) => e.id === "e1")!;
    expect(stored.severity).toBe("High");
    expect(stored.mitreTechniques).toContain("T1543");
  });

  it("is idempotent — a second run adds no new tags and changes no severity", async () => {
    await request(app()).post("/cases/c1/tagger/run").send({});
    const res = await request(app()).post("/cases/c1/tagger/run").send({});
    expect(res.body.tagsWritten).toBe(0);
    expect(res.body.mutatedCount).toBe(0);
  });
});

describe("POST /cases/:id/tagger/clear", () => {
  it("removes only tagger-authored tags, leaving analyst tags intact", async () => {
    await request(app()).post("/cases/c1/tagger/run").send({});
    // add a manual analyst tag on the same event
    await request(app()).post("/cases/c1/tags").send({ targetType: "event", targetId: "e1", label: "key-evidence", author: "alice" });

    const clear = await request(app()).post("/cases/c1/tagger/clear").send({});
    expect(clear.status).toBe(200);
    expect(clear.body.removed).toBe(2);

    const tags = (await request(app()).get("/cases/c1/tags")).body as Array<{ label: string; author: string }>;
    expect(tags).toHaveLength(1);
    expect(tags[0]).toMatchObject({ label: "key-evidence", author: "alice" });
  });
});

function appAi(suggest: (caseId: string, desc: string) => Promise<SuggestOutcome>) {
  const fakePipeline = {
    hasAiProvider: () => true,
    hasSynthesisProvider: () => true,   // suggest-rule is TEXT work — gated on the synthesis provider
    suggestTaggerRule: suggest,
  } as unknown as import("../../src/analysis/pipeline.js").AnalysisPipeline;
  return createApp(store, {
    stateStore, tagsStore, taggerStore,
    superTimelineStore: new SuperTimelineStore(store),
    pipeline: fakePipeline,
    aiConfigured: true,
  });
}

describe("POST /cases/:id/tagger/suggest-rule", () => {
  it("is 501 when no AI provider is configured", async () => {
    const res = await request(app()).post("/cases/c1/tagger/suggest-rule").send({ description: "flag log clears" });
    expect(res.status).toBe(501);
  });

  it("returns a rule outcome from the pipeline", async () => {
    const outcome: SuggestOutcome = {
      kind: "rule", ruleId: "logon", explanation: "e",
      ruleYaml: "logon:\n  any:\n    - { field: message, contains: 'logged on' }\n  tags: ['logon']\n",
    };
    const res = await request(appAi(async () => outcome)).post("/cases/c1/tagger/suggest-rule").send({ description: "x" });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ kind: "rule", ruleId: "logon" });
  });

  it("400s on an empty description", async () => {
    const res = await request(appAi(async () => ({ kind: "decline", reason: "n/a" }))).post("/cases/c1/tagger/suggest-rule").send({ description: "  " });
    expect(res.status).toBe(400);
  });
});

describe("POST /cases/:id/tagger/preview", () => {
  it("counts matches and returns a sample of matching events without writing tags or mutating state", async () => {
    const ruleYaml = "svc:\n  any:\n    - { field: message, contains: '7045' }\n  tags: ['t']\n";
    const res = await request(app()).post("/cases/c1/tagger/preview").send({ ruleYaml });
    expect(res.status).toBe(200);
    expect(res.body.matched).toBe(1);
    // the sample lists the actual matching event (e1), with its identifying fields
    expect(Array.isArray(res.body.sample)).toBe(true);
    expect(res.body.sample).toHaveLength(1);
    expect(res.body.sample[0]).toMatchObject({ id: "e1" });
    expect(res.body.sample[0]).toHaveProperty("timestamp");
    expect(res.body.sample[0]).toHaveProperty("description");
    const tags = (await request(app()).get("/cases/c1/tags")).body as unknown[];
    expect(tags).toHaveLength(0);
  });

  it("400s on an invalid rule YAML", async () => {
    const res = await request(app()).post("/cases/c1/tagger/preview").send({ ruleYaml: "bad:\n  any:\n    - { field: nope, contains: 'x' }\n  tags: ['t']\n" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/nope/);
  });
});

describe("POST /tagger/rules/add", () => {
  it("merges the rule and GET reflects source=user with both rules", async () => {
    const ruleYaml = "logon:\n  any:\n    - { field: message, contains: 'logged on' }\n  tags: ['logon']\n";
    const res = await request(app()).post("/tagger/rules/add").send({ ruleYaml });
    expect(res.status).toBe(200);
    expect(res.body.id).toBe("logon");
    expect(res.body.ruleCount).toBe(2);
    const get = await request(app()).get("/tagger/rules");
    expect(get.body.rules.map((r: { id: string }) => r.id).sort()).toEqual(["logon", "svc"]);
  });
});

describe("DELETE /tagger/rules/:ruleId", () => {
  it("removes a rule (200) and 404s for an unknown id", async () => {
    await request(app()).post("/tagger/rules/add").send({ ruleYaml: "logon:\n  any:\n    - { field: message, contains: 'logged on' }\n  tags: ['logon']\n" });
    const del = await request(app()).delete("/tagger/rules/svc");
    expect(del.status).toBe(200);
    expect(del.body.ruleCount).toBe(1);
    const missing = await request(app()).delete("/tagger/rules/nope");
    expect(missing.status).toBe(404);
  });
});

describe("POST /tagger/rules/reset", () => {
  it("restores the shipped default ruleset", async () => {
    await request(app()).post("/tagger/rules/add").send({ ruleYaml: "logon:\n  any:\n    - { field: message, contains: 'x' }\n  tags: ['t']\n" });
    expect((await request(app()).get("/tagger/rules")).body.source).toBe("user");
    const reset = await request(app()).post("/tagger/rules/reset");
    expect(reset.status).toBe(200);
    const get = await request(app()).get("/tagger/rules");
    expect(get.body.source).toBe("default");
    expect(get.body.ruleCount).toBe(1);
  });
});
