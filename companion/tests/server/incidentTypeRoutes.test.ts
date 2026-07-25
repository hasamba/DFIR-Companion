import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { TemplateStore } from "../../src/analysis/templateStore.js";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { TYPE_SEED_PREFIX, type IncidentType } from "../../src/analysis/incidentTypes.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";

// Incident-type routes (#236). The custom-types dir sits beside the cases root, as it does at
// runtime, so a test can drop a JSON definition in and exercise the analyst-authored path.
async function makeApp(opts: { withStore?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-itype-"));
  const casesRoot = join(root, "cases");
  const customDir = join(root, "incident-types");
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const incidentTypeStore = new IncidentTypeStore(store, customDir);
  const app = createApp(store, {
    stateStore, aiConfigured: false,
    activityLogStore: new ActivityLogStore(store),
    templateStore: new TemplateStore(join(root, "templates")),
    ...(opts.withStore === false ? {} : { incidentTypeStore }),
  });
  const writeCustom = async (type: Partial<IncidentType> & { id: string }) => {
    await mkdir(customDir, { recursive: true });
    await writeFile(join(customDir, `${type.id}.json`), JSON.stringify(type), "utf8");
  };
  const writeRaw = async (file: string, body: string) => {
    await mkdir(customDir, { recursive: true });
    await writeFile(join(customDir, file), body, "utf8");
  };
  return { app, store, stateStore, incidentTypeStore, writeCustom, writeRaw };
}

const CUSTOM: Partial<IncidentType> & { id: string } = {
  id: "org-cryptolocker",
  name: "Org CryptoLocker",
  description: "Org-specific variant",
  initialKeyQuestions: ["Which share was hit first?"],
  initialNextSteps: [{ action: "Isolate the file server", priority: "critical", rationale: "contain", pointer: "EDR" }],
  findingsSeeds: ["Share encryption confirmed"],
  synthesisHint: "Org variant — prioritize share encryption.",
};

describe("GET /incident-types", () => {
  it("lists the built-in library", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/incident-types");
    expect(res.status).toBe(200);
    expect(res.body.map((t: IncidentType) => t.id)).toContain("ransomware");
    expect(res.body).toHaveLength(8);
    expect(res.body.every((t: IncidentType) => t.builtIn)).toBe(true);
  });

  it("appends custom types from the data dir, and skips malformed files", async () => {
    const { app, writeCustom, writeRaw } = await makeApp();
    await writeCustom(CUSTOM);
    await writeRaw("broken.json", "{ not json");
    await writeRaw("no-id.json", JSON.stringify({ name: "missing an id" }));
    await writeRaw("notes.txt", "ignored — not a .json");

    const res = await request(app).get("/incident-types");
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(9);
    const custom = res.body.find((t: IncidentType) => t.id === "org-cryptolocker");
    expect(custom.builtIn).toBe(false);
  });

  it("a custom file cannot shadow a built-in id or claim builtIn", async () => {
    const { app, writeCustom } = await makeApp();
    await writeCustom({ id: "ransomware", name: "Impostor", builtIn: true, synthesisHint: "hijacked" });
    const res = await request(app).get("/incident-types");
    const ransomware = res.body.filter((t: IncidentType) => t.id === "ransomware");
    expect(ransomware).toHaveLength(1);
    expect(ransomware[0].name).toBe("Ransomware");
  });

  it("returns an empty list rather than an error when the store is not configured", async () => {
    const { app } = await makeApp({ withStore: false });
    const res = await request(app).get("/incident-types");
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });
});

describe("GET /incident-types/:id", () => {
  it("returns a single definition, 404 for unknown", async () => {
    const { app } = await makeApp();
    const ok = await request(app).get("/incident-types/bec");
    expect(ok.status).toBe(200);
    expect(ok.body.name).toBe("BEC / Email Compromise");
    expect((await request(app).get("/incident-types/nope")).status).toBe(404);
  });
});

describe("POST /cases/:id/incident-type", () => {
  async function withCase() {
    const made = await makeApp();
    await request(made.app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    return made;
  }

  it("applies the type, seeds confirm/deny questions, and records the choice", async () => {
    const { app, stateStore, incidentTypeStore } = await withCase();
    const res = await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });
    expect(res.status).toBe(200);
    expect(res.body.questionsAdded).toBeGreaterThan(0);
    expect(res.body.nextStepsAdded).toBeGreaterThan(0);
    expect(res.body.record.typeId).toBe("ransomware");
    expect(res.body.record.appliedAt).not.toBe("");

    const state = await stateStore.load("c1");
    expect(state.keyQuestions.some((q) => q.question.includes("Was data exfiltrated before encryption"))).toBe(true);
    expect(state.keyQuestions.some((q) => q.question.startsWith(TYPE_SEED_PREFIX))).toBe(true);
    // The hint reaches the AI from the record, never from the case summary (which reports print).
    expect(state.lastSummary).toBe("");
    expect((await incidentTypeStore.loadType("c1"))?.id).toBe("ransomware");
  });

  it("re-applying merges — analyst-written questions survive and seeds are not duplicated", async () => {
    const { app, stateStore } = await withCase();
    await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });
    const before = await stateStore.load("c1");
    await stateStore.save({
      ...before,
      keyQuestions: [...before.keyQuestions, { id: "mine", question: "My own question", status: "unknown", answer: "", pointer: "", pinned: false }],
    });

    const res = await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });
    expect(res.body.questionsAdded).toBe(0);
    const after = await stateStore.load("c1");
    expect(after.keyQuestions.some((q) => q.question === "My own question")).toBe(true);
    expect(after.keyQuestions.length).toBe(before.keyQuestions.length + 1);
  });

  it("replace: true overwrites, for an analyst who picked the wrong type", async () => {
    const { app, stateStore } = await withCase();
    await request(app).post("/cases/c1/incident-type").send({ typeId: "ransomware" });
    await request(app).post("/cases/c1/incident-type").send({ typeId: "bec", replace: true });
    const state = await stateStore.load("c1");
    expect(state.keyQuestions.some((q) => q.question.includes("Which mailboxes were compromised"))).toBe(true);
    expect(state.keyQuestions.some((q) => q.question.includes("Was data exfiltrated before encryption"))).toBe(false);
  });

  it("applies a custom type through the same path", async () => {
    const { app, stateStore, writeCustom } = await withCase();
    await writeCustom(CUSTOM);
    const res = await request(app).post("/cases/c1/incident-type").send({ typeId: "org-cryptolocker" });
    expect(res.status).toBe(200);
    const state = await stateStore.load("c1");
    expect(state.keyQuestions.some((q) => q.question === "Which share was hit first?")).toBe(true);
    expect(state.nextSteps.some((s) => s.action === "Isolate the file server")).toBe(true);
  });

  it("rejects a missing or unknown typeId", async () => {
    const { app } = await withCase();
    expect((await request(app).post("/cases/c1/incident-type").send({})).status).toBe(400);
    expect((await request(app).post("/cases/c1/incident-type").send({ typeId: "  " })).status).toBe(400);
    expect((await request(app).post("/cases/c1/incident-type").send({ typeId: "nope" })).status).toBe(404);
  });
});

describe("GET /cases/:id/incident-type", () => {
  it("returns an empty record for a case that never picked one", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).get("/cases/c1/incident-type");
    expect(res.status).toBe(200);
    expect(res.body.record.typeId).toBe("");
    expect(res.body.type).toBeNull();
  });

  it("returns the chosen type after an apply", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await request(app).post("/cases/c1/incident-type").send({ typeId: "intrusion" });
    const res = await request(app).get("/cases/c1/incident-type");
    expect(res.body.record.typeId).toBe("intrusion");
    expect(res.body.type.name).toBe("Network Intrusion");
  });
});

describe("POST /cases with incidentTypeId", () => {
  it("auto-configures the fresh case", async () => {
    const { app, stateStore, incidentTypeStore } = await makeApp();
    const res = await request(app).post("/cases").send({
      caseId: "c1", name: "n", investigator: "i", aiProvider: null, incidentTypeId: "ransomware",
    });
    expect(res.status).toBe(201);
    const state = await stateStore.load("c1");
    expect(state.keyQuestions.length).toBeGreaterThan(0);
    expect(state.nextSteps.length).toBeGreaterThan(0);
    expect(state.lastSummary).toBe("");
    expect((await incidentTypeStore.loadRecord("c1")).typeId).toBe("ransomware");
  });

  // The dashboard sends one or the other, but an API caller may send both — and the type used to
  // replace the template's questions outright, silently losing what the caller asked for.
  it("keeps the template's questions when a template AND a type are both supplied", async () => {
    const { app, stateStore } = await makeApp();
    await request(app).post("/cases").send({
      caseId: "c1", name: "n", investigator: "i", aiProvider: null,
      templateId: "web-intrusion", incidentTypeId: "ransomware",
    });
    const state = await stateStore.load("c1");
    // From the web-intrusion template…
    expect(state.keyQuestions.some((q) => q.question.includes("web application"))).toBe(true);
    // …and from the ransomware incident type.
    expect(state.keyQuestions.some((q) => q.question.includes("Was data exfiltrated before encryption"))).toBe(true);
  });

  it("creates the case normally when the incident type id is unknown", async () => {
    const { app, incidentTypeStore } = await makeApp();
    const res = await request(app).post("/cases").send({
      caseId: "c1", name: "n", investigator: "i", aiProvider: null, incidentTypeId: "nope",
    });
    expect(res.status).toBe(201);
    expect((await incidentTypeStore.loadRecord("c1")).typeId).toBe("");
  });
});
