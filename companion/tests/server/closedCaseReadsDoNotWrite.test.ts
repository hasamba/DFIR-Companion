import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { PlaybookStore } from "../../src/analysis/playbookStore.js";
import { PlaybookHuntStore } from "../../src/analysis/playbookHuntStore.js";
import { emptyState, type Finding } from "../../src/analysis/stateTypes.js";

// #2437 Part A: opening a closed or archived case must not change it. GET /playbook and the coach
// GETs re-derive the playbook (syncPlaybook) and GET /playbook also saved a pruned hunt-suggestion
// list — two writes on a read of a frozen case. They now return what is stored and save nothing.

function finding(id: string, title: string): Finding {
  return {
    id,
    severity: "Critical",
    title,
    description: title,
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
  };
}

async function makeApp() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-2437a-")));
  const stateStore = new StateStore(store);
  const playbookStore = new PlaybookStore(store);
  const playbookHuntStore = new PlaybookHuntStore(store);
  const app = createApp(store, { stateStore, playbookStore, playbookHuntStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const playbookFile = () => join(store.stateDir("c1"), "playbook.json");
  const huntFile = () => join(store.stateDir("c1"), "playbook-hunts.json");
  return { app, store, stateStore, playbookStore, playbookHuntStore, playbookFile, huntFile };
}

async function seedOneFinding(stateStore: StateStore) {
  const s = emptyState("c1");
  s.findings.push(finding("f1", "Webshell on WEB01"));
  await stateStore.save(s);
}

async function addSecondFinding(stateStore: StateStore) {
  const s = await stateStore.load("c1");
  await stateStore.save({ ...s, findings: [...s.findings, finding("f2", "Credential dump on DC01")] });
}

async function fingerprint(path: string) {
  return { content: await readFile(path, "utf8"), mtimeMs: (await stat(path)).mtimeMs };
}

const taskIds = (body: { tasks: { id: string }[] }) => body.tasks.map((t) => t.id).sort();

describe("reading a frozen case writes nothing (#2437)", () => {
  it("GET /playbook on a closed case returns the stored tasks without syncing, and reopen syncs again", async () => {
    const { app, stateStore, playbookFile } = await makeApp();
    await seedOneFinding(stateStore);
    const open = await request(app).get("/cases/c1/playbook");
    expect(open.status).toBe(200);
    expect(taskIds(open.body)).toEqual(["finding:f1"]);

    expect((await request(app).patch("/cases/c1/status").send({ status: "closed" })).status).toBe(200);
    await addSecondFinding(stateStore);
    const before = await fingerprint(playbookFile());
    const closed = await request(app).get("/cases/c1/playbook");
    expect(closed.status).toBe(200);
    expect(taskIds(closed.body)).toEqual(["finding:f1"]);
    expect(await fingerprint(playbookFile())).toEqual(before);

    expect((await request(app).patch("/cases/c1/status").send({ status: "open" })).status).toBe(200);
    const reopened = await request(app).get("/cases/c1/playbook");
    expect(taskIds(reopened.body)).toEqual(["finding:f1", "finding:f2"]);
  });

  it("the coach GETs on a closed case do not write the playbook", async () => {
    const { app, stateStore, playbookFile } = await makeApp();
    await seedOneFinding(stateStore);
    await request(app).get("/cases/c1/playbook");
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    await addSecondFinding(stateStore);
    const before = await fingerprint(playbookFile());
    expect((await request(app).get("/cases/c1/coach/next-actions")).status).toBe(200);
    expect((await request(app).get("/cases/c1/coach/next-action")).status).toBe(200);
    expect(await fingerprint(playbookFile())).toEqual(before);
  });

  it("GET /playbook on a closed case omits a stale hunt suggestion but leaves the saved list alone", async () => {
    const { app, stateStore, playbookHuntStore, huntFile } = await makeApp();
    await seedOneFinding(stateStore);
    await request(app).get("/cases/c1/playbook");
    // A suggestion for a task the playbook no longer has: stale, so a read prunes it.
    await playbookHuntStore.save("c1", {
      generatedAt: "2026-11-01T00:00:00.000Z",
      suggestions: [
        {
          taskId: "finding:gone",
          title: "hunt",
          rationale: "r",
          vql: "SELECT * FROM info()",
          severity: "High",
          mitreTechniques: [],
          mode: "hunt",
        },
      ],
      taskHashes: { "finding:gone": "x" },
    });
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    const before = await fingerprint(huntFile());
    const res = await request(app).get("/cases/c1/playbook");
    expect(res.status).toBe(200);
    expect(res.body.huntSuggestions).toEqual([]);
    expect(await fingerprint(huntFile())).toEqual(before);

    // An open case still prunes the saved list on read.
    await request(app).patch("/cases/c1/status").send({ status: "open" });
    await request(app).get("/cases/c1/playbook");
    expect((await playbookHuntStore.load("c1")).suggestions).toEqual([]);
  });

  it("an archived case takes the same read-only path", async () => {
    const { app, store, stateStore, playbookFile } = await makeApp();
    await seedOneFinding(stateStore);
    await request(app).get("/cases/c1/playbook");
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    await store.archiveCaseFolder("c1", "archived");
    await addSecondFinding(stateStore);
    const before = await fingerprint(playbookFile());
    const res = await request(app).get("/cases/c1/playbook");
    expect(res.status).toBe(200);
    expect(taskIds(res.body)).toEqual(["finding:f1"]);
    expect(await fingerprint(playbookFile())).toEqual(before);
  });
});
