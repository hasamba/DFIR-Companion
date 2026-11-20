// AI Agent Forensics (#2690): the HTTP surface. Sweep cases stay out of the analyst's case list.
import { beforeEach, describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";

let store: CaseStore;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-aiagent-routes-")));
  app = createApp(store);
});

describe("sweep cases and GET /cases", () => {
  it("hides a sweep case from the case list the pickers read", async () => {
    await request(app)
      .post("/cases")
      .send({ caseId: "c1", name: "Incident A", investigator: "y", aiProvider: null });
    await store.createCase({
      caseId: "aiagent-sweep-1",
      name: "sweep",
      investigator: "x",
      aiProvider: null,
      kind: "sweep",
    });
    const res = await request(app).get("/cases");
    expect(res.status).toBe(200);
    expect(res.body.map((c: { caseId: string }) => c.caseId)).toEqual(["c1"]);
  });
});

describe("AI Agent Forensics routes", () => {
  it("serves the rule version, scopes and the rules not run, with grades marked provisional", async () => {
    const res = await request(app).get("/ai-agent/rules");
    expect(res.status).toBe(200);
    expect(res.body.version).toBe("ai-dfir-toolkit @ 5960308 (2026-11-18)");
    expect(res.body.provisionalGrades).toBe(true);
    expect(res.body.scopes.filter((s: { default: boolean }) => s.default)).toHaveLength(3);
    expect(res.body.notRun.length).toBeGreaterThan(0);
  });

  it("refuses a run with no endpoint, and creates no sweep case", async () => {
    const res = await request(app).post("/ai-agent/runs").send({ clientIds: [] });
    expect([400, 501]).toContain(res.status);
    expect((await store.listCases()).length).toBe(0);
  });

  it("serves runs without their raw rows, and exports the report escaped", async () => {
    await store.createCase({ caseId: "c1", name: "A", investigator: "y", aiProvider: null });
    const { AiAgentRunStore } = await import("../../src/analysis/aiAgentRunStore.js");
    const hostile = '=HYPERLINK("http://evil") | <img src=x onerror=alert(1)>';
    await new AiAgentRunStore(store).upsert("c1", {
      runId: "aar-1",
      huntId: "H.AI1",
      launchedAt: "2026-11-19T10:00:00.000Z",
      endpoints: [],
      failedEndpoints: [],
      skippedEndpoints: [],
      scopes: ["agent-home"],
      uploadMaxBytes: 1,
      ruleSetVersion: "v",
      artifacts: [],
      preserved: true,
      warnings: [],
      sensitive: true,
      rows: [{ MatchedText: "raw secret snippet" }],
      report: {
        builtAt: "2026-11-19T11:00:00.000Z",
        ruleSetVersion: "v",
        endpoints: [
          { host: "DEV|WS", tools: [], mcpServers: [], credentialStores: 1, hits: 1, coverage: [] },
        ],
        hits: [
          {
            host: "DEV|WS",
            rule: "R",
            family: "yara",
            ruleFile: "",
            author: "",
            link: "",
            atlas: "",
            scope: "agent-home",
            severity: "High",
            selfScan: false,
            path: hostile,
            sha256: "",
            time: "2026-11-12T03:14:00.000Z",
            timeBasis: "file last modified",
            timeLabel: "latest time the content could have been planted",
            scanTime: "",
            snippet: hostile,
            preserved: "",
          },
        ],
        notRun: [],
        unreadableRows: 0,
        provisionalGrades: true,
      },
    });
    const runs = await request(app).get("/cases/c1/ai-agent/runs");
    expect(runs.status).toBe(200);
    expect(JSON.stringify(runs.body)).not.toContain("raw secret snippet");
    expect(runs.body.runs[0].rowCount).toBe(1);

    const csv = await request(app).get("/cases/c1/ai-agent/runs/aar-1/report.csv");
    expect(csv.status).toBe(200);
    expect(csv.text).toContain(`"'=HYPERLINK(""http://evil"")`); // formula guard + quote doubling
    const md = await request(app).get("/cases/c1/ai-agent/runs/aar-1/report.md");
    expect(md.text).toContain("DEV\\|WS"); // a pipe cannot break the table
    expect(md.text).toContain("Grades are provisional");
    expect(md.text).toContain("Sensitive run");
    expect(md.text).toContain('=HYPERLINK("http://evil") \\| <img'); // the cell stays one cell
  });
});

describe("AI Agent Forensics routes: a case named in the body", () => {
  it("refuses a run into a closed case, and an unknown one", async () => {
    await store.createCase({ caseId: "closed-1", name: "A", investigator: "y", aiProvider: null });
    await store.updateCaseMeta("closed-1", { status: "closed" });
    const { VeloHuntStore } = await import("../../src/analysis/veloHuntStore.js");
    const wired = createApp(store, { veloHuntStore: new VeloHuntStore(store) });
    const unknown = await request(wired)
      .post("/ai-agent/runs")
      .send({ caseId: "nope", clientIds: ["C.1"] });
    expect(unknown.status).toBe(404);
    const closed = await request(wired)
      .post("/ai-agent/runs")
      .send({ caseId: "closed-1", clientIds: ["C.1"] });
    expect(closed.status).toBe(423);
  });
});
