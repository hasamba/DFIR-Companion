// AI Agent Forensics (#2690): the HTTP surface. Sweep cases stay out of the analyst's case list.
import { beforeEach, describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { pollFor } from "../helpers/poll.js";

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
          {
            host: "DEV|WS",
            tools: [],
            mcpServers: [],
            credentialStores: 1,
            hits: 1,
            coverage: [],
            sigma: [{ rule: hostile, status: "ran (live state)", hits: 1 }],
          },
          { host: "=cmd|WS2", tools: [], mcpServers: [], credentialStores: 0, hits: 0, coverage: [] },
        ],
        sigmaRules: [{ rule: hostile, mode: "compiled", basis: "live state" }],
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
            sha256: "a".repeat(64),
            preservedSha256: "b".repeat(64),
            hashCheck: "differs",
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

    // #2722: both hashes and the check, in both exports.
    expect(csv.text.split("\r\n")[0]).toContain(`"scan_sha256","preserved_sha256","hash_check"`);
    expect(csv.text).toContain(`"${"a".repeat(64)}","${"b".repeat(64)}","differs"`);
    expect(md.text).toContain("| Scan SHA-256 | Preserved SHA-256 | Hash check |");
    expect(md.text).toContain("differs");
    // #2722: the rule-by-endpoint Sigma table — hostile rule and host names stay one escaped cell.
    expect(md.text).toContain("## Sigma coverage per rule and endpoint");
    expect(md.text).toContain("| Rule | Basis | DEV\\|WS | =cmd\\|WS2 |");
    expect(md.text).toContain("ran (live state), 1 hit(s) | not recorded |");
    const sig = await request(app).get("/cases/c1/ai-agent/runs/aar-1/sigma-coverage.csv");
    expect(sig.status).toBe(200);
    expect(sig.headers["content-type"]).toContain("text/csv");
    const [head, first] = sig.text.split("\r\n");
    expect(head).toBe(`"rule","basis","DEV|WS","'=cmd|WS2"`);
    expect(first).toContain(`"'=HYPERLINK(""http://evil"")`);
    expect(first).toContain(`"ran (live state) - 1 hit(s)","not recorded"`);
  });

  it("exports a report stored before #2722 (no hash check, no Sigma table) without failing", async () => {
    await store.createCase({ caseId: "c2", name: "A", investigator: "y", aiProvider: null });
    const { AiAgentRunStore } = await import("../../src/analysis/aiAgentRunStore.js");
    await new AiAgentRunStore(store).upsert("c2", {
      runId: "aar-2",
      huntId: "H.AI2",
      launchedAt: "2026-11-19T10:00:00.000Z",
      endpoints: [],
      failedEndpoints: [],
      skippedEndpoints: [],
      scopes: [],
      uploadMaxBytes: 1,
      ruleSetVersion: "v",
      artifacts: [],
      preserved: true,
      warnings: [],
      sensitive: true,
      report: {
        builtAt: "x",
        ruleSetVersion: "v",
        endpoints: [{ host: "H", tools: [], mcpServers: [], credentialStores: 0, hits: 0, coverage: [] }],
        hits: [],
        notRun: [],
        unreadableRows: 0,
        provisionalGrades: true,
      } as never,
    });
    expect((await request(app).get("/cases/c2/ai-agent/runs/aar-2/report.md")).status).toBe(200);
    expect((await request(app).get("/cases/c2/ai-agent/runs/aar-2/report.csv")).status).toBe(200);
    const sig = await request(app).get("/cases/c2/ai-agent/runs/aar-2/sigma-coverage.csv");
    expect(sig.status).toBe(200);
    expect(sig.text).toBe(`"rule","basis","H"\r\n`);
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

// #2722: a run started through the route leaves an activity entry in its case.
describe("AI Agent Forensics routes: activity log", () => {
  it("records the run in the case's activity log, with counts and ids only", async () => {
    await store.createCase({ caseId: "c1", name: "A", investigator: "y", aiProvider: null });
    const { VeloHuntStore } = await import("../../src/analysis/veloHuntStore.js");
    const { ActivityLogStore } = await import("../../src/analysis/activityLog.js");
    const velo = {
      huntGuiUrlFor: (h: string) => `https://velo.example/#/hunts/${h}`,
      listClientArtifacts: async () => [
        { name: "Windows.Triage.Targets", description: "", parameters: [{ name: "AICodingAgents" }] },
      ],
      huntArtifactRows: async () => ({ rows: [], total: 0, truncated: false }),
      async runProgram(p: string) {
        if (p.includes("FROM clients()"))
          return { rows: [{ client_id: "C.w1", OS: "windows", Hostname: "WS-01" }], reason: "" };
        if (p.includes("artifact_set")) return { rows: [{ Set: {} }], reason: "" };
        if (p.includes("hunt(")) return { rows: [{ Hunt: { HuntId: "H.AI9" } }], reason: "" };
        if (p.includes("hunt_add")) return { rows: [{ Added: "C.w1" }], reason: "" };
        return { rows: [], reason: "" };
      },
    };
    const servers = { ok: true, servers: { setId: "set-1", setName: "Lab", velociraptor: velo } };
    const activity = new ActivityLogStore(store);
    const wired = createApp(store, {
      veloHuntStore: new VeloHuntStore(store),
      activityLogStore: activity,
      serverClients: {
        forCase: () => servers,
        forSet: () => servers,
        forDefault: () => servers,
        invalidate: () => undefined,
      } as never,
    });
    const res = await request(wired)
      .post("/ai-agent/runs")
      .send({ caseId: "c1", clientIds: ["C.w1"], scopes: ["agent-home"] });
    expect(res.status).toBe(202);
    // The append is best-effort, after the response.
    const entries = await pollFor("the run's activity entry", async () => {
      const got = await activity.load("c1");
      return got.length ? got : undefined;
    });
    expect(entries.map((e) => [e.category, e.action])).toEqual([["hunt", "ai-agent-run"]]);
    expect(entries[0].detail).toMatch(
      /^started AI Agent Forensics on 1 endpoint\(s\) \(hunt H\.AI9, rules .+, scopes agent-home\)$/,
    );
  });
});
