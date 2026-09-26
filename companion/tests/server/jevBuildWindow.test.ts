// The missed-evidence review and the host's own build window (#1700).
//
// On INC-2026-014 the review graded 216 build-day rows (Chocolatey firewall churn, Packer script
// blocks, the provisioning log clears) as Medium, High and even Critical, because the grader never
// knew they were the machine being built. The analyst ticked them, the promotion exempted them from
// the build-window cap (#1529), and the next synthesis raised four High auto findings on them.
//
// Two seams now know about the windows: the review sets the rows aside before it spends anything,
// and the promote route refuses them again, so an older tab or a grade recorded before the fix
// cannot bring them back. A row the analyst promotes one by one from the super-timeline is the
// explicit override, and is not affected.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { HostRenameRecord } from "../../src/analysis/hostRenameRecord.js";
import { JevGradeStore } from "../../src/analysis/ai/jev/jevGradeRecord.js";

const HOST = "DESKTOP-16OJFO6";
const renames: HostRenameRecord[] = [
  { formerName: "WIN-UK1GV882OK6", currentName: HOST, until: "2025-12-05T03:11:54.000Z", basis: "collector" },
];

const row = (id: string, timestamp: string, p: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp,
  description: `row ${id}`,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: HOST,
  sources: ["Chainsaw"],
  ...p,
});

// The 2025-12-05 build, as archive-only rows: two provisioners (Chocolatey, Packer) plus the rows the
// build produced. Nothing here is in the forensic timeline, so only the archive can open the window.
const buildRows = (): ForensicEvent[] => [
  row("b-choco", "2025-12-05T02:43:39Z", { path: "c:\\programdata\\chocolatey\\tools\\7z.exe" }),
  row("b-packer", "2025-12-05T03:04:31Z", {
    description:
      'Sigma: Potentially Malicious PwSh (EID 4104) - ScriptBlockText=$name = "packer-69324bbd-78e3"',
  }),
  row("b-fw", "2025-12-05T03:10:00Z", {
    description: "Sigma: Uncommon New Firewall Rule Added In Windows Firewall Exception List (EID 2097)",
  }),
  row("b-clear", "2025-12-05T03:26:42Z", {
    description: "Sigma: Security Eventlog Cleared (EID 1102)",
  }),
];

// Months later, outside every window.
const incidentRow = () =>
  row("x-incident", "2026-09-26T13:10:43Z", { description: "operator.exe echo BLACKSUIT-CANARY systeminfo" });

async function caseWith(archive: ForensicEvent[], forensic: ForensicEvent[] = []) {
  const root = await mkdtemp(join(tmpdir(), "dfir-jev-build-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState("c1"), forensicTimeline: forensic, hostRenames: renames });
  const superTimelineStore = new SuperTimelineStore(cases);
  await superTimelineStore.append("c1", archive);
  return { cases, stateStore, superTimelineStore };
}

const JEV_ENV = [
  "DFIR_JEV_ENABLED",
  "DFIR_JEV_KEY",
  "DFIR_JEV_PROVIDER",
  "DFIR_JEV_BASE_URL",
  "DFIR_JEV_MODEL",
] as const;

describe("the missed-evidence review sets build-window rows aside (#1700)", () => {
  const saved: Record<string, string | undefined> = {};
  let jev: ReturnType<typeof createServer>;
  let asked: string[] = [];

  beforeEach(async () => {
    for (const k of JEV_ENV) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    asked = [];
    // A Jev stand-in that grades everything High and remembers which rows it was asked about.
    jev = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const questions = JSON.parse(body).questions as Record<string, { type: string }>;
        const answers: Record<string, unknown> = {};
        for (const [id, q] of Object.entries(questions)) {
          asked.push(id);
          answers[id] =
            q.type === "noul"
              ? { type: "noul", noul: 0 }
              : { type: "score", score: 4, legend: {}, probabilities: {}, confidence: 0.9 };
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ model: "jev-stub", answers, usage: { input_tokens: 1, output_tokens: 1 } }));
      });
    });
    await new Promise<void>((resolve) => jev.listen(0, "127.0.0.1", resolve));
    process.env.DFIR_JEV_ENABLED = "1";
    process.env.DFIR_JEV_KEY = "jev-test-credential-NOTAREALKEY";
    process.env.DFIR_JEV_BASE_URL = `http://127.0.0.1:${(jev.address() as AddressInfo).port}/decisions`;
  });

  afterEach(async () => {
    for (const k of JEV_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await new Promise<void>((resolve) => jev.close(() => resolve()));
  });

  it("does not grade rows inside a window that only the archive's own markers open, and says how many", async () => {
    const { cases, stateStore, superTimelineStore } = await caseWith([...buildRows(), incidentRow()]);
    const app = createApp(cases, { stateStore, superTimelineStore });
    const res = await request(app).post("/cases/c1/jev/review").send({});
    expect(res.status).toBe(200);
    expect(res.body.buildWindow).toBe(4);
    expect(res.body.graded).toBe(1);
    expect(res.body.rows.map((r: { id: string }) => r.id)).toEqual(["x-incident"]);
    expect(res.body.alreadyAnalyzed + res.body.buildWindow + res.body.graded).toBe(res.body.read);
  });

  it("reviews the whole window when the archive holds a hard attacker signal inside it", async () => {
    const dump = row("b-ntds", "2025-12-05T03:20:00Z", {
      description: "Credential store theft: ntdsutil ifm create full c:\\temp\\ntds.dit",
    });
    const { cases, stateStore, superTimelineStore } = await caseWith([...buildRows(), dump]);
    const app = createApp(cases, { stateStore, superTimelineStore });
    const res = await request(app).post("/cases/c1/jev/review").send({});
    expect(res.body.buildWindow).toBe(0);
    expect(res.body.graded).toBe(5);
  });

  it("calls Jev for nothing when every candidate is build-window activity", async () => {
    const { cases, stateStore, superTimelineStore } = await caseWith(buildRows());
    const app = createApp(cases, { stateStore, superTimelineStore });
    const res = await request(app).post("/cases/c1/jev/review").send({});
    expect(res.status).toBe(200);
    expect(res.body.buildWindow).toBe(4);
    expect(res.body.graded).toBe(0);
    expect(asked).toEqual([]);
  });
});

describe("the promote route refuses build-window rows (#1700)", () => {
  async function promoteHarness(archive: ForensicEvent[], graded: string[]) {
    const { cases, stateStore, superTimelineStore } = await caseWith(archive);
    const pipeline = buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store: cases,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    // Grades recorded as a review before the fix would have left them: Critical on a log clear.
    await new JevGradeStore(cases).record(
      "c1",
      "typesafe/jev-1.13",
      graded.map((id) => ({ id, grade: "Critical" as const, confidence: 0.6, score: 4.5 })),
    );
    const app = createApp(cases, { pipeline, stateStore, superTimelineStore });
    return { app, stateStore };
  }

  it("skips a stale grade on a build-window row, says why, and still promotes the rest", async () => {
    const { app, stateStore } = await promoteHarness(
      [...buildRows(), incidentRow()],
      ["b-clear", "x-incident"],
    );
    const res = await request(app)
      .post("/cases/c1/jev/promote")
      .send({ rows: [{ id: "b-clear" }, { id: "x-incident" }] });
    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(1);
    expect(res.body.skipped).toBe(1);
    expect(res.body.reasons.join(" ")).toMatch(/build window/i);
    const ids = (await stateStore.load("c1")).forensicTimeline.map((e) => e.id);
    expect(ids).toContain("x-incident");
    expect(ids).not.toContain("b-clear");
  });

  it("promotes a row inside a vetoed window — a hard signal keeps the whole window reviewable", async () => {
    const dump = row("b-ntds", "2025-12-05T03:20:00Z", {
      description: "Credential store theft: ntdsutil ifm create full c:\\temp\\ntds.dit",
    });
    const { app } = await promoteHarness([...buildRows(), dump], ["b-clear", "b-ntds"]);
    const res = await request(app)
      .post("/cases/c1/jev/promote")
      .send({ rows: [{ id: "b-clear" }, { id: "b-ntds" }] });
    expect(res.body.promoted).toBe(2);
  });
});
