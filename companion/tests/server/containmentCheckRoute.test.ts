import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { PlaybookStore } from "../../src/analysis/playbookStore.js";
import { AiCostStore } from "../../src/analysis/aiCost.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { createApp } from "../../src/server.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { CONTAINMENT_QUESTION_IDS } from "../../src/analysis/ai/jev/containmentQuestions.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

// The per-finding containment check (#1925): one Jev call about one finding's cited forensic-timeline
// events, turned into suggested steps by a fixed rule; and the add route that turns ticked steps
// into Playbook tasks carrying their attribution. Jev is a local stand-in — no network.

const JEV_ENV = [
  "DFIR_JEV_ENABLED",
  "DFIR_JEV_KEY",
  "DFIR_JEV_PROVIDER",
  "DFIR_JEV_BASE_URL",
  "DFIR_JEV_MODEL",
  "DFIR_JEV_GRADING",
] as const;
const KEY = "jev-test-credential-NOTAREALKEY";

const ev = (id: string, description: string, asset = "DC01"): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description,
  severity: "High",
  asset,
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const FINDING: Finding = {
  id: "f1",
  severity: "High",
  title: "Credential theft on DC01",
  description: "mimikatz ran on DC01",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: ["T1003"],
  relatedEventIds: ["e1", "e2"],
  firstSeen: "2026-01-01T00:00:00Z",
  lastUpdated: "2026-01-01T00:00:00Z",
  status: "open",
};

/** Default verdicts: credentials exposed and persistence (yes), in progress unsure, the rest no. */
const DEFAULT_NOUL: Record<string, number> = { credentials_exposed: 0.9, persistence: 0.9, in_progress: 0.3 };

const PATH = "/cases/c1/findings/f1/containment-check";

/** A super-timeline that fails the test on any use. */
function forbiddenSuperTimeline(cases: CaseStore, touched: string[]): SuperTimelineStore {
  const real = new SuperTimelineStore(cases);
  return new Proxy(real, {
    get(target, prop) {
      const value = Reflect.get(target, prop) as unknown;
      if (typeof value !== "function") return value;
      return (...args: unknown[]) => {
        touched.push(String(prop));
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
}

describe("the containment check routes", () => {
  const saved: Record<string, string | undefined> = {};
  let jev: ReturnType<typeof createServer>;
  let bodies: string[];
  let status: number;
  let delayMs: number;
  let omit: string | null;
  let noul: Record<string, number>;
  let onFirst: (() => Promise<void>) | null;

  beforeEach(async () => {
    resetLimiters(); // every case here is "c1": the per-case AI cap must not carry across tests
    for (const k of JEV_ENV) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    bodies = [];
    status = 200;
    delayMs = 0;
    omit = null;
    noul = { ...DEFAULT_NOUL };
    onFirst = null;
    jev = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", async () => {
        bodies.push(body);
        const replyStatus = status; // read before onFirst, which may change it for the retry
        if (bodies.length === 1 && onFirst) await onFirst();
        setTimeout(() => {
          if (replyStatus !== 200) {
            res.writeHead(replyStatus, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: { message: `bad key ${KEY}` } }));
            return;
          }
          const questions = JSON.parse(body).questions as Record<string, { type: string; criteria: object }>;
          const answers: Record<string, unknown> = {};
          for (const [id, q] of Object.entries(questions)) {
            if (id === omit) continue;
            answers[id] =
              q.type === "noul"
                ? { type: "noul", noul: noul[id] ?? 0 }
                : {
                    type: "choice",
                    choice: Object.keys(q.criteria)[0],
                    probabilities: {},
                    confidence: 0.9,
                  };
          }
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              model: "jev-stub",
              answers,
              usage: { input_tokens: 10, output_tokens: 2, cost: 0.001 },
            }),
          );
        }, delayMs);
      });
    });
    await new Promise<void>((resolve) => jev.listen(0, "127.0.0.1", resolve));
    process.env.DFIR_JEV_ENABLED = "1";
    process.env.DFIR_JEV_KEY = KEY;
    process.env.DFIR_JEV_BASE_URL = `http://127.0.0.1:${(jev.address() as AddressInfo).port}/decisions`;
  });

  afterEach(async () => {
    for (const k of JEV_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await new Promise<void>((resolve) => jev.close(() => resolve()));
  });

  async function harness() {
    const root = await mkdtemp(join(tmpdir(), "dfir-ccheck-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save({
      ...emptyState("c1"),
      findings: [FINDING],
      forensicTimeline: [
        ev("e1", "mimikatz sekurlsa::logonpasswords on DC01"),
        ev("e2", "lsass memory read"),
        ev("e3", "uncited chrome update"),
      ],
    });
    const touched: string[] = [];
    const playbookStore = new PlaybookStore(cases);
    const aiCostStore = new AiCostStore(cases);
    const app = createApp(cases, {
      stateStore,
      superTimelineStore: forbiddenSuperTimeline(cases, touched),
      playbookStore,
      aiCostStore,
    });
    return { root, cases, app, stateStore, playbookStore, aiCostStore, touched };
  }

  describe("POST …/containment-check", () => {
    it("refuses with 501 when Jev is not configured", async () => {
      delete process.env.DFIR_JEV_ENABLED;
      const { app } = await harness();
      const res = await request(app).post(PATH).send({});
      expect(res.status).toBe(501);
      expect(String(res.body.error)).toMatch(/\S/);
      expect(bodies).toHaveLength(0);
    });

    it("answers 404 for a case that does not exist, and creates nothing on disk", async () => {
      const { app, root } = await harness();
      const before = [...(await readdir(root))].sort();
      const res = await request(app).post("/cases/typo/findings/f1/containment-check").send({});
      expect(res.status).toBe(404);
      expect([...(await readdir(root))].sort()).toEqual(before);
      expect(bodies).toHaveLength(0);
    });

    it("answers 404 for a finding the case does not hold", async () => {
      const { app } = await harness();
      const res = await request(app).post("/cases/c1/findings/nope/containment-check").send({});
      expect(res.status).toBe(404);
      expect(bodies).toHaveLength(0);
    });

    it("answers with the answers, the suggested steps and the coverage", async () => {
      const { app } = await harness();
      const res = await request(app).post(PATH).send({});
      expect(res.status).toBe(200);
      const body = res.body;
      expect(body.checkId).toMatch(/^[0-9a-f-]{36}$/);
      expect(body.model).toBe("jev-stub");
      expect(Number.isNaN(Date.parse(body.checkedAt))).toBe(false);
      expect(body.answers.map((a: { id: string }) => a.id)).toEqual([...CONTAINMENT_QUESTION_IDS]);
      for (const a of body.answers)
        expect(Object.keys(a).sort()).toEqual(["checkManually", "id", "kind", "label", "value", "verdict"]);
      expect(body.answers.find((a: { id: string }) => a.id === "in_progress")).toMatchObject({
        verdict: "unsure",
        checkManually: true,
      });
      expect(body.steps.map((s: { id: string }) => s.id)).toEqual(["revoke-keys-reauth", "isolate-host"]);
      expect(body.steps[0]).toEqual({
        id: "revoke-keys-reauth",
        title: "Reset the exposed credentials and require re-authentication",
        priority: "high",
        basis: ["credentials_exposed"],
        basisLabels: ["Credentials reached someone unauthorized"],
        checkManually: false,
        inPlaybook: false,
      });
      expect(body.coverage).toEqual({ cited: 2, sent: 2, notInTimeline: 0, truncated: false });
      expect(body.snapshotCaveat).toMatch(/end of the collected evidence/);
      expect(body.usage).toEqual({ inputTokens: 10, outputTokens: 2, costUSD: 0.001 });
    });

    it("sends only the cited events, masked, and never the API key", async () => {
      const { app } = await harness();
      await request(app).post(PATH).send({});
      expect(bodies).toHaveLength(1);
      const sent = bodies[0];
      expect(sent).toContain("mimikatz sekurlsa");
      expect(sent).toContain("lsass memory read");
      expect(sent).not.toContain("uncited chrome update");
      expect(sent).not.toContain("DC01");
      expect(sent).toMatch(/ANON_HOST_\d+/);
      expect(sent).not.toContain(KEY);
    });

    it("never touches the super-timeline", async () => {
      const { app, touched } = await harness();
      const res = await request(app).post(PATH).send({});
      expect(res.status).toBe(200);
      expect(touched).toEqual([]);
    });

    it("records the cost and leaves the investigation state unchanged", async () => {
      const { app, stateStore, aiCostStore } = await harness();
      const before = JSON.stringify(await stateStore.load("c1"));
      await request(app).post(PATH).send({});
      const cost = await aiCostStore.load("c1");
      expect(cost.other.totalCalls).toBe(1);
      expect(cost.other.byModel["jev/jev-stub"]).toMatchObject({ calls: 1, costUSD: 0.001 });
      expect(JSON.stringify(await stateStore.load("c1"))).toBe(before);
    });

    it("answers 502 without the key when Jev refuses the call", async () => {
      status = 401;
      const { app, playbookStore } = await harness();
      const res = await request(app).post(PATH).send({});
      expect(res.status).toBe(502);
      expect(String(res.body.error)).toMatch(/^Jev containment check failed: /);
      expect(String(res.body.error)).not.toContain(KEY);
      expect(await playbookStore.load("c1")).toEqual([]);
    });

    it("answers 502 on a partial answer set and suggests nothing", async () => {
      omit = "persistence";
      const { app, playbookStore, aiCostStore } = await harness();
      const res = await request(app).post(PATH).send({});
      expect(res.status).toBe(502);
      expect(String(res.body.error)).toMatch(/persistence/);
      expect(res.body.steps).toBeUndefined();
      expect(await playbookStore.load("c1")).toEqual([]);
      expect((await aiCostStore.load("c1")).other.totalCalls).toBe(0);
    });

    it("refuses a second check of the same finding while the first is in flight", async () => {
      const { app } = await harness();
      delayMs = 250;
      const [a, b] = await Promise.all([request(app).post(PATH).send({}), request(app).post(PATH).send({})]);
      expect([a.status, b.status].sort()).toEqual([200, 409]);
      expect(bodies).toHaveLength(1);
      // Released once it finished.
      delayMs = 0;
      expect((await request(app).post(PATH).send({})).status).toBe(200);
    });

    it("holds the retry when the analyst hides a value mid-call", async () => {
      const { app, cases } = await harness();
      status = 503;
      onFirst = async () => {
        status = 200;
        await new CustomEntitiesStore(cases).save("c1", [{ value: "lsass", category: "PERSON" }]);
      };
      const res = await request(app).post(PATH).send({});
      expect(res.status).toBe(502);
      expect(String(res.body.error)).toMatch(/anonymization/i);
      expect(bodies).toHaveLength(1);
    });
  });

  describe("POST …/containment-check/playbook", () => {
    async function checked() {
      const h = await harness();
      const res = await request(h.app).post(PATH).send({});
      expect(res.status).toBe(200);
      return { ...h, check: res.body as { checkId: string; model: string; checkedAt: string } };
    }

    it("adds the ticked steps as attributed tasks linked to the finding", async () => {
      const { app, playbookStore, check } = await checked();
      const res = await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: check.checkId, steps: ["isolate-host"] });
      expect(res.status).toBe(200);
      expect(res.body.alreadyInPlaybook).toEqual([]);
      expect(res.body.added).toHaveLength(1);
      const [task] = await playbookStore.load("c1");
      expect(task).toMatchObject({
        title: "Isolate the host",
        priority: "high",
        source: "custom",
        relatedFindingId: "f1",
      });
      expect(task.containmentCheck).toMatchObject({
        kind: "jev-containment",
        rule: "containment-v1",
        model: "jev-stub",
        checkedAt: check.checkedAt,
        findingId: "f1",
        stepId: "isolate-host",
        basis: ["persistence"],
        inProgressCaveat: false,
      });
      expect(task.containmentCheck!.answers).toHaveLength(11);
      expect(res.body.added[0].id).toBe(task.id);
    });

    it("never adds a step twice, and a re-run shows it as in the Playbook", async () => {
      const { app, playbookStore, check } = await checked();
      await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: check.checkId, steps: ["isolate-host"] });
      const again = await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: check.checkId, steps: ["isolate-host"] });
      expect(again.status).toBe(200);
      expect(again.body).toEqual({ added: [], alreadyInPlaybook: ["isolate-host"] });
      expect(await playbookStore.load("c1")).toHaveLength(1);

      const rerun = await request(app).post(PATH).send({});
      const iso = rerun.body.steps.find((s: { id: string }) => s.id === "isolate-host");
      const [task] = await playbookStore.load("c1");
      expect(iso).toMatchObject({ inPlaybook: true, taskShortId: task.shortId });
      expect(rerun.body.steps.find((s: { id: string }) => s.id === "revoke-keys-reauth").inPlaybook).toBe(
        false,
      );
    });

    it("lets a deleted task be added again", async () => {
      const { app, playbookStore, check } = await checked();
      await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: check.checkId, steps: ["isolate-host"] });
      const [task] = await playbookStore.load("c1");
      expect(await playbookStore.remove("c1", task.id)).toBe(true);
      const res = await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: check.checkId, steps: ["isolate-host"] });
      expect(res.body.added).toHaveLength(1);
    });

    it("ignores everything in the body but the check id and the step ids", async () => {
      const { app, playbookStore, check } = await checked();
      const res = await request(app)
        .post(`${PATH}/playbook`)
        .send({
          checkId: check.checkId,
          steps: ["revoke-keys-reauth"],
          title: "forged",
          priority: "low",
          model: "forged-model",
          containmentCheck: { model: "forged-model" },
          answers: [],
        });
      expect(res.status).toBe(200);
      const [task] = await playbookStore.load("c1");
      expect(task.title).toBe("Reset the exposed credentials and require re-authentication");
      expect(task.priority).toBe("high");
      expect(task.containmentCheck!.model).toBe("jev-stub");
      expect(JSON.stringify(task)).not.toContain("forged");
    });

    it("asks for a re-run when the check id is unknown", async () => {
      const { app, playbookStore } = await checked();
      const res = await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: "00000000-0000-0000-0000-000000000000", steps: ["isolate-host"] });
      expect(res.status).toBe(409);
      expect(res.body.rerun).toBe(true);
      expect(String(res.body.error)).toMatch(/run the check again/i);
      expect(await playbookStore.load("c1")).toEqual([]);
    });

    it("asks for a re-run when a check id is used on another finding", async () => {
      const { app, stateStore, check } = await checked();
      const state = await stateStore.load("c1");
      await stateStore.save({ ...state, findings: [...state.findings, { ...FINDING, id: "f2" }] });
      const res = await request(app)
        .post("/cases/c1/findings/f2/containment-check/playbook")
        .send({ checkId: check.checkId, steps: ["isolate-host"] });
      expect(res.status).toBe(409);
      expect(res.body.rerun).toBe(true);
    });

    it("asks for a re-run when the finding's evidence changed since the check", async () => {
      const { app, stateStore, playbookStore, check } = await checked();
      const state = await stateStore.load("c1");
      await stateStore.save({ ...state, findings: [{ ...FINDING, relatedEventIds: ["e1"] }] });
      const res = await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: check.checkId, steps: ["isolate-host"] });
      expect(res.status).toBe(409);
      expect(res.body.rerun).toBe(true);
      expect(await playbookStore.load("c1")).toEqual([]);
    });

    it("still accepts the check after the finding was only reworded", async () => {
      const { app, stateStore, check } = await checked();
      const state = await stateStore.load("c1");
      await stateStore.save({ ...state, findings: [{ ...FINDING, title: "Reworded title" }] });
      const res = await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: check.checkId, steps: ["isolate-host"] });
      expect(res.status).toBe(200);
    });

    it("asks for a re-run when the finding is gone", async () => {
      const { app, stateStore, check } = await checked();
      const state = await stateStore.load("c1");
      await stateStore.save({ ...state, findings: [] });
      const res = await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: check.checkId, steps: ["isolate-host"] });
      expect(res.status).toBe(409);
      expect(res.body.rerun).toBe(true);
    });

    it("refuses a step the check did not suggest", async () => {
      const { app, playbookStore, check } = await checked();
      const res = await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: check.checkId, steps: ["isolate-host", "purge-mail"] });
      expect(res.status).toBe(400);
      expect(String(res.body.error)).toContain("purge-mail");
      expect(await playbookStore.load("c1")).toEqual([]);
    });

    it("refuses a malformed body", async () => {
      const { app, check } = await checked();
      for (const body of [
        {},
        { checkId: check.checkId },
        { checkId: check.checkId, steps: [] },
        { checkId: check.checkId, steps: [42] },
        { checkId: 7, steps: ["isolate-host"] },
      ]) {
        const res = await request(app).post(`${PATH}/playbook`).send(body);
        expect(res.status).toBe(400);
      }
    });

    it("keeps both of two tabs' checks addable", async () => {
      const { app, playbookStore } = await harness();
      const first = (await request(app).post(PATH).send({})).body.checkId as string;
      const second = (await request(app).post(PATH).send({})).body.checkId as string;
      expect(first).not.toBe(second);
      const a = await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: first, steps: ["isolate-host"] });
      const b = await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: second, steps: ["revoke-keys-reauth"] });
      expect(a.status).toBe(200);
      expect(b.status).toBe(200);
      expect((await playbookStore.load("c1")).map((t) => t.containmentCheck?.stepId).sort()).toEqual([
        "isolate-host",
        "revoke-keys-reauth",
      ]);
    });

    it("refuses with 501 when there is no Playbook store", async () => {
      const root = await mkdtemp(join(tmpdir(), "dfir-ccheck-nopb-"));
      const cases = new CaseStore(root);
      await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
      const stateStore = new StateStore(cases);
      await stateStore.save({ ...emptyState("c1"), findings: [FINDING] });
      const app = createApp(cases, { stateStore });
      const res = await request(app)
        .post(`${PATH}/playbook`)
        .send({ checkId: "x", steps: ["isolate-host"] });
      expect(res.status).toBe(501);
    });
  });
});
