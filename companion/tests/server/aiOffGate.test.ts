// #2757: with a case's AI switch off, every route that would call a model refuses with 409 before
// its handler runs — manual buttons included. Watson and the AI-dependent imports keep their own
// AI-off answers.
import { describe, it, expect, beforeEach } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { createApp } from "../../src/server.js";
import { AI_LIMIT_PATHS, AI_LIMIT_PATTERNS } from "../../src/composition/aiRateLimit.js";
import {
  AI_OFF_EXTRA_PATHS,
  AI_OFF_IN_HANDLER,
  AI_OFF_OWN_ANSWER,
  aiOffGateApplies,
} from "../../src/composition/aiCallRoutes.js";
import { AI_OFF_TEXT } from "../../src/routes/aiOffRefusal.js";

/** Every route the gate must refuse, as a concrete POST path under /cases/c1 plus its body. */
const GATED: Array<[string, Record<string, unknown>]> = [
  ["/synthesize", {}],
  ["/events/e1/explain", {}],
  ["/executive-summary", {}],
  ["/starred-report", {}],
  ["/view-summary", {}],
  ["/remediation-plan", {}],
  ["/hypothesis-review", {}],
  ["/narrative", {}],
  ["/memory/next-steps", {}],
  ["/adversary-hints/hunt-technique", { technique: "T1059" }],
  ["/deep-pass", {}],
  ["/second-opinion", {}],
  ["/second-opinion/referee", {}],
  ["/second-look", {}],
  ["/jev/review", {}],
  ["/findings/f1/containment-check", {}],
  ["/timeline-gaps/hypothesize", {}],
  ["/sessions/s1/summary", {}],
  ["/translate-query", { text: "x" }],
  ["/tagger/suggest-rule", {}],
  ["/playbook/suggest-hunts", {}],
  ["/velociraptor/suggest-hunts", {}],
  ["/false-positive/suggest", { kind: "ioc", ref: "x", ai: true }],
  ["/mcp/agent", {}],
  ["/mcp/agent-upload", {}],
];

/** A pipeline whose every method call is counted; `hasSynthesisProvider` says a provider exists. */
function countingPipeline(): { pipeline: unknown; calls: string[] } {
  const calls: string[] = [];
  const pipeline = new Proxy(
    {},
    {
      get: (_t, prop) => {
        if (prop === "then") return undefined;
        if (prop === "hasSynthesisProvider") return () => true;
        return (..._args: unknown[]) => {
          calls.push(String(prop));
          return Promise.reject(new Error("stub provider: a model call was attempted"));
        };
      },
    },
  );
  return { pipeline, calls };
}

let store: CaseStore;
let control: AiControlStore;

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-aioff-")));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  control = new AiControlStore(store);
});

describe("AI switched off (#2757)", () => {
  it("refuses every model-calling route with 409 and never reaches the pipeline", async () => {
    const { pipeline, calls } = countingPipeline();
    const app = createApp(store, { pipeline: pipeline as never });
    for (const [rel, body] of GATED) {
      const res = await request(app).post(`/cases/c1${rel}`).send(body);
      expect(res.status, rel).toBe(409);
      expect(res.body, rel).toEqual({ error: AI_OFF_TEXT, aiOff: true });
    }
    expect(calls).toEqual([]);
  });

  it("folds case and a trailing slash, like Express routing does", async () => {
    const app = createApp(store, { pipeline: countingPipeline().pipeline as never });
    expect((await request(app).post("/cases/c1/SYNTHESIZE/").send({})).status).toBe(409);
  });

  it("lets the same routes through once AI is on", async () => {
    await control.save("c1", { enabled: true, lastAnalyzedSeq: 0 });
    const app = createApp(store, { pipeline: countingPipeline().pipeline as never });
    for (const [rel, body] of GATED) {
      const res = await request(app).post(`/cases/c1${rel}`).send(body);
      expect(res.body?.aiOff, rel).toBeUndefined();
    }
  });

  it("leaves the deterministic false-positive suggestion alone (no `ai`)", async () => {
    const app = createApp(store, { pipeline: countingPipeline().pipeline as never });
    const res = await request(app).post("/cases/c1/false-positive/suggest").send({ kind: "ioc", ref: "x" });
    expect(res.body?.aiOff).toBeUndefined();
  });

  it("keeps Watson's own AI-off answer", async () => {
    const app = createApp(store, { pipeline: countingPipeline().pipeline as never });
    const res = await request(app).post("/cases/c1/watson/message").send({ text: "hi" });
    expect(res.body?.aiOff).toBeUndefined();
  });

  it("answers 404 first for a case that does not exist, and 423 first for a closed case", async () => {
    const app = createApp(store, { pipeline: countingPipeline().pipeline as never });
    expect((await request(app).post("/cases/nope/synthesize").send({})).status).toBe(404);
    expect((await request(app).patch("/cases/c1/status").send({ status: "closed" })).status).toBe(200);
    expect((await request(app).post("/cases/c1/synthesize").send({})).status).toBe(423);
  });

  it("refuses a synthesis replay in the handler, after the run is loaded", async () => {
    const analysisRunStore = {
      get: async () => ({ id: "r1", caseId: "c1", kind: "synthesis", versions: {}, input: {} }),
    };
    const { pipeline, calls } = countingPipeline();
    const app = createApp(store, {
      pipeline: pipeline as never,
      analysisRunStore: analysisRunStore as never,
    });
    const res = await request(app).post("/cases/c1/analysis-runs/r1/replay").send({});
    expect(res.status).toBe(409);
    expect(res.body).toEqual({ error: AI_OFF_TEXT, aiOff: true });
    expect(calls).toEqual([]);
  });
});

// ── Drift guard: a new AI route cannot skip the gate ─────────────────────────────────────────────

const ROUTES_DIR = fileURLToPath(new URL("../../src/routes/", import.meta.url));

/** Routes that look AI-gated to the scan but call no model, or answer AI-off another way. */
const NOT_GATED = new Map([
  ["/ai-preview", "stops every action at the AI-call gate — no provider is ever called (#2491)"],
  ["/push", "collector ingest; its imports and synthesis read the AI switch themselves"],
  ["/import", "AI-dependent kinds are saved as evidence when AI is off (refuseAiOffImport)"],
  [
    "/mcp/:serverId/run-upload",
    "runs one named MCP tool directly, no model; the scan sees the startAgent helper declared below it",
  ],
]);

/** Every /cases/:id POST whose handler gates on a provider or calls a model-run pipeline method. */
function aiCallingRoutes(): string[] {
  const signal =
    /hasSynthesisProvider|AI provider not configured|synthesisProvider|askJev|gradeEvents|runMcpAgent|startAgent\(|secondOpinionEnabled|pipeline\.(synthesize|deepPass|secondOpinion|rerunSecondOpinionReferee|secondLook)\b/;
  const found = new Set<string>();
  for (const file of readdirSync(ROUTES_DIR).filter((f) => f.endsWith(".ts"))) {
    const src = readFileSync(join(ROUTES_DIR, file), "utf8");
    const re = /\n {2}app\.post\("(\/cases\/:id[^"]*)"/g;
    for (let m = re.exec(src); m; m = re.exec(src)) {
      const rest = src.slice(m.index + m[0].length);
      const next = rest.indexOf("\n  app.");
      if (signal.test(next > 0 ? rest.slice(0, next) : rest)) found.add(m[1].slice("/cases/:id".length));
    }
  }
  return [...found].sort();
}

const concrete = (suffix: string): string => suffix.replace(/:[A-Za-z]+/g, "x").toLowerCase();
const AI_BODY = { ai: true };

describe("the AI-off gate covers every model-calling route (#2757)", () => {
  it("finds the routes at all", () => {
    const routes = aiCallingRoutes();
    expect(routes).toContain("/synthesize");
    expect(routes).toContain("/second-opinion");
    expect(routes).toContain("/mcp/agent");
  });

  it("gates, self-answers or explicitly excludes every scanned route", () => {
    const uncovered = aiCallingRoutes().filter(
      (s) =>
        !aiOffGateApplies("POST", concrete(s), AI_BODY) &&
        !AI_OFF_OWN_ANSWER.has(s) &&
        !AI_OFF_IN_HANDLER.has(s) &&
        !NOT_GATED.has(s),
    );
    expect(uncovered, "add these to composition/aiCallRoutes.ts or NOT_GATED with a reason").toEqual([]);
  });

  it("gates every route the AI rate limiter meters, except the ones that answer AI-off themselves", () => {
    for (const rel of AI_LIMIT_PATHS) {
      if (AI_OFF_OWN_ANSWER.has(rel)) continue;
      expect(aiOffGateApplies("POST", rel, AI_BODY), rel).toBe(true);
    }
    for (const sample of ["/events/x/explain", "/sessions/x/summary", "/findings/x/containment-check"]) {
      expect(AI_LIMIT_PATTERNS.some((re) => re.test(sample))).toBe(true);
      expect(aiOffGateApplies("POST", sample, AI_BODY), sample).toBe(true);
    }
    for (const rel of AI_OFF_EXTRA_PATHS.keys()) expect(aiOffGateApplies("POST", rel, {}), rel).toBe(true);
  });

  it("covers the in-handler replay route in the scan list it guards", () => {
    expect(readFileSync(join(ROUTES_DIR, "analysisRuns.ts"), "utf8")).toMatch(/sendAiOff/);
  });
});
