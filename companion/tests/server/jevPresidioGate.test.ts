import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { PresidioClient } from "../../src/analysis/presidio.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

// #1952: the two Jev routes masked their payload but never ran the Presidio gate, so a name the
// built-in masking cannot see reached the external model with no scan and no approval hold. They
// now obey the same fail-closed gate as every other AI call.

const HOST = "FIN-SRV-07";
const PERSON = "Rob Roe";
const ENV = ["DFIR_JEV_ENABLED", "DFIR_JEV_KEY", "DFIR_JEV_BASE_URL", "DFIR_ANONYMIZE"] as const;

const row = (id: string, severity: ForensicEvent["severity"], description: string): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description,
  severity,
  asset: HOST,
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const FINDING: Finding = {
  id: "f1",
  severity: "High",
  title: "Credential theft",
  description: "mimikatz ran",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: ["T1003"],
  relatedEventIds: ["e1"],
  firstSeen: "2026-01-01T00:00:00Z",
  lastUpdated: "2026-01-01T00:00:00Z",
  status: "open",
};

class NoProvider implements AIProvider {
  readonly name = "none";
  readonly model = "none";
  async analyze(): Promise<AnalyzeResult> {
    throw new Error("the chat provider must not be called");
  }
}

type Mode = "flags" | "down" | "clean";

describe("the Jev routes run the Presidio gate (#1952)", () => {
  const saved: Record<string, string | undefined> = {};
  let jev: ReturnType<typeof createServer>;
  let bodies: string[];
  let scanned: string[];

  beforeEach(async () => {
    resetLimiters();
    for (const k of ENV) saved[k] = process.env[k];
    delete process.env.DFIR_ANONYMIZE;
    bodies = [];
    scanned = [];
    jev = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        bodies.push(body);
        const questions = JSON.parse(body).questions as Record<string, { type: string; criteria?: object }>;
        const answers: Record<string, unknown> = {};
        for (const [id, q] of Object.entries(questions))
          answers[id] =
            q.type === "noul"
              ? { type: "noul", noul: 0 }
              : q.type === "choice"
                ? {
                    type: "choice",
                    choice: Object.keys(q.criteria ?? {})[0],
                    probabilities: {},
                    confidence: 0.9,
                  }
                : { type: "score", score: 1, legend: {}, probabilities: {}, confidence: 0.5 };
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
    for (const k of ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await new Promise<void>((resolve) => jev.close(() => resolve()));
  });

  async function harness(mode: Mode, presidioOff = false) {
    const root = await mkdtemp(join(tmpdir(), "dfir-jev-presidio-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save({
      ...emptyState("c1"),
      findings: [FINDING],
      forensicTimeline: [row("e1", "High", `mimikatz run by ${PERSON}`)],
    });
    const superTimelineStore = new SuperTimelineStore(cases);
    await superTimelineStore.append("c1", [row("r1", "Info", `logon by ${PERSON}`)]);
    if (presidioOff) {
      const control = new AnonControlStore(cases);
      await control.save("c1", { ...(await control.load("c1")), presidio: false });
    }
    const client: PresidioClient = {
      analyze: async (text) => {
        scanned.push(text);
        if (mode === "down") throw new Error("connect ECONNREFUSED");
        return mode === "flags" && text.includes(PERSON)
          ? [{ entityType: "PERSON", value: PERSON, score: 0.95 }]
          : [];
      },
    };
    const pipeline = buildRuntimePipeline({
      provider: new NoProvider(),
      stateStore,
      store: cases,
      imageLoader: async () => ({ base64: "AA", mimeType: "image/webp" }),
      presidio: { client, url: "http://localhost:5002", minScore: 0.6 },
    });
    return createApp(cases, { pipeline, stateStore, superTimelineStore });
  }

  const routes = [
    ["missed-evidence review", "/cases/c1/jev/review"],
    ["containment check", "/cases/c1/findings/f1/containment-check"],
  ] as const;

  for (const [label, path] of routes) {
    describe(label, () => {
      it("holds for approval and sends nothing when Presidio finds a new name", async () => {
        const app = await harness("flags");
        const res = await request(app).post(path).send({});
        expect(res.status, JSON.stringify(res.body)).toBe(409);
        expect(res.body.error).toBe("presidio_approval_required");
        expect(bodies, "nothing may reach Jev").toHaveLength(0);
        // Presidio sees masked text only, never the host the built-in masking hides.
        expect(scanned.join("\n")).not.toContain(HOST);
      });

      it("fails closed and sends nothing when Presidio cannot be reached", async () => {
        const app = await harness("down");
        const res = await request(app).post(path).send({});
        expect(res.status).toBeGreaterThanOrEqual(500);
        expect(String(res.body.error)).toMatch(/Presidio/);
        expect(bodies).toHaveLength(0);
      });

      it("sends after a clean scan", async () => {
        const app = await harness("clean");
        const res = await request(app).post(path).send({});
        expect(res.status, JSON.stringify(res.body)).toBe(200);
        expect(scanned.length).toBeGreaterThan(0);
        expect(bodies.length).toBeGreaterThan(0);
      });

      it("skips the scan when Presidio is off for the case", async () => {
        const app = await harness("flags", true);
        const res = await request(app).post(path).send({});
        expect(res.status, JSON.stringify(res.body)).toBe(200);
        expect(scanned).toHaveLength(0);
        expect(bodies.length).toBeGreaterThan(0);
      });
    });
  }
});
