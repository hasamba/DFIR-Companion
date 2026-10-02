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
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { createApp } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1934: the missed-evidence review built its mask from the route options, which carry no
// anonymization store — only the pipeline's options do. So the mask was the identity function and
// every review sent hosts and hidden values to Jev in clear, on every case (masking is on by
// default). These tests use the production option shape: createApp gets NO injected anon stores.

const HOST = "FIN-SRV-07";
const NAME = "Jane Doe";
const ENV = ["DFIR_JEV_ENABLED", "DFIR_JEV_KEY", "DFIR_JEV_BASE_URL", "DFIR_ANONYMIZE"] as const;

const archiveRow: ForensicEvent = {
  id: "r1",
  timestamp: "2026-01-01T00:00:00Z",
  description: `logon by ${NAME} on ${HOST}`,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
};

describe("the Jev review masks what it sends (#1934)", () => {
  const saved: Record<string, string | undefined> = {};
  let jev: ReturnType<typeof createServer>;
  let bodies: string[];

  beforeEach(async () => {
    for (const k of ENV) saved[k] = process.env[k];
    delete process.env.DFIR_ANONYMIZE; // the shipped default: masking on
    bodies = [];
    jev = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        bodies.push(body);
        const questions = JSON.parse(body).questions as Record<string, { type: string }>;
        const answers: Record<string, unknown> = {};
        for (const [id, q] of Object.entries(questions))
          answers[id] =
            q.type === "noul"
              ? { type: "noul", noul: 0 }
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

  /** A case whose forensic timeline names HOST (so the anonymizer knows it) and whose analyst hid NAME. */
  async function caseWith(maskingOff = false) {
    const root = await mkdtemp(join(tmpdir(), "dfir-jev-mask-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const state = emptyState("c1");
    state.forensicTimeline = [
      { ...archiveRow, id: "f1", severity: "High", asset: HOST, description: "seen" },
    ];
    await stateStore.save(state);
    const superTimelineStore = new SuperTimelineStore(cases);
    await superTimelineStore.append("c1", [archiveRow]);
    await new CustomEntitiesStore(cases).save("c1", [{ value: NAME, category: "PERSON" }]);
    if (maskingOff) {
      const control = new AnonControlStore(cases);
      await control.save("c1", { ...(await control.load("c1")), enabled: false });
    }
    return createApp(cases, { stateStore, superTimelineStore });
  }

  it("sends tokens, not the host or the hidden name, on a default case", async () => {
    const app = await caseWith();
    const res = await request(app).post("/cases/c1/jev/review").send({});
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(bodies.length).toBeGreaterThan(0);
    const wire = bodies.join("\n");
    expect(wire).not.toContain(HOST);
    expect(wire).not.toContain(NAME);
    expect(wire).toMatch(/ANON_HOST_\d+/);
  });

  it("sends the row in clear when the analyst switched masking off for the case", async () => {
    const app = await caseWith(true);
    const res = await request(app).post("/cases/c1/jev/review").send({});
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const wire = bodies.join("\n");
    expect(wire).toContain(HOST);
    expect(wire).toContain(NAME);
  });
});
