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
import { createApp } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1840, the Jev path: the missed-evidence review masks every batch with ONE snapshot taken at the
// start, and sends batches four at a time. A Hide that lands mid-review must stop every batch that
// has not left yet — none of them may carry the value in clear.

const NAME = "Jane Doe";
const ENV = ["DFIR_JEV_ENABLED", "DFIR_JEV_KEY", "DFIR_JEV_BASE_URL", "DFIR_JEV_BATCH_SIZE"] as const;
const row = (i: number): ForensicEvent => ({
  id: `r${i}`,
  timestamp: "2026-01-01T00:00:00Z",
  description: `logon by ${NAME} number ${i}`,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

describe("a Hide during a Jev review (#1840)", () => {
  const saved: Record<string, string | undefined> = {};
  let jev: ReturnType<typeof createServer>;
  let bodies: string[];
  let onFirst: () => Promise<void>;

  beforeEach(async () => {
    for (const k of ENV) saved[k] = process.env[k];
    bodies = [];
    jev = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", async () => {
        bodies.push(body);
        if (bodies.length === 1) await onFirst();
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
    process.env.DFIR_JEV_BATCH_SIZE = "1";
  });

  afterEach(async () => {
    for (const k of ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await new Promise<void>((resolve) => jev.close(() => resolve()));
  });

  it("holds every batch that had not left when the Hide landed", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-jev-anonrev-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save(emptyState("c1"));
    const superTimelineStore = new SuperTimelineStore(cases);
    await superTimelineStore.append(
      "c1",
      Array.from({ length: 12 }, (_, i) => row(i)),
    );
    const custom = new CustomEntitiesStore(cases);
    onFirst = async () => {
      await custom.save("c1", [{ value: NAME, category: "PERSON" }]); // the analyst presses Hide
    };
    const app = createApp(cases, { stateStore, superTimelineStore });
    const res = await request(app).post("/cases/c1/jev/review").send({});
    expect(res.status).toBe(502);
    expect(String(res.body.error)).toMatch(/anonymization/i);
    // Only the first concurrent wave (sent before the Hide) reached the service; 12 batches were planned.
    expect(bodies.length).toBeGreaterThan(0);
    expect(bodies.length).toBeLessThan(12);
  });
});
