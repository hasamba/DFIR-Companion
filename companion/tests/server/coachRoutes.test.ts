import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import type { Express } from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { PlaybookStore } from "../../src/analysis/playbookStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";
import type { EnrichmentProvider } from "../../src/enrichment/provider.js";

// GET /cases/:id/coach/next-action[s] (#271). The scoring heuristics themselves are unit-tested in
// tests/analysis/coach.test.ts; what matters here is the WIRING — the card's two derived signals come
// from the enrichment provider set and the playbook, so a recommendation can't survive work the
// analyst has already done or advertise a run that would query nothing.

// Scope decides whether a provider is enabled for a case by DEFAULT: self-hosted ("local") ones are,
// key-based external SaaS are opt-in per case (resolveEnabledProviders).
function provider(name: string, kinds: string[], scope: "local" | "external" = "local"): EnrichmentProvider {
  return { name, scope, supports: (k) => kinds.includes(k), lookup: async () => null };
}

async function makeApp(opts: { providers?: EnrichmentProvider[]; playbook?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-coach-routes-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const playbookStore = opts.playbook === false ? undefined : new PlaybookStore(store);
  const app = createApp(store, {
    stateStore,
    playbookStore,
    ...(opts.providers ? { enrichmentProviders: opts.providers } : {}),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, stateStore, playbookStore };
}

// A case with evidence, one confirmed finding, all questions answered, and one next step — so the
// only two cards in play are enrich-iocs and run-next-steps.
function triagedState(over: Partial<InvestigationState> = {}): InvestigationState {
  return {
    ...emptyState("c1"),
    forensicTimeline: [
      {
        id: "e1",
        timestamp: "2026-06-01T00:00:00Z",
        description: "d",
        severity: "High",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        asset: "WS-01",
        sources: ["EVTX"],
      },
    ],
    findings: [
      {
        id: "f1",
        title: "Beacon",
        description: "d",
        severity: "High",
        status: "confirmed",
        relatedIocs: [],
        sourceScreenshots: [],
        mitreTechniques: [],
        firstSeen: "2026-06-01T00:00:00Z",
        lastUpdated: "2026-06-01T00:00:00Z",
      },
    ],
    nextSteps: [{ id: "s1", priority: "high", action: "Pull Security.evtx", rationale: "R", pointer: "P" }],
    updatedAt: new Date().toISOString(),
    ...over,
  };
}

async function ids(app: Express, caseId = "c1"): Promise<string[]> {
  const res = await request(app).get(`/cases/${caseId}/coach/next-actions`);
  expect(res.status).toBe(200);
  return (res.body.recommendations as { id: string }[]).map((r) => r.id);
}

describe("GET /cases/:id/coach/next-actions", () => {
  it("counts only the IOCs an enrichment run would actually query", async () => {
    const { app, stateStore } = await makeApp({ providers: [provider("virustotal", ["ip", "hash"])] });
    await stateStore.save(
      triagedState({
        iocs: [
          // Already checked by the only enabled provider.
          {
            id: "i1",
            type: "ip",
            value: "185.220.101.47",
            firstSeen: "2026-06-01T00:00:00Z",
            enrichedBy: ["virustotal"],
          },
          // Never queryable: no provider supports these kinds, so they are not pending work.
          { id: "i2", type: "file", value: "C:\\Users\\j\\invoice.xlsm", firstSeen: "2026-06-01T00:00:00Z" },
          { id: "i3", type: "sid", value: "S-1-5-21-1", firstSeen: "2026-06-01T00:00:00Z" },
          // Pending: enabled provider supports "hash" and hasn't checked it.
          { id: "i4", type: "hash", value: "abc", firstSeen: "2026-06-01T00:00:00Z" },
        ],
      }),
    );

    const res = await request(app).get("/cases/c1/coach/next-action");
    expect(res.status).toBe(200);
    expect(res.body.recommendation.id).toBe("enrich-iocs");
    expect(res.body.recommendation.action).toBe("Enrich 1 IOC");
  });

  it("stops recommending enrichment once every provider has checked every IOC", async () => {
    const { app, stateStore } = await makeApp({ providers: [provider("virustotal", ["ip"])] });
    await stateStore.save(
      triagedState({
        iocs: [
          {
            id: "i1",
            type: "ip",
            value: "1.1.1.1",
            firstSeen: "2026-06-01T00:00:00Z",
            enrichedBy: ["virustotal"],
          },
          { id: "i2", type: "other", value: "GLOBALTECH\\admin-deploy", firstSeen: "2026-06-01T00:00:00Z" },
        ],
      }),
    );
    expect(await ids(app)).not.toContain("enrich-iocs");
  });

  it("recommends nothing about enrichment when no providers are configured", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      triagedState({
        iocs: [{ id: "i1", type: "ip", value: "1.1.1.1", firstSeen: "2026-06-01T00:00:00Z" }],
      }),
    );
    expect(await ids(app)).not.toContain("enrich-iocs");
  });

  it("recommends nothing about enrichment when the configured provider is not enabled for the case", async () => {
    // POST /cases/:id/enrich — the card's own CTA — answers 422 in this state, so offering the card
    // would send the analyst at a button that cannot run.
    const { app, stateStore } = await makeApp({ providers: [provider("virustotal", ["ip"], "external")] });
    await stateStore.save(
      triagedState({
        iocs: [{ id: "i1", type: "ip", value: "1.1.1.1", firstSeen: "2026-06-01T00:00:00Z" }],
      }),
    );
    expect(await ids(app)).not.toContain("enrich-iocs");
    expect((await request(app).post("/cases/c1/enrich").send({})).status).toBe(422);
  });

  it("stops recommending next steps once the analyst completes the playbook tasks", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(triagedState());

    expect(await ids(app)).toContain("run-next-steps");

    // Work the playbook the way the dashboard does: read the synced task list, then mark every
    // next-step task done. The coach must follow the analyst's progress, not synthesis's proposal.
    const playbook = await request(app).get("/cases/c1/playbook");
    expect(playbook.status).toBe(200);
    const tasks = playbook.body.tasks as { id: string; source: string }[];
    expect(tasks.some((t) => t.source === "next_step")).toBe(true);
    for (const t of tasks.filter((t) => t.source === "next_step")) {
      const patched = await request(app).patch(`/cases/c1/playbook/${t.id}`).send({ status: "done" });
      expect(patched.status).toBe(200);
    }

    expect(await ids(app)).not.toContain("run-next-steps");
  });

  it("falls back to the raw next-step list when no playbook store is configured", async () => {
    const { app, stateStore } = await makeApp({ playbook: false });
    await stateStore.save(triagedState());
    const res = await request(app).get("/cases/c1/coach/next-action");
    expect(res.status).toBe(200);
    expect(res.body.recommendation.id).toBe("run-next-steps");
    expect(res.body.recommendation.action).toBe("Run 1 recommended next step");
  });

  it("404s on a case that does not exist, and writes nothing for it", async () => {
    const { app, store } = await makeApp();
    for (const path of ["/cases/nope/coach/next-action", "/cases/nope/coach/next-actions"]) {
      const res = await request(app).get(path);
      expect(res.status).toBe(404);
      expect(res.body.error).toContain("does not exist");
    }
    expect(await store.caseExists("nope")).toBe(false);
  });

  it("501s when no state store is configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-coach-nostate-"));
    const app = createApp(new CaseStore(root), {});
    const res = await request(app).get("/cases/c1/coach/next-action");
    expect(res.status).toBe(501);
  });
});
