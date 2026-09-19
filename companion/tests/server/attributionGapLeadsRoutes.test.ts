// #1405: GET /cases/:id/attribution-gap-leads — leads from a posted assertion, over the real dataset.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AttributionAssertionStore } from "../../src/analysis/attributionAssertionStore.js";
import { createApp } from "../../src/server.js";

const body = (over: Record<string, unknown> = {}) => ({
  tier: "operator",
  label: "APT29",
  sources: "s",
  alternatives: "a",
  analystAssessment: "x",
  ...over,
});

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-gap-leads-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return createApp(cases, {
    stateStore: new StateStore(cases),
    attributionAssertionStore: new AttributionAssertionStore(cases),
  });
}

describe("GET /cases/:id/attribution-gap-leads", () => {
  it("501 without the stores", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-gap-leads-"));
    const cases = new CaseStore(root);
    expect((await request(createApp(cases, {})).get("/cases/c1/attribution-gap-leads")).status).toBe(501);
    expect(
      (
        await request(createApp(cases, { stateStore: new StateStore(cases) })).get(
          "/cases/c1/attribution-gap-leads",
        )
      ).status,
    ).toBe(501);
  });

  it("a matching assertion yields the group's unshown techniques; a non-group label yields none and is counted", async () => {
    const app = await makeApp();
    expect((await request(app).get("/cases/c1/attribution-gap-leads")).body).toMatchObject({
      leads: [],
      unmatchedAssertions: 0,
    });
    await request(app).post("/cases/c1/attribution-assertions").send(body());
    await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(body({ tier: "cluster", label: "UNC-nothing" }));
    const res = await request(app).get("/cases/c1/attribution-gap-leads");
    expect(res.status).toBe(200);
    expect(res.body.unmatchedAssertions).toBe(1);
    expect(res.body.leads).toHaveLength(1);
    const lead = res.body.leads[0];
    expect(lead.group.id).toBe("G0016");
    expect(lead.label).toBe("APT29");
    expect(lead.techniques.length).toBeGreaterThan(0);
    expect(lead.observedCount).toBe(0);
    expect(lead.caveat).toMatch(/never attribution/);
    expect(typeof res.body.attackVersion).toBe("string");
    // The assertion record itself is untouched by the read.
    const list = await request(app).get("/cases/c1/attribution-assertions");
    expect(list.body.assertions[0].gapLeads).toBeUndefined();
  });
});
