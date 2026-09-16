import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AttributionAssertionStore } from "../../src/analysis/attributionAssertionStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;

function assertionBody(over: Record<string, unknown> = {}) {
  return {
    tier: "cluster",
    label: "UNC1234",
    sources: "Internal correlation of C2 infrastructure across three hosts",
    alternatives: "Considered coincidental reuse of a bulletproof host; rejected — shared TLS cert",
    analystAssessment: "Consistent naming and infra reuse across the incident window",
    ...over,
  };
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-attribution-assertions-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, {
    stateStore: new StateStore(cases),
    attributionAssertionStore: new AttributionAssertionStore(cases),
  });
});

describe("/cases/:id/attribution-assertions", () => {
  it("returns an empty list for a fresh case", async () => {
    const res = await request(app).get("/cases/c1/attribution-assertions");
    expect(res.status).toBe(200);
    expect(res.body.assertions).toEqual([]);
  });

  it("creates an assertion and reflects it in the list", async () => {
    const res = await request(app).post("/cases/c1/attribution-assertions").send(assertionBody());
    expect(res.status).toBe(200);
    expect(res.body.assertion.tier).toBe("cluster");
    expect(res.body.assertion.createdBy).toBe("local");
    const list = await request(app).get("/cases/c1/attribution-assertions");
    expect(list.body.assertions).toHaveLength(1);
  });

  it("annotates a matching label with matchedAdversaryGroupId, read-time only", async () => {
    const created = await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(assertionBody({ tier: "operator", label: "APT29" }));
    // Pins "read-time only, never written": the POST response and the persisted record itself
    // must never carry the annotation — only GET computes it live.
    expect(created.body.assertion.matchedAdversaryGroupId).toBeUndefined();
    const res = await request(app).get("/cases/c1/attribution-assertions");
    expect(res.body.assertions[0].matchedAdversaryGroupId).toBeTruthy();
  });

  it("never breaks the primary read when the AdversaryGroup dataset annotation itself is dropped", async () => {
    // The annotation is optional/informational — the audit trail (tier/label/sources/etc.) must
    // still come back even if group-matching finds nothing (a real dataset lookup, exercised
    // with a label that cannot match, standing in for "the dataset step contributes nothing").
    await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(assertionBody({ label: "UNC-not-a-group" }));
    const res = await request(app).get("/cases/c1/attribution-assertions");
    expect(res.status).toBe(200);
    expect(res.body.assertions[0].tier).toBe("cluster");
    expect(res.body.assertions[0].matchedAdversaryGroupId).toBeNull();
  });

  it("flags buildsOnRetracted when a cited weaker-tier assertion has since been retracted", async () => {
    const cluster = await request(app).post("/cases/c1/attribution-assertions").send(assertionBody());
    await request(app).delete(`/cases/c1/attribution-assertions/${cluster.body.assertion.id}`);
    await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(
        assertionBody({ tier: "campaign", label: "Operation Foobar", buildsOn: [cluster.body.assertion.id] }),
      );
    const res = await request(app).get("/cases/c1/attribution-assertions");
    const campaign = res.body.assertions.find((a: { tier: string }) => a.tier === "campaign");
    expect(campaign.buildsOnRetracted).toBe(true);
  });

  it("does not flag buildsOnRetracted when the cited assertion is still open", async () => {
    const cluster = await request(app).post("/cases/c1/attribution-assertions").send(assertionBody());
    await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(
        assertionBody({ tier: "campaign", label: "Operation Foobar", buildsOn: [cluster.body.assertion.id] }),
      );
    const res = await request(app).get("/cases/c1/attribution-assertions");
    const campaign = res.body.assertions.find((a: { tier: string }) => a.tier === "campaign");
    expect(campaign.buildsOnRetracted).toBe(false);
  });

  it("rejects a periodEnd before periodStart, with 400 not 500", async () => {
    const res = await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(assertionBody({ periodStart: "2026-06-01T00:00:00Z", periodEnd: "2026-01-01T00:00:00Z" }));
    expect(res.status).toBe(400);
  });

  it("does not annotate a label that matches nothing", async () => {
    await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(assertionBody({ label: "UNC9999" }));
    const res = await request(app).get("/cases/c1/attribution-assertions");
    expect(res.body.assertions[0].matchedAdversaryGroupId).toBeNull();
  });

  it("rejects an assertion missing a required field", async () => {
    const res = await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(assertionBody({ sources: "" }));
    expect(res.status).toBe(400);
  });

  it("rejects an unrecognized tier", async () => {
    const res = await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(assertionBody({ tier: "bogus" }));
    expect(res.status).toBe(400);
  });

  it("rejects buildsOn referencing a non-existent id, with 400 not 500", async () => {
    const res = await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(assertionBody({ buildsOn: ["does-not-exist"] }));
    expect(res.status).toBe(400);
  });

  it("rejects buildsOn referencing an equal-or-stronger tier, with 400 not 500", async () => {
    const cluster = await request(app).post("/cases/c1/attribution-assertions").send(assertionBody());
    const res = await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(assertionBody({ buildsOn: [cluster.body.assertion.id] }));
    expect(res.status).toBe(400);
  });

  it("allows buildsOn referencing a strictly weaker tier", async () => {
    const cluster = await request(app).post("/cases/c1/attribution-assertions").send(assertionBody());
    const res = await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(
        assertionBody({ tier: "campaign", label: "Operation Foobar", buildsOn: [cluster.body.assertion.id] }),
      );
    expect(res.status).toBe(200);
    expect(res.body.assertion.buildsOn).toEqual([cluster.body.assertion.id]);
  });

  it("retracts an assertion", async () => {
    const created = await request(app).post("/cases/c1/attribution-assertions").send(assertionBody());
    const res = await request(app).delete(`/cases/c1/attribution-assertions/${created.body.assertion.id}`);
    expect(res.status).toBe(200);
    expect(res.body.assertions[0].status).toBe("retracted");
  });

  it("retracting an unknown id is a no-op, not an error", async () => {
    const res = await request(app).delete("/cases/c1/attribution-assertions/does-not-exist");
    expect(res.status).toBe(200);
  });

  it("rejects a supersedesId pointing at an assertion that is not retracted, with 400 not 500", async () => {
    const old = await request(app).post("/cases/c1/attribution-assertions").send(assertionBody());
    const res = await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(assertionBody({ supersedesId: old.body.assertion.id }));
    expect(res.status).toBe(400);
  });

  it("allows a supersedesId pointing at a retracted assertion", async () => {
    const old = await request(app).post("/cases/c1/attribution-assertions").send(assertionBody());
    await request(app).delete(`/cases/c1/attribution-assertions/${old.body.assertion.id}`);
    const res = await request(app)
      .post("/cases/c1/attribution-assertions")
      .send(assertionBody({ supersedesId: old.body.assertion.id }));
    expect(res.status).toBe(200);
  });

  it("returns 501 when the store is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-attribution-assertions-unconfigured-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const bareApp = createApp(cases, {});
    const res = await request(bareApp).get("/cases/c1/attribution-assertions");
    expect(res.status).toBe(501);
  });
});

// #933 item 20: the human-identity write gate (humanIdentityFor, imported unmodified from
// routes/evidenceAttestation.ts and already covered by its own unit tests there) — same wiring
// check applied to huntRequirements.ts's own route test.
describe("/cases/:id/attribution-assertions with team-auth on", () => {
  it("rejects POST with no session identity", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-attribution-assertions-teamauth-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const teamAuth = new TeamAuth({
      store: new AuthStore(join(root, "auth.sqlite")),
      bootstrapToken: "test-bootstrap-token",
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    });
    const teamApp = createApp(cases, {
      teamAuth,
      attributionAssertionStore: new AttributionAssertionStore(cases),
    });
    const res = await request(teamApp).post("/cases/c1/attribution-assertions").send(assertionBody());
    expect(res.status).toBe(401);
  });

  it("rejects DELETE with no session identity", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-attribution-assertions-teamauth-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const teamAuth = new TeamAuth({
      store: new AuthStore(join(root, "auth.sqlite")),
      bootstrapToken: "test-bootstrap-token",
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    });
    const teamApp = createApp(cases, {
      teamAuth,
      attributionAssertionStore: new AttributionAssertionStore(cases),
    });
    const res = await request(teamApp).delete("/cases/c1/attribution-assertions/anything");
    expect(res.status).toBe(401);
  });
});
