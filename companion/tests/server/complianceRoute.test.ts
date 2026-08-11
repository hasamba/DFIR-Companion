import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ComplianceControlStore } from "../../src/analysis/complianceControl.js";
import { emptyState, type Finding } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";

// Route-level coverage for the compliance mapping. mapFindings has its own unit tests; what is
// exercised here is what those cannot see — that the URL reaches this handler, that a case which
// does not exist 404s instead of answering "no obligations", and that the not-legal-advice
// disclaimer actually ships in the response body rather than sitting unread in the dataset.

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "f1",
    severity: "High",
    title: "Ransomware deployed on VICTIM-PC",
    description: "Files encrypted",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: ["T1486"],
    firstSeen: "2026-01-01T00:00:00.000Z",
    lastUpdated: "2026-01-01T00:00:00.000Z",
    status: "confirmed",
    ...overrides,
  };
}

let app: ReturnType<typeof createApp>;
let cases: CaseStore;
let stateStore: StateStore;
let complianceControlStore: ComplianceControlStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-compliance-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "Ransomware Case", investigator: "Alice", aiProvider: null });

  stateStore = new StateStore(cases);
  await stateStore.save({
    ...emptyState("c1"),
    findings: [makeFinding({ id: "f-confirmed" }), makeFinding({ id: "f-open", status: "open" })],
  });

  complianceControlStore = new ComplianceControlStore(cases);
  app = createApp(cases, { stateStore, complianceControlStore });
});

describe("GET /cases/:id/compliance", () => {
  it("maps the case's confirmed findings", async () => {
    const res = await request(app).get("/cases/c1/compliance");

    expect(res.status).toBe(200);
    expect(res.body.caseId).toBe("c1");
    expect(res.body.results).toHaveLength(1);
    expect(res.body.results[0]).toMatchObject({ technique: "T1486", findingId: "f-confirmed" });

    const frameworks = res.body.results[0].frameworks.map((f: { framework: string }) => f.framework);
    expect(frameworks).toEqual(
      expect.arrayContaining(["NIST 800-53", "PCI-DSS", "HIPAA", "GDPR", "SEC", "ISO 27001"]),
    );
  });

  it("ships the not-legal-advice disclaimer and the framework editions with the mapping", async () => {
    const res = await request(app).get("/cases/c1/compliance");

    expect(res.status).toBe(200);
    expect(res.body.disclaimer).toMatch(/not legal advice/i);
    expect(res.body.frameworkVersions["ISO 27001"]).toContain("2022");
    expect(res.body.generated).toBeTruthy();
  });

  it("404s for a case that does not exist instead of reporting no obligations", async () => {
    const res = await request(app).get("/cases/typo/compliance");

    expect(res.status).toBe(404);
    // The failure mode this pins: StateStore.load answers a missing case with an empty state, so
    // the handler would otherwise return 200 with results: [].
    expect(res.body.results).toBeUndefined();
  });

  it("400s on a case id that could escape the cases root", async () => {
    // "a..b" reaches the handler as-is (a literal "../" is normalized away by the client before
    // the server ever sees it), so this exercises createCaseIdGate rather than URL normalization.
    const res = await request(app).get("/cases/a..b/compliance");

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid caseId");
  });

  it("501s when the state store is not configured", async () => {
    const bare = createApp(cases, {});
    const res = await request(bare).get("/cases/c1/compliance");
    expect(res.status).toBe(501);
  });

  it("computes no deadlines until the analyst sets a discovery date", async () => {
    const res = await request(app).get("/cases/c1/compliance");

    expect(res.body.discoveredAt).toBeNull();
    const rows = res.body.results[0].frameworks as Array<{ deadline?: unknown }>;
    for (const row of rows) expect(row.deadline).toBeUndefined();
  });

  it("attaches deadlines once a discovery date is set, and only to real clocks", async () => {
    await request(app)
      .patch("/cases/c1/compliance/control")
      .send({ discoveredAt: "2026-03-05T00:00:00.000Z" })
      .expect(200);

    const res = await request(app).get("/cases/c1/compliance");
    expect(res.body.discoveredAt).toBe("2026-03-05T00:00:00.000Z");

    const byControl = Object.fromEntries(
      (res.body.results[0].frameworks as Array<{ control: string; deadline?: { dueAt: string } }>).map(
        (r) => [r.control, r],
      ),
    );
    // GDPR Art. 33: +72 calendar hours.
    expect(byControl["Art. 33"].deadline?.dueAt).toBe("2026-03-08T00:00:00.000Z");
    // Form 8-K: four BUSINESS days from a Thursday, so the weekend pushes it to Wednesday.
    expect(byControl["Item 1.05 of Form 8-K (17 CFR 249.308)"].deadline?.dueAt).toBe(
      "2026-03-11T00:00:00.000Z",
    );
    // A control cadence is not a deadline.
    expect(byControl["CP-9"].deadline).toBeUndefined();
  });

  it("applies the stored framework filter but still offers the full roster", async () => {
    await request(app)
      .patch("/cases/c1/compliance/control")
      .send({ frameworks: ["GDPR"] })
      .expect(200);

    const res = await request(app).get("/cases/c1/compliance");
    const frameworks = (res.body.results[0].frameworks as Array<{ framework: string }>).map(
      (r) => r.framework,
    );
    expect([...new Set(frameworks)]).toEqual(["GDPR"]);
    // The filter must not hide its own options — the roster comes from the unfiltered mapping.
    expect(res.body.availableFrameworks).toEqual(
      expect.arrayContaining(["NIST 800-53", "PCI-DSS", "HIPAA", "GDPR", "SEC", "ISO 27001"]),
    );
  });
});

describe("/cases/:id/compliance/control", () => {
  it("round-trips the discovery date and framework filter", async () => {
    const patched = await request(app)
      .patch("/cases/c1/compliance/control")
      .send({ discoveredAt: "2026-03-05T00:00:00.000Z", frameworks: ["GDPR", "HIPAA"] });
    expect(patched.status).toBe(200);

    const res = await request(app).get("/cases/c1/compliance/control");
    expect(res.body).toEqual({
      discoveredAt: "2026-03-05T00:00:00.000Z",
      frameworks: ["GDPR", "HIPAA"],
    });
  });

  it("clears the date with null, switching every countdown back off", async () => {
    await request(app)
      .patch("/cases/c1/compliance/control")
      .send({ discoveredAt: "2026-03-05T00:00:00.000Z" });
    await request(app).patch("/cases/c1/compliance/control").send({ discoveredAt: null }).expect(200);

    const res = await request(app).get("/cases/c1/compliance");
    expect(res.body.discoveredAt).toBeNull();
    const rows = res.body.results[0].frameworks as Array<{ deadline?: unknown }>;
    for (const row of rows) expect(row.deadline).toBeUndefined();
  });

  it("distinguishes null (all frameworks) from [] (none)", async () => {
    await request(app).patch("/cases/c1/compliance/control").send({ frameworks: [] }).expect(200);
    expect((await request(app).get("/cases/c1/compliance")).body.results).toHaveLength(0);

    await request(app).patch("/cases/c1/compliance/control").send({ frameworks: null }).expect(200);
    expect((await request(app).get("/cases/c1/compliance")).body.results).toHaveLength(1);
  });

  it("400s on an unparseable date rather than storing NaN", async () => {
    const res = await request(app)
      .patch("/cases/c1/compliance/control")
      .send({ discoveredAt: "last tuesday" });
    expect(res.status).toBe(400);
  });

  it("400s when frameworks is not an array of strings", async () => {
    const res = await request(app).patch("/cases/c1/compliance/control").send({ frameworks: "GDPR" });
    expect(res.status).toBe(400);
  });

  it("501s when the compliance control store is not configured", async () => {
    const bare = createApp(cases, { stateStore });
    expect((await request(bare).get("/cases/c1/compliance/control")).status).toBe(501);
    expect((await request(bare).patch("/cases/c1/compliance/control").send({})).status).toBe(501);
  });
});
