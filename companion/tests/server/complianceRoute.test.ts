import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
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

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-compliance-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "Ransomware Case", investigator: "Alice", aiProvider: null });

  stateStore = new StateStore(cases);
  await stateStore.save({
    ...emptyState("c1"),
    findings: [
      makeFinding({ id: "f-confirmed" }),
      makeFinding({ id: "f-open", status: "open" }),
    ],
  });

  app = createApp(cases, { stateStore });
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
});
