import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";
import { EvidenceAttestationStore } from "../../src/analysis/evidenceAttestationStore.js";
import { HuntRequirementStore } from "../../src/analysis/huntRequirementStore.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;

function requirementBody(over: Record<string, unknown> = {}) {
  return {
    decision: "recommend containment vs. monitor",
    audience: "IR lead",
    deadline: "2026-09-20T00:00:00Z",
    subjectScope: { kind: "hosts", hosts: ["ws-01"] },
    expectedObservableEvidence: "the binary executed and wrote files to disk",
    ...over,
  };
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hunt-requirements-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, {
    stateStore: new StateStore(cases),
    hypothesisStore: new HypothesisStore(cases),
    evidenceAttestationStore: new EvidenceAttestationStore(cases),
    huntRequirementStore: new HuntRequirementStore(cases),
  });
});

describe("/cases/:id/hunt-requirements", () => {
  it("returns an empty list for a fresh case", async () => {
    const res = await request(app).get("/cases/c1/hunt-requirements");
    expect(res.status).toBe(200);
    expect(res.body.requirements).toEqual([]);
  });

  it("creates a requirement and reflects it in the list", async () => {
    const res = await request(app).post("/cases/c1/hunt-requirements").send(requirementBody());
    expect(res.status).toBe(200);
    expect(res.body.requirement.decision).toBe("recommend containment vs. monitor");
    expect(res.body.requirement.createdBy).toBe("local");
    const list = await request(app).get("/cases/c1/hunt-requirements");
    expect(list.body.requirements).toHaveLength(1);
  });

  it("rejects a requirement missing a required field", async () => {
    const res = await request(app)
      .post("/cases/c1/hunt-requirements")
      .send(requirementBody({ decision: "" }));
    expect(res.status).toBe(400);
  });

  it("rejects a requirement with no subjectScope", async () => {
    const res = await request(app)
      .post("/cases/c1/hunt-requirements")
      .send(requirementBody({ subjectScope: undefined }));
    expect(res.status).toBe(400);
  });

  it("revokes a requirement", async () => {
    const created = await request(app).post("/cases/c1/hunt-requirements").send(requirementBody());
    const res = await request(app).delete(`/cases/c1/hunt-requirements/${created.body.requirement.id}`);
    expect(res.status).toBe(200);
    expect(res.body.requirements[0].revokedAt).toBeTruthy();
  });

  it("revoking an unknown id is a no-op, not an error", async () => {
    const res = await request(app).delete("/cases/c1/hunt-requirements/does-not-exist");
    expect(res.status).toBe(200);
  });

  it("returns 404 for a checklist on an unknown requirement id", async () => {
    const res = await request(app).get("/cases/c1/hunt-requirements/does-not-exist/checklist");
    expect(res.status).toBe(404);
  });

  it("returns a live checklist for a real requirement, with the expected shape", async () => {
    const created = await request(app).post("/cases/c1/hunt-requirements").send(requirementBody());
    const res = await request(app).get(
      `/cases/c1/hunt-requirements/${created.body.requirement.id}/checklist`,
    );
    expect(res.status).toBe(200);
    expect(res.body.checklist.requiredClasses.sort()).toEqual(["execution", "file-activity"]);
    expect(res.body.checklist.gaps.map((g: { evidenceClass: string }) => g.evidenceClass).sort()).toEqual([
      "execution",
      "file-activity",
    ]);
    expect(res.body.checklist.discriminatorAvailable).toBe(false);
    expect(res.body.checklist.expired).toBe(false);
  });

  it("returns 501 when the store is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hunt-requirements-unconfigured-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const bareApp = createApp(cases, {});
    const res = await request(bareApp).get("/cases/c1/hunt-requirements");
    expect(res.status).toBe(501);
  });
});
