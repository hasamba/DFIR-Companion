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
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;

function requirementBody(over: Record<string, unknown> = {}) {
  return {
    decision: "recommend containment vs. monitor",
    audience: "IR lead",
    // Always relative to "now", never a hardcoded literal — Ollama code review finding D3: a
    // fixed future date is a time bomb that silently flips `expired` once that date passes.
    deadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
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

  it("records supersedesId on the new record when a changed-question requirement supersedes a revoked one", async () => {
    const old = await request(app).post("/cases/c1/hunt-requirements").send(requirementBody());
    await request(app).delete(`/cases/c1/hunt-requirements/${old.body.requirement.id}`);
    const next = await request(app)
      .post("/cases/c1/hunt-requirements")
      .send(requirementBody({ decision: "new question", supersedesId: old.body.requirement.id }));
    expect(next.status).toBe(200);
    expect(next.body.requirement.supersedesId).toBe(old.body.requirement.id);
  });

  it("rejects a supersedesId pointing at a requirement that is still active, with 400 not 500", async () => {
    const old = await request(app).post("/cases/c1/hunt-requirements").send(requirementBody());
    const res = await request(app)
      .post("/cases/c1/hunt-requirements")
      .send(requirementBody({ decision: "new question", supersedesId: old.body.requirement.id }));
    expect(res.status).toBe(400);
  });

  it("rejects a supersedesId that does not exist, with 400 not 500", async () => {
    const res = await request(app)
      .post("/cases/c1/hunt-requirements")
      .send(requirementBody({ supersedesId: "does-not-exist" }));
    expect(res.status).toBe(400);
  });

  it("rejects a deadline that is not a real ISO datetime", async () => {
    const res = await request(app)
      .post("/cases/c1/hunt-requirements")
      .send(requirementBody({ deadline: "EOD Friday" }));
    expect(res.status).toBe(400);
  });
});

// #933 item 17 code review (Ollama): the human-identity write gate (humanIdentityFor, imported
// unmodified from routes/evidenceAttestation.ts and already covered by ITS OWN unit tests there —
// including the service-token/service-identity rejection cases) had no test proving THIS route is
// actually reachable only by an authenticated caller under team-auth. These build a real
// TeamAuth-backed app (no session established) and confirm an entirely unauthenticated write is
// refused (401, from the upstream session gate, before humanIdentityFor's own 403 branch would
// ever run) — combined with humanIdentityFor's own existing unit tests, this closes the gap: an
// unauthenticated caller never reaches the store, and an authenticated-but-non-human caller is
// rejected by the exact, already-proven logic this route imports unmodified.
describe("/cases/:id/hunt-requirements with team-auth on", () => {
  it("rejects POST with no session identity", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hunt-requirements-teamauth-"));
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
      huntRequirementStore: new HuntRequirementStore(cases),
    });
    const res = await request(teamApp).post("/cases/c1/hunt-requirements").send(requirementBody());
    expect(res.status).toBe(401);
  });

  it("rejects DELETE with no session identity", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hunt-requirements-teamauth-"));
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
      huntRequirementStore: new HuntRequirementStore(cases),
    });
    const res = await request(teamApp).delete("/cases/c1/hunt-requirements/anything");
    expect(res.status).toBe(401);
  });
});
