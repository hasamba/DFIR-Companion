import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { ReportMetaStore } from "../../src/reports/reportMeta.js";
import { ReportVersionStore } from "../../src/reports/reportVersionStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";

interface Session {
  agent: ReturnType<typeof request.agent>;
  csrf: string;
  identityId: string;
}

async function sessionCsrf(
  agent: ReturnType<typeof request.agent>,
): Promise<{ csrf: string; identityId: string }> {
  const me = await agent.get("/auth/me");
  expect(me.status).toBe(200);
  return { csrf: me.body.csrfToken as string, identityId: me.body.identity.id as string };
}

describe("optional team authentication", () => {
  let cases: CaseStore;
  let authStore: AuthStore;
  let auth: TeamAuth;
  let app: ReturnType<typeof createApp>;
  let jobs: JobManager;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-team-auth-"));
    cases = new CaseStore(join(root, "cases"));
    authStore = new AuthStore(join(root, "auth.sqlite"));
    auth = new TeamAuth({
      store: authStore,
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    });
    jobs = new JobManager();
    app = createApp(cases, {
      teamAuth: auth,
      jobManager: jobs,
      stateLock: new StateLock(),
      stateStore: new StateStore(cases),
      activityLogStore: new ActivityLogStore(cases),
      commentsStore: new CommentsStore(cases),
    });
  });

  async function bootstrap(): Promise<Session> {
    const agent = request.agent(app);
    const res = await agent.post("/auth/bootstrap").send({
      bootstrapToken: BOOTSTRAP_TOKEN,
      username: "admin",
      password: "correct horse battery staple",
      displayName: "Primary Admin",
    });
    expect(res.status).toBe(201);
    return { agent, ...(await sessionCsrf(agent)) };
  }

  async function createLocalUser(admin: Session, username: string): Promise<string> {
    const res = await admin.agent.post("/auth/users").set("X-DFIR-CSRF", admin.csrf).send({
      username,
      password: "a different sufficiently long password",
      displayName: username.toUpperCase(),
    });
    expect(res.status).toBe(201);
    return res.body.id as string;
  }

  async function login(username: string): Promise<Session> {
    const agent = request.agent(app);
    const res = await agent.post("/auth/local/login").send({
      username,
      password: "a different sufficiently long password",
    });
    expect(res.status).toBe(200);
    return { agent, ...(await sessionCsrf(agent)) };
  }

  it("leaves the existing single-user app unchanged when team auth is not configured", async () => {
    const localApp = createApp(cases, {});
    expect((await request(localApp).get("/cases")).status).toBe(200);
    expect(
      (
        await request(localApp).post("/cases").send({
          caseId: "local",
          name: "Local",
          investigator: "analyst",
        })
      ).status,
    ).toBe(201);
  });

  it("requires a session and CSRF token in team mode", async () => {
    expect((await request(app).get("/cases")).status).toBe(401);
    const admin = await bootstrap();
    expect((await admin.agent.post("/cases").send({ caseId: "c1", name: "Case" })).status).toBe(403);
    expect(
      (await admin.agent.post("/cases").set("X-DFIR-CSRF", admin.csrf).send({ caseId: "c1", name: "Case" }))
        .status,
    ).toBe(201);
  });

  it("filters case lists and refuses horizontal access without revealing case existence", async () => {
    const admin = await bootstrap();
    await admin.agent
      .post("/cases")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ caseId: "secret", name: "Secret Case" });
    await createLocalUser(admin, "reader");
    const reader = await login("reader");

    expect((await reader.agent.get("/cases")).body).toEqual([]);
    const denied = await reader.agent.get("/cases/secret/state");
    expect(denied.status).toBe(404);
    expect(denied.body.error).not.toContain("secret");
    const hiddenJob = jobs.register({ caseId: "secret", kind: "synthesis", cancellable: true });
    jobs.register({ kind: "synthesis", cancellable: true });
    expect((await reader.agent.get("/api/jobs")).body.jobs).toEqual([]);
    expect((await reader.agent.get(`/api/jobs/${hiddenJob.jobId}`)).status).toBe(404);
  });

  it("enforces reader, investigator, reviewer, and administrator capabilities", async () => {
    const admin = await bootstrap();
    await admin.agent.post("/cases").set("X-DFIR-CSRF", admin.csrf).send({ caseId: "c1", name: "Case" });
    const userId = await createLocalUser(admin, "reader");
    const reader = await login("reader");

    const grant = async (role: string) =>
      admin.agent
        .put(`/auth/cases/c1/roles/${encodeURIComponent(userId)}`)
        .set("X-DFIR-CSRF", admin.csrf)
        .send({ role });

    expect((await grant("reader")).status).toBe(200);
    expect((await reader.agent.get("/cases/c1/state")).status).toBe(200);
    const caseJob = jobs.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    expect((await reader.agent.get("/api/jobs")).body.jobs).toEqual([
      expect.objectContaining({ id: caseJob.jobId }),
    ]);
    expect(
      (await reader.agent.post(`/api/jobs/${caseJob.jobId}/cancel`).set("X-DFIR-CSRF", reader.csrf)).status,
    ).toBe(403);
    expect(
      (await reader.agent.post(`/api/jobs/${caseJob.jobId}/resume`).set("X-DFIR-CSRF", reader.csrf)).status,
    ).toBe(403);
    expect(
      (
        await reader.agent
          .post("/cases/c1/export/encrypted")
          .set("X-DFIR-CSRF", reader.csrf)
          .send({ password: "short" })
      ).status,
    ).toBe(400);
    expect(
      (
        await reader.agent
          .post("/cases/c1/export/encrypted")
          .set("X-DFIR-CSRF", reader.csrf)
          .send({ password: "short", removeFromList: true })
      ).status,
    ).toBe(403);
    expect(
      (
        await reader.agent
          .post("/cases/c1/events")
          .set("X-DFIR-CSRF", reader.csrf)
          .send({ timestamp: "2026-07-31T10:00:00.000Z", description: "one" })
      ).status,
    ).toBe(403);

    expect((await grant("investigator")).status).toBe(200);
    expect(
      (await reader.agent.post(`/api/jobs/${caseJob.jobId}/cancel`).set("X-DFIR-CSRF", reader.csrf)).status,
    ).toBe(200);
    expect(
      (
        await reader.agent
          .post("/cases/c1/events")
          .set("X-DFIR-CSRF", reader.csrf)
          .send({ timestamp: "2026-07-31T10:00:00.000Z", description: "one" })
      ).status,
    ).toBe(201);

    expect((await grant("reviewer")).status).toBe(200);
    expect(
      (
        await reader.agent
          .post("/cases/c1/events")
          .set("X-DFIR-CSRF", reader.csrf)
          .send({ timestamp: "2026-07-31T10:01:00.000Z", description: "two" })
      ).status,
    ).toBe(403);
  });

  it("uses the authenticated immutable identity in activity records", async () => {
    const admin = await bootstrap();
    await admin.agent.post("/cases").set("X-DFIR-CSRF", admin.csrf).send({ caseId: "c1", name: "Case" });
    const added = await admin.agent.post("/cases/c1/comments").set("X-DFIR-CSRF", admin.csrf).send({
      targetType: "case",
      targetId: "c1",
      text: "manual note",
      author: "forged-name",
    });
    expect(added.status).toBe(201);

    const log = await admin.agent.get("/cases/c1/activity-log");
    const entry = log.body.find((candidate: { action: string }) => candidate.action === "comment-added");
    expect(entry.actorId).toBe(admin.identityId);
    expect(entry.actorDisplayName).toBe("Primary Admin");
    expect(entry.actor).toBe("Primary Admin");
  });

  it("enforces investigator/reviewer separation through report approval and release", async () => {
    const stateStore = new StateStore(cases);
    const reportMetaStore = new ReportMetaStore(cases);
    const reportVersionStore = new ReportVersionStore(cases);
    const analysisRunStore = new AnalysisRunStore(cases, { appVersion: "test" });
    const custodyStore = new CustodyStore(cases);
    const reportWriter = new ReportWriter(cases, stateStore, {
      reportMeta: reportMetaStore,
      reportVersions: reportVersionStore,
      analysisRuns: analysisRunStore,
    });
    app = createApp(cases, {
      teamAuth: auth,
      stateStore,
      reportMetaStore,
      reportVersionStore,
      analysisRunStore,
      custodyStore,
      reportWriter,
    });
    const admin = await bootstrap();
    await admin.agent.post("/cases").set("X-DFIR-CSRF", admin.csrf).send({ caseId: "c1", name: "Case" });
    const investigatorId = await createLocalUser(admin, "investigator");
    const reviewerId = await createLocalUser(admin, "reviewer");
    for (const [identityId, role] of [
      [investigatorId, "investigator"],
      [reviewerId, "reviewer"],
    ]) {
      expect(
        (
          await admin.agent
            .put(`/auth/cases/c1/roles/${encodeURIComponent(identityId)}`)
            .set("X-DFIR-CSRF", admin.csrf)
            .send({ role })
        ).status,
      ).toBe(200);
    }
    const investigator = await login("investigator");
    const reviewer = await login("reviewer");

    expect(
      (await investigator.agent.post("/cases/c1/report").set("X-DFIR-CSRF", investigator.csrf)).status,
    ).toBe(200);
    const version = (await investigator.agent.get("/cases/c1/report-versions")).body[0];
    const submitted = await investigator.agent
      .post(`/cases/c1/report-versions/${version.id}/workflow/submit`)
      .set("X-DFIR-CSRF", investigator.csrf)
      .send({ reviewerId });
    expect(submitted.status).toBe(200);
    expect(submitted.body.assignedReviewer.id).toBe(reviewerId);
    expect(
      (
        await investigator.agent
          .post(`/cases/c1/report-versions/${version.id}/review/approve`)
          .set("X-DFIR-CSRF", investigator.csrf)
          .send({ note: "self approval" })
      ).status,
    ).toBe(403);

    const approved = await reviewer.agent
      .post(`/cases/c1/report-versions/${version.id}/review/approve`)
      .set("X-DFIR-CSRF", reviewer.csrf)
      .send({ note: "Evidence and limitations checked" });
    expect(approved.status).toBe(200);
    expect(approved.body.approvals[0]).toMatchObject({ actorId: reviewerId, independent: true });
    expect(
      (
        await reviewer.agent
          .post(`/cases/c1/report-versions/${version.id}/workflow/release`)
          .set("X-DFIR-CSRF", reviewer.csrf)
          .send({})
      ).status,
    ).toBe(403);
    expect(
      (
        await investigator.agent
          .post(`/cases/c1/report-versions/${version.id}/workflow/release`)
          .set("X-DFIR-CSRF", investigator.csrf)
          .send({})
      ).status,
    ).toBe(201);
  });

  it("issues case-scoped service tokens that cannot cross case boundaries", async () => {
    const admin = await bootstrap();
    for (const caseId of ["one", "two"]) {
      await admin.agent.post("/cases").set("X-DFIR-CSRF", admin.csrf).send({ caseId, name: caseId });
    }
    const created = await admin.agent
      .post("/auth/service-tokens")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ name: "capture extension", caseId: "one", permissions: ["capture", "write"] });
    expect(created.status).toBe(201);
    const token = created.body.token as string;
    const listed = await request(app).get("/cases").set("Authorization", `Bearer ${token}`);
    expect(listed.body.map((item: { caseId: string }) => item.caseId)).toEqual(["one"]);

    const allowed = await request(app)
      .post("/captures")
      .set("Authorization", `Bearer ${token}`)
      .send({ caseId: "one" });
    expect(allowed.status).toBe(400);
    const denied = await request(app)
      .post("/captures")
      .set("Authorization", `Bearer ${token}`)
      .send({ caseId: "two" });
    expect(denied.status).toBe(404);

    const captureOnly = await admin.agent
      .post("/auth/service-tokens")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ name: "blind collector", caseId: "one", permissions: ["capture"] });
    const captureOnlyToken = captureOnly.body.token as string;
    expect((await request(app).get("/cases").set("Authorization", `Bearer ${captureOnlyToken}`)).status).toBe(
      403,
    );
    expect(
      (
        await request(app)
          .post("/captures")
          .set("Authorization", `Bearer ${captureOnlyToken}`)
          .send({ caseId: "one" })
      ).status,
    ).toBe(400);
  });

  it("does not lose either analyst's event when two authenticated sessions edit concurrently", async () => {
    const admin = await bootstrap();
    await admin.agent.post("/cases").set("X-DFIR-CSRF", admin.csrf).send({ caseId: "c1", name: "Case" });
    const userId = await createLocalUser(admin, "investigator");
    await admin.agent
      .put(`/auth/cases/c1/roles/${encodeURIComponent(userId)}`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ role: "investigator" });
    const investigator = await login("investigator");

    const [first, second] = await Promise.all([
      admin.agent
        .post("/cases/c1/events")
        .set("X-DFIR-CSRF", admin.csrf)
        .send({ timestamp: "2026-07-31T10:00:00.000Z", description: "admin event" }),
      investigator.agent
        .post("/cases/c1/events")
        .set("X-DFIR-CSRF", investigator.csrf)
        .send({ timestamp: "2026-07-31T10:00:01.000Z", description: "investigator event" }),
    ]);
    expect(first.status).toBe(201);
    expect(second.status).toBe(201);

    const state = await admin.agent.get("/cases/c1/state");
    expect(state.body.forensicTimeline.map((event: { description: string }) => event.description)).toEqual(
      expect.arrayContaining(["admin event", "investigator event"]),
    );
  });

  it("lets case administrators manage access and scoped tokens without global administration", async () => {
    const admin = await bootstrap();
    await admin.agent
      .post("/cases")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ caseId: "managed", name: "Managed" });
    const userId = await createLocalUser(admin, "caseadmin");
    await admin.agent
      .put(`/auth/cases/managed/roles/${encodeURIComponent(userId)}`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ role: "administrator" });
    const caseAdmin = await login("caseadmin");

    expect((await caseAdmin.agent.get("/admin")).status).toBe(200);
    expect((await caseAdmin.agent.get("/auth/directory")).body).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: admin.identityId })]),
    );
    expect((await caseAdmin.agent.get("/auth/users")).status).toBe(403);
    const token = await caseAdmin.agent
      .post("/auth/service-tokens")
      .set("X-DFIR-CSRF", caseAdmin.csrf)
      .send({ name: "collector", caseId: "managed", permissions: ["capture"] });
    expect(token.status).toBe(201);
    expect((await caseAdmin.agent.get("/auth/service-tokens")).body).toEqual([
      expect.objectContaining({ caseId: "managed" }),
    ]);
  });

  it("keeps an active emergency administrator account", async () => {
    const admin = await bootstrap();
    const disabled = await admin.agent
      .patch(`/auth/users/${encodeURIComponent(admin.identityId)}`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ disabled: true });
    expect(disabled.status).toBe(400);
    expect(disabled.body.error).toMatch(/last active global administrator/i);
  });

  it("revokes stale roles and service identities when a case is permanently deleted", async () => {
    const admin = await bootstrap();
    await admin.agent
      .post("/cases")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ caseId: "reused", name: "Original" });
    const created = await admin.agent
      .post("/auth/service-tokens")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ name: "old collector", caseId: "reused", permissions: ["read"] });
    await admin.agent.patch("/cases/reused/status").set("X-DFIR-CSRF", admin.csrf).send({ status: "closed" });
    expect(
      (
        await admin.agent
          .post("/cases/reused/delete")
          .set("X-DFIR-CSRF", admin.csrf)
          .send({ archiveFirst: "none" })
      ).status,
    ).toBe(200);
    await admin.agent
      .post("/cases")
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ caseId: "reused", name: "Replacement" });
    expect(
      (
        await request(app)
          .get("/cases/reused/state")
          .set("Authorization", `Bearer ${created.body.token as string}`)
      ).status,
    ).toBe(401);
  });
});
