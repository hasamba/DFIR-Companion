import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { SlashCommandChannelStore } from "../../src/analysis/slashCommandStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

/**
 * THE BODY PARSERS SIT ABOVE THE AUTHENTICATOR, SO WHO PAYS FOR A BODY IS A SECURITY QUESTION (#681).
 *
 * express.json() was mounted before teamAuth.middleware(), at a limit meant for bulk evidence
 * imports (DFIR_MAX_BODY_MB, 256 MB by default). On a team deployment that answers the network,
 * that made every 401 expensive: a stranger's body was received, inflated, allocated, decoded and
 * JSON-parsed in full, and only then refused. A handful of concurrent requests is enough to exhaust
 * the heap or stall the single-threaded event loop.
 *
 * composition/httpStack.ts now resolves the request policy — a pure function of method and path —
 * and demands a credential BEFORE those parsers. These tests pin the observable consequence, which
 * is a status code: a body that used to come back 413 or 400 (proving it was read) must now come
 * back 401 (proving it was not). They also pin the two things that must NOT change — an
 * authenticated caller still gets the generous limit, and the routes that legitimately take a body
 * from a stranger still parse one, under their own small cap.
 *
 * DFIR_MAX_BODY_MB is 2 here so both limits can be crossed with small bodies instead of pushing
 * 256 MB through supertest. TWO sizes, and the difference is the whole test:
 *   1.5 MB  over the 1 MB pre-auth floor, under the configured limit — what a credential buys
 *   2.5 MB  over BOTH, so without the gate the parser reads it and answers 413
 * Mutation-proven on that second size: stub the gate out and the 401 assertions go back to 413.
 */

const BOOTSTRAP_TOKEN = "body-gate-bootstrap-token-with-entropy";
const TELEGRAM_SECRET = "telegram-webhook-secret-token";
const OVER_THE_PRE_AUTH_CAP = "x".repeat(1_500_000);
const OVER_EVERY_CAP = "x".repeat(2_500_000);

describe("team mode authenticates before it parses a body", () => {
  let cases: CaseStore;
  let authStore: AuthStore;
  let app: ReturnType<typeof createApp>;
  const previous: Record<string, string | undefined> = {};

  beforeAll(() => {
    previous.DFIR_MAX_BODY_MB = process.env.DFIR_MAX_BODY_MB;
    previous.DFIR_TELEGRAM_SECRET_TOKEN = process.env.DFIR_TELEGRAM_SECRET_TOKEN;
    process.env.DFIR_MAX_BODY_MB = "2";
    process.env.DFIR_TELEGRAM_SECRET_TOKEN = TELEGRAM_SECRET;
  });

  afterAll(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-body-gate-"));
    cases = new CaseStore(join(root, "cases"));
    authStore = new AuthStore(join(root, "auth.sqlite"));
    app = createApp(cases, {
      teamAuth: new TeamAuth({
        store: authStore,
        bootstrapToken: BOOTSTRAP_TOKEN,
        cookieSecure: false,
        sessionTtlMs: 60 * 60_000,
      }),
      stateLock: new StateLock(),
      stateStore: new StateStore(cases),
      activityLogStore: new ActivityLogStore(cases),
      commentsStore: new CommentsStore(cases),
      slashCommandChannelStore: new SlashCommandChannelStore(join(root, "slash.json")),
    });
  });

  async function admin(): Promise<{ agent: ReturnType<typeof request.agent>; csrf: string }> {
    const agent = request.agent(app);
    const created = await agent.post("/auth/bootstrap").send({
      bootstrapToken: BOOTSTRAP_TOKEN,
      username: "admin",
      password: "correct horse battery staple",
      displayName: "Primary Admin",
    });
    expect(created.status).toBe(201);
    const me = await agent.get("/auth/me");
    expect(me.status).toBe(200);
    return { agent, csrf: me.body.csrfToken as string };
  }

  it("answers 401 to an oversized body on a protected route, instead of reading it", async () => {
    const res = await request(app)
      .post("/cases/c1/import-siem")
      .send({ filename: "big.json", json: OVER_EVERY_CAP });
    // 413 would mean the parser ran to the limit and then gave up — the very work being refused.
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("authentication required");
  });

  it("answers 401 to a malformed body on a protected route, instead of parsing it", async () => {
    const res = await request(app)
      .post("/cases/c1/import-siem")
      .set("Content-Type", "application/json")
      .send("{ not json at all");
    // 400 "request body is not valid JSON" is what the parser says. Never reaching it is the fix.
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("authentication required");
  });

  it("answers 401 to an oversized text body too, not only JSON", async () => {
    const res = await request(app)
      .post("/cases/c1/push")
      .set("Content-Type", "text/plain")
      .send(OVER_EVERY_CAP);
    expect(res.status).toBe(401);
  });

  it("refuses concurrent oversized unauthenticated requests without parsing any of them", async () => {
    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        request(app).post("/cases/c1/import-siem").send({ filename: "big.json", json: OVER_EVERY_CAP }),
      ),
    );
    expect(results.map((r) => r.status)).toEqual(Array(8).fill(401));
  });

  it("redirects a browser navigation to the login page rather than 401-ing it", async () => {
    // The pre-parse gate answers for requests that used to reach teamAuth.middleware(), so it has
    // to answer the same way: a human typing a URL gets the login page, not a JSON error.
    const res = await request(app).get("/dashboard").set("Accept", "text/html");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/login?returnTo=%2Fdashboard");
  });

  it("still gives an authenticated caller the full DFIR_MAX_BODY_MB budget", async () => {
    const { agent, csrf } = await admin();
    const created = await agent
      .post("/cases")
      .set("X-DFIR-CSRF", csrf)
      .send({ caseId: "c1", name: "n", investigator: "i" });
    expect(created.status).toBe(201);

    // 1.5 MB is over the 1 MB pre-auth floor and under the 2 MB configured limit. A credential is
    // what buys the difference, so this must parse rather than 413.
    const res = await agent
      .post("/cases/c1/import-siem")
      .set("X-DFIR-CSRF", csrf)
      .send({ filename: "big.json", json: OVER_THE_PRE_AUTH_CAP });
    expect(res.status).not.toBe(413);
    expect(res.status).not.toBe(401);
  });

  it("still parses the login body, which is how a caller gets a credential at all", async () => {
    await admin();
    const res = await request(app)
      .post("/auth/local/login")
      .send({ username: "admin", password: "not the right password" });
    // The route's own answer, not the gate's — proof the gate let the body through and it parsed.
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("invalid username or password");
  });

  it("still parses a public webhook body, and caps it at 1 MB", async () => {
    const accepted = await request(app)
      .post("/integrations/telegram/command")
      .set("X-Telegram-Bot-Api-Secret-Token", "wrong-secret")
      .send({ message: { chat: { id: "42" }, text: "/dfir status" } });
    // "secret token mismatch" is the handler talking, so the gate did not intercept the webhook.
    expect(accepted.status).toBe(401);
    expect(accepted.body.error).toBe("secret token mismatch");

    const oversized = await request(app)
      .post("/integrations/telegram/command")
      .set("X-Telegram-Bot-Api-Secret-Token", TELEGRAM_SECRET)
      .send({ message: { chat: { id: "42" }, text: OVER_THE_PRE_AUTH_CAP } });
    expect(oversized.status).toBe(413);
    expect(oversized.body.error).toMatch(/exceeds the 1 MB limit/);
    // And the advice has to be advice. The pre-auth cap is a floor under DFIR_MAX_BODY_MB, so
    // "raise DFIR_MAX_BODY_MB and restart" sends an operator to do the one thing that cannot work.
    expect(oversized.body.error).toMatch(/DFIR_MAX_BODY_MB does not raise it/);
    expect(oversized.body.error).not.toMatch(/raise DFIR_MAX_BODY_MB and restart/);
  });

  it("still tells an AUTHENTICATED caller to raise the knob, because for them it works", async () => {
    const { agent, csrf } = await admin();
    const created = await agent
      .post("/cases")
      .set("X-DFIR-CSRF", csrf)
      .send({ caseId: "c1", name: "n", investigator: "i" });
    expect(created.status).toBe(201);

    const res = await agent
      .post("/cases/c1/import-siem")
      .set("X-DFIR-CSRF", csrf)
      .send({ filename: "big.json", json: OVER_EVERY_CAP });
    expect(res.status).toBe(413);
    expect(res.body.error).toMatch(/exceeds the 2 MB limit/);
    expect(res.body.error).toMatch(/raise DFIR_MAX_BODY_MB and restart/);
  });

  it("reports a fractional DFIR_MAX_BODY_MB exactly, instead of rounding it into a lie", async () => {
    // 0.25 is a value Number() accepts and body-parser honours — it caps bodies at 262,144 bytes.
    // Rounding the reported limit to whole MB answered that real cap with "exceeds the 0 MB limit",
    // which reads as a broken server rather than as a limit the caller crossed.
    process.env.DFIR_MAX_BODY_MB = "0.25";
    try {
      const root = await mkdtemp(join(tmpdir(), "dfir-body-gate-fraction-"));
      const fractional = createApp(new CaseStore(join(root, "cases")), {
        teamAuth: new TeamAuth({
          store: new AuthStore(join(root, "auth.sqlite")),
          bootstrapToken: BOOTSTRAP_TOKEN,
          cookieSecure: false,
          sessionTtlMs: 60 * 60_000,
        }),
      });
      const res = await request(fractional)
        .post("/auth/local/login")
        .send({ username: "admin", password: OVER_THE_PRE_AUTH_CAP });
      expect(res.status).toBe(413);
      expect(res.body.error).toMatch(/exceeds the 0\.25 MB limit/);
    } finally {
      process.env.DFIR_MAX_BODY_MB = "2";
    }
  });

  it("leaves the public GETs reachable", async () => {
    expect((await request(app).get("/health")).status).toBe(200);
  });

  it("keeps demanding a credential for POST /captures, whose body it no longer pre-parses", async () => {
    const res = await request(app).post("/captures").send({ caseId: "c1", imageBase64: "AAAA" });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("authentication required");
  });
});
