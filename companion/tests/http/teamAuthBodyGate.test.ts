import { mkdtemp } from "node:fs/promises";
import { type AddressInfo, connect } from "node:net";
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
 *
 * The concurrency test is the exception. It cannot use a full upload at all: refusing pre-parse
 * means answering mid-upload and hanging up, so everything the client observes then — the status,
 * and the bytes that reach the socket — is decided by the platform's TCP stack rather than by the
 * server. So it announces a 2.5 MB body, sends 16 KB, and sends no more. An answer arriving while
 * the body does not exist proves the same thing with nothing left to race.
 */

const BOOTSTRAP_TOKEN = "body-gate-bootstrap-token-with-entropy";
const TELEGRAM_SECRET = "telegram-webhook-secret-token";
const OVER_THE_PRE_AUTH_CAP = "x".repeat(1_500_000);
const OVER_EVERY_CAP = "x".repeat(2_500_000);
const CONCURRENT_CALLERS = 8;
/** What each concurrent caller ANNOUNCES it is about to upload, and then never sends. */
const DECLARED_BODY_BYTES = 2_500_203;
/** What it actually puts on the wire: a token prefix, then silence. */
const PREFIX_BYTES = 16 * 1024;

/** What one refused caller saw. */
type Refusal =
  | { kind: "answered"; status: number; body: string; sentBytes: number }
  | { kind: "reset"; code: string; sentBytes: number };

/**
 * One unauthenticated caller that announces a large upload and then does not send it: request
 * headers declaring DECLARED_BODY_BYTES, a PREFIX_BYTES prefix, and nothing more. Resolves once the
 * server has answered in full, or once the socket dies.
 *
 * Raw sockets rather than supertest, because supertest always sends the whole body and the body
 * that never arrives is the entire point.
 */
function announceAnUploadWithoutSendingIt(port: number): Promise<Refusal> {
  return new Promise((resolve) => {
    let received = "";
    let sentBytes = 0;
    let settled = false;
    const settle = (outcome: Refusal): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(outcome);
    };
    const socket = connect(port, "127.0.0.1", () => {
      socket.write(
        "POST /cases/c1/import-siem HTTP/1.1\r\n" +
          "Host: 127.0.0.1\r\n" +
          "Content-Type: application/json\r\n" +
          `Content-Length: ${DECLARED_BODY_BYTES}\r\n\r\n`,
      );
      socket.write(Buffer.alloc(PREFIX_BYTES, 0x78));
      sentBytes = PREFIX_BYTES;
    });
    socket.on("data", (chunk: Buffer) => {
      received += chunk.toString("latin1");
      const headerEnd = received.indexOf("\r\n\r\n");
      if (headerEnd === -1) return;
      const head = received.slice(0, headerEnd);
      const status = /^HTTP\/1\.\d (\d{3})/.exec(head);
      const length = /\r\ncontent-length: *(\d+)/i.exec(head);
      const body = received.slice(headerEnd + 4);
      // Wait for the answer's own body before settling, so reading it is never a race either.
      if (length && body.length < Number(length[1])) return;
      settle({ kind: "answered", status: Number(status?.[1] ?? 0), body, sentBytes });
    });
    socket.on("error", (err: NodeJS.ErrnoException) =>
      settle({ kind: "reset", code: err.code ?? String(err), sentBytes }),
    );
    socket.on("close", () => settle({ kind: "reset", code: "CLOSED WITHOUT ANSWERING", sentBytes }));
  });
}

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
    // Eight strangers each ANNOUNCE a 2.5 MB upload and then send 16 KB and stop. A final answer
    // arriving while 2.48 MB of the declared body does not yet exist can only have come from above
    // the parsers, because no parser can finish a body it has not received. That is the property,
    // and it is proven by what this test refuses to send rather than by anything it measures.
    //
    // The earlier version of this test asserted the status code of a full 2.5 MB upload, and that
    // could never be stable. Refusing pre-parse means answering mid-upload and hanging up, so
    // whether the 401 or the RST reaches the client first is a TCP race the platform decides —
    // Linux delivered the 401, Windows delivered ECONNRESET. Counting bytes off the wire instead
    // was no better: Node calls req._dump() on the unread request BEFORE destroySoon(), so the
    // socket keeps draining for a scheduling-dependent while, and Windows CI drained 2,097,152
    // bytes of a body no parser ever saw. Both oracles measured the transport. This one does not
    // touch it: bytes the client never wrote cannot be read, buffered, drained or raced.
    //
    // Mutation-checked, and the mutant is the bug itself rather than a status change — stub the
    // gate out and all eight callers get NO answer at all, because express.json() is sitting on
    // eight open connections waiting for bodies that will never arrive. The test then fails on
    // vitest's own timeout, which is the right failure: that hang is what #681 exists to prevent.
    const server = app.listen(0);
    try {
      await new Promise<void>((resolve, reject) => {
        server.once("listening", resolve);
        server.once("error", reject);
      });
      const port = (server.address() as AddressInfo).port;

      const outcomes = await Promise.all(
        Array.from({ length: CONCURRENT_CALLERS }, () => announceAnUploadWithoutSendingIt(port)),
      );

      for (const outcome of outcomes) {
        // Nobody had to send more than the prefix to be turned away.
        expect(outcome.sentBytes).toBe(PREFIX_BYTES);
        if (outcome.kind === "answered") {
          // 413 or 400 here would be the parser talking, which is the thing being refused.
          expect(outcome.status).toBe(401);
          expect(JSON.parse(outcome.body)).toEqual({ error: "authentication required" });
        } else {
          // The server refused and hung up on a socket still holding an unread prefix, which some
          // platforms surface as a reset. Any other errno — and "closed without answering", which
          // is the hang above — is a failure, so the accepted set is named rather than caught.
          expect(["ECONNRESET", "EPIPE"]).toContain(outcome.code);
        }
      }

      // And the server is still standing, so the refusals above were refusals and not a crash.
      const stillServing = await request(`http://127.0.0.1:${port}`)
        .post("/cases/c1/import-siem")
        .send({ filename: "small.json", json: "small" });
      expect(stillServing.status).toBe(401);
      expect(stillServing.body.error).toBe("authentication required");
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
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
