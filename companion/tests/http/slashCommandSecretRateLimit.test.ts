import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SlashCommandChannelStore } from "../../src/analysis/slashCommandStore.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import {
  assertSlashCommandSecretLengths,
  MIN_SHARED_SECRET_LENGTH,
} from "../../src/analysis/slashCommandAuth.js";
import { setServerLogger, getServerLogger } from "../../src/logging/serverLogger.js";
import type { Logger } from "../../src/logging/logger.js";

/**
 * POST /integrations/teams/command and /integrations/telegram/command, brute-force bounds (#944).
 *
 * Both routes are public in team mode and compared the operator's shared secret BEFORE any limiter
 * ran, so a wrong token never reached a budget: a caller could guess DFIR_TEAMS_TOKEN or
 * DFIR_TELEGRAM_SECRET_TOKEN as fast as the server answered. A valid token runs slash commands —
 * AI queries over case data — from an unauthenticated network position.
 *
 * Same shape as the bootstrap limiter (#920): there is ONE secret per platform, so the budget is
 * keyed on the platform constant, not on the client or the (caller-chosen) channel id. A locked
 * secret refuses even the correct value. The per-channel AI limiter still runs AFTER a good token;
 * that one bounds AI spend, not guesses.
 */
const TEAMS_TOKEN = "teams-shared-secret-with-enough-entropy-1";
const TELEGRAM_SECRET = "telegram-webhook-secret-with-enough-entropy";

let app: ReturnType<typeof createApp>;
const warnings: string[] = [];
let previousLogger: Logger;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-slash-limit-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  vi.stubEnv("DFIR_TEAMS_TOKEN", TEAMS_TOKEN);
  vi.stubEnv("DFIR_TELEGRAM_SECRET_TOKEN", TELEGRAM_SECRET);
  vi.stubGlobal("fetch", async () => new Response("ok", { status: 200 }));
  warnings.length = 0;
  previousLogger = getServerLogger();
  setServerLogger({
    debug: () => {},
    info: () => {},
    warn: (m: string) => warnings.push(m),
    error: () => {},
    getLevel: () => "info",
    setLevel: () => {},
    close: async () => {},
  });
  // Reset BEFORE createApp: the route captures the limiter singleton at registration time.
  resetLimiters();
  app = createApp(store, {
    slashCommandChannelStore: new SlashCommandChannelStore(join(root, "bindings.json")),
  });
});

afterEach(() => {
  setServerLogger(previousLogger);
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  resetLimiters();
});

function teams(token: string | undefined, channelId = "T-CH") {
  const req = request(app).post("/integrations/teams/command");
  if (token !== undefined) req.set("authorization", `Bearer ${token}`);
  return req.send({ channel: { id: channelId }, from: { id: "U1" }, text: "help" });
}

function telegram(secret: string | undefined, chatId = -100123) {
  const req = request(app).post("/integrations/telegram/command");
  if (secret !== undefined) req.set("x-telegram-bot-api-secret-token", secret);
  return req.send({ update_id: 1, message: { chat: { id: chatId }, from: { id: 555 }, text: "/help" } });
}

describe("Teams token limiter", () => {
  it("locks the token out after five wrong guesses, with a Retry-After", async () => {
    for (let i = 0; i < 5; i++) expect((await teams(`wrong-${i}`)).status).toBe(401);
    const res = await teams("wrong-6");
    expect(res.status).toBe(429);
    expect(Number(res.headers["retry-after"])).toBeGreaterThan(0);
  });

  it("refuses the CORRECT token while locked — the lockout is the token's, not the guesser's", async () => {
    for (let i = 0; i < 5; i++) await teams(`wrong-${i}`);
    expect((await teams(TEAMS_TOKEN)).status).toBe(429);
  });

  it("rotating the caller-chosen channel id buys no extra guesses", async () => {
    for (let i = 0; i < 5; i++) expect((await teams(`wrong-${i}`, `chan-${i}`)).status).toBe(401);
    expect((await teams("wrong-6", "chan-fresh")).status).toBe(429);
  });

  it("a correct token clears the failure count", async () => {
    for (let i = 0; i < 4; i++) await teams(`wrong-${i}`);
    expect((await teams(TEAMS_TOKEN)).status).toBe(200);
    for (let i = 0; i < 4; i++) expect((await teams(`again-${i}`)).status).toBe(401);
    expect((await teams(TEAMS_TOKEN)).status).toBe(200);
  });

  it("warns on every rejected guess, naming the platform and never the presented value", async () => {
    await teams("the-guess-that-must-not-be-logged");
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain("teams");
    expect(warnings[0]).not.toContain("the-guess-that-must-not-be-logged");
  });

  it("a request with no credential is refused but not counted — the manual's health check is one", async () => {
    for (let i = 0; i < 7; i++) {
      const res = await teams(undefined);
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("missing Authorization header");
    }
    expect(warnings.length).toBe(0);
    expect((await teams("still-a-first-guess")).status).toBe(401);
  });

  it("an unconfigured token refuses without consulting the limiter — nothing was guessed", async () => {
    vi.stubEnv("DFIR_TEAMS_TOKEN", "");
    for (let i = 0; i < 7; i++) {
      const res = await teams(`probe-${i}`);
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("no Teams token configured");
    }
  });
});

describe("Telegram secret limiter", () => {
  it("locks the secret out after five wrong guesses, with a Retry-After", async () => {
    for (let i = 0; i < 5; i++) expect((await telegram(`wrong-${i}`)).status).toBe(401);
    const res = await telegram("wrong-6");
    expect(res.status).toBe(429);
    expect(Number(res.headers["retry-after"])).toBeGreaterThan(0);
  });

  it("refuses the CORRECT secret while locked", async () => {
    for (let i = 0; i < 5; i++) await telegram(`wrong-${i}`);
    expect((await telegram(TELEGRAM_SECRET)).status).toBe(429);
  });

  it("rotating the caller-chosen chat id buys no extra guesses", async () => {
    for (let i = 0; i < 5; i++) expect((await telegram(`wrong-${i}`, i)).status).toBe(401);
    expect((await telegram("wrong-6", 999)).status).toBe(429);
  });

  it("warns on every rejected guess, naming the platform and never the presented value", async () => {
    await telegram("the-guess-that-must-not-be-logged");
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain("telegram");
    expect(warnings[0]).not.toContain("the-guess-that-must-not-be-logged");
  });
});

describe("Telegram — a header-less probe is not a guess", () => {
  it("refuses with the healthy diagnostic and leaves the budget untouched", async () => {
    for (let i = 0; i < 7; i++) {
      const res = await telegram(undefined);
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("missing X-Telegram-Bot-Api-Secret-Token header");
    }
    expect(warnings.length).toBe(0);
    expect((await telegram("still-a-first-guess")).status).toBe(401);
  });
});

describe("the two budgets are independent", () => {
  it("a locked Teams token does not lock Telegram, and the reverse", async () => {
    for (let i = 0; i < 5; i++) await teams(`wrong-${i}`);
    expect((await teams("wrong-6")).status).toBe(429);
    expect((await telegram(TELEGRAM_SECRET)).status).toBe(200);
    for (let i = 0; i < 5; i++) await telegram(`wrong-${i}`);
    expect((await telegram("wrong-6")).status).toBe(429);
  });
});

describe("shared-secret length floor at startup", () => {
  const ok = "x".repeat(MIN_SHARED_SECRET_LENGTH);

  it("is 32 characters", () => {
    expect(MIN_SHARED_SECRET_LENGTH).toBe(32);
  });

  it("accepts unset secrets — the integrations are optional", () => {
    expect(() => assertSlashCommandSecretLengths({})).not.toThrow();
    expect(() =>
      assertSlashCommandSecretLengths({ DFIR_TEAMS_TOKEN: "", DFIR_TELEGRAM_SECRET_TOKEN: "  " }),
    ).not.toThrow();
  });

  it("accepts a secret at the floor", () => {
    expect(() =>
      assertSlashCommandSecretLengths({ DFIR_TEAMS_TOKEN: ok, DFIR_TELEGRAM_SECRET_TOKEN: ok }),
    ).not.toThrow();
  });

  it("refuses a short Teams token, naming the variable and the length it got", () => {
    expect(() => assertSlashCommandSecretLengths({ DFIR_TEAMS_TOKEN: "x" })).toThrow(
      /DFIR_TEAMS_TOKEN.*32.*got 1/,
    );
  });

  it("refuses a short Telegram secret, naming the variable", () => {
    expect(() => assertSlashCommandSecretLengths({ DFIR_TELEGRAM_SECRET_TOKEN: "s3cret" })).toThrow(
      /DFIR_TELEGRAM_SECRET_TOKEN.*32/,
    );
  });

  it("measures the trimmed value — surrounding whitespace is not entropy", () => {
    expect(() => assertSlashCommandSecretLengths({ DFIR_TEAMS_TOKEN: "  " + "x".repeat(31) + "  " })).toThrow(
      /DFIR_TEAMS_TOKEN/,
    );
  });

  it("leaves the Slack signing secret alone — Slack issues it and signs the body with it", () => {
    expect(() => assertSlashCommandSecretLengths({ DFIR_SLACK_SIGNING_SECRET: "short" })).not.toThrow();
  });
});
