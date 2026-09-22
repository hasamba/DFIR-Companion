import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";

const KEYS = [
  "DFIR_JEV_KEY",
  "DFIR_AI_VELO_KEY",
  "DFIR_AI_SYNTH_KEY",
  "DFIR_VISION_KEY",
  "DFIR_AI_KEY",
] as const;

async function app() {
  return createApp(new CaseStore(await mkdtemp(join(tmpdir(), "dfir-jev-keysrc-"))));
}

describe("GET /settings/jev/key-source", () => {
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const k of KEYS) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });
  afterEach(() => {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  it("says nothing can be inherited when no AI role has a key", async () => {
    const res = await request(await app()).get("/settings/jev/key-source");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ownKeySet: false, inheritable: false });
  });

  it("names the setting the key would come from", async () => {
    process.env.DFIR_AI_VELO_KEY = "whatever";
    const res = await request(await app()).get("/settings/jev/key-source");
    expect(res.body.inheritable).toBe(true);
    expect(res.body.inheritedFrom).toBe("DFIR_AI_VELO_KEY");
  });

  it("reports a key set on the review itself", async () => {
    process.env.DFIR_JEV_KEY = "whatever";
    expect((await request(await app()).get("/settings/jev/key-source")).body).toEqual({
      ownKeySet: true,
      inheritable: false,
    });
  });

  it("never puts a key value on the wire, from any source", async () => {
    const secret = "do-not-leak-this-value";
    for (const k of KEYS) process.env[k] = secret;
    const res = await request(await app()).get("/settings/jev/key-source");
    expect(JSON.stringify(res.body)).not.toContain(secret);
    expect(res.text).not.toContain(secret);
  });

  it("answers without a case, because settings are read before one is open", async () => {
    // It is deliberately not under /cases/:id — the analyst configures this with nothing loaded.
    expect((await request(await app()).get("/settings/jev/key-source")).status).toBe(200);
  });
});
