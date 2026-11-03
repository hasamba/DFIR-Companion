import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger } from "../../src/server.js";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";
import { readZip } from "../../src/analysis/zipArchive.js";

const IRIS_KEY = "iris-key-sentinel-alpha";
const TS_PASS = "ts-pass-sentinel-bravo";
const VELO_CERT = "velo-cert-sentinel-charlie";

let dir: string;
let sets: ServerSetStore;
let velo: string;
let restorePaths: () => void = () => undefined;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ss-bundle-"));
  velo = join(dir, "api.config.yaml");
  writeFileSync(
    velo,
    `client_private_key: |\n  -----BEGIN RSA PRIVATE KEY-----\n  ${VELO_CERT}\n  -----END RSA PRIVATE KEY-----\napi_connection_string: velo.example.com:8001\n`,
  );
  sets = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 7)));
  sets.create({
    name: "Alpha",
    iris: { url: "https://iris.example.com", apiKey: IRIS_KEY },
    timesketch: { url: "https://ts.example.com", user: "analyst", password: TS_PASS },
    velociraptor: { apiConfigPath: velo },
  });
});
afterEach(() => {
  restorePaths();
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

describe("support bundle redacts server set secrets", () => {
  it("a set secret that reached a log line is redacted in the zip", async () => {
    const session = join(dir, "session.log");
    writeFileSync(
      session,
      [
        `2026-11-03T10:00:00.000Z ERROR iris call failed with key ${IRIS_KEY}`,
        `2026-11-03T10:00:01.000Z ERROR timesketch login ${TS_PASS} refused`,
        `2026-11-03T10:00:02.000Z ERROR bad key material ${VELO_CERT}`,
        "",
      ].join("\n"),
    );
    const logger = getServerLogger();
    const originalPaths = logger.paths;
    restorePaths = () => {
      logger.paths = originalPaths;
    };
    logger.paths = () => ({ sessionLogPath: session, debugLog: null });
    const app = createApp(new CaseStore(join(dir, "cases")), { serverSetStore: sets });
    const res = await request(app)
      .post("/diagnostics/support-bundle")
      .send({})
      .buffer(true)
      .parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on("data", (c: Buffer) => chunks.push(c));
        r.on("end", () => cb(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);
    const entries = readZip(res.body as Buffer);
    const log = entries.find((e) => e.path.includes("session"));
    expect(log, "session log is in the bundle").toBeDefined();
    const text = Buffer.from(log!.data).toString("utf8");
    expect(text).toContain("iris call failed"); // the line is there, only the secret is gone
    for (const e of entries) {
      const body = Buffer.from(e.data).toString("utf8");
      for (const s of [IRIS_KEY, TS_PASS, VELO_CERT]) expect(body, `${e.path} ${s}`).not.toContain(s);
    }
  });
});

describe("ServerSetStore.secretValues", () => {
  it("returns every secret and skips a set it cannot decrypt", () => {
    expect(sets.secretValues().sort()).toEqual([IRIS_KEY, TS_PASS, VELO_CERT].sort());
    const wrongKey = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 9)));
    expect(wrongKey.secretValues()).toEqual([]);
  });

  it("a missing Velociraptor config file adds nothing and does not throw", () => {
    rmSync(velo);
    expect(sets.secretValues().sort()).toEqual([IRIS_KEY, TS_PASS].sort());
  });
});
