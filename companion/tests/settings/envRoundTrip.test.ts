import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "dotenv";
import {
  readEnvFile,
  reloadEnvPrefix,
  updateEnv,
  updateEnvFrom,
  validateEnvUpdates,
} from "../../src/settings/envManager.js";
import { encodeEnvValue } from "../../src/settings/envCodec.js";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";

/**
 * A SAVED SETTING READS THE SAME EVERYWHERE (#2280).
 *
 * The settings file had three readers that disagreed: dotenv at startup, a hand-rolled line parser
 * for Test / reconnect, and the Docker entrypoint's shell reader. A secret containing `#` saved
 * bare, passed Test, and was cut at the `#` after a restart. Now every Node reader is dotenv, the
 * writer quotes a value only when the round trip needs it, and a value no quoting both dotenv and
 * the entrypoint read identically is refused instead of written lossy.
 */
const KEY = "DFIR_TIMESKETCH_PASSWORD";
const originalEnv = { ...process.env };
let dir: string;
let envFile: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-envroundtrip-"));
  envFile = join(dir, ".env");
  process.env.DFIR_ENV_FILE = envFile;
});

afterEach(async () => {
  process.env = { ...originalEnv };
  await rm(dir, { recursive: true, force: true });
});

const STORABLE = [
  "pa#ss",
  "'secret'",
  " lead",
  "trail ",
  "it's#1",
  'say "hi" #now',
  "x\\ny#",
  "'starts-with-quote",
  '"starts-with-dquote',
  "`tick",
  "https://iris.example.test:8443/api?x=1&y=2#frag",
  "sk-live_A1b2/C3+d4=e5==",
  "hunter2 — don't tell",
  "plain",
];

/** Values that only a backtick-quoted line could hold — which the entrypoint does not understand. */
const UNSTORABLE = ["a'b\"c#", "x\\ny#'", "'both\" ", "a\"b'c`#"];

describe("settings file round trip", () => {
  it.each(STORABLE)("reads %j back unchanged through startup, readEnvFile and reload", async (v) => {
    await writeFile(envFile, "# header\nDFIR_OTHER=keep\n", "utf8");
    await updateEnv({ [KEY]: v });

    expect(parse(await readFile(envFile, "utf8"))[KEY]).toBe(v);
    expect((await readEnvFile())[KEY]).toBe(v);
    delete process.env[KEY];
    await reloadEnvPrefix("DFIR_TIMESKETCH_");
    expect(process.env[KEY]).toBe(v);
  });

  it("writes values that need no quoting bare, so existing files do not churn", async () => {
    await updateEnv({ [KEY]: "plain", DFIR_TIMESKETCH_URL: "sk-live_A1b2/C3+d4=e5==" });
    const lines = (await readFile(envFile, "utf8")).split("\n");
    expect(lines).toContain(`${KEY}=plain`);
    expect(lines).toContain("DFIR_TIMESKETCH_URL=sk-live_A1b2/C3+d4=e5==");
  });

  it("prefers single quotes, which every reader takes literally", () => {
    expect(encodeEnvValue("pa#ss")).toBe("'pa#ss'");
    expect(encodeEnvValue("x\\ny#")).toBe("'x\\ny#'");
    expect(encodeEnvValue("it's#1")).toBe('"it\'s#1"');
  });

  it("never writes a backtick-quoted value", () => {
    for (const v of [...STORABLE, ...UNSTORABLE]) expect(encodeEnvValue(v) ?? "").not.toMatch(/^`/);
  });
});

describe("hand-edited lines reload the way startup reads them", () => {
  it("strips quotes and inline comments on Test / reconnect", async () => {
    await writeFile(
      envFile,
      `${KEY}='secret'\nDFIR_TIMESKETCH_URL=https://ts.example.test  # note\n`,
      "utf8",
    );
    await reloadEnvPrefix("DFIR_TIMESKETCH_");
    expect(process.env[KEY]).toBe("secret");
    expect(process.env.DFIR_TIMESKETCH_URL).toBe("https://ts.example.test");
  });
});

describe("values that cannot be stored losslessly are refused", () => {
  it.each(UNSTORABLE)("validateEnvUpdates rejects %j", (v) => {
    expect(encodeEnvValue(v)).toBeNull();
    expect(validateEnvUpdates({ [KEY]: v })).toEqual([KEY]);
  });

  it("updateEnv throws and leaves the file unchanged", async () => {
    await writeFile(envFile, `${KEY}=old\n`, "utf8");
    await expect(updateEnv({ [KEY]: "a'b\"c#" })).rejects.toThrow(/malformed/);
    expect(await readFile(envFile, "utf8")).toBe(`${KEY}=old\n`);
  });

  it("updateEnvFrom throws and leaves the file unchanged", async () => {
    await writeFile(envFile, `${KEY}=old\n`, "utf8");
    await expect(updateEnvFrom(() => ({ updates: { [KEY]: "a'b\"c#" }, result: 1 }))).rejects.toThrow(
      /malformed/,
    );
    expect(await readFile(envFile, "utf8")).toBe(`${KEY}=old\n`);
  });
});

describe("POST /settings/env with a value that cannot be stored", () => {
  it("answers 400 naming the key, says why, and writes nothing", async () => {
    await writeFile(envFile, `${KEY}=old\n`, "utf8");
    setServerLogger(createConsoleLogger("info"));
    const app = createApp(new CaseStore(await mkdtemp(join(dir, "cases-"))), {});
    const res = await request(app)
      .post("/settings/env")
      .send({ updates: { [KEY]: "a'b\"c#" } });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain(KEY);
    expect(res.body.error).toMatch(/cannot be saved/);
    expect(await readFile(envFile, "utf8")).toBe(`${KEY}=old\n`);
  });
});

describe("updateEnvFrom round trip", () => {
  it("stores a computed value with # so every reader agrees", async () => {
    await writeFile(envFile, `${KEY}=old\n`, "utf8");
    const result = await updateEnvFrom((env) => ({ updates: { [KEY]: `${env[KEY]}#new` }, result: "ok" }));
    expect(result).toBe("ok");
    expect(parse(await readFile(envFile, "utf8"))[KEY]).toBe("old#new");
    expect((await readEnvFile())[KEY]).toBe("old#new");
  });
});

/**
 * The Docker entrypoint reads path settings out of the same file with its own shell parser before
 * dropping privileges. Run its real `env_file_get` against what the writer produced.
 */
function entrypointReader(): string {
  const script = readFileSync(new URL("../../../docker-entrypoint.sh", import.meta.url), "utf8");
  const match = /^ {2}env_file_get\(\) \{\n[\s\S]*?\n {2}\}\n/m.exec(script);
  if (!match) throw new Error("env_file_get not found in docker-entrypoint.sh");
  return match[0];
}

describe.skipIf(process.platform === "win32")("Docker entrypoint reads the same value", () => {
  it.each(STORABLE)("entrypoint env_file_get reads %j unchanged", async (v) => {
    await updateEnv({ [KEY]: v });
    const out = execFileSync("sh", ["-c", `${entrypointReader()}env_file_get "$1"`, "sh", KEY], {
      env: { PATH: process.env.PATH ?? "", env_file: envFile },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    expect(out).toBe(v);
  });
});
