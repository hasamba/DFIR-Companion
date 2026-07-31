import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createTeamAuthRuntime } from "../../src/auth/authFactory.js";
import { acquireWriterGuard } from "../../src/auth/writerGuard.js";

describe("team-auth runtime", () => {
  it("preserves the zero-config single-user runtime", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-auth-runtime-"));
    expect(createTeamAuthRuntime(root, "127.0.0.1", 4773, {})).toEqual({});
  });

  it("creates team authentication and releases its single-writer guard", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-auth-runtime-"));
    const dataDir = join(root, "auth");
    const casesRoot = join(root, "cases");
    const runtime = createTeamAuthRuntime(casesRoot, "127.0.0.1", 4773, {
      DFIR_AUTH_MODE: "team",
      DFIR_AUTH_COOKIE_SECURE: "false",
      DFIR_AUTH_DATA_DIR: dataDir,
    });
    expect(runtime.teamAuth).toBeDefined();
    const guardPath = join(casesRoot, ".dfir-team-writer.lock");
    expect(JSON.parse(await readFile(guardPath, "utf8"))).toMatchObject({
      pid: process.pid,
    });
    runtime.writerGuard?.release();
    const reacquired = acquireWriterGuard(guardPath);
    reacquired.release();
  });

  it("refuses a second active writer and recovers a stale guard", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-writer-guard-"));
    const path = join(root, "writer.lock");
    const first = acquireWriterGuard(path);
    expect(() => acquireWriterGuard(path)).toThrow(/one DFIR Companion writer/i);
    first.release();

    await writeFile(
      path,
      JSON.stringify({
        pid: 2_147_483_647,
        token: "stale-token",
        startedAt: "2020-01-01T00:00:00.000Z",
      }),
      "utf8",
    );
    const replacement = acquireWriterGuard(path);
    replacement.release();
  });

  it("derives only loopback HTTP callbacks and requires an explicit public URL remotely", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-auth-runtime-"));
    const base = {
      DFIR_AUTH_MODE: "team",
      DFIR_AUTH_OIDC_ISSUER: "https://id.example.com",
      DFIR_AUTH_OIDC_CLIENT_ID: "companion",
      DFIR_AUTH_DATA_DIR: join(root, "auth"),
      DFIR_AUTH_BOOTSTRAP_TOKEN: "bootstrap-token",
    };
    expect(() => createTeamAuthRuntime(join(root, "cases"), "0.0.0.0", 4773, base)).toThrow(
      /PUBLIC_URL|REDIRECT_URI/,
    );
  });

  it("requires a bootstrap token before exposing an empty identity store remotely", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-auth-runtime-"));
    expect(() =>
      createTeamAuthRuntime(join(root, "cases"), "0.0.0.0", 4773, {
        DFIR_AUTH_MODE: "team",
        DFIR_AUTH_DATA_DIR: join(root, "auth"),
      }),
    ).toThrow(/BOOTSTRAP_TOKEN/);
  });
});
