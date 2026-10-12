import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

// THE COMPOSE HEALTHCHECK MUST PROBE THE PORT THE SERVER ACTUALLY BINDS (#2160).
//
// docker-compose.yml overrides the image's baked HEALTHCHECK. The override hardcoded 4773 while
// the server binds DFIR_PORT, so an operator who changed DFIR_PORT got a permanently "unhealthy"
// container — and Portainer/autoheal setups restart a working server in a loop. These tests run
// the actual probe script with a stub fetch and pin it to the image probe so the two cannot drift.
const root = new URL("../../../", import.meta.url);
const read = (p: string): string => readFileSync(new URL(p, root), "utf8");

function composeProbeScript(): string {
  const doc = parse(read("docker-compose.yml")) as {
    services: { companion: { healthcheck: { test: string[] } } };
  };
  const test = doc.services.companion.healthcheck.test;
  expect(test[0]).toBe("CMD");
  const flag = test.indexOf("-e");
  expect(flag).toBeGreaterThan(0);
  const script = test[flag + 1];
  expect(typeof script).toBe("string");
  return script;
}

function dockerfileProbeScript(): string {
  const match = read("Dockerfile").match(/HEALTHCHECK[^\n]*\\\n\s*CMD node -e "([^"\n]+)"/);
  expect(match).not.toBeNull();
  return (match as RegExpMatchArray)[1];
}

interface ProbeResult {
  url: string | undefined;
  exitCode: number | undefined;
}

async function runProbe(script: string, env: Record<string, string>, ok = true): Promise<ProbeResult> {
  const result: ProbeResult = { url: undefined, exitCode: undefined };
  let resolveExit: () => void = () => {};
  const exited = new Promise<void>((r) => {
    resolveExit = r;
  });
  const sandbox = {
    fetch: (url: string) => {
      result.url = url;
      return Promise.resolve({ ok });
    },
    process: {
      env,
      exit: (code: number) => {
        result.exitCode = code;
        resolveExit();
      },
    },
  };
  runInNewContext(script, sandbox);
  await exited;
  return result;
}

const CASES: ReadonlyArray<{ env: Record<string, string>; url: string }> = [
  { env: { DFIR_PORT: "5123" }, url: "http://127.0.0.1:5123/health" },
  { env: {}, url: "http://127.0.0.1:4773/health" },
  { env: { PORT: "8080", DFIR_PORT: "5123" }, url: "http://127.0.0.1:8080/health" },
];

describe("compose healthcheck (#2160)", () => {
  it.each(CASES)("probes $url for env $env", async ({ env, url }) => {
    const r = await runProbe(composeProbeScript(), env);
    expect(r.url).toBe(url);
    expect(r.exitCode).toBe(0);
  });

  it("exits 1 when /health is not ok", async () => {
    const r = await runProbe(composeProbeScript(), {}, false);
    expect(r.exitCode).toBe(1);
  });

  it.each(CASES)("matches the image HEALTHCHECK for env $env", async ({ env }) => {
    const compose = await runProbe(composeProbeScript(), env);
    const image = await runProbe(dockerfileProbeScript(), env);
    expect(compose.url).toBe(image.url);
  });
});
