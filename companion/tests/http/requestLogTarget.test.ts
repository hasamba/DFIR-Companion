import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApp, getServerLogger, setServerLogger } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { requestLogTarget } from "../../src/http/requestLogTarget.js";
import type { Logger } from "../../src/logging/logger.js";

/**
 * The request log is persistent and is copied into support bundles, so it records where a request
 * went, never the values it carried in its query string.
 */
describe("requestLogTarget", () => {
  it("keeps a path with no query string as it is", () => {
    expect(requestLogTarget("/cases/abc/events")).toBe("/cases/abc/events");
  });

  it("keeps the parameter names and drops every value", () => {
    const out = requestLogTarget("/auth/oidc/callback?code=SAMPLE-CODE-1&state=SAMPLE-STATE-2");
    expect(out).toBe("/auth/oidc/callback?code&state");
    expect(out).not.toContain("SAMPLE");
  });

  it("drops an encoded return address", () => {
    expect(requestLogTarget("/login?returnTo=%2Fcases%2Fsecret-case")).toBe("/login?returnTo");
  });

  it("lists a repeated name once and ignores empty pairs", () => {
    expect(requestLogTarget("/x?a=1&&a=2&b")).toBe("/x?a&b");
  });

  it("drops a name that is not a plain identifier", () => {
    expect(requestLogTarget("/x?ok=1&bad%20name=2&<script>=3")).toBe("/x?ok");
  });

  it("caps how many names are kept", () => {
    const qs = Array.from({ length: 40 }, (_, i) => `p${i}=v`).join("&");
    const out = requestLogTarget(`/x?${qs}`);
    expect(out.split("?")[1].split("&")).toHaveLength(16);
  });

  it("drops the fragment and a bare question mark", () => {
    expect(requestLogTarget("/x?")).toBe("/x");
    expect(requestLogTarget("/x#frag")).toBe("/x");
  });
});

describe("request logger", () => {
  let lines: string[];
  let previous: Logger;

  beforeEach(() => {
    lines = [];
    previous = getServerLogger();
    const sink = (m: string) => lines.push(m);
    setServerLogger({
      debug: sink,
      info: sink,
      warn: sink,
      error: sink,
      getLevel: () => "debug",
      setLevel: () => {},
      close: async () => {},
    });
  });

  afterEach(() => setServerLogger(previous));

  it("writes the path and parameter names, not the sign-in code, state or return address", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-reqlog-"));
    const app = createApp(new CaseStore(join(root, "cases")));
    await request(app).get("/auth/oidc/callback?code=SAMPLE-CODE-12345&state=SAMPLE-STATE-67890");
    await request(app).get("/login?returnTo=%2Fcases%2Fsample-case-name");
    const reqLines = lines.filter((l) => l.startsWith("[req]"));
    expect(reqLines).toHaveLength(2);
    expect(reqLines[0]).toMatch(/^\[req\] GET \/auth\/oidc\/callback\?code&state -> \d{3}$/);
    expect(reqLines[1]).toMatch(/^\[req\] GET \/login\?returnTo -> \d{3}$/);
    const all = lines.join("\n");
    expect(all).not.toContain("SAMPLE-CODE");
    expect(all).not.toContain("SAMPLE-STATE");
    expect(all).not.toContain("sample-case-name");
  });
});
