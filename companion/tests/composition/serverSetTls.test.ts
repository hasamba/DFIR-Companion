import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { tlsFetchFor, tlsFetchForSettings } from "../../src/composition/tlsFetch.js";
import { buildIrisClientFrom, buildTimesketchClientFrom } from "../../src/composition/integrationClients.js";
import { probeError } from "../../src/routes/serverSetBody.js";
import { getServerLogger, setServerLogger } from "../../src/server.js";
import type { Logger } from "../../src/logging/logger.js";

// A server set's "Skip TLS verify" box is the analyst's consent for that set's server, loopback or
// not. Every env-based integration keeps the #246 guard: insecure toward a non-loopback host still
// needs DFIR_TLS_ALLOW_INSECURE_EXTERNAL=true.

const KEYS = ["DFIR_TLS_ALLOW_INSECURE_EXTERNAL", "DFIR_MISP_URL", "DFIR_MISP_INSECURE"];
const saved: Record<string, string | undefined> = {};
let original: Logger;
let warn: ReturnType<typeof vi.fn>;

beforeEach(() => {
  original = getServerLogger();
  warn = vi.fn();
  setServerLogger({ ...original, warn });
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
  setServerLogger(original);
});

const warnings = () => warn.mock.calls.map(([m]) => String(m));

describe("server set TLS trust", () => {
  it("a set with Skip TLS verify on a LAN host gets a skip-verify fetch, with the global flag unset", () => {
    const fetchFn = tlsFetchForSettings({ url: "https://iris.example.org", insecure: true, label: "IRIS" });
    expect(fetchFn).toBeTypeOf("function");
    expect(warnings().some((m) => /refused|DISABLED for a non-loopback/i.test(m))).toBe(false);
    // One warn line that names the host only.
    const line = warnings().find((m) => m.includes("iris.example.org"));
    expect(line).toBeDefined();
    expect(line).not.toContain("https://");
  });

  it("an env integration with insecure toward a non-loopback host is still refused", () => {
    process.env.DFIR_MISP_URL = "https://misp.example.com";
    process.env.DFIR_MISP_INSECURE = "true";
    expect(tlsFetchFor("MISP")).toBeUndefined();
    expect(warnings().some((m) => /non-loopback/i.test(m))).toBe(true);
  });

  // A set's CA bundle that cannot be read must say so. Falling back to the default trust only shows
  // a certificate error that points at the CA bundle the analyst already set.
  it("a CA bundle that cannot be read fails each request with its path, not a certificate error", async () => {
    const ca = "/nonexistent/dfir-test/ca.pem";
    const fetchFn = tlsFetchForSettings({ url: "https://iris.example.org", ca, label: "IRIS" });
    expect(fetchFn).toBeTypeOf("function");
    await expect(fetchFn!("https://iris.example.org/api/ping")).rejects.toThrow(
      `CA bundle '${ca}' could not be read`,
    );
  });

  it("the IRIS and Timesketch test results name the unreadable CA bundle", async () => {
    const ca = "/nonexistent/dfir-test/ca.pem";
    const iris = buildIrisClientFrom({ url: "https://iris.example.org", apiKey: "k", ca });
    const irisErr = await iris.ping().catch((e: unknown) => e);
    expect(probeError(irisErr)).toBe(`IRIS request failed: CA bundle '${ca}' could not be read`);
    const ts = buildTimesketchClientFrom({ url: "https://ts.example.org", user: "u", password: "p", ca });
    const tsErr = await ts.login().catch((e: unknown) => e);
    expect(probeError(tsErr)).toContain(`CA bundle '${ca}' could not be read`);
  });
});

// A server-set IRIS client gets its key from the set, not from DFIR_IRIS_KEY.
describe("IRIS 401", () => {
  it("points at the IRIS API key in the server set", async () => {
    const iris = buildIrisClientFrom({ url: "https://iris.example.org", apiKey: "k" });
    const client = iris as unknown as { fetchFn: unknown };
    client.fetchFn = async () => new Response("{}", { status: 401 });
    await expect(iris.ping()).rejects.toThrow("IRIS auth failed (check the IRIS API key in this server set)");
  });
});
