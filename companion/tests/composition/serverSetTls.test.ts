import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { tlsFetchFor, tlsFetchForSettings } from "../../src/composition/tlsFetch.js";
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
});
