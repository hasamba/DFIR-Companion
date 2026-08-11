import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { buildEnrichmentProviders, tlsFetchFor, setServerLogger, getServerLogger } from "../../src/server.js";
import type { Logger } from "../../src/logging/logger.js";

// #246's insecureSkipVerify guard is unreachable from the real server unless tlsFetchFor() passes
// hostUrl to buildTlsFetch — its only call site originally didn't. These exercise the REAL wiring
// (buildEnrichmentProviders, the same function server.ts calls at boot and on live reload), not
// buildTlsFetch in isolation, so a regression in the wiring itself would fail here.

const ENV_KEYS = [
  "DFIR_MISP_URL",
  "DFIR_MISP_KEY",
  "DFIR_MISP_INSECURE",
  "DFIR_TLS_ALLOW_INSECURE_EXTERNAL",
  "DFIR_NOTIFY_INSECURE",
];
const saved: Record<string, string | undefined> = {};
let originalLogger: Logger;

beforeEach(() => {
  originalLogger = getServerLogger();
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  setServerLogger(originalLogger);
});

describe("tlsFetchFor wiring — insecureSkipVerify guard (#246)", () => {
  it("does not crash provider construction when insecureSkipVerify targets a non-loopback host — disables custom TLS trust for that provider instead, and warns loudly", () => {
    process.env.DFIR_MISP_URL = "https://misp.example.com";
    process.env.DFIR_MISP_KEY = "key123";
    process.env.DFIR_MISP_INSECURE = "true";
    const warn = vi.fn();
    setServerLogger({ ...originalLogger, warn });

    let providers: ReturnType<typeof buildEnrichmentProviders> = [];
    expect(() => {
      providers = buildEnrichmentProviders();
    }).not.toThrow();
    expect(providers.some((p) => p.name === "MISP")).toBe(true); // still configured
    expect(warn).toHaveBeenCalled();
    expect(warn.mock.calls.some(([m]) => /non-loopback/i.test(m as string))).toBe(true);
  });

  it("allows insecureSkipVerify for a loopback MISP host with no override needed", () => {
    process.env.DFIR_MISP_URL = "http://127.0.0.1:8080";
    process.env.DFIR_MISP_KEY = "key123";
    process.env.DFIR_MISP_INSECURE = "true";
    expect(() => buildEnrichmentProviders()).not.toThrow();
  });

  it("allows insecureSkipVerify for a non-loopback host when DFIR_TLS_ALLOW_INSECURE_EXTERNAL is set", () => {
    process.env.DFIR_MISP_URL = "https://misp.example.com";
    process.env.DFIR_MISP_KEY = "key123";
    process.env.DFIR_MISP_INSECURE = "true";
    process.env.DFIR_TLS_ALLOW_INSECURE_EXTERNAL = "true";
    expect(() => buildEnrichmentProviders()).not.toThrow();
  });

  it("builds normally when insecureSkipVerify is not requested at all", () => {
    process.env.DFIR_MISP_URL = "https://misp.example.com";
    process.env.DFIR_MISP_KEY = "key123";
    expect(() => buildEnrichmentProviders()).not.toThrow();
  });
});

// A notification webhook's host is only known at send time, so there is no env var for
// tlsFetchFor to read — which meant hostUrl was undefined, the guard defaulted to "loopback",
// and DFIR_NOTIFY_INSECURE turned off certificate verification for every Slack/Teams/Mattermost
// webhook with nothing to stop it (#7).
describe("tlsFetchFor(NOTIFY) — the guard must apply to webhooks too", () => {
  it("refuses to skip verification on DFIR_NOTIFY_INSECURE alone, and says why", () => {
    process.env.DFIR_NOTIFY_INSECURE = "1";
    const warn = vi.fn();
    setServerLogger({ ...originalLogger, warn });

    // undefined = no custom TLS trust → createNotifier falls back to the verified global fetch.
    expect(tlsFetchFor("NOTIFY")).toBeUndefined();
    expect(warn.mock.calls.some(([m]) => /non-loopback/i.test(m as string))).toBe(true);
  });

  it("honours DFIR_NOTIFY_INSECURE once the operator also opts in to external insecure TLS", () => {
    process.env.DFIR_NOTIFY_INSECURE = "1";
    process.env.DFIR_TLS_ALLOW_INSECURE_EXTERNAL = "true";
    expect(tlsFetchFor("NOTIFY")).toBeTypeOf("function");
  });

  it("builds no custom fetch at all when insecure is not requested", () => {
    expect(tlsFetchFor("NOTIFY")).toBeUndefined();
  });
});
