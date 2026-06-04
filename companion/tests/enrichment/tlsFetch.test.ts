import { describe, it, expect, vi } from "vitest";
import { buildTlsFetch } from "../../src/enrichment/tlsFetch.js";

// Construction-level tests: no disk, no network — the file reader, dispatcher factory, and
// underlying fetch are all injectable so we assert WHAT gets configured, not real TLS.
describe("buildTlsFetch", () => {
  it("returns undefined when no TLS customization is requested (caller keeps global fetch)", () => {
    expect(buildTlsFetch({})).toBeUndefined();
    expect(buildTlsFetch({ insecureSkipVerify: false })).toBeUndefined();
    expect(buildTlsFetch({ caCertPath: "" })).toBeUndefined();
  });

  it("reads the CA bundle and builds a dispatcher with it (verification stays ON)", async () => {
    const pem = "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----";
    const readFile = vi.fn(() => pem);
    const makeDispatcher = vi.fn((c) => ({ tag: "agent", connect: c }));
    const baseFetch = vi.fn(async () => new Response("{}"));

    const f = buildTlsFetch(
      { caCertPath: "/etc/ssl/internal-ca.pem" },
      { readFile, makeDispatcher, baseFetch },
    );

    expect(f).toBeTypeOf("function");
    expect(readFile).toHaveBeenCalledWith("/etc/ssl/internal-ca.pem");
    expect(makeDispatcher).toHaveBeenCalledWith({ ca: pem });

    await f!("https://misp.internal/x", { method: "POST" });
    const passedInit = baseFetch.mock.calls[0][1] as RequestInit & { dispatcher?: unknown };
    expect(passedInit.dispatcher).toMatchObject({ tag: "agent" });
    expect(passedInit.method).toBe("POST"); // original init is preserved
  });

  it("disables verification and warns loudly when insecureSkipVerify is set", () => {
    const onWarn = vi.fn();
    const makeDispatcher = vi.fn((c) => ({ connect: c }));

    const f = buildTlsFetch({ insecureSkipVerify: true, onWarn }, { makeDispatcher });

    expect(f).toBeTypeOf("function");
    expect(makeDispatcher).toHaveBeenCalledWith({ rejectUnauthorized: false });
    expect(onWarn).toHaveBeenCalledOnce();
    expect(onWarn.mock.calls[0][0]).toMatch(/verification disabled/i);
  });

  it("supports a CA bundle and insecure-skip together (CA present, verification off)", () => {
    const makeDispatcher = vi.fn((c) => c);
    const f = buildTlsFetch(
      { caCertPath: "ca.pem", insecureSkipVerify: true },
      { readFile: () => "CA", makeDispatcher },
    );
    expect(f).toBeTypeOf("function");
    expect(makeDispatcher).toHaveBeenCalledWith({ ca: "CA", rejectUnauthorized: false });
  });
});
