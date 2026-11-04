import { describe, expect, it } from "vitest";
import { resolveHttpsConfig } from "../../src/http/httpsConfig.js";

const ctx = { teamMode: false, mainPort: 4773, baseDir: "/srv/dfir" };

describe("resolveHttpsConfig (#2285)", () => {
  it("auto is off in single-user mode and on in team mode", () => {
    expect(resolveHttpsConfig({}, ctx).enabled).toBe(false);
    const team = resolveHttpsConfig({}, { ...ctx, teamMode: true });
    expect(team.enabled).toBe(true);
    expect(team.enabledBy).toBe("team-mode");
  });

  it("on and off override team mode either way", () => {
    expect(resolveHttpsConfig({ DFIR_HTTPS: "on" }, ctx)).toMatchObject({
      enabled: true,
      enabledBy: "setting",
    });
    expect(resolveHttpsConfig({ DFIR_HTTPS: "OFF" }, { ...ctx, teamMode: true }).enabled).toBe(false);
  });

  it("rejects an unknown mode instead of guessing", () => {
    expect(() => resolveHttpsConfig({ DFIR_HTTPS: "yes" }, ctx)).toThrow(/DFIR_HTTPS must be one of/);
    expect(() => resolveHttpsConfig({ DFIR_HTTPS_PLAIN_HTTP: "open" }, ctx)).toThrow(/DFIR_HTTPS_PLAIN_HTTP/);
  });

  it("requires certificate and key together, resolving relative paths against the base dir", () => {
    expect(() => resolveHttpsConfig({ DFIR_HTTPS_CERT: "a.pem" }, ctx)).toThrow(/set together/);
    const cfg = resolveHttpsConfig({ DFIR_HTTPS_CERT: "tls/a.pem", DFIR_HTTPS_KEY: "/etc/k.pem" }, ctx);
    expect(cfg.certFile).toMatch(/[\\/]srv[\\/]dfir[\\/]tls[\\/]a\.pem$/);
    expect(cfg.keyFile).toBe("/etc/k.pem");
  });

  it("parses the plain-HTTP door and refuses to share the main port", () => {
    const cfg = resolveHttpsConfig(
      { DFIR_HTTPS: "on", DFIR_HTTPS_PLAIN_HTTP: "redirect", DFIR_HTTPS_PLAIN_HTTP_PORT: "8080" },
      ctx,
    );
    expect(cfg).toMatchObject({ plainHttp: "redirect", plainHttpPort: 8080 });
    expect(resolveHttpsConfig({}, ctx)).toMatchObject({ plainHttp: "off", plainHttpPort: 4774 });
    expect(() =>
      resolveHttpsConfig(
        { DFIR_HTTPS: "on", DFIR_HTTPS_PLAIN_HTTP: "serve", DFIR_HTTPS_PLAIN_HTTP_PORT: "4773" },
        ctx,
      ),
    ).toThrow(/must differ/);
    expect(() => resolveHttpsConfig({ DFIR_HTTPS_PLAIN_HTTP_PORT: "99999" }, ctx)).toThrow(/port number/);
  });

  it("splits extra hostnames", () => {
    expect(resolveHttpsConfig({ DFIR_HTTPS_HOSTNAMES: " dfir.lab , 10.0.0.5,," }, ctx).extraNames).toEqual([
      "dfir.lab",
      "10.0.0.5",
    ]);
  });
});
