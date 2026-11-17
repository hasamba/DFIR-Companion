import { describe, expect, it } from "vitest";
import {
  FalconAuthError,
  FalconTokenSource,
  resolveFalconBase,
} from "../../src/integrations/crowdstrike/falconAuth.js";
import { ngsiemCredentialsFromEnv } from "../../src/integrations/crowdstrike/ngsiemConfig.js";

// #2666: the Falcon sign-in extracted from the threat-intel provider, shared with the NG-SIEM client.

describe("resolveFalconBase", () => {
  it("maps clouds and aliases, defaults to us-1, and lets an explicit base win", () => {
    expect(resolveFalconBase({})).toBe("https://api.crowdstrike.com");
    expect(resolveFalconBase({ cloud: "EU" })).toBe("https://api.eu-1.crowdstrike.com");
    expect(resolveFalconBase({ cloud: "usgov2" })).toBe("https://api.us-gov-2.crowdstrike.mil");
    expect(resolveFalconBase({ cloud: "mars" })).toBe("https://api.crowdstrike.com");
    expect(resolveFalconBase({ cloud: "eu-1", baseUrl: "https://proxy.test///" })).toBe("https://proxy.test");
  });
});

describe("FalconTokenSource", () => {
  const source = (status = 201) => {
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      return status === 201
        ? Response.json({ access_token: `t${calls}`, expires_in: 1799 }, { status })
        : new Response("{}", { status });
    }) as unknown as typeof fetch;
    const tokens = new FalconTokenSource({
      clientId: "id",
      clientSecret: "secret-value",
      base: "https://falcon.test",
      fetchFn,
      timeoutMs: 1000,
      authFailedMessage: "check the SIEM client",
      label: "Falcon",
    });
    return { tokens, calls: () => calls };
  };

  it("caches the token and refreshes it when forced", async () => {
    const { tokens, calls } = source();
    expect(await tokens.get()).toBe("t1");
    expect(await tokens.get()).toBe("t1");
    expect(await tokens.get(true)).toBe("t2");
    expect(calls()).toBe(2);
  });

  it("a rejected sign-in throws the configured sentence", async () => {
    const { tokens } = source(401);
    const err = await tokens.get().then(
      () => new Error("expected a rejection"),
      (e: unknown) => e as Error,
    );
    expect(err).toBeInstanceOf(FalconAuthError);
    expect(err.message).toBe("check the SIEM client");
  });
});

describe("ngsiemCredentialsFromEnv", () => {
  it("is null without both SIEM credentials; the threat-intel ones never switch it on", () => {
    expect(
      ngsiemCredentialsFromEnv({ DFIR_CROWDSTRIKE_CLIENT_ID: "a", DFIR_CROWDSTRIKE_CLIENT_SECRET: "b" }),
    ).toBeNull();
  });

  it("falls back to the threat-intel cloud only for the region", () => {
    const env = {
      DFIR_CROWDSTRIKE_SIEM_CLIENT_ID: "sid",
      DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET: "ssec",
      DFIR_CROWDSTRIKE_CLOUD: "eu-1",
      DFIR_CROWDSTRIKE_CLIENT_ID: "intel",
    };
    expect(ngsiemCredentialsFromEnv(env)).toEqual({ clientId: "sid", clientSecret: "ssec", cloud: "eu-1" });
    expect(ngsiemCredentialsFromEnv({ ...env, DFIR_CROWDSTRIKE_SIEM_CLOUD: "us-2" })?.cloud).toBe("us-2");
  });
});
