import { describe, expect, it } from "vitest";
import {
  classifyFailure,
  describeFetchFailure,
  fetchFailureLogLine,
  redact,
} from "../../src/integrations/crowdstrike/fetchFailure.js";
import { issuerLabel } from "../../src/integrations/crowdstrike/tlsPeerIssuer.js";

// #2685: every way Node's fetch fails without an HTTP answer gets its own sentence naming what to
// check, instead of "Could not reach CrowdStrike NG-SIEM."

const HOST = "api.us-2.crowdstrike.com";
const ctx = { host: HOST, label: "CrowdStrike NG-SIEM" };

/** What undici throws: TypeError("fetch failed") with the real reason on cause. */
function fetchFailed(code: string, message = `boom ${code}`): Error {
  const cause = Object.assign(new Error(message), { code });
  return new TypeError("fetch failed", { cause });
}

describe("describeFetchFailure", () => {
  it("DNS: names the host, the base URL setting and DNS", () => {
    const m = describeFetchFailure(fetchFailed("ENOTFOUND"), ctx);
    expect(m).toContain(`could not resolve ${HOST}`);
    expect(m).toMatch(/base URL/);
    expect(m).toMatch(/DNS/);
  });

  it.each(["ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "UND_ERR_CONNECT_TIMEOUT"])(
    "network (%s): names the network path, firewall or proxy",
    (code) => {
      const m = describeFetchFailure(fetchFailed(code), ctx);
      expect(m).toContain(code);
      expect(m).toMatch(/firewall or proxy/);
      expect(m).not.toMatch(/resolve|certificate/);
    },
  );

  it("TLS trust: points at DFIR_CROWDSTRIKE_SIEM_CA and names the issuer when known", () => {
    const err = fetchFailed("UNABLE_TO_GET_ISSUER_CERT_LOCALLY");
    const m = describeFetchFailure(err, { ...ctx, issuer: "O=CrowdStrike, CN=Falcon ROOT CA Proxy" });
    expect(m).toContain("UNABLE_TO_GET_ISSUER_CERT_LOCALLY");
    expect(m).toContain('issued by "O=CrowdStrike, CN=Falcon ROOT CA Proxy"');
    expect(m).toContain("DFIR_CROWDSTRIKE_SIEM_CA");
    expect(m).toMatch(/inspects TLS/);
    expect(describeFetchFailure(err, ctx)).not.toContain("issued by");
  });

  it("an expired certificate says check the clock, not add a CA", () => {
    const m = describeFetchFailure(fetchFailed("CERT_HAS_EXPIRED"), ctx);
    expect(m).toMatch(/clock/);
    expect(m).not.toContain("DFIR_CROWDSTRIKE_SIEM_CA");
  });

  it("a hostname mismatch points at the base URL", () => {
    const m = describeFetchFailure(fetchFailed("ERR_TLS_CERT_ALTNAME_INVALID"), ctx);
    expect(m).toMatch(/different host/);
    expect(m).toMatch(/base URL/);
  });

  it("an invalid URL names the base URL setting", () => {
    const err = Object.assign(new TypeError("Invalid URL"), { code: "ERR_INVALID_URL" });
    const m = describeFetchFailure(err, ctx);
    expect(m).toContain("DFIR_CROWDSTRIKE_SIEM_BASE_URL");
    expect(classifyFailure(new TypeError("Invalid URL")).kind).toBe("url");
  });

  it("the four main kinds are four distinct sentences", () => {
    const msgs = ["ENOTFOUND", "ECONNREFUSED", "SELF_SIGNED_CERT_IN_CHAIN", "ERR_INVALID_URL"].map((c) =>
      describeFetchFailure(fetchFailed(c), ctx),
    );
    expect(new Set(msgs).size).toBe(4);
  });

  it("finds a code two levels deep and inside an AggregateError, and survives a cycle", () => {
    const deep = new TypeError("fetch failed", {
      cause: new Error("x", { cause: fetchFailed("ENOTFOUND") }),
    });
    expect(classifyFailure(deep).kind).toBe("dns");
    const agg = new TypeError("fetch failed", {
      cause: new AggregateError([Object.assign(new Error("a"), { code: "ECONNREFUSED" })], "all failed"),
    });
    expect(classifyFailure(agg).kind).toBe("network");
    const loop: Record<string, unknown> = { message: "loop" };
    loop.cause = loop;
    expect(classifyFailure(loop).kind).toBe("other");
    expect(classifyFailure("not an error").kind).toBe("other");
  });

  it("an unknown failure still names the host", () => {
    expect(describeFetchFailure(new Error("weird"), ctx)).toContain(HOST);
  });
});

describe("fetchFailureLogLine / redact", () => {
  it("logs every level of the chain with its code", () => {
    const line = fetchFailureLogLine(fetchFailed("ENOTFOUND", "getaddrinfo ENOTFOUND api.x"));
    expect(line).toContain("TypeError: fetch failed");
    expect(line).toContain("[ENOTFOUND]");
    expect(line).toContain("getaddrinfo");
  });

  it("never carries the secret, a bearer token or URL credentials, even when an error does", () => {
    const secret = "s3cr3t-client-secret";
    const err = new TypeError(`fetch failed for client_secret=${secret}`, {
      cause: Object.assign(new Error(`Bearer abc.def.ghi at https://user:pw@api.x/ ${secret}`), {
        code: "ECONNRESET",
      }),
    });
    const line = fetchFailureLogLine(err, [secret]);
    expect(line).not.toContain(secret);
    expect(line).not.toContain("abc.def.ghi");
    expect(line).not.toContain("user:pw");
    expect(redact("x", [""])).toBe("x");
  });
});

describe("issuerLabel", () => {
  it("formats O and CN and strips control characters and quotes", () => {
    expect(issuerLabel({ issuer: { O: "CrowdStrike", CN: "Falcon ROOT CA Proxy" } })).toBe(
      "O=CrowdStrike, CN=Falcon ROOT CA Proxy",
    );
    expect(issuerLabel({ issuer: { CN: 'evil"\nname' } })).toBe("CN=evilname");
    expect(issuerLabel(undefined)).toBeUndefined();
    expect(issuerLabel({ issuer: {} })).toBeUndefined();
  });
});
