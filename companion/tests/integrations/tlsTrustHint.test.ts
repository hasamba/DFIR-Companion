import { describe, it, expect } from "vitest";
import {
  describeFetchError,
  isCertFailureCode,
  serverSetTrustHint,
  tlsCauseCode,
  tlsTrustHint,
} from "../../src/integrations/tlsTrustHint.js";

/**
 * The bug this closes is a message, so the tests are about a message: a self-signed Timesketch
 * reported "self-signed certificate; ... try running Node.js with --use-system-ca
 * (DEPTH_ZERO_SELF_SIGNED_CERT)" — Node's advice, naming none of the Companion's own TLS settings,
 * while "Skip TLS verify" sat one Settings tab away.
 *
 * The other half matters just as much: a hint fired on the WRONG error is worse than none, because
 * it sends the operator disabling certificate verification to fix a refused connection.
 */

// undici's real shape: TypeError("fetch failed") with the errno error on `cause`.
const fetchFailure = (code: string, message = code) =>
  new TypeError("fetch failed", { cause: Object.assign(new Error(message), { code }) });

describe("tlsCauseCode", () => {
  it("finds the code on a nested cause, not just the top-level error", () => {
    expect(tlsCauseCode(fetchFailure("DEPTH_ZERO_SELF_SIGNED_CERT"))).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");
    // Two levels down — undici sometimes wraps once more.
    const deep = new TypeError("fetch failed", { cause: fetchFailure("CERT_HAS_EXPIRED") });
    expect(tlsCauseCode(deep)).toBe("CERT_HAS_EXPIRED");
  });

  it("returns '' rather than inventing a code", () => {
    expect(tlsCauseCode(new Error("boom"))).toBe("");
    expect(tlsCauseCode("not an error")).toBe("");
    expect(tlsCauseCode(undefined)).toBe("");
  });
});

describe("isCertFailureCode", () => {
  it("recognises the OpenSSL family, not one spelling", () => {
    for (const code of [
      "DEPTH_ZERO_SELF_SIGNED_CERT",
      "SELF_SIGNED_CERT_IN_CHAIN",
      "CERT_HAS_EXPIRED",
      "UNABLE_TO_VERIFY_LEAF_SIGNATURE", // no "CERT" substring — the one that is easy to miss
      "ERR_TLS_CERT_ALTNAME_INVALID",
    ])
      expect({ code, cert: isCertFailureCode(code) }).toEqual({ code, cert: true });
  });

  it("never claims a transport failure is a certificate problem", () => {
    for (const code of ["ECONNREFUSED", "ENOTFOUND", "ETIMEDOUT", "EPROTO", ""])
      expect({ code, cert: isCertFailureCode(code) }).toEqual({ code, cert: false });
  });
});

describe("tlsTrustHint", () => {
  it("names the failing integration's OWN env vars", () => {
    const hint = tlsTrustHint(fetchFailure("DEPTH_ZERO_SELF_SIGNED_CERT"), "TIMESKETCH");
    expect(hint).toContain("DFIR_TIMESKETCH_CA");
    expect(hint).toContain("DFIR_TIMESKETCH_INSECURE=1");
    // The insecure flag ALONE is refused for a non-loopback host (#246), so an operator who is
    // told only about it sets it, retries, and meets the identical error with nothing new.
    expect(hint).toContain("DFIR_TLS_ALLOW_INSECURE_EXTERNAL=true");
    // The label as it reads in Settings, so the sentence points at something findable.
    expect(hint).toContain("Skip TLS verify");
  });

  it("is per-integration, not a fixed pair", () => {
    expect(tlsTrustHint(fetchFailure("SELF_SIGNED_CERT_IN_CHAIN"), "IRIS")).toContain("DFIR_IRIS_CA");
  });

  it("stays silent on every non-certificate failure", () => {
    expect(tlsTrustHint(fetchFailure("ECONNREFUSED"), "TIMESKETCH")).toBe("");
    expect(tlsTrustHint(new Error("boom"), "TIMESKETCH")).toBe("");
  });
});

describe("serverSetTrustHint", () => {
  it("points at the tool's CA bundle in its server set, not an env var", () => {
    const hint = serverSetTrustHint(fetchFailure("DEPTH_ZERO_SELF_SIGNED_CERT"), "Timesketch");
    expect(hint).toContain("Set the CA bundle for Timesketch in this server set (Settings → Server sets)");
    expect(hint).not.toContain("DFIR_");
  });

  it("stays silent on every non-certificate failure", () => {
    expect(serverSetTrustHint(fetchFailure("ECONNREFUSED"), "IRIS")).toBe("");
  });
});

describe("describeFetchError", () => {
  it("walks the cause chain so 'fetch failed' carries the reason", () => {
    expect(describeFetchError(fetchFailure("ECONNREFUSED", "connect ECONNREFUSED 127.0.0.1:443"))).toBe(
      "fetch failed -> connect ECONNREFUSED 127.0.0.1:443 (ECONNREFUSED)",
    );
  });
});
