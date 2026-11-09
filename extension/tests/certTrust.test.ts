import { describe, expect, it } from "vitest";
import { unreachableReason, untrustedCertHint } from "../src/certTrust.js";

// #2473: a browser that does not trust the team-mode certificate makes fetch throw with no detail —
// indistinguishable from a stopped companion — so over https both causes must be named.
describe("untrustedCertHint", () => {
  it("is null for an http companion — there is no certificate to trust", () => {
    expect(untrustedCertHint("http://127.0.0.1:4773")).toBeNull();
  });

  it("points an https companion at its public CA download", () => {
    const hint = untrustedCertHint("https://companion.example:4773/");
    expect(hint).not.toBeNull();
    expect(hint!.caUrl).toBe("https://companion.example:4773/tls/ca.crt");
    expect(hint!.before).toMatch(/certificate/i);
    expect(hint!.after).toMatch(/trusted certificate authority/i);
    expect(hint!.after).toMatch(/restart the browser/i);
  });

  it("treats the scheme case-insensitively", () => {
    expect(untrustedCertHint(" HTTPS://companion.example ")?.caUrl).toBe("HTTPS://companion.example/tls/ca.crt");
  });
});

describe("unreachableReason", () => {
  it("keeps the plain offline wording for http", () => {
    expect(unreachableReason("http://127.0.0.1:4773")).toBe("companion offline");
  });

  it("names both causes for https", () => {
    const reason = unreachableReason("https://companion.example:4773");
    expect(reason).toMatch(/isn't running/i);
    expect(reason).toMatch(/certificate/i);
    expect(reason).not.toMatch(/offline/i);
  });
});
