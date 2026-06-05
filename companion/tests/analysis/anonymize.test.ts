import { describe, it, expect } from "vitest";
import { createAnonymizer, isInternalIp, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

const NONE: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };
function policy(over: Partial<AnonPolicy["categories"]> = {}, redactSecrets = false): AnonPolicy {
  return {
    enabled: true,
    redactSecrets,
    categories: { IP: false, EMAIL: false, USER: false, HOST: false, DOMAIN: false, PATH: false, ...over },
  };
}

describe("isInternalIp", () => {
  it("classifies RFC1918 / loopback / link-local as internal", () => {
    expect(isInternalIp("10.0.0.5")).toBe(true);
    expect(isInternalIp("192.168.1.20")).toBe(true);
    expect(isInternalIp("172.16.4.9")).toBe(true);
    expect(isInternalIp("172.31.0.1")).toBe(true);      // last /12 octet
    expect(isInternalIp("127.0.0.1")).toBe(true);
    expect(isInternalIp("169.254.10.1")).toBe(true);
    expect(isInternalIp("100.64.0.1")).toBe(true);      // CGNAT 100.64/10
    expect(isInternalIp("100.127.255.255")).toBe(true); // CGNAT upper bound
  });
  it("classifies public IPs as NOT internal (adversary C2 must survive)", () => {
    expect(isInternalIp("8.8.8.8")).toBe(false);
    expect(isInternalIp("45.61.136.10")).toBe(false);
    expect(isInternalIp("172.32.0.1")).toBe(false);  // just outside 172.16/12
    expect(isInternalIp("100.128.0.1")).toBe(false); // just outside CGNAT 100.64/10
  });
});

describe("anonymizer — internal IPs", () => {
  it("tokenizes internal IPs and preserves public ones; restore reverses", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const out = a.apply("victim 10.0.0.5 beaconed to 45.61.136.10");
    expect(out).not.toContain("10.0.0.5");
    expect(out).toContain("45.61.136.10");
    expect(out).toMatch(/ANON_IP_1/);
    expect(a.restore(out)).toBe("victim 10.0.0.5 beaconed to 45.61.136.10");
  });
  it("gives the same token to repeated values (within-call correlation)", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const out = a.apply("10.0.0.5 -> 10.0.0.9 ; 10.0.0.5 again");
    const first = out.match(/ANON_IP_\d+/g)!;
    expect(first[0]).toBe(first[2]);   // both 10.0.0.5
    expect(first[0]).not.toBe(first[1]); // 10.0.0.9 differs
  });
  it("restore leaves unknown/hallucinated tokens untouched and is case-insensitive", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    a.apply("10.0.0.5");
    expect(a.restore("see ANON_IP_99")).toBe("see ANON_IP_99");
    expect(a.restore("see anon_ip_1")).toBe("see 10.0.0.5");
  });
  it("restoreDeep walks arrays and object string fields", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    a.apply("10.0.0.5");
    const restored = a.restoreDeep({ items: [{ description: "src ANON_IP_1" }], n: 3 });
    expect(restored).toEqual({ items: [{ description: "src 10.0.0.5" }], n: 3 });
  });
  it("apply is a no-op when the category is disabled", () => {
    const a = createAnonymizer(policy({ IP: false }), NONE);
    expect(a.apply("10.0.0.5")).toBe("10.0.0.5");
  });
});
