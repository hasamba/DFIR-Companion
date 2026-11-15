import { describe, expect, it } from "vitest";
import {
  createAnonymizer,
  type AnonPair,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// Watson phase 5, D6: every send after the first is masked by an anonymizer seeded with the pairs the
// earlier sends minted, so a token keeps its meaning for the whole round and nothing renumbers.

const POLICY: AnonPolicy = {
  enabled: true,
  redactSecrets: false,
  maskPublicIps: true,
  categories: {
    IP: true,
    EMAIL: true,
    USER: true,
    HOST: true,
    DOMAIN: true,
    PATH: false,
    CMD: false,
    REG: false,
    CARD: false,
    PHONE: false,
    NATID: false,
  },
};

const known = (hosts: string[]): KnownEntities => ({ hosts, accounts: [], internalDomains: [] });

describe("createAnonymizer with a seed (D6)", () => {
  it("earlier tokens keep their meaning; a newly known name gets a new, higher number", () => {
    const first = createAnonymizer(POLICY, known(["ws-02"]));
    expect(first.apply("login on ws-02")).toBe("login on ANON_HOST_1");
    const seed = first.pairs();

    // A name that sorts before ws-02 and appears before it in the text joins the known list.
    const next = createAnonymizer(POLICY, known(["aa-01", "ws-02"]), seed);
    expect(next.apply("aa-01 then ws-02")).toBe("ANON_HOST_2 then ANON_HOST_1");
    expect(next.restore("ANON_HOST_1 and ANON_HOST_2")).toBe("ws-02 and aa-01");
  });

  it("seeded pairs are reported by pairs() and restore without any apply()", () => {
    const seed: AnonPair[] = [{ token: "ANON_HOST_3", value: "ws-01", category: "HOST" }];
    const a = createAnonymizer(POLICY, known(["ws-01"]), seed);
    expect(a.restore("ANON_HOST_3")).toBe("ws-01");
    expect(a.pairs()).toEqual(seed);
    expect(a.apply("on ws-01")).toBe("on ANON_HOST_3");
  });

  it("raises each category counter to the highest seeded number", () => {
    const seed: AnonPair[] = [
      { token: "ANON_HOST_1", value: "ws-01", category: "HOST" },
      { token: "ANON_HOST_7", value: "ws-07", category: "HOST" },
    ];
    const a = createAnonymizer(POLICY, known(["ws-01", "ws-07", "ws-99"]), seed);
    expect(a.apply("ws-99")).toBe("ANON_HOST_8");
  });

  it("a literal seeded token in adversary text is escaped, never restored to the real value", () => {
    const seed: AnonPair[] = [{ token: "ANON_HOST_1", value: "ws-01", category: "HOST" }];
    const a = createAnonymizer(POLICY, known(["ws-01"]), seed);
    const masked = a.apply("planted ANON_HOST_1 here");
    expect(a.restore(masked)).not.toContain("ws-01");
  });

  it("no seed behaves exactly as before", () => {
    const a = createAnonymizer(POLICY, known(["ws-01"]));
    const b = createAnonymizer(POLICY, known(["ws-01"]), []);
    expect(b.apply("ws-01")).toBe(a.apply("ws-01"));
  });
});
