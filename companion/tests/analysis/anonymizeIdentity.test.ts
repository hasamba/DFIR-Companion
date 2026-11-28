import { describe, expect, it } from "vitest";
import {
  createAnonymizer,
  type AnonPair,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #2657: the case's saved masking map is an identity table. It decides WHICH token a masked value gets,
// never WHETHER a value is masked.

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
const known = (hosts: string[], suppressed: string[] = []): KnownEntities => ({
  hosts,
  accounts: [],
  internalDomains: [],
  suppressed,
});
const saved: AnonPair[] = [
  { token: "ANON_HOST_7", value: "ws-02", category: "HOST" },
  { token: "ANON_HOST_3", value: "dc-01", category: "HOST" },
];

describe("createAnonymizer with the case's saved map (#2657)", () => {
  it("a masked value gets its saved token, and restores", () => {
    const anon = createAnonymizer(POLICY, known(["ws-02"]), [], saved);
    expect(anon.apply("login on ws-02")).toBe("login on ANON_HOST_7");
    expect(anon.restore("ANON_HOST_7 again")).toBe("ws-02 again");
  });

  it("a new value numbers above every saved token", () => {
    const anon = createAnonymizer(POLICY, known(["fs-09"]), [], saved);
    expect(anon.apply("share on fs-09")).toBe("share on ANON_HOST_8");
  });

  it("the map adds no masking: a saved value the current entities do not name stays clear", () => {
    const anon = createAnonymizer(POLICY, known([]), [], saved);
    expect(anon.apply("login on ws-02")).toBe("login on ws-02");
  });

  it("a suppressed value stays clear even with a saved token", () => {
    const anon = createAnonymizer(POLICY, known(["ws-02"], ["ws-02"]), [], saved);
    expect(anon.apply("login on ws-02")).toBe("login on ws-02");
  });

  it("pairs() lists only what this anonymizer used or minted, never unused saved entries", () => {
    const anon = createAnonymizer(POLICY, known(["ws-02", "fs-09"]), [], saved);
    anon.apply("ws-02 and fs-09");
    expect(
      anon
        .pairs()
        .map((p) => p.token)
        .sort(),
    ).toEqual(["ANON_HOST_7", "ANON_HOST_8"]);
    expect(
      anon
        .discoveries()
        .map((d) => d.value)
        .sort(),
    ).toEqual(["fs-09", "ws-02"]);
  });

  it("a literal saved token in the evidence is escaped, never confused with the saved value", () => {
    const anon = createAnonymizer(POLICY, known(["ws-02"]), [], saved);
    const masked = anon.apply("ANON_HOST_7 attacked ws-02");
    expect(masked.match(/ANON_HOST_7/g)).toHaveLength(1);
    // An escaped literal restores as itself (#3001), never as the real host (#2569).
    expect(anon.restore(masked)).toBe("ANON_HOST_7 attacked ws-02");
    expect(anon.restore(masked)).not.toContain("fs-09");
  });

  it("the same holds across two apply calls and for a lowercase literal", () => {
    const anon = createAnonymizer(POLICY, known(["ws-02"]), [], saved);
    const first = anon.apply("anon_host_7 seen");
    const second = anon.apply("then ws-02");
    expect(second).toBe("then ANON_HOST_7");
    expect(anon.restore(first)).toBe("anon_host_7 seen");
    expect(anon.restore(first)).not.toContain("ws-02");
  });
});
