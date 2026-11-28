import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  deriveKnownEntities,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";
import { validatePatternEntity } from "../../src/analysis/anonPatterns.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

// #3009: a custom value, known host or internal domain of ~13,000 letters was compiled into one regex
// literal, and V8 overflowed the stack on its first use — so every masked call threw, even on
// unrelated text. A long timeline asset made it case-wide. A long value is now matched in chunks.

const NONE: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };
function policy(): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps: true,
    categories: {
      IP: true,
      EMAIL: true,
      USER: true,
      HOST: true,
      DOMAIN: true,
      PATH: true,
      CMD: true,
      REG: true,
      CARD: false,
      PHONE: false,
      NATID: false,
    },
  };
}
const LONG = "abcdefghij".repeat(1300); // 13,000 letters

describe("a very long exact value never overflows the stack (#3009)", () => {
  it("masks a long custom value whole, restores it, and leaves unrelated text alone", () => {
    const a = createAnonymizer(policy(), { ...NONE, custom: [{ value: LONG, category: "OTHER" }] });
    expect(a.apply("hello world")).toBe("hello world");
    const text = `x ${LONG.toUpperCase()} y`;
    const out = a.apply(text);
    expect(out).toBe("x ANON_OTHER_1 y");
    expect(a.restore(out).toLowerCase()).toBe(text.toLowerCase());
  });

  it("masks a long known host and a long internal domain whole", () => {
    const host = `ws-${LONG}`;
    const domain = `${LONG}.lab`;
    const a = createAnonymizer(policy(), { ...NONE, hosts: [host], internalDomains: [domain] });
    expect(a.apply(`on ${host} in ${domain} ok`)).toBe("on ANON_HOST_1 in ANON_DOMAIN_1 ok");
  });

  it("keeps the whole-word boundary of a long value", () => {
    const a = createAnonymizer(policy(), { ...NONE, custom: [{ value: LONG, category: "OTHER" }] });
    expect(a.apply(`${LONG}s x${LONG}`)).toBe(`${LONG}s x${LONG}`);
  });

  it("matches across a chunk boundary case-insensitively (Kelvin sign and k)", () => {
    const value = "a".repeat(255) + "k" + "b".repeat(300);
    const typed = "A".repeat(255) + "K" + "B".repeat(300);
    const a = createAnonymizer(policy(), { ...NONE, custom: [{ value, category: "OTHER" }] });
    expect(a.apply(`x ${typed} y`)).toBe("x ANON_OTHER_1 y");
  });

  it("keeps every masked call working when a long asset sits in the forensic timeline", () => {
    const s = emptyState("c1");
    s.forensicTimeline = [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00Z",
        description: "logon",
        asset: LONG,
        severity: "High",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
      },
    ];
    const a = createAnonymizer(policy(), deriveKnownEntities(s));
    expect(a.apply("the user ran whoami")).toBe("the user ran whoami");
  });

  it("refuses a pattern longer than the cap, and a stored one masks its literal spelling", () => {
    const pattern = `${LONG}*`;
    expect(validatePatternEntity({ value: pattern, category: "HOST", match: "pattern" })).toMatch(/at most/);
    expect(validatePatternEntity({ value: "prod-*", category: "HOST", match: "pattern" })).toBeNull();
    const a = createAnonymizer(policy(), {
      ...NONE,
      custom: [{ value: pattern, category: "HOST", match: "pattern" }],
    });
    expect(a.apply(`hello ${LONG}x`)).toBe(`hello ${LONG}x`);
    expect(a.apply(`hello ${pattern} end`)).toContain("ANON_HOST_1");
  });
});
