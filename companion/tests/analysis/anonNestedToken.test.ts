import { describe, expect, it } from "vitest";
import {
  createAnonymizer,
  type AnonPolicy,
  type CustomEntity,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #2991: a pass that runs after the custom pass (accounts, emails, hosts, …) can match text that
// already holds a token this anonymizer minted — "ANON_OTHER_1@<domain>" reads as an email. The
// new token must stand for the ORIGINAL text, so restore() round-trips and discoveries() never
// persist a token-bearing value. Synthetic values only; addresses are built at runtime so the
// publish scan never sees a literal one.

const DOM = ["corp", "local"].join(".");
const at = (local: string, domain = DOM) => [local, domain].join("@");
const TOKEN = /ANON_[A-Z]+_\d+/;

function policy(maskPublicIps: boolean, cats: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps,
    categories: {
      IP: true,
      EMAIL: true,
      USER: false,
      HOST: false,
      DOMAIN: false,
      PATH: false,
      CMD: false,
      REG: false,
      CARD: false,
      PHONE: false,
      NATID: false,
      ...cats,
    },
  };
}
function known(custom: CustomEntity[], over: Partial<KnownEntities> = {}): KnownEntities {
  return { hosts: [], accounts: [], internalDomains: [], custom, ...over };
}
const other = (value: string): CustomEntity => ({ value, category: "OTHER" });

function roundTrip(
  input: string,
  mask: boolean,
  k: KnownEntities,
  cats: Partial<AnonPolicy["categories"]> = {},
  literalInInput = false,
) {
  const a = createAnonymizer(policy(mask, cats), k);
  const out = a.apply(input);
  expect(a.restore(out)).toBe(input);
  if (!literalInInput) for (const p of a.pairs()) expect(p.value).not.toMatch(TOKEN);
  return { a, out };
}

describe.each([true, false])("nested token before @domain (maskPublicIps=%s)", (mask) => {
  it("restores the issue's IPv6 custom group before @domain", () => {
    const input = "a " + at("Evtx::a00:5::1");
    const { out } = roundTrip(input, mask, known([other("Evtx::a00")]));
    expect(out).toBe("a ANON_EMAIL_1");
  });

  it("restores a plain custom value before @domain", () => {
    const { out } = roundTrip("a " + at("Evtx::a00"), mask, known([other("Evtx::a00")]));
    expect(out).toBe("a ANON_EMAIL_1");
  });

  it("restores a custom value in the middle of the local part", () => {
    const { out } = roundTrip("mail " + at("x.jdoe.y"), mask, known([other("jdoe")]));
    expect(out).toBe("mail ANON_EMAIL_1");
  });

  it("restores several custom values and punctuation in one local part, and two addresses", () => {
    const input = `${at("alpha.beta")} and ${at("beta-x")}`;
    const { out } = roundTrip(input, mask, known([other("alpha"), other("beta")]));
    expect(out).toBe("ANON_EMAIL_1 and ANON_EMAIL_2");
  });

  it("restores through the account pass when the domain is internal (USER on)", () => {
    const k = known([other("Evtx::a00")], { internalDomains: [DOM] });
    const { out } = roundTrip("a " + at("Evtx::a00"), mask, k, { USER: true });
    expect(out).not.toContain("Evtx");
    expect(out).not.toContain(DOM);
  });

  it("restores the two-level chain when the internal domain is suppressed", () => {
    const k = known([other("Evtx::a00")], { internalDomains: [DOM], suppressed: [DOM] });
    const { out } = roundTrip("a " + at("Evtx::a00"), mask, k, { USER: true });
    expect(out).not.toContain("Evtx");
  });

  it("keeps the custom value masked when the real address is suppressed", () => {
    const input = "a " + at("Evtx::a00");
    const { out } = roundTrip(input, mask, known([other("Evtx::a00")], { suppressed: [at("Evtx::a00")] }));
    expect(out).not.toContain("Evtx");
    expect(out).not.toContain("a00");
  });

  it("leaves a planted literal token before @domain as it is today", () => {
    for (const lit of ["ANON_HOST_7", "anon_host_7"]) {
      const input = "a " + at(lit);
      const { a, out } = roundTrip(input, mask, known([]), {}, true);
      expect(out).toBe("a ANON_EMAIL_1");
      expect(a.pairs().map((p) => [p.token, p.value, p.category])).toEqual([
        ["ANON_EMAIL_1", at(lit), "EMAIL"],
      ]);
    }
  });

  it("round-trips across two apply() calls and a standalone repeat of the custom value", () => {
    const k = known([other("Evtx::a00")], { internalDomains: [DOM] });
    const a = createAnonymizer(policy(mask, { USER: true }), k);
    const first = "a " + at("Evtx::a00");
    const second = "then Evtx::a00 alone and " + at("Evtx::a00");
    const o1 = a.apply(first);
    const o2 = a.apply(second);
    expect(a.restore(o1)).toBe(first);
    expect(a.restore(o2)).toBe(second);
    expect(o2).not.toContain("Evtx");
    for (const p of a.pairs()) expect(p.value).not.toMatch(TOKEN);
  });

  it("persists the real address as a discovery, which round-trips when re-injected", () => {
    const input = "a " + at("Evtx::a00");
    const { a } = roundTrip(input, mask, known([other("Evtx::a00")]));
    const disc = a.discoveries();
    expect(disc).toContainEqual({ value: at("Evtx::a00"), category: "EMAIL" });
    roundTrip(input, mask, known(disc));
  });
});

describe("unchanged pins", () => {
  it("keeps 2019:fd00::1 unmasked with public masking off", () => {
    const a = createAnonymizer(policy(false), known([]));
    expect(a.apply("x 2019:fd00::1 y")).toBe("x 2019:fd00::1 y");
  });

  it("keeps an ordinary address one EMAIL token", () => {
    const { out } = roundTrip("from " + at("jdoe"), true, known([]));
    expect(out).toBe("from ANON_EMAIL_1");
  });
});
