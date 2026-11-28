import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3030: a very short or digit-only ACCOUNT name ("CORP\12", "ab@" an internal domain) was masked and
// also saved as a discovery. On a later call the saved value came back as a custom value and cut a
// SID ("S-1-5-21-ANON_USER_1-…") or an address apart. #3014 stopped that for profile-path names; an
// account name now follows the same rule: masked in place, never saved.

const LOCAL = ["corp", "local"].join("."); // built at runtime: a synthetic internal domain
const KNOWN: KnownEntities = { hosts: [], accounts: [], internalDomains: [LOCAL] };
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
const upn = (user: string) => [user, LOCAL].join("@"); // built at runtime: no literal address
const LATER = `sid S-1-5-21-12-5-5-1001 from 10.12.0.5 user ab and 12, CORP\\12 and ${upn("ab")} then jdoe`;

describe("a short or digit-only account name is masked but never saved (#3030)", () => {
  it.each([["logon CORP\\12 ok"], [`mail ${upn("ab")} ok`], ["logon CORP\\ab ok"]])(
    "masks %s in place and saves no USER value for it",
    (text) => {
      const a = createAnonymizer(policy(), KNOWN);
      const out = a.apply(text);
      expect(out).toMatch(/ANON_USER_1/);
      expect(a.restore(out)).toBe(text);
      expect(a.discoveries().filter((d) => d.category === "USER")).toEqual([]);
    },
  );

  it("leaves a later call exactly as a fresh call would mask it", () => {
    const first = createAnonymizer(policy(), KNOWN);
    first.apply(`logon CORP\\12 and ${upn("ab")}`);
    const later = createAnonymizer(policy(), { ...KNOWN, custom: first.discoveries() });
    const fresh = createAnonymizer(policy(), KNOWN);
    expect(later.apply(LATER)).toBe(fresh.apply(LATER));
  });

  it("masks the user half behind a qualifier a saved value already masked, and restores it", () => {
    const first = createAnonymizer(policy(), KNOWN);
    first.apply(`logon CORP\\jdoe and ${upn("jdoe")}`);
    const later = createAnonymizer(policy(), { ...KNOWN, custom: first.discoveries() });
    const text = `later CORP\\zz, ${upn("zz")} and CORP\\12`;
    const out = later.apply(text);
    expect(out).not.toMatch(/zz|\\12/);
    expect(later.restore(out)).toBe(text);
  });

  it("keeps a suppressed account verbatim behind a saved qualifier", () => {
    const first = createAnonymizer(policy(), KNOWN);
    first.apply("logon CORP\\jdoe");
    const later = createAnonymizer(policy(), {
      ...KNOWN,
      custom: first.discoveries(),
      suppressed: ["CORP\\12"],
    });
    expect(later.apply("by CORP\\12")).toMatch(/\\12$/);
  });

  it("still saves an ordinary account name", () => {
    const a = createAnonymizer(policy(), KNOWN);
    a.apply("logon CORP\\jdoe ok");
    expect(a.discoveries()).toContainEqual({ value: "jdoe", category: "USER" });
  });
});
