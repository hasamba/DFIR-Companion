import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3070: a learned user name glued to an address that starts with a digit ("someuser0::2", where "0::2"
// is never masked) was no whole word, so the bare-name pass skipped it and the name went out in clear.
// The name is now masked when what follows it is a whole address; any other digit after it ("name0",
// a year, a version, a time) still leaves it alone, as before.

const NONE: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };
function policy(maskPublicIps: boolean): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: {
      IP: true,
      EMAIL: true,
      USER: true,
      HOST: true,
      DOMAIN: true,
      PATH: true,
      CMD: true,
      REG: true,
      CARD: true,
      PHONE: true,
      NATID: true,
    },
  };
}
const anon = (usernames: string[], pm = false) => createAnonymizer(policy(pm), { ...NONE, usernames });
const dotted = (...parts: number[]) => parts.join("."); // built at runtime: no literal address in source

describe("a learned user name glued to a digit-led address (#3070)", () => {
  for (const pm of [false, true]) {
    it(`masks the name and keeps the unmasked tail (public masking ${pm ? "on" : "off"})`, () => {
      const a = anon(["someuser"], pm);
      for (const text of ["x someuser0::2", "someuser0::2 y", "x someuser1:: end", "x someuser0::2."]) {
        const out = a.apply(text);
        expect(out).not.toMatch(/someuser/i);
        expect(out).toContain(text.replace(/^.*someuser/, "").split(" ")[0]); // the tail stays as it is
        expect(a.restore(out)).toBe(text);
      }
      expect(a.apply("x someuser0::2")).toMatch(/^x ANON_USER_1·0::2$/);
    });
  }

  it("keeps the token readable as itself when ten or more users are known", () => {
    const names = Array.from({ length: 12 }, (_, i) => `user${String.fromCharCode(97 + i)}x`);
    const a = anon(names);
    const all = names.join(" ");
    a.apply(all); // mint ANON_USER_1..12
    const text = `x ${names[0]}0::2 and ${names[0]}1::`;
    const out = a.apply(text);
    expect(out).not.toMatch(/userax/i);
    expect(a.restore(out)).toBe(text);
    expect(a.restore(a.apply(all))).toBe(all);
  });

  // The internal address after the name gets its own token too (#3071).
  it("masks a name glued to an IPv4 address", () => {
    const a = anon(["someuser"]);
    const text = `x someuser${dotted(10, 0, 0, 5)} y`;
    const out = a.apply(text);
    expect(out).not.toMatch(/someuser/i);
    expect(out).toBe("x ANON_USER_1ANON_IP_1 y");
    expect(a.restore(out)).toBe(text);
  });

  it("leaves a name followed by digits that are no address as it was", () => {
    const a = anon(["someuser"]);
    for (const text of [
      "x someuser0 y",
      "x someuser2019 y",
      "x someuser0: y",
      "x someuser10:30:00 y",
      "x someuser00:11:22:33:44:55 y",
      "x someuser1.2.3 y",
      `x someuser${dotted(1, 2, 3, 4, 5)} y`,
      "x someuser0x1f y",
      "x someuser1::2abcz y",
    ])
      expect(a.apply(text)).toBe(text);
  });

  it("keeps a maskable tail masked and a public address clear with public masking off", () => {
    const a = anon(["someuser"]);
    expect(a.apply("x 2019:fd00::1")).toBe("x 2019:fd00::1");
    const out = a.apply("x someuser2019:fd00::1");
    expect(out).not.toContain("fd00::1");
    expect(a.restore(out)).toBe("x someuser2019:fd00::1");
  });

  it("never masks a suppressed name glued to an address", () => {
    const a = createAnonymizer(policy(false), { ...NONE, usernames: ["someuser"], suppressed: ["someuser"] });
    expect(a.apply("x someuser0::2")).toBe("x someuser0::2");
  });
});
