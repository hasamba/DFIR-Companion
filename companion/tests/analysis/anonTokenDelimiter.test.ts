import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  isAnonToken,
  neutralizeAnonTokens,
  type AnonPolicy,
  type CustomEntity,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";
import { TOKEN_DELIMITER, tokenEnds } from "../../src/analysis/anonTokenLiterals.js";
import { previewDiff } from "../../src/analysis/ai/previewDiff.js";

// #2992 — a token placed directly before a digit read back as a different token: "ANON_IP_1"
// followed by "0" is "ANON_IP_10". Such a token is now followed by a delimiter that restore()
// consumes. Synthetic values only.

const D = TOKEN_DELIMITER;
function policy(maskPublicIps: boolean, IP = true): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps,
    categories: {
      IP,
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
const known = (over: Partial<KnownEntities> = {}): KnownEntities => ({
  hosts: ["srv01"],
  accounts: [],
  internalDomains: [],
  ...over,
});
const make = (mask: boolean, over: Partial<KnownEntities> = {}, IP = true) =>
  createAnonymizer(policy(mask, IP), known(over));
// A base64 blob, built at runtime.
const BLOB = ["SQBFAFgAIAAo", "AE4AZQB3AC0ATwBi"].join("");

describe.each([true, false])("a digit right after a token (maskPublicIps=%s) (#2992)", (mask) => {
  it("an IPv6 token before a digit gets the delimiter and round-trips", () => {
    const a = make(mask);
    const s = "fd00::1fd00::2";
    const out = a.apply(s);
    expect(out).toBe(`ANON_IP_1${D}0::2`);
    expect(a.restore(out)).toBe(s);
  });

  it("restores the right address when ANON_IP_10 exists too", () => {
    const a = make(mask);
    const ips = Array.from({ length: 10 }, (_, i) => `fd00::${(i + 1).toString(16)}`).join(" ");
    const s = `${ips} fd00::bfd00::10`;
    const out = a.apply(s);
    expect(out).toContain(`ANON_IP_11${D}0::10`);
    expect(out).toContain("ANON_IP_10 ");
    expect(a.restore(out)).toBe(s);
    // The AI quoting the glued text back: the right address, not ANON_IP_10's.
    expect(a.restore(`see ANON_IP_11${D}0::10`)).toBe("see fd00::bfd00::10");
  });

  it("an encoded command blob with padding before a digit", () => {
    const a = make(mask);
    const s = `powershell -enc ${BLOB}==5`;
    const out = a.apply(s);
    expect(out).toBe(`powershell -enc ANON_CMD_1${D}5`);
    expect(a.restore(out)).toBe(s);
  });

  it("a delimiter already in the input after a token survives the round trip", () => {
    const a = make(mask);
    for (const s of [`srv01${D}5`, `srv01${D}${D}5`, `srv01${D}x`, `fd00::1${D}5`, `x fd00::1fd0${D}0::2`]) {
      expect(a.restore(a.apply(s))).toBe(s);
    }
    expect(a.apply(`srv01${D}5`)).toBe(`ANON_HOST_1${D}${D}5`);
    expect(a.apply(`srv01${D}x`)).toBe(`ANON_HOST_1${D}x`); // not followed by a digit: as is
  });

  it("a planted token followed by the delimiter and a digit stays as it is", () => {
    const a = make(mask);
    const s = `ANON_IP_1${D}0 fd00::1`;
    const out = a.apply(s);
    expect(a.restore(out)).toBe(s);
    expect(a.restore(`ANON_IP_7${D}0`)).toBe(`ANON_IP_7${D}0`); // unknown: left visible
  });

  it("a value returned as it is (suppressed) gets no delimiter", () => {
    const a = make(mask, { suppressed: ["fd00::1fd0"] });
    expect(a.apply("fd00::1fd00::2")).toBe("fd00::1fd00::2");
  });

  it("2019:fd00::1 is unchanged", () => {
    const a = make(mask);
    expect(a.apply("2019:fd00::1")).toBe(mask ? "ANON_EXTIP_1" : "2019:fd00::1");
  });

  it("a set-aside custom group before a digit", () => {
    const custom: CustomEntity[] = [{ value: "fd00::1fd0", category: "HOST" }];
    const a = make(mask, { custom });
    const s = "fd00::1fd00::2";
    const out = a.apply(s);
    expect(out).toMatch(new RegExp(`^ANON_[A-Z]+_\\d+${D}0::2$`));
    expect(a.restore(out)).toBe(s);
  });

  it("a token beside an address that comes back as it is and starts with a digit", () => {
    const a = make(false, { internalDomains: ["lab.example"] });
    const s = "lab.example2001:db8::1 srv012001:db8::2";
    const out = a.apply(s);
    expect(out).toBe(`ANON_DOMAIN_1${D}2001:db8::1 ANON_HOST_1${D}2001:db8::2`);
    expect(a.restore(out)).toBe(s);
  });

  it("a token before an address returned as it is that starts with a digit", () => {
    const a = make(mask, { suppressed: ["0::ffff:a00:5"] });
    const s = "fd00::1fd00::ffff:a00:5";
    expect(a.restore(a.apply(s))).toBe(s);
  });
});

describe("the internal marks never change what is masked (#2992)", () => {
  it("a private-use character in the input is kept and cannot forge a mark", () => {
    const a = make(true);
    for (const ch of ["\uE002", "\uE003"]) {
      const s = `srv01${ch}5 fd00::1fd0${ch}0::2`;
      const out = a.apply(s);
      expect(out).toContain(`ANON_HOST_1${ch}5`);
      expect(a.restore(out)).toBe(s);
    }
  });

  it("a site's token is spliced as an alias of the same shape and put back at the end", () => {
    const ends = tokenEnds("ANON_(?:IP|HOST)_\\d+", ["IP", "HOST"]);
    const text = "fd00::1fd00::2";
    ends.start(text);
    const spliced = ends.ended("ANON_IP_1", "fd00::1fd0", 0, 10, text);
    expect(spliced).toMatch(/^ANON_[A-Z]{2}_1$/);
    expect(spliced).not.toBe("ANON_IP_1");
    // A later pass swallowed the alias into a value: the value gets the real text back.
    const toReal = new Map([
      ["ANON_IP_1", "fd00::1fd0"],
      ["ANON_HOST_1", `${spliced}0x`],
    ]);
    expect(ends.finish(`${spliced}0::2`, toReal)).toBe(`ANON_IP_1${D}0::2`);
    expect(toReal.get("ANON_HOST_1")).toBe("fd00::1fd00x"); // its real text, as #2991 does
  });

  it("the preview diff lines up a delimiter that was already in the input", () => {
    const a = make(true);
    const clear = `srv01${D}5 fd00::1fd00::2`;
    const masked = a.apply(clear);
    const diff = previewDiff(clear, masked, a, { maskPublicIps: true });
    expect(diff.mode).toBe("text");
    expect(diff.marks).toHaveLength(2);
  });
});

describe("token readers consume the delimiter (#2992)", () => {
  it("neutralizeAnonTokens and isAnonToken", () => {
    expect(neutralizeAnonTokens(`ANON_IP_1${D}0::2`, "#")).toBe("#0::2");
    expect(isAnonToken(`ANON_IP_1${D}0`)).toBe(true);
  });

  it("the preview diff lines the text up", () => {
    const a = make(true);
    const clear = "a fd00::1fd00::2 b";
    const masked = a.apply(clear);
    const diff = previewDiff(clear, masked, a, { maskPublicIps: true });
    expect(diff.mode).toBe("text");
    expect(diff.marks).toHaveLength(1);
    expect(clear.slice(...diff.marks[0].c)).toBe("fd00::1fd0");
    expect(masked.slice(...diff.marks[0].m)).toBe("ANON_IP_1");
  });
});
