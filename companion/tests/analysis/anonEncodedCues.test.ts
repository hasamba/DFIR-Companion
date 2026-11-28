import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3060: an encoded command after a JSON `\n` or glued to a number, an address glued after the
// blob's padding, a keyed value swallowing the registry command after it, and an e-mail domain with
// `_` or a number glued on (also with e-mail masking off). Values are synthetic and built at runtime.
const BLOB = ["SQBFAFgAIAAo", "AE4AZQB3AC0ATwBiAGoAZQBjAHQA"].join("");
const PW = ["Hunt", "er2", "Value77"].join("");
const IP = ["10", "0", "0", "5"].join(".");
const AT = "@";
const DOM = ["corp", "local"].join(".");
const NL = "\\n"; // a JSON-escaped newline: a backslash and an n

function policy(over: Partial<AnonPolicy["categories"]> = {}, maskPublicIps = true): AnonPolicy {
  const categories = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true };
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: { ...categories, CMD: true, REG: true, CARD: true, PHONE: true, NATID: true, ...over },
  };
}
function run(text: string, over: Partial<AnonPolicy["categories"]> = {}, maskPublicIps = true) {
  const an = createAnonymizer(policy(over, maskPublicIps), {
    hosts: [],
    accounts: [],
    internalDomains: [DOM],
    usernames: ["jdoe"],
  });
  const out = an.apply(text);
  const held = an.pairs().map((p) => p.value);
  return { out, back: an.restore(out), held };
}

describe("an encoded command after a JSON newline or a number (#3060)", () => {
  for (const pm of [true, false]) {
    it(`gives the blob a CMD token (maskPublicIps=${pm})`, () => {
      for (const text of [
        `{"m":"ab${NL}-enc ${BLOB}"}`,
        `{"m":"ab${NL}FromBase64String('${BLOB}')"}`,
        `{"m":"x${NL}-EncodedCommand ${BLOB}"}`,
        `ran 1-enc ${BLOB} x`,
      ]) {
        const r = run(text, {}, pm);
        expect(r.out).toMatch(/ANON_CMD_\d/);
        expect(r.out).not.toContain(BLOB);
        expect(r.back).toBe(text);
      }
    });
  }

  it("still masks the word before the JSON newline as it did", () => {
    const r = run(`{"m":"ab${NL}-enc ${BLOB}"}`);
    expect(r.out).not.toMatch(/\bab\\n/);
  });

  it("keeps real accounts that start with n, t or r masked", () => {
    for (const user of ["nancy", "tsmith", "rjones"]) {
      const r = run(`logon CORP\\${user} ok`);
      expect(r.out).not.toContain(user);
      expect(r.back).toBe(`logon CORP\\${user} ok`);
    }
  });

  it("does not read a cue inside a word", () => {
    const r = run(`ran x-enc ${BLOB} y`);
    expect(r.out).not.toMatch(/ANON_CMD_\d/);
  });
});

describe("an address glued after an encoded blob (#3060)", () => {
  for (const pm of [true, false]) {
    it(`masks the address (maskPublicIps=${pm})`, () => {
      for (const text of [
        `ran -enc ${BLOB}==${IP} x`,
        `ran 1-enc ${BLOB}=${IP} x`,
        `-enc ${BLOB}==${IP}23456789|x`,
      ]) {
        const r = run(text, {}, pm);
        expect(r.out).not.toContain(BLOB);
        expect(r.out).not.toContain(IP);
        expect(r.back).toBe(text);
      }
    });
  }

  it("keeps a number after the padding readable as itself", () => {
    const text = `-enc ${BLOB}==5 x`;
    const r = run(text);
    expect(r.out).toMatch(/ANON_CMD_1(?:==|\u00B7)5 x/);
    expect(r.back).toBe(text);
  });
});

describe("a keyed value before a registry command (#3060)", () => {
  it("hides the value the command writes one way", () => {
    for (const text of [
      `x password=v|sp HKLM:\\x DefaultPassword '${PW}'`,
      `password=v|Set-ItemProperty HKLM:\\x -Name DefaultPassword -Value '${PW}'`,
    ]) {
      const r = run(text);
      expect(r.out).not.toContain(PW);
      expect(r.held.some((v) => v.includes(PW))).toBe(false);
    }
  });

  it("hides a blob after a registry value when a later key is redacted", () => {
    const text = `sp HKLM:\\x DefaultPassword "C:\\Users\\jdoe FromBase64String(""${BLOB}"")": password= Set-ItemProperty HKLM:\\x -Name DefaultPassword -Value 'v'`;
    expect(run(text).out).not.toContain(BLOB);
  });
});

describe("an e-mail domain with text glued after its TLD (#3060)", () => {
  it("masks the domain with an underscore glued on", () => {
    for (const text of [
      `mail jdoe${AT}${DOM}_x ok`,
      `mail zed${AT}${DOM}_x ok`,
      `mail bob${AT}example.com_x ok`,
    ]) {
      const r = run(text);
      expect(r.out).not.toContain(DOM);
      expect(r.out).not.toContain("example.com");
      expect(r.back).toBe(text);
    }
  });

  it("masks a glued internal address as an account with e-mail masking off", () => {
    for (const text of [`mail jdoe${AT}${DOM}0|x`, `mail jdoe${AT}${DOM}_x`]) {
      const r = run(text, { EMAIL: false });
      expect(r.out).not.toContain(DOM);
      expect(r.back).toBe(text);
    }
  });

  it("leaves an external address alone with e-mail masking off", () => {
    const text = `mail bob${AT}example.com0 x`;
    expect(run(text, { EMAIL: false }).out).toContain("example.com");
  });
});

describe("a suppressed encoded blob (#3060)", () => {
  for (const pm of [true, false]) {
    it(`shows only the blob; an address glued after it keeps its token (maskPublicIps=${pm})`, () => {
      for (const text of [`x -enc ${BLOB}==${IP} y`, `x -enc ${BLOB}=${IP} y`, `x 1-enc ${BLOB}==${IP} y`]) {
        const an = createAnonymizer(policy({}, pm), {
          hosts: [],
          accounts: [],
          internalDomains: [DOM],
          suppressed: [BLOB],
        });
        const out = an.apply(text);
        expect(out).toContain(BLOB);
        expect(out).not.toContain(IP);
        expect(an.restore(out)).toBe(text);
      }
    });
  }
});

describe("a second registry write later on the same line (#3060)", () => {
  it("is read after the first one", () => {
    const pw3 = ["Zq9", "pw", "Q44"].join("");
    const text = `sp HKLM:\\x DefaultPassword '${PW}' {"CommandLine":"powershell sp HKLM:\\\\x DefaultPassword ${pw3}"}`;
    const r = run(text);
    expect(r.out).not.toContain(PW);
    expect(r.out).not.toContain(pw3);
    expect(r.held.some((v) => v.includes(pw3))).toBe(false);
  });
});
