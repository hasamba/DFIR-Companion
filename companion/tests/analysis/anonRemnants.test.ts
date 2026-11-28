import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3067: the rest of a profile name after a redacted value, a JSON-doubled DOMAIN\\user, a dangling
// `''` in a quoted registry value, and an IPv4 address glued after an encoded blob without padding.
// Values are synthetic and built at runtime.
const BLOB = ["SQBFAFgAIAAo", "AE4AZQB3AC0ATwBi"].join("");
const IP = ["10", "0", "0", "5"].join(".");
const PUB = ["8", "8", "8", "8"].join(".");
const BS = "\\";
const PROFILE = ["C:", "Users", "jdoe"].join(BS);
const SECRET = ["[REDACTED", "SECRET]"].join("_");

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
    hosts: ["srv01"],
    accounts: ["jdoe"],
    internalDomains: [["corp", "local"].join(".")],
  });
  const out = an.apply(text);
  const held = an.pairs().map((p) => p.value);
  return { out, back: an.restore(out), held };
}

describe("the rest of a profile name after a redacted value (#3067)", () => {
  for (const pm of [true, false]) {
    it(`masks what the profile name held, the value stays one way (maskPublicIps=${pm})`, () => {
      for (const text of [
        `New-ItemProperty HKLM:${BS}x -Name DefaultPassword -Value ${PROFILE}·0 jdoe0::2`,
        `sp HKLM:${BS}x DefaultPassword ${PROFILE} x jdoe0::2 y`,
      ]) {
        const { out, held } = run(text, {}, pm);
        expect(out).toContain(SECRET);
        expect(out).not.toMatch(/jdoe| x /);
        expect(out).toMatch(/ANON_USER_\d+::2/);
        expect(held.some((v) => v.includes("Users"))).toBe(false);
      }
    });
  }
  it("leaves a value that ends at the profile name's own stop alone", () => {
    const { out } = run(`sp HKLM:${BS}x DefaultPassword '${PROFILE}' next`);
    expect(out).toBe(`sp HKLM:${BS}x DefaultPassword '${SECRET}' next`);
  });
  it("keeps an encoded blob in the rest its own CMD token", () => {
    const { out } = run(
      `New-ItemProperty HKLM:${BS}x -Name DefaultPassword -Value ${PROFILE}\u00B70 ran -enc ${BLOB} x`,
    );
    expect(out).toMatch(/\[REDACTED_SECRET\] ANON_USER_\d+ ANON_CMD_\d+ ANON_USER_\d+$/);
    expect(out).not.toContain(BLOB);
    expect(out).not.toContain("jdoe");
  });
  it("still masks a profile path that holds no secret as before", () => {
    const { out, back } = run(`New-ItemProperty HKLM:${BS}x -Name Updater -Value ${PROFILE} x jdoe0::2`);
    expect(out).toBe(`New-ItemProperty HKLM:${BS}x -Name Updater -Value C:${BS}Users${BS}ANON_USER_1::2`);
    expect(back).toBe(`New-ItemProperty HKLM:${BS}x -Name Updater -Value ${PROFILE} x jdoe0::2`);
  });
});

describe("an account written with a JSON-doubled backslash (#3067)", () => {
  it("masks both halves and keeps the doubled separator", () => {
    for (const user of ["zed", "jdoe"]) {
      const text = `{"m":"a CORP${BS}${BS}${user} ok"}`;
      const { out, back } = run(text);
      expect(out).toMatch(/^\{"m":"a ANON_DOMAIN_\d+\\\\ANON_USER_\d+ ok"\}$/);
      expect(back).toBe(text);
    }
  });
  it("never saves the qualifier, so a seeded call restores an internal domain as it was", () => {
    const text = `a CORP${BS}${BS}zed ok x jdoe@${["corp", "local"].join(".")}1`;
    const first = createAnonymizer(policy(), {
      hosts: [],
      accounts: ["jdoe"],
      internalDomains: [["corp", "local"].join(".")],
    });
    first.apply(text);
    const custom = first.discoveries();
    expect(custom.map((d) => d.value)).not.toContain("CORP");
    const seeded = createAnonymizer(policy(), {
      hosts: [],
      accounts: ["jdoe"],
      internalDomains: [["corp", "local"].join(".")],
      custom,
    });
    expect(seeded.restore(seeded.apply(text))).toBe(text);
  });
  it("leaves an address before a doubly escaped line break to the e-mail pass", () => {
    const text = `{"m":"ab@${["corp", "local"].join(".")}${BS}${BS}nnext ok"}`;
    const { out, back } = run(text);
    expect(out).toBe(`{"m":"ANON_USER_1@ANON_DOMAIN_1${BS}${BS}nnext ok"}`);
    expect(back).toBe(text);
  });
  it("leaves doubled paths, hives and files alone", () => {
    for (const text of [
      `{"p":"C:${BS}${BS}Windows${BS}${BS}System32${BS}${BS}cmd.exe"}`,
      `{"k":"HKLM${BS}${BS}SOFTWARE"}`,
      `{"p":"Users${BS}${BS}Public"}`,
      `{"f":"Temp${BS}${BS}evil.exe"}`,
    ]) {
      expect(run(text).out).toBe(text);
    }
  });
});

describe("a quoted registry value with a dangling '' (#3067)", () => {
  it("hides the word after the dangling quote with the value", () => {
    for (const [text, rest] of [
      [`sp HKLM:${BS}x DefaultPassword 'a''tail`, ""],
      [`sp HKLM:${BS}x DefaultPassword 'a''tail next`, " next"],
      [`Set-ItemProperty HKLM:${BS}x -Name DefaultPassword -Value 'a''tail; x`, "; x"],
    ]) {
      const { out, held } = run(text);
      expect(out).not.toContain("tail");
      expect(out.endsWith(`${SECRET}${rest}`)).toBe(true);
      expect(held).not.toContain("tail");
    }
  });
  it("keeps a closed '' value and the old reading of an unclosed one", () => {
    expect(run(`sp HKLM:${BS}x DefaultPassword 'a''b' next`).out).toBe(
      `sp HKLM:${BS}x DefaultPassword '${SECRET}' next`,
    );
    expect(run(`sp HKLM:${BS}x DefaultPassword 'abc tail`).out).toBe(
      `sp HKLM:${BS}x DefaultPassword '${SECRET} tail`,
    );
  });
  it("keeps a word the closed part held hidden (`'my jdoe;x''tail`)", () => {
    const { out } = run(`sp HKLM:${BS}x DefaultPassword 'my jdoe;x''tail ${IP}`);
    expect(out).not.toMatch(/jdoe|tail|my /);
  });
});

describe("an IPv4 address glued after an encoded blob without padding (#3067)", () => {
  for (const pm of [true, false]) {
    it(`hides the address whole with the blob (maskPublicIps=${pm})`, () => {
      for (const ip of [IP, PUB]) {
        for (const glue of ["", "x"]) {
          const text = `ran -enc ${BLOB}${glue}${ip} y`;
          const { out, back } = run(text, {}, pm);
          expect(out).toBe("ran -enc ANON_CMD_1 y");
          expect(back).toBe(text);
        }
      }
    });
  }
  it("does so with the IP category off and after a short blob", () => {
    expect(run(`ran -enc ${BLOB}${IP} y`, { IP: false }).out).toBe("ran -enc ANON_CMD_1 y");
    expect(run(`ran -enc ${BLOB.slice(0, 15)}${IP} y`).out).toBe("ran -enc ANON_CMD_1 y");
  });
  it("leaves a padded blob and a blob before plain text as they were", () => {
    expect(run(`ran -enc ${BLOB}==${IP} y`).out).toMatch(/^ran -enc ANON_CMD_1==ANON_IP_\d+ y$/);
    expect(run(`ran -enc ${BLOB}5.x y`).out).toBe("ran -enc ANON_CMD_1.x y");
  });
});
