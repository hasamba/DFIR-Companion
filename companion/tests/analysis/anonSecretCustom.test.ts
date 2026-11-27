import { describe, it, expect } from "vitest";
import { expectLinearScan } from "../helpers/growth.js";
import {
  createAnonymizer,
  type AnonPolicy,
  type CustomEntity,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";
import { coverCustomSecrets, locateSecrets, redactToSentinel } from "../../src/analysis/anonSecretCustom.js";

// #2952: with secret redaction on, a custom entity whose value contains (or touches) a secret must
// be hidden WHOLE and one way — never partly in clear, never as a restorable token. Synthetic values
// only; secret-shaped fixtures are assembled at runtime so the publish scanner sees no literal.

const PW = ["pass", "word"].join("");
const SECRET = ["hunter2", "fake"].join("-");
const VALUE = `srv01:confidential?${PW}=${SECRET}`;
const R = "[REDACTED_SECRET]";
const S = "";
const [KEY_HEAD, KEY_TAIL] = ["BEGIN", "END"].map((edge) => `-----${edge} PRIVATE KEY-----`);

function policy(over: Partial<AnonPolicy> = {}, cats: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps: true,
    ...over,
    categories: {
      IP: true,
      EMAIL: false,
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
const known = (custom: CustomEntity[]): KnownEntities => ({
  hosts: [],
  accounts: [],
  internalDomains: [],
  custom,
});
const mask = (custom: CustomEntity[], text: string, p: AnonPolicy = policy()) => {
  const a = createAnonymizer(p, known(custom));
  const out = a.apply(text);
  return { out, back: a.restore(out), a };
};
const other = (value: string): CustomEntity => ({ value, category: "OTHER" });
const noFragments = (a: ReturnType<typeof createAnonymizer>, ...frags: string[]) => {
  for (const pair of a.pairs()) for (const f of frags) expect(pair.value).not.toContain(f);
  for (const d of a.discoveries()) for (const f of frags) expect(d.value).not.toContain(f);
};

describe("custom entity that contains a secret (#2952)", () => {
  for (const IP of [false, true]) {
    it(`hides the whole value one way (IP ${IP ? "on" : "off"})`, () => {
      const { out, back, a } = mask([other(VALUE)], `x ${VALUE} y`, policy({}, { IP }));
      expect(out).toBe(`x ${R} y`);
      expect(back).toBe(`x ${R} y`);
      expect(a.pairs()).toEqual([]);
      noFragments(a, "srv01", "confidential", SECRET);
    });
  }

  it("a custom value that starts where the secret ends is hidden with it", () => {
    const cred = ["abc1", "defgz/"].join("");
    const { out } = mask([other(":tail")], `Bearer ${cred}:tail z`);
    expect(out).toBe(`Bearer ${R} z`);
  });

  it("a key outside the custom value and the credential inside it", () => {
    const cred = ["abc1", "defgz"].join("");
    const { out, a } = mask([other(`${cred} tail`)], `Bearer ${cred} tail z`);
    expect(out).toBe(`Bearer ${R} z`);
    noFragments(a, cred, "tail");
  });

  it("a wildcard custom match running into a secret", () => {
    const custom: CustomEntity[] = [{ value: "srv0*", category: "OTHER", match: "pattern" }];
    const { out } = mask(custom, `x ${VALUE} y`);
    expect(out).not.toContain("srv01");
    expect(out).not.toContain("confidential");
    expect(out).not.toContain(SECRET);
  });

  it("a custom value that starts inside an IPv6 address and runs into a secret", () => {
    const text = `x [fd00:abcd::1]:${PW}=${SECRET} y`;
    const { out, a } = mask([other(`abcd::1]:${PW}=${SECRET}`)], text);
    expect(out).toBe(`x [${R} y`);
    noFragments(a, "fd00", "abcd", SECRET);
  });

  it("a public IPv6 address cut by the region is hidden even with public IPs visible", () => {
    const text = `x [2a01:4f8::5]:${PW}=${SECRET} y 2a01:4f8::5`;
    const { out } = mask([other(`4f8::5]:${PW}=${SECRET}`)], text, policy({ maskPublicIps: false }));
    expect(out).toBe(`x [${R} y 2a01:4f8::5`);
  });

  it("a forged IPv6 sentinel cannot hide the custom value from the secret pass", () => {
    const cred = ["abc12", "fake"].join("");
    const { out } = mask([other(`srv01?${PW}=${cred}`)], `srv01?${PW}=${cred} z`);
    expect(out).not.toContain("srv01");
    expect(out).not.toContain(cred);
  });

  for (const IP of [false, true])
    it(`a forged IPv6 sentinel beside the custom value changes nothing (IP ${IP ? "on" : "off"})`, () => {
      const p = policy({}, { IP });
      const F = String.fromCharCode(0xe000);
      expect(mask([other(VALUE)], `${F}${VALUE}${F} y`, p).out).toBe(`${R} y`);
      expect(mask([other("srv01")], `${F}srv01${F} y`, p).out).toBe("ANON_OTHER_1 y");
    });

  it("a custom value inside a private-key block leaves the block as it was", () => {
    const text = `${KEY_HEAD}\nabc srv01 def\n${KEY_TAIL} tail`;
    const { out, a } = mask([other("srv01")], text);
    expect(out).toBe(`${R} tail`);
    expect(a.pairs()).toEqual([]);
  });

  it("with secret redaction off the value is tokenized as before", () => {
    const { out, back } = mask([other(VALUE)], `x ${VALUE} y`, policy({ redactSecrets: false }));
    expect(out).toBe("x ANON_OTHER_1 y");
    expect(back).toBe(`x ${VALUE} y`);
  });

  it("other occurrences and untouched secrets keep today's output", () => {
    const text = `a ${VALUE} b srv01 c ${PW}=other9fake d`;
    const { out, back } = mask([other(VALUE), other("srv01")], text);
    expect(out).toBe(`a ${R} b ANON_OTHER_1 c ${PW}=${R} d`);
    expect(back).toBe(`a ${R} b srv01 c ${PW}=${R} d`);
  });

  it("JSON secrets keep their quotes when another line is covered", () => {
    const text = `{"${PW}": 123456, "k": 1}\n{"${PW}":"abcfake99"}\nx ${VALUE} y`;
    const { out } = mask([other(VALUE), other("abcfake99")], text);
    expect(out).toBe(`{"${PW}": "${R}", "k": 1}\n{"${PW}":"${R}"}\nx ${R} y`);
  });

  it("a chain of touching custom values joins the hidden region", () => {
    const cred = ["abc1", "defgz/"].join("");
    const { out } = mask([other(":aaa1-"), other("-bbb2:")], `Bearer ${cred}:aaa1--bbb2: z`);
    expect(out).toBe(`Bearer ${R} z`);
  });

  it("a literal placeholder in the input is not a way to keep a custom value in clear", () => {
    const { out } = mask([other("tail")], `x ${R}tail y`);
    expect(out).not.toContain("tail");
  });

  it("a USER value redacted this way teaches no token", () => {
    const custom: CustomEntity[] = [{ value: `jdoe:${PW}=${SECRET}`, category: "USER" }];
    const { out, a } = mask(custom, `login jdoe:${PW}=${SECRET} ok`, policy({}, { USER: true }));
    expect(out).toBe(`login ${R} ok`);
    noFragments(a, "jdoe", SECRET);
  });

  it("scales linearly with many secrets and custom matches", () => {
    const anon = createAnonymizer(policy(), known([other(VALUE), other("srv01")]));
    const line = `a ${VALUE} b srv01 c ${PW}=x1fake d\n`;
    expectLinearScan("secret+custom", (n) => anon.apply(line.repeat(n)), 200);
  });
});

describe("locating secrets in the clear text", () => {
  it("finds exact intervals and reproduces the quoted form", () => {
    const text = `{"k": 12, "a": "b"} t=xyz`;
    const red = `{"k": "${S}", "a": "b"} t=${S}`;
    const spans = locateSecrets(text, red, S);
    expect(spans?.map((s) => text.slice(s.exact.start, s.exact.end))).toEqual(["12", "xyz"]);
    expect(spans?.map((s) => s.form)).toEqual([`"${S}"`, S]);
  });

  it("bounds an ambiguous placement on both sides", () => {
    // The "-" between the two secrets can be either of two; the loose bounds cover both.
    const text = "a-b-c-d-e";
    const red = `a${S}-${S}e`;
    const spans = locateSecrets(text, red, S)!;
    expect(spans[0].exact).toEqual({ start: 1, end: 3 });
    expect(spans[0].loose).toEqual({ start: 1, end: 5 });
    expect(spans[1].loose).toEqual({ start: 4, end: 8 });
    expect(spans[1].sure).toEqual({ start: 6, end: 8 });
  });

  it("returns null when the redacted text cannot be lined up", () => {
    expect(locateSecrets("abc", `zz${S}`, S)).toBeNull();
  });

  it("fails closed when the text cannot be lined up and a custom value touches the change", () => {
    const text = "head srv01 secret tail";
    const red = `head srv01 ${S}X tail`; // not an interval replacement: no alignment exists
    const out = coverCustomSecrets(text, red, S, [{ start: 5, end: 12 }], []);
    expect(out).toBe(`head ${S} tail`);
    expect(coverCustomSecrets(text, red, S, [{ start: 0, end: 4 }], [])).toBe(red);
  });
});

describe("every redactor shape lines up without the fallback", () => {
  const key = ["Authori", "zation"].join("");
  const shapes = [
    `${PW}=${SECRET} and ${PW}: "${SECRET}" end`,
    `{"${PW}": 4242, "${PW}2": "${SECRET}", "list": ["a"], "api_key": ["${SECRET}", "b"]}`,
    `run.exe --${PW} ${SECRET} -u admin --token="${SECRET}"`,
    `https://admin:${SECRET}@db.corp.example/x`,
    `${key}: Bearer ${["abc1", "defgz"].join("")} and Bearer ${["q9", "rstuvw"].join("")}x`,
    `https://acct.blob.example/c?sv=2020&${["si", "g"].join("")}=${["abcdEFGH", "1234"].join("")}%3D&x=1`,
    `${KEY_HEAD}\nMIIBfake\n${KEY_TAIL} then ${PW}=${SECRET}`,
    `${["AK", "IA"].join("")}${"ABCDEFGHIJKLMNOP"} twice ${PW}=${SECRET}`,
    `a ${R} literal and ${PW}=${SECRET}`,
  ];
  for (const text of shapes)
    it(text.slice(0, 40), () => {
      const red = redactToSentinel(text, S);
      expect(red).toContain(S);
      const spans = locateSecrets(text, red, S);
      expect(spans).not.toBeNull();
      let rebuilt = "";
      let at = 0;
      for (const s of spans!) {
        rebuilt += text.slice(at, s.exact.start) + s.form;
        at = s.exact.end;
      }
      expect(rebuilt + text.slice(at)).toBe(red);
    });
});
