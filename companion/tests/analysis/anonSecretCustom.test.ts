import { describe, it, expect } from "vitest";
import { expectLinearScan } from "../helpers/growth.js";
import {
  createAnonymizer,
  type AnonPolicy,
  type CustomEntity,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";
import { coverCustomSecrets, locateSecrets, redactToSentinel } from "../../src/analysis/anonSecretCustom.js";
import { previewDiff } from "../../src/analysis/ai/previewDiff.js";

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

  it("a word-glued address ending in :: cut by the region is hidden whole (#2953)", () => {
    const text = `x node12:fd00:abcd::]:${PW}=${SECRET} y`;
    const { out, a } = mask([other(`abcd::]:${PW}=${SECRET}`)], text);
    expect(out).toBe(`x node12:${R} y`);
    noFragments(a, "fd00", "abcd", SECRET);
  });

  it("a public IPv6 address cut by the region is hidden even with public IPs visible", () => {
    const text = `x [2a01:4f8::5]:${PW}=${SECRET} y 2a01:4f8::5`;
    const { out } = mask([other(`4f8::5]:${PW}=${SECRET}`)], text, policy({ maskPublicIps: false }));
    expect(out).toBe(`x [${R} y 2a01:4f8::5`);
  });

  // #2957: the same growth for an IPv4 address or a host name the region starts or ends inside.
  // Not gated on the IP/HOST/DOMAIN categories: the occurrence is already redacted one way.
  for (const IP of [false, true])
    it(`an IPv4 address cut by the region is hidden whole (IP ${IP ? "on" : "off"})`, () => {
      const text = `x 10.0.0.5:token=${SECRET} y 10.0.0.5`;
      const { out, a } = mask([other(`0.0.5:token=${SECRET}`)], text, policy({}, { IP }));
      expect(out).toBe(`x ${R} y ${IP ? "ANON_IP_1" : "10.0.0.5"}`);
      noFragments(a, "token", SECRET);
    });

  for (const on of [false, true])
    it(`a host name cut by the region is hidden whole (HOST/DOMAIN ${on ? "on" : "off"})`, () => {
      const text = `x http://srv01.lab.example/x?token=${SECRET} y`;
      const a = createAnonymizer(policy({}, { HOST: on, DOMAIN: on }), {
        hosts: ["srv01.lab.example"],
        accounts: [],
        internalDomains: ["lab.example"],
        custom: [other(`lab.example/x?token=${SECRET}`)],
      });
      const out = a.apply(text);
      expect(out).toBe(`x http://${R} y`);
      noFragments(a, "srv01", "corp", SECRET);
    });

  it("a hyphenated name and a decomposed Unicode label are hidden whole", () => {
    expect(mask([other(`01:token=${SECRET}`)], `x srv-01:token=${SECRET} y`).out).toBe(`x ${R} y`);
    const cafe = "café";
    const text = `x ${cafe}.lab.example/x?token=${SECRET} y`;
    expect(mask([other(`lab.example/x?token=${SECRET}`)], text).out).toBe(`x ${R} y`);
  });

  it("a region that ends inside a host name grows to its end", () => {
    const text = `x token=${SECRET}&host=srv01.lab.example z`;
    const { out } = mask([other(`token=${SECRET}&host=srv01`)], text);
    expect(out).toBe(`x ${R} z`);
  });

  it("growth repeats until the region cuts no address or name", () => {
    const text = `x 10.0.0.5:token=${SECRET} 10.0.0.9-tail/more.stuff y`;
    const custom = [other(`0.0.5:token=${SECRET} 10.0.0`), other("9-tail/more")];
    expect(mask(custom, text).out).toBe(`x ${R} y`);
  });

  it("an address or name beside the region, not cut by it, keeps today's output", () => {
    expect(mask([other(`token=${SECRET}`)], `x 10.0.0.5 token=${SECRET} y`).out).toBe(`x ANON_IP_1 ${R} y`);
    const key = `${["AK", "IA"].join("")}${"ABCDEFGHIJKLMNOP"}`;
    expect(mask([other("case")], `x case-${key} y`).out).toBe(`x ANON_OTHER_1-${R} y`);
  });

  it("a forged IPv6 sentinel cannot hide the custom value from the secret pass", () => {
    const cred = ["abc12", "fake"].join("");
    const { out } = mask(
      [other(`srv01?${PW}=${cred}`)],
      `srv01${String.fromCharCode(0xe000)}?${PW}=${cred} z`,
    );
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

  it("the preview marks the whole hidden span as one one-way secret", () => {
    const text = `x ${VALUE} y`;
    const { out, a } = mask([other(VALUE)], text);
    const diff = previewDiff(text, out, a, policy());
    expect(diff.mode).toBe("text");
    expect(diff.marks).toEqual([{ c: [2, 2 + VALUE.length], m: [2, 2 + R.length], pair: -1 }]);
  });

  it("scales linearly with many secrets and custom matches", () => {
    const anon = createAnonymizer(policy(), known([other(VALUE), other("srv01")]));
    const line = `a ${VALUE} b srv01 c ${PW}=x1fake d\n`;
    expectLinearScan("secret+custom", (n) => anon.apply(line.repeat(n)), 200);
  });

  // #2957 review: a big untouched group before a region that grows across many groups.
  it("growth stays linear with a long chain of merges", () => {
    const build = (n: number) => {
      const head = `${"a".repeat(n)} `;
      const runs = Array.from({ length: n }, (_, i) => `q${i}.w${i}`);
      const text = `${head}token=${SECRET} ${runs.join(" ")} end`;
      const custom = Array.from({ length: n }, (_, i) => ({ start: i, end: i + 1 }));
      let at = text.indexOf(" q0");
      custom.push({ start: head.length, end: at + 3 });
      for (let i = 1; i < n; i++) {
        at = text.indexOf(` q${i}.`, at + 1);
        custom.push({ start: at, end: at + 1 + `q${i}`.length });
      }
      return { text, custom, redacted: redactToSentinel(text, S) };
    };
    const small = build(3);
    expect(coverCustomSecrets(small.text, small.redacted, S, small.custom, [])).toBe(`aaa ${S} end`);
    const built = new Map<number, ReturnType<typeof build>>(); // the redactor is not what is timed
    const at = (n: number) => built.get(n) ?? built.set(n, build(n)).get(n)!;
    at(2000);
    at(16000);
    expectLinearScan(
      "region growth chain",
      (n) => coverCustomSecrets(at(n).text, at(n).redacted, S, at(n).custom, []),
      2000,
    );
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
