import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER as SEC,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";
import { ENTITY_PATTERNS, valueEntities } from "../../src/analysis/anonSecretEntities.js";
import { checkRegexSafety } from "../../src/analysis/regexSafety.js";

// #3059: a user, account or internal e-mail anywhere inside a redacted value (after other text, after
// a JSON line break, JSON-escaped more than once) was never learned, so a bare mention of that user
// elsewhere went to the AI in clear. Only the user name is learned, never the value. Synthetic values
// only, assembled at runtime.
const join = (...parts: string[]) => parts.join("");
const AT = String.fromCharCode(0x40);
const BS = String.fromCharCode(0x5c);
const Q = `${BS}"`; // a quote escaped inside a JSON string
const DOMAIN = join("corp", ".local");
const USER = "jdoe";
const MAIL = join(USER, AT, DOMAIN);
const LONG = "x".repeat(1100);
const SK = join("sk", "_live_", "Ab12Cd34Ef56Gh78Ij90");

function policy(maskPublicIps: boolean): AnonPolicy {
  const on = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true };
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: { ...on, CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
  };
}
const known = (): KnownEntities => ({ hosts: [], accounts: [], internalDomains: [DOMAIN] });

function run(text: string, mask: boolean) {
  const a = createAnonymizer(policy(mask), known());
  const out = a.apply(text);
  const held = [...a.pairs().map((p) => p.value), ...a.discoveries().map((d) => d.value)];
  return { out, held, back: a.restore(out) };
}

const VALUES: [string, string][] = [
  ["e-mail after a long here-string line", `sp K DefaultPassword @'\n${LONG}\n${MAIL}\n'@`],
  ["account after a long here-string line", `sp K DefaultPassword @'\n${LONG}\nCORP${BS}${USER}\n'@`],
  [
    "account escaped twice in a .reg body inside JSON",
    `{"Content":"[HKEY_LOCAL_MACHINE${BS}${BS}SOFTWARE${BS}${BS}Winlogon]${BS}n${Q}DefaultPassword${Q}=${Q}CORP${BS}${BS}${BS}${BS}${USER}${Q}${BS}n"}`,
  ],
  [
    "e-mail after a JSON line break",
    `{"ScriptBlockText":"sp K DefaultPassword @'${BS}nabc${BS}n${MAIL}${BS}n'@"}`,
  ],
  ["e-mail after other words", `reg add K /v DefaultPassword /d "token for ${MAIL}" /f`],
  ["profile path after a comma", `reg add K /v DefaultPassword /d "a,C:${BS}Users${BS}${USER}${BS}x" /f`],
  [
    "JSON account after a semicolon",
    `{"ValueData":"pw;CORP${BS}${BS}${USER}","ValueName":"DefaultPassword"}`,
  ],
];

describe.each([true, false])("a user anywhere inside a redacted value, maskPublicIps=%s (#3059)", (mask) => {
  it.each(VALUES)("%s: a bare mention before or after is masked", (_n, value) => {
    for (const text of [`${USER} logged on${"\n"}${value}`, `${value}${"\n"}seen ${USER} again`]) {
      const r = run(text, mask);
      expect(r.out).toContain(SEC);
      expect(r.out).not.toMatch(/\bjdoe\b/);
      expect(r.held).toContain(USER);
      // only the user name is held, never the value or a piece of it
      expect(r.held.some((v) => v !== USER && v.toLowerCase().includes(USER))).toBe(false);
      expect(r.held.some((v) => v.includes("xxxx") || v.includes("token"))).toBe(false);
      expect(r.back).not.toContain(MAIL);
    }
  });

  it("a backslash inside a password after other text teaches nothing", () => {
    const r = run(`reg add K /v DefaultPassword /d "x P${AT}ss${BS}w0rdX9" /f${"\n"}w0rdX9 here`, mask);
    expect(r.held.some((v) => v.includes("w0rd"))).toBe(false);
  });

  it("a profile path inside a value lends only its first word", () => {
    const r = run(
      `reg add K /v DefaultPassword /d "x C:${BS}Users${BS}${USER} Tail9" /f${"\n"}${USER}`,
      mask,
    );
    expect(r.out).not.toMatch(/\bjdoe\b/);
    expect(r.held.some((v) => v.includes("Tail9"))).toBe(false);
  });

  it("a short user or one holding a secret is never learned into a token", () => {
    const short = run(`reg add K /v DefaultPassword /d "q CORP${BS}ab" /f${"\n"}seen ab here`, mask);
    expect(short.held).not.toContain("ab");
    const value = `reg add K /v DefaultPassword /d "x C:${BS}Users${BS}bob${SK}" /f`;
    const r = run(`${value}${"\n"}bob${SK} here`, mask);
    expect(r.out).not.toContain(SK.slice(8));
    expect(r.held.some((v) => v.includes(SK.slice(8)))).toBe(false);
  });
});

describe("valueEntities (#3059)", () => {
  const rules = { internal: (d: string) => d === DOMAIN, fileUser: /\.exe$/i, addressAt: () => -1 };

  it("reads every entity in the value, in both JSON readings", () => {
    expect(valueEntities(`a CORP${BS}alice; b ${join("bob", AT, DOMAIN)}`, rules)).toEqual(["alice", "bob"]);
    expect(valueEntities(`x${BS}n${MAIL}`, rules)).toContain(USER);
    expect(valueEntities(`P${AT}ss${BS}w0rd`, rules)).toEqual([]);
    expect(valueEntities(`a ${join("bob", AT, "example", ".org")}`, rules)).toEqual([]);
  });

  it("stays linear on a long value", () => {
    const t0 = performance.now();
    for (const v of [
      "a.".repeat(8000),
      `${BS}`.repeat(16000),
      `a${BS}`.repeat(8000),
      `${"a".repeat(14)}${BS}`.repeat(1000),
      `x ${"a".repeat(30)}${AT}`.repeat(500),
    ])
      valueEntities(v, rules);
    expect(performance.now() - t0).toBeLessThan(5000);
  });

  it("its patterns pass the regex safety check", () => {
    for (const re of ENTITY_PATTERNS) expect(checkRegexSafety(re.source, re.flags).ok).toBe(true);
  });
});

// #3059 part 2: a data-first registry record inside a JSON string, with escaped quotes.
const rec = (...fields: [string, string][]) =>
  `{${fields.map(([k, v]) => `${Q}${k}${Q}:${Q}${v}${Q}`).join(",")}}`;
const PW = join("Hunt3r", "Pw9");
const UPD = `C:${BS}${BS}${BS}${BS}u.exe`;

describe.each([true, false])("an escaped-quote JSON registry record, maskPublicIps=%s (#3059)", (mask) => {
  const hidden: [string, string][] = [
    ["data first", rec(["ValueData", PW], ["ValueName", "DefaultPassword"])],
    ["name first", rec(["ValueName", "DefaultPassword"], ["ValueData", PW])],
    [
      "key path first",
      rec(
        ["TargetObject", `HKLM${BS}${BS}${BS}${BS}Winlogon`],
        ["ValueData", PW],
        ["ValueName", "DefaultPassword"],
      ),
    ],
    ["a field between", rec(["ValueData", PW], ["Type", "REG_SZ"], ["ValueName", "DefaultPassword"])],
    ["a brace in the password", rec(["ValueData", `a{${PW}}`], ["ValueName", "DefaultPassword"])],
  ];
  it.each(hidden)("%s: the data is hidden one way", (_n, record) => {
    const r = run(`{"Rec":"${record}"}`, mask);
    expect(r.out).toContain(SEC);
    expect(r.out).not.toContain(PW);
    expect(r.held.some((v) => v.includes(PW))).toBe(false);
  });

  it("in an array, each record keeps its own data, in either order", () => {
    const pw = rec(["ValueData", PW], ["ValueName", "DefaultPassword"]);
    const upd = rec(["ValueData", UPD], ["ValueName", "Updater"]);
    const named = rec(["ValueName", "DefaultPassword"], ["ValueData", PW]);
    for (const list of [`[${pw},${upd}]`, `[${upd},${pw}]`, `[${named},${upd}]`]) {
      const r = run(`{"Recs":"${list}"}`, mask);
      expect(r.out).not.toContain(PW);
      expect(r.out).toContain("u.exe");
    }
  });

  it("a value that is not a stored credential keeps its data", () => {
    for (const name of ["Updater", "AutoAdminLogon"]) {
      const r = run(`{"Rec":"${rec(["ValueData", PW], ["ValueName", name])}"}`, mask);
      expect(r.out).toContain(PW);
    }
  });
});
