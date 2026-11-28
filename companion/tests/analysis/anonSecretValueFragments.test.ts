import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER as SEC,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";
import { valueEntities } from "../../src/analysis/anonSecretEntities.js";
import { levelOfRun, quoteAt, readQuotedField } from "../../src/analysis/anonSecretRegCommands.js";
import { REG_PAIR_PATTERNS } from "../../src/analysis/anonSecretRegPairs.js";
import { REG_FILE_PATTERNS } from "../../src/analysis/anonSecretRegFile.js";
import { checkRegexSafety } from "../../src/analysis/regexSafety.js";

// #3061: (1) a registry record escaped twice or three times (a JSON string inside a JSON string) was
// not paired, so its stored password went out in clear; (2) a password shaped like DOMAIN\user lent
// a piece of itself to user learning, which stored it as a reversible USER token; (3) a JSON `\n`
// before an e-mail lent the bogus name `njdoe`. Synthetic values only, assembled at runtime.
const join = (...parts: string[]) => parts.join("");
const AT = String.fromCharCode(0x40);
const BS = String.fromCharCode(0x5c);
const DOMAIN = join("corp", ".local");
const USER = "jdoe";
const MAIL = join(USER, AT, DOMAIN);
const PW = join("Hunt", "3r", "Pw9");
const FRAG = "cdefgh";

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

// A quote and a backslash at JSON level `l` (0 = plain JSON).
const q = (l: number) => `${BS.repeat(2 ** l - 1)}"`;
const bs = (l: number) => BS.repeat(2 ** l);
const rec = (l: number, ...kv: [string, string][]) =>
  `{${kv.map(([k, v]) => `${q(l)}${k}${q(l)}:${q(l)}${v}${q(l)}`).join(",")}}`;
const inString = (inner: string) => `{"A":"{${q(1)}Rec${q(1)}:${q(1)}${inner}${q(1)}}"}`;

const HIDDEN: [string, string][] = [
  ["data first, level 2", inString(rec(2, ["ValueData", PW], ["ValueName", "DefaultPassword"]))],
  ["name first, level 2", inString(rec(2, ["ValueName", "DefaultPassword"], ["ValueData", PW]))],
  [
    "key path first, level 2",
    inString(
      rec(
        2,
        ["TargetObject", `HKLM${bs(2)}x${bs(2)}Winlogon`],
        ["ValueData", PW],
        ["ValueName", "DefaultPassword"],
      ),
    ),
  ],
  [
    "a field between, level 2",
    inString(rec(2, ["ValueData", PW], ["Type", "REG_SZ"], ["ValueName", "DefaultPassword"])),
  ],
  [
    "spaces after the separators, level 2",
    inString(
      `{${q(2)}ValueData${q(2)}: ${q(2)}${PW}${q(2)}, ${q(2)}ValueName${q(2)}: ${q(2)}DefaultPassword${q(2)}}`,
    ),
  ],
  ["data first, level 3", `"x":"${rec(3, ["ValueData", PW], ["ValueName", "DefaultPassword"])}"`],
  [
    ".reg body, level 2",
    `{"A":"{${q(1)}C${q(1)}:${q(1)}[HKLM${bs(2)}Winlogon]${bs(1)}n${q(2)}DefaultPassword${q(2)}=${q(2)}${PW}${q(2)}${bs(1)}n${q(1)}}"}`,
  ],
];

describe.each([true, false])("doubly escaped registry records, maskPublicIps=%s (#3061)", (mask) => {
  it.each(HIDDEN)("%s: the stored password is hidden one way", (_n, text) => {
    const r = run(text, mask);
    expect(r.out).not.toContain(PW);
    expect(r.out).toContain(SEC);
    expect(r.held.some((v) => v.includes(PW))).toBe(false);
    expect(r.back).not.toContain(PW);
  });

  it("a value that is not a stored credential keeps its data", () => {
    for (const name of ["Updater", "AutoAdminLogon"]) {
      const r = run(inString(rec(2, ["ValueData", PW], ["ValueName", name])), mask);
      expect(r.out).toContain(PW);
    }
  });
});

describe.each([true, false])("no piece of a credential is learned, maskPublicIps=%s (#3061)", (mask) => {
  const shaped: [string, string][] = [
    ["mixed-case qualifier", `reg add K /v DefaultPassword /d "Zx9-ab${BS}${FRAG}" /f`],
    ["one capitalised word", `reg add K /v DefaultPassword /d "Winter${BS}${FRAG}" /f`],
    ["JSON", `{"ValueData":"Word-ab${BS}${BS}${FRAG}","ValueName":"DefaultPassword"}`],
    ["after other words", `reg add K /v DefaultPassword /d "Summer Zx9-ab${BS}${FRAG}" /f`],
    ["after a separator", `reg add K /v DefaultPassword /d "x=AB${BS}${FRAG}" /f`],
    ["keyed value", `password=Zq7${BS}${FRAG}`],
    [
      "JSON account after a semicolon",
      `{"ValueData":"pw;CORP${BS}${BS}${FRAG}","ValueName":"DefaultPassword"}`,
    ],
    ["e-mail glued to other text", `reg add K /v DefaultPassword /d "Xy9!${FRAG}${AT}${DOMAIN}" /f`],
    ["profile path inside a word", `reg add K /v DefaultPassword /d "Pw${BS}Users${BS}${FRAG}" /f`],
  ];
  it.each(shaped)("%s: the fragment is neither held nor taught", (_n, value) => {
    const r = run(`${value}${"\n"}seen ${FRAG} here`, mask);
    expect(r.out).toContain(SEC);
    expect(r.held.some((v) => v.toLowerCase().includes(FRAG))).toBe(false);
  });

  it("an upper-case DOMAIN\\user that is the whole value still teaches its user", () => {
    const r = run(`reg add K /v DefaultPassword /d "CORP${BS}${USER}" /f${"\n"}seen ${USER} here`, mask);
    expect(r.out).not.toMatch(/\bjdoe\b/);
    expect(r.held).toContain(USER);
  });
});

describe.each([true, false])("a JSON escape before an e-mail, maskPublicIps=%s (#3061)", (mask) => {
  const value = `{"ScriptBlockText":"sp K DefaultPassword @'${BS}nabc${BS}n${MAIL}${BS}n'@"}`;
  it("lends the real user, never the escape's letter glued to it", () => {
    const r = run(`n${USER} and ${USER}${"\n"}${value}`, mask);
    expect(r.out).toContain(SEC);
    expect(r.held).toContain(USER);
    expect(r.held).not.toContain(`n${USER}`);
    expect(r.out).toMatch(/\bnjdoe\b/);
  });
});

describe("valueEntities (#3061)", () => {
  const rules = { internal: (d: string) => d === DOMAIN, fileUser: /\.exe$/i, addressAt: () => -1 };

  it("reads a DOMAIN\\user only as a whole word with a domain-cased qualifier", () => {
    expect(valueEntities(`CORP${BS}alice`, rules)).toEqual(["alice"]);
    expect(valueEntities(`"CORP${BS}alice", next`, rules)).toEqual(["alice"]);
    expect(valueEntities(`CORP${BS}alice;`, rules)).toEqual(["alice"]);
    expect(valueEntities(`Corp${BS}alice`, rules)).toEqual([]);
    expect(valueEntities(`ab;CORP${BS}alice`, rules)).toEqual([]);
    expect(valueEntities(`CORP${BS}alice;x`, rules)).toEqual([]);
  });

  it("reads users that start with n, r or t", () => {
    expect(valueEntities(`CORP${BS}${BS}nancy`, rules)).toContain("nancy");
    expect(valueEntities(`C:${BS}${BS}Users${BS}${BS}tsmith`, rules)).toContain("tsmith");
    expect(valueEntities(`x ${join("rsmith", AT, DOMAIN)}`, rules)).toEqual(["rsmith"]);
  });

  it("never lends the letter of a JSON escape", () => {
    expect(valueEntities(`abc${BS}n${MAIL}`, rules)).toEqual([USER]);
    expect(valueEntities(`${BS}n${MAIL}${BS}n`, rules)).toEqual([USER]);
  });
});

describe("quote levels (#3061)", () => {
  it("names the level of a quote by the backslashes before it", () => {
    expect([0, 1, 2, 3, 5, 7].map(levelOfRun)).toEqual([0, 1, 0, 2, 1, 3]);
    const t = `x${q(2)}a${q(1)}b"`;
    expect(quoteAt(t, t.indexOf('"'), 2)).toBe("toggle");
    expect(quoteAt(t, t.indexOf('"', 6), 2)).toBe("end");
    expect(quoteAt(t, t.indexOf('"'), 1)).toBeNull();
  });

  it("reads a quoted value at levels 2 and 3, and stops at an outer quote", () => {
    const two = `${q(2)}pw${bs(2)}x${q(2)},`;
    expect(readQuotedField(two, 0)?.span).toEqual([4, 4 + `pw${bs(2)}x`.length]);
    const three = `${q(3)}pw${q(3)}`;
    expect(readQuotedField(three, 0)?.span).toEqual([8, 10]);
    const outer = `${q(2)}pw${q(1)}`;
    expect(readQuotedField(outer, 0)?.span).toEqual([4, 6]);
  });

  it("stays linear on a long run of backslashes and quotes", () => {
    const t0 = performance.now();
    run(`${BS.repeat(3)}"ValueName${BS.repeat(3)}":`.repeat(4000), true);
    run(`${q(2)}${"a".repeat(20000)}`, true);
    expect(performance.now() - t0).toBeLessThan(10000);
  });

  it("the registry patterns pass the regex safety check", () => {
    for (const re of [...REG_PAIR_PATTERNS, ...REG_FILE_PATTERNS])
      expect(checkRegexSafety(re.source, re.flags).ok).toBe(true);
  });
});
