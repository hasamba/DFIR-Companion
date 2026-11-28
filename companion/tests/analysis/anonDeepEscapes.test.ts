import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3063: a reg add value in a quote escaped twice (`\\\"`) and a DefaultPassword here-string written right
// after a tab (`@'\t`) went to the AI in clear. Values are synthetic and built at runtime.
const PW = ["Zx9", "-ab ", "cdef"].join("");
const PW2 = ["Hunt", "er2", "Value77"].join("");
const B = "\\";
const TAB = `${B}t`; // a JSON-escaped tab: a backslash and a t
const NL = `${B}n`;
const DOM = ["corp", "local"].join(".");

function policy(maskPublicIps: boolean): AnonPolicy {
  const categories = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true };
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: { ...categories, CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
  };
}
function run(text: string, maskPublicIps = true) {
  const an = createAnonymizer(policy(maskPublicIps), {
    hosts: [],
    accounts: [],
    internalDomains: [DOM],
    usernames: ["jdoe"],
  });
  const out = an.apply(text);
  return { out, held: an.pairs().map((p) => p.value) };
}
const hidden = (r: { out: string; held: string[] }, ...parts: string[]) => {
  for (const p of parts) {
    expect(r.out).not.toContain(p);
    expect(r.held.some((v) => v.includes(p))).toBe(false);
  }
};

describe("reg add with a quote escaped twice (#3063)", () => {
  for (const pm of [true, false]) {
    it(`redacts the value one way (maskPublicIps=${pm})`, () => {
      const q = `${B}${B}${B}"`;
      for (const value of [PW, PW2]) {
        const r = run(`{"cmd":"reg add HKLM${B}${B}x /v DefaultPassword /d ${q}${value}${q} /f"}`, pm);
        hidden(r, ...value.split(" "));
        expect(r.out).toContain("/f");
      }
    });
  }

  it("still redacts the once-escaped and plain forms", () => {
    hidden(run(`{"cmd":"reg add HKLM${B}${B}x /v DefaultPassword /d ${B}"${PW}${B}" /f"}`), "cdef");
    hidden(run(`reg add HKLM${B}x /v DefaultPassword /d "${PW}" /f`), "cdef");
  });

  it("leaves an unclosed escaped quote to the old reading", () => {
    const r = run(`{"cmd":"reg add K /v Updater /d ${B}${B}${B}"C:${B}${B}u.exe"}`);
    expect(r.out).toContain("Updater");
  });
});

describe("a DefaultPassword here-string after a tab (#3063)", () => {
  it("hides the value, JSON-escaped and raw", () => {
    for (const text of [
      `{"ScriptBlockText":"sp K DefaultPassword @'${TAB}CORP${B}${B}jdoe${NL}'@"}`,
      `{"m":"Set-ItemProperty HKLM:${B}${B}x -Name DefaultPassword -Value @'${TAB}${PW2}${NL}'@"}`,
      `sp HKLM:${B}x DefaultPassword @'\t${PW2}\n'@`,
    ]) {
      const r = run(text);
      hidden(r, PW2, "jdoe");
    }
  });

  it("still reads a here-string opened with a line break", () => {
    hidden(run(`sp HKLM:${B}x DefaultPassword @'\n${PW2}\n'@`), PW2);
  });

  it("keeps real accounts that start with n, t or r masked", () => {
    for (const user of ["nancy", "tsmith", "rjones"])
      expect(run(`logon CORP${B}${user} ok`).out).not.toContain(user);
  });
});
