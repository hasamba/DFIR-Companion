import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";
import { SECRET_PLACEHOLDER, redactSecretText } from "../../src/analysis/anonSecrets.js";

// #3053: a FromBase64String blob in doubled ('' / "") or JSON-escaped (\") quotes got no CMD token,
// and a key=value secret after a JSON-escaped newline was not redacted one way. Values are synthetic
// and built at runtime.
const BLOB = ["SQBFAFgAIAAo", "AE4AZQB3AC0ATwBiAGoAZQBjAHQA"].join("");
const PW = ["Hunt", "er2", "Value77"].join("");
const NL = "\\n"; // a JSON-escaped newline: a backslash and an n

function policy(over: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
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
      CARD: true,
      PHONE: true,
      NATID: true,
      ...over,
    },
  };
}
const make = () => createAnonymizer(policy(), { hosts: [], accounts: [], internalDomains: [] });

describe("FromBase64String blobs in doubled or JSON-escaped quotes (#3053)", () => {
  const shapes = [
    `powershell -c 'iex ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(''${BLOB}'')))'`,
    `powershell -c "iex ([Convert]::FromBase64String(""${BLOB}""))"`,
    `{"cmd":"iex ([Convert]::FromBase64String(\\"${BLOB}\\"))"}`,
    `password=X|FromBase64String(''${BLOB}'')`,
    `password=X|FromBase64String(\\"${BLOB}\\")`,
  ];
  for (const text of shapes) {
    it(`gives the blob a CMD token: ${text.slice(0, 40)}`, () => {
      const a = make();
      const out = a.apply(text);
      expect(out).not.toContain(BLOB);
      expect(out).toMatch(/FromBase64String\((?:''|""|\\"|["'])ANON_CMD_\d+/);
      const back = a.restore(out);
      expect(
        back.includes(SECRET_PLACEHOLDER) ? back.endsWith(text.slice(text.indexOf("From"))) : back === text,
      ).toBe(true);
    });
  }
});

describe("a keyed secret after a JSON-escaped newline (#3053)", () => {
  for (const text of [
    `{"m":"line1${NL}password=${PW}"}`,
    `{"m":"ok${NL}password: ${PW}${NL}next"}`,
    `{"m":"ok${NL}password: ${PW}${NL}next line"}`,
    `{"m":"a${NL}password: ${PW}, user=x"}`,
    `{"m":"ab\\r${NL}password=${PW}"}`,
    `{"m":"ab\\tapi_key=${PW}"}`,
    `{"m":"x${NL}\\"password\\":\\"${PW}\\""}`,
  ]) {
    it(`redacts the value one way: ${text.slice(0, 32)}`, () => {
      expect(redactSecretText(text)).not.toContain(PW);
      const a = make();
      const out = a.apply(text);
      expect(out).not.toContain(PW);
      expect(out).toContain(SECRET_PLACEHOLDER);
      expect(a.pairs().some((p) => p.value.includes(PW))).toBe(false);
    });
  }

  it("still reads a non-secret word after the escape as text", () => {
    expect(redactSecretText(`{"m":"a${NL}note=hello"}`)).toBe(`{"m":"a${NL}note=hello"}`);
  });

  it("still hides the stored credential of a registry record or command after the value", () => {
    const record = `{"ValueData":"CORP\\\\jdoe","ValueName":"DefaultPassword"}`;
    const out = make().apply(`x${NL}password=${PW}|${record}`);
    expect(out).not.toContain(PW);
    expect(out).toContain(`"ValueData":"${SECRET_PLACEHOLDER}"`);
    const splat = `$p=@{Path='K';Name='DefaultPassword';Value='${PW}'}; Set-ItemProperty @p`;
    expect(make().apply(`x${NL}password=v${splat}`)).not.toContain(PW);
    const cmd = `x${NL}password= Set-ItemProperty K -Name DefaultPassword -Value '${PW}'`;
    expect(make().apply(cmd)).not.toContain(PW);
  });

  it("reads only an exact key after the escape, never a file or value name", () => {
    for (const text of ["C:\\src\\reset-password.ts: error", "HKCU\\Run\\newpasswordmanager=C:\\pm.exe"]) {
      expect(redactSecretText(text)).toBe(text);
    }
  });

  it("keeps a real account whose name starts with n, r or t masked", () => {
    for (const user of ["nancy", "tsmith", "rjones"]) {
      const a = make();
      const text = `logon CORP\\${user} ok`;
      const out = a.apply(text);
      expect(out).not.toContain(user);
      expect(a.restore(out)).toBe(text);
    }
  });

  it("keeps a raw value that holds a backslash-n hidden whole", () => {
    const out = make().apply(`password=P@ss${NL}ew0rd next`);
    expect(out).not.toMatch(/P@ss|ew0rd/);
  });
});
