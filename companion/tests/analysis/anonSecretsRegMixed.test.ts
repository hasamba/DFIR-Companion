import { describe, it, expect } from "vitest";
import { redactSecretText, SECRET_PLACEHOLDER as PH } from "../../src/analysis/anonSecrets.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";
import { REG_PAIR_PATTERNS } from "../../src/analysis/anonSecretRegPairs.js";
import { checkRegexSafety } from "../../src/analysis/regexSafety.js";

// #3056 — a JSON registry record (key path, data, then the value name in one object) inside a longer
// line that also holds an UNQUOTED name field before it. The bare name value ran on over the JSON, so
// the record's own fields were skipped. Every fixture value is built at runtime.
const join = (...parts: string[]) => parts.join("");
const VALUE = join("Hunt", "er2Value77");
const UPD = "C:\\\\u.exe";
const record = (data: string, name = "DefaultPassword", label = "ValueData") =>
  `{"TargetObject":"HKLM\\\\x\\\\Winlogon","${label}":"${data}","ValueName":"${name}"}`;
const policy: AnonPolicy = {
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
  },
};

describe("redactSecretText — a JSON record after an unquoted name field (#3056)", () => {
  it("pairs the record in its own object", () => {
    for (const row of [
      `TgtObj=HKLM\\y\\Run ${record(VALUE)}`,
      `ValueName=Updater ${record(VALUE)}`,
      `TargetObject: HKLM\\y\\Run ${record(VALUE)}`,
      `RegValueName=Updater,${record(VALUE)}`,
      `ValueName=Updater ${record(VALUE, "DefaultPassword", "Details")}`,
      `ValueName=Updater - {"CommandLine":"x","Rec":${record(VALUE)}}`,
      `ValueName=Updater [${record(VALUE)}] more=1`,
    ]) {
      const out = redactSecretText(row);
      expect(out, row).not.toContain(VALUE);
      expect(out).toContain(PH);
    }
  });

  it("keeps persistence data and the earlier field's own value", () => {
    for (const row of [
      `TgtObj=HKLM\\x\\Winlogon\\DefaultPassword {"ValueData":"${UPD}","ValueName":"Updater"}`,
      `ValueName=DefaultPassword {"ValueData":"${UPD}","ValueName":"Updater"}`,
      `ValueName=Updater ${record(UPD, "Updater")}`,
      `TgtObj=HKLM\\y\\Run\\Updater Details=${UPD} ${record(UPD, "AutoAdminLogon")}`,
    ])
      expect(redactSecretText(row), row).toBe(row);
  });

  it("still reads a bare key path with spaces up to the next field", () => {
    const row = `TgtObj=HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DefaultPassword Details=${VALUE} Proc=x`;
    expect(redactSecretText(row)).not.toContain(VALUE);
  });

  it("uses only safe patterns and stays linear", () => {
    for (const re of REG_PAIR_PATTERNS) expect(checkRegexSafety(re.source, re.flags).ok).toBe(true);
    const rows = [
      `${'ValueName=x "ValueName":"y" '.repeat(5000)}`,
      'ValueName=x"ValueName":"y"'.repeat(20000),
      `${'TgtObj=a {"TargetObject":"b"} '.repeat(5000)}`,
      `ValueName=${" ".repeat(50000)}"ValueData":"x"`,
    ];
    const t0 = performance.now();
    for (const row of rows) redactSecretText(row);
    expect(performance.now() - t0).toBeLessThan(5000);
  });
});

describe("full anonymizer — #3056", () => {
  for (const maskPublicIps of [true, false])
    it(`sends the value in no form, and restore keeps it hidden (public masking ${maskPublicIps})`, () => {
      for (const row of [`TgtObj=HKLM\\y\\Run ${record(VALUE)}`, `ValueName=Updater ${record(VALUE)}`]) {
        const anon = createAnonymizer(
          { ...policy, maskPublicIps },
          { hosts: [], accounts: [], internalDomains: [] },
        );
        const out = anon.apply(row);
        expect(out).not.toContain(VALUE);
        expect(anon.restore(out)).not.toContain(VALUE);
      }
    });
});
