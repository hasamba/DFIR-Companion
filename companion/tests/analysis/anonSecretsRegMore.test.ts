import { describe, it, expect } from "vitest";
import { redactSecretText, SECRET_PLACEHOLDER as PH } from "../../src/analysis/anonSecrets.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3047 (part 1) — the last registry shapes that sent DefaultPassword to the AI in clear: two
// `reg add` commands on one line, the dotted static `Registry.SetValue(key, name, value)`, a
// multi-line colon record with the data line before the name line, and a PowerShell `''` escape
// inside a single-quoted value. Every fixture value is built at runtime.
const join = (...parts: string[]) => parts.join("");
const VALUE = join("Hunt", "er2Value77");
const HEAD = "Hunt";
const TAIL = join("er2", "Value77");
const ESCAPED = `'${HEAD}''${TAIL}'`;
const WINLOGON = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const KEY = `"${WINLOGON}"`;
const WP = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const RUN = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const UPD = "C:\\ProgramData\\upd.exe";
const B64 = join("SQBFAFgAIAAo", "AE4AZQB3AC0ATwBi", "AGoAZQBjAHQA");
const CARD = ["4111", "1111", "1111", "1111"].join(" ");
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
const hides = (row: string, secret = VALUE) => {
  const out = redactSecretText(row);
  expect(out).not.toContain(secret);
  expect(out).toContain(PH);
  return out;
};

describe("redactSecretText — two reg add commands on one line (#3047)", () => {
  it("pairs the second command's name with its own data", () => {
    const first = `reg add ${KEY} /v AutoAdminLogon /d 1 /f`;
    const second = `reg add ${KEY} /v DefaultPassword /t REG_SZ /d ${VALUE} /f`;
    for (const sep of [" ", "; ", " & "]) {
      const out = hides(`${first}${sep}${second}`);
      expect(out).toContain("/v AutoAdminLogon /d 1 /f");
      expect(out).toContain(`/d ${PH} /f`);
    }
    hides(`reg.exe add ${KEY} /v X /d 1 reg.exe add ${KEY} /v DefaultPassword /d ${VALUE}`);
  });

  it("keeps the other command's data when the credential comes first", () => {
    const row = `reg add ${KEY} /v DefaultPassword /d ${VALUE} /f reg add ${KEY} /v AutoAdminLogon /d 1 /f`;
    expect(hides(row)).toContain("/v AutoAdminLogon /d 1 /f");
  });

  it("ends the first command at a quoted, path or JSON-escaped launcher", () => {
    hides(
      `reg add ${KEY} /v X /d 1 "C:\\Windows\\System32\\reg.exe" add ${KEY} /v DefaultPassword /d ${VALUE}`,
    );
    hides(
      `reg add ${KEY} /v X /d 1 C:\\Windows\\System32\\reg.exe add ${KEY} /v DefaultPassword /d ${VALUE}`,
    );
    const launcher = `"C:\\Windows\\System32\\reg.exe"`;
    const two = `reg add ${KEY} /v X /d 1 /f ${launcher} add ${KEY} /v DefaultPassword /d ${VALUE} /f`;
    hides(JSON.stringify({ CommandLine: two }));
    hides(JSON.stringify({ CommandLine: `cmd /c "${two}"` }));
    hides(`cmd /c "${two}"`);
    hides(
      JSON.stringify({
        CommandLine: `cmd /c "reg add ${KEY} /v X /d 1 /f reg add ${KEY} /v DefaultPassword /d ${VALUE} /f"`,
      }),
    );
  });

  it("does not split a command at reg add text inside a quoted value", () => {
    hides(`reg add ${KEY} /v DefaultPassword /d "${VALUE} reg add x" /f`);
    hides(`reg add "HKLM\\x reg add y" /v DefaultPassword /d ${VALUE} /f`);
  });

  it("hides a card number given as the second command's data whole", () => {
    const out = hides(`reg add ${KEY} /v X /d 1 reg add ${KEY} /v DefaultPassword /d ${CARD}`, "1111");
    expect(out).toContain(`/v DefaultPassword /d ${PH}`);
  });

  it("never swallows an encoded command after the second command", () => {
    const out = hides(
      `reg add ${KEY} /v X /d 1 reg add ${KEY} /v DefaultPassword /d ${VALUE} & powershell -enc ${B64}`,
    );
    expect(out).toContain(`-enc ${B64}`);
  });
});

describe("redactSecretText — dotted static Registry.SetValue (#3047)", () => {
  it("reads key, name, value when the first argument is a key path or not a literal", () => {
    hides(`Registry.SetValue("${WINLOGON}","DefaultPassword","${VALUE}")`);
    hides(
      `Microsoft.Win32.Registry.SetValue('HKEY_LOCAL_MACHINE\\SOFTWARE\\x','DefaultPassword','${VALUE}')`,
    );
    hides(`Registry.SetValue(@"${WINLOGON}", "DefaultPassword", "${VALUE}", RegistryValueKind.String);`);
    hides(`Registry.SetValue(keyName, "DefaultPassword", "${VALUE}");`);
  });

  it("keeps the instance reading for a key object", () => {
    hides(`$registry.SetValue('DefaultPassword','${VALUE}')`);
    hides(`$k.SetValue('DefaultPassword','${VALUE}','String')`);
    expect(redactSecretText(`$k.SetValue('Updater','DefaultPassword','String')`)).not.toContain(PH);
    const run = `Registry.SetValue("${RUN}","PasswordManager","${UPD}")`;
    expect(redactSecretText(run)).toBe(run);
  });
});

describe("redactSecretText — multi-line colon record, data line first (#3047)", () => {
  it("pairs a bare value name with the data line right before it", () => {
    expect(hides(`ValueData: ${VALUE}\nValueName: DefaultPassword`)).toBe(
      `ValueData: ${PH}\nValueName: DefaultPassword`,
    );
    hides(`TargetObject: ${WINLOGON}\nValueData: ${VALUE}\nValueName: DefaultPassword\nType: REG_SZ`);
  });

  it("never takes another value's data", () => {
    for (const row of [
      `ValueName: Updater\nValueData: ${UPD}\nValueName: DefaultPassword`,
      `TargetObject: ${RUN}\\Updater\nDetails: ${UPD}\nTargetObject: ${WINLOGON}\\DefaultPassword`,
      `ValueData: ${UPD}\nValueName: Updater\n\nValueName: DefaultPassword`,
      `ValueData: ${UPD}\n\nValueName: DefaultPassword`,
      `Details: ${UPD}\nValueName: DefaultPassword`,
      `ValueData: ${UPD}\nImage: C:\\x.exe\nValueName: DefaultPassword`,
    ])
      expect(redactSecretText(row)).toBe(row);
  });

  it("keeps forward pairing when the name comes first", () => {
    const row = `ValueName: Updater\nValueData: ${UPD}\nValueName: DefaultPassword\nValueData: ${VALUE}`;
    expect(hides(row)).toContain(UPD);
  });
});

describe("redactSecretText — PowerShell '' escape in a single-quoted value (#3047)", () => {
  it("hides the whole value across the escape", () => {
    for (const row of [
      `sp '${WP}' DefaultPassword ${ESCAPED}`,
      `Set-ItemProperty -Path '${WP}' -Name DefaultPassword -Value ${ESCAPED}`,
      `Set-ItemProperty -Path '${WP}' -Name DefaultPassword -Value:${ESCAPED}`,
      `$p=@{Path='${WP}';Name='DefaultPassword';Value=${ESCAPED}}; Set-ItemProperty @p`,
      `[Microsoft.Win32.Registry]::SetValue('HKEY_LOCAL_MACHINE\\x','DefaultPassword',${ESCAPED})`,
      `$k.SetValue('DefaultPassword',${ESCAPED})`,
      JSON.stringify({
        ScriptBlockText: `Set-ItemProperty -Path '${WP}' -Name DefaultPassword -Value ${ESCAPED}`,
      }),
    ]) {
      const out = hides(row, TAIL);
      expect(out).not.toContain(HEAD);
    }
  });

  it("hides one word after a continuation that never closes (#3067)", () => {
    const out = hides(`sp '${WP}' DefaultPassword 'my ${VALUE};x''tail`);
    expect(out).toContain(`'${PH}`);
    expect(out).not.toContain("tail");
  });

  it("stops before an encoded command after the value", () => {
    const out = hides(`sp '${WP}' DefaultPassword 'a''${TAIL}'; powershell -enc ${B64}`, TAIL);
    expect(out).toContain(`-enc ${B64}`);
  });
});

describe("redactSecretText — the #3047 shapes stay linear", () => {
  it("reads long quote runs, many commands and many records quickly", () => {
    const quotes = `sp HKLM:\\x DefaultPassword ${"'".repeat(60000)}`;
    const segments = `sp HKLM:\\x DefaultPassword ${"'x'".repeat(30000)}`;
    const regs = Array.from({ length: 3000 }, (_, i) => `reg add HKLM\\x /v V${i} /d ${i}`).join(" ");
    const records = Array.from(
      { length: 3000 },
      (_, i) => `ValueData: v${i}\nValueName: DefaultPassword`,
    ).join("\n");
    const calls = `Registry.SetValue(`.repeat(20000);
    const t0 = performance.now();
    for (const row of [quotes, segments, regs, records, calls]) redactSecretText(row);
    expect(performance.now() - t0).toBeLessThan(5000);
  });
});

describe("full anonymizer — the #3047 registry shapes", () => {
  const rows: [string, string][] = [
    [`reg add ${KEY} /v X /d 1 /f reg add ${KEY} /v DefaultPassword /d ${VALUE} /f`, VALUE],
    [`Registry.SetValue("${WINLOGON}","DefaultPassword","${VALUE}")`, VALUE],
    [`ValueData: ${VALUE}\nValueName: DefaultPassword`, VALUE],
    [`sp '${WP}' DefaultPassword ${ESCAPED}`, TAIL],
  ];
  for (const maskPublicIps of [true, false])
    it(`sends none of them in clear, and restore keeps them hidden (public masking ${maskPublicIps})`, () => {
      for (const [row, secret] of rows) {
        const anon = createAnonymizer(
          { ...policy, maskPublicIps },
          { hosts: [], accounts: [], internalDomains: [] },
        );
        const out = anon.apply(row);
        expect(out).not.toContain(secret);
        expect(anon.restore(out)).not.toContain(secret);
      }
    });
});
