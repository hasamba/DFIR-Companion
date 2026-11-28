import { describe, it, expect } from "vitest";
import { redactSecretText, SECRET_PLACEHOLDER as PH } from "../../src/analysis/anonSecrets.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3040 — more shapes of a stored-credential registry value (DefaultPassword) that went to the AI
// in clear: a glued JSON name field, pretty-printed JSON, a key path + data + name in one object,
// a flat data-first line, and PowerShell positional/abbreviated/`sp`/splat/SetValue forms. Every
// fixture value is built at runtime.
const join = (...parts: string[]) => parts.join("");
const VALUE = join("Hunt", "er2Value77");
const WINLOGON = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const WP = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const RUN = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const UPD = "C:\\ProgramData\\upd.exe";
const B64 = join("SQBFAFgAIAAo", "AE4AZQB3AC0ATwBi", "AGoAZQBjAHQA");
const CARD = ["4111", "1111", "1111", "1111"].join(" ");
const EMAIL = join("jdoe", "@", "corp.example");
const pretty = (o: unknown) => JSON.stringify(o, null, 2);
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
const hides = (row: string) => {
  const out = redactSecretText(row);
  expect(out).not.toContain(VALUE);
  expect(out).toContain(PH);
  return out;
};

describe("redactSecretText — JSON registry rows in more shapes (#3040)", () => {
  it("reads a quoted name field glued to the character before it", () => {
    expect(hides(`{"a":5}5"ValueName":"DefaultPassword","ValueData":"${VALUE}"}`)).toContain(
      `"ValueName":"DefaultPassword","ValueData":"${PH}"`,
    );
    hides(`{"ValueData":"${VALUE}"5"ValueName":"DefaultPassword"}`);
    hides(`x"ValueName":"DefaultPassword","ValueData":"${VALUE}"`);
  });

  it("pairs within a pretty-printed record, in both orders", () => {
    for (const o of [
      { ValueName: "DefaultPassword", ValueData: VALUE },
      { ValueData: VALUE, ValueName: "DefaultPassword" },
      { TargetObject: `${WINLOGON}\\DefaultPassword`, Details: VALUE },
      { Details: VALUE, TargetObject: `${WINLOGON}\\DefaultPassword` },
    ]) {
      const out = hides(pretty(o));
      expect(() => JSON.parse(out)).not.toThrow();
    }
  });

  it("never reaches the next or previous pretty-printed record", () => {
    const rows = [
      { ValueData: VALUE, ValueName: "DefaultPassword" },
      { ValueData: UPD, ValueName: "Updater" },
    ];
    const out = hides(pretty(rows));
    expect(JSON.parse(out)[1].ValueData).toBe(UPD);
    const reversed = hides(
      pretty([
        { ValueName: "Updater", ValueData: UPD },
        { ValueName: "DefaultPassword", ValueData: VALUE },
      ]),
    );
    expect(JSON.parse(reversed)[0].ValueData).toBe(UPD);
    const noData = pretty([{ ValueName: "DefaultPassword" }, { ValueData: UPD, ValueName: "Updater" }]);
    expect(redactSecretText(noData)).toBe(noData);
  });

  it("pairs a value name with the data before it when a key path comes first", () => {
    const row = JSON.stringify({ TargetObject: WINLOGON, ValueData: VALUE, ValueName: "DefaultPassword" });
    expect(JSON.parse(hides(row))).toEqual({
      TargetObject: WINLOGON,
      ValueData: PH,
      ValueName: "DefaultPassword",
    });
  });

  it("keeps the data of a setting or persistence value in the same shapes", () => {
    for (const row of [
      pretty({ ValueData: "C:\\pm.exe", ValueName: "PasswordManager" }),
      JSON.stringify({ TargetObject: WINLOGON, ValueData: "1", ValueName: "AutoAdminLogon" }),
      `{"a":5}5"ValueName":"LimitBlankPasswordUse","ValueData":"0"}`,
    ])
      expect(redactSecretText(row)).toBe(row);
  });
});

describe("redactSecretText — flat line with the data before the name (#3040)", () => {
  it("hides the data of a strictly data-first line", () => {
    expect(hides(`ValueData=${VALUE} - ValueName=DefaultPassword - Type=REG_SZ`)).toBe(
      `ValueData=${PH} - ValueName=DefaultPassword - Type=REG_SZ`,
    );
    hides(`TargetObject=${WINLOGON} ValueData=${VALUE} ValueName=DefaultPassword`);
  });

  it("pairs each name with its own data on a data-first line", () => {
    const row = `ValueData=${UPD} - ValueName=Updater - ValueData=${VALUE} - ValueName=DefaultPassword`;
    expect(hides(row)).toBe(
      `ValueData=${UPD} - ValueName=Updater - ValueData=${PH} - ValueName=DefaultPassword`,
    );
    const two = `ValueData=${VALUE} - ValueName=DefaultPassword - ValueData=${UPD} - ValueName=Updater`;
    expect(hides(two)).toContain(UPD);
  });

  it("keeps forward pairing on any other line", () => {
    hides(`ValueData=x1 - ValueName=DefaultPassword - ValueData=${VALUE}`);
    hides(`ValueName=Updater - ValueData=${UPD} - ValueName=DefaultPassword - ValueData=${VALUE}`);
    const setting = "ValueData=0 - ValueName=LimitBlankPasswordUse";
    expect(redactSecretText(setting)).toBe(setting);
  });
});

describe("redactSecretText — PowerShell forms that set the value (#3040)", () => {
  it("binds Name and Value by position, prefix, colon and the sp alias", () => {
    for (const row of [
      `Set-ItemProperty '${WP}' DefaultPassword ${VALUE}`,
      `Set-ItemProperty -Path '${WP}' DefaultPassword ${VALUE}`,
      `Set-ItemProperty -Name DefaultPassword '${WP}' ${VALUE}`,
      `Set-ItemProperty -Force '${WP}' DefaultPassword ${VALUE}`,
      `Set-ItemProperty -Confirm:$false '${WP}' DefaultPassword ${VALUE}`,
      `Set-ItemProperty -Path '${WP}' -N DefaultPassword -Va ${VALUE}`,
      `Set-ItemProperty -Path '${WP}' -Name:DefaultPassword -Value:${VALUE}`,
      `Set-ItemProperty -Value:'${VALUE} x' -Name:'DefaultPassword' -Path '${WP}'`,
      `sp '${WP}' DefaultPassword ${VALUE}`,
      `sp -Path '${WP}' -Name DefaultPassword -Value ${VALUE}`,
    ])
      hides(row);
  });

  it("hides a splatted hashtable value and a .NET SetValue argument", () => {
    hides(`$p=@{Path='${WP}';Name='DefaultPassword';Value='${VALUE}'}; Set-ItemProperty @p`);
    hides(`$p = @{\n  Path = '${WP}'\n  "Name" = "DefaultPassword"\n  Value = '${VALUE}'\n}`);
    hides(`[Microsoft.Win32.Registry]::SetValue('${WINLOGON}','DefaultPassword','${VALUE}')`);
    hides(`[Microsoft.Win32.Registry]::SetValue("${WINLOGON}", "DefaultPassword", "${VALUE}", 'String')`);
    hides(`$k.SetValue('DefaultPassword','${VALUE}')`);
    hides(`$k.SetValue('DefaultPassword','${VALUE}','String')`);
  });

  it("does not guess a value it cannot bind", () => {
    for (const row of [
      `New-ItemProperty -Path HKLM:\\x -Name DefaultPassword -PropertyType String`,
      `New-ItemProperty HKLM:\\x DefaultPassword -PropertyType String -Force`,
      `Set-ItemProperty -Path HKLM:\\x -Name DefaultPassword -Verbose`,
      `Set-ItemProperty -Path HKLM:\\x -Name DefaultPassword -V ${VALUE}`,
      `Set-ItemProperty -Zork HKLM:\\x DefaultPassword ${VALUE}`,
      `Set-ItemProperty HKLM:\\x DefaultPassword $pw`,
      `$k.SetValue('${VALUE}','DefaultPassword','x')`,
      `[Microsoft.Win32.Registry]::SetValue('DefaultPassword','x','${VALUE}')`,
      `[Microsoft.Win32.Registry]::SetValue('K','DefaultPassword',$pw)`,
      `echo sp is a word DefaultPassword ${VALUE}`,
    ])
      expect(redactSecretText(row)).toBe(row);
  });

  it("keeps the data of a setting or persistence value", () => {
    for (const row of [
      `sp '${WP}' AutoAdminLogon 1`,
      `Set-ItemProperty '${WP}' DefaultUserName svc_x`,
      `[Microsoft.Win32.Registry]::SetValue('${RUN}','PasswordManager','C:\\pm.exe')`,
      `$p=@{Name='AutoAdminLogon';Value='1'}`,
    ])
      expect(redactSecretText(row)).toBe(row);
  });

  it("never swallows a following encoded command or splits a card number", () => {
    const enc = redactSecretText(`sp '${WP}' DefaultPassword ${VALUE}; powershell -enc ${B64}`);
    expect(enc).toContain(`DefaultPassword ${PH}; powershell -enc ${B64}`);
    const cue = redactSecretText(
      `[Microsoft.Win32.Registry]::SetValue('K','DefaultPassword','v FromBase64String(')`,
    );
    expect(cue).toContain("FromBase64String(");
    expect(redactSecretText(`sp HKLM:\\x DefaultPassword ${CARD}`)).toBe(`sp HKLM:\\x DefaultPassword ${PH}`);
  });

  it("reads a second cmdlet on the same line as its own command", () => {
    const row = `Set-ItemProperty -Path HKLM:\\x -N DefaultUserName -Va svc_x Set-ItemProperty HKLM:\\x -Name DefaultPassword -Value ${VALUE}`;
    expect(hides(row)).toBe(
      `Set-ItemProperty -Path HKLM:\\x -N DefaultUserName -Va svc_x Set-ItemProperty HKLM:\\x -Name DefaultPassword -Value ${PH}`,
    );
  });

  it("never takes a following parameter as an unknown option's argument", () => {
    hides(`Set-ItemProperty -Path HKLM:\\x -Zork -Name DefaultPassword -Value ${VALUE}`);
    hides(`Set-ItemProperty -Path HKLM:\\x -Name DefaultPassword -wh -Value ${VALUE}`);
    hides(`Set-ItemProperty -Path HKLM:\\x -verb -Name DefaultPassword -Value ${VALUE}`);
  });

  it("hides the value inside a JSON CommandLine or a powershell -c string", () => {
    hides(JSON.stringify({ CommandLine: `powershell sp HKLM:\\x DefaultPassword ${VALUE}` }));
    hides(
      JSON.stringify({
        CommandLine: `powershell Set-ItemProperty -Path "HKLM:\\x" -N DefaultPassword -Va "${VALUE}"`,
      }),
    );
    hides(
      JSON.stringify({
        ScriptBlockText: `$p=@{Name="DefaultPassword";Value="${VALUE}"}; Set-ItemProperty @p`,
      }),
    );
    hides(
      JSON.stringify({
        ScriptBlockText: `[Microsoft.Win32.Registry]::SetValue("K", "DefaultPassword", "${VALUE}")`,
      }),
    );
    hides(`powershell -c "Set-ItemProperty -Path 'HKLM:\\x' -N DefaultPassword -Va '${VALUE}'"`);
    hides(`powershell -c "$p=@{Name='DefaultPassword';Value='${VALUE}'}; sp @p"`);
  });

  it("reads a second cmdlet glued to the end of the first one", () => {
    const row = `Set-ItemProperty -Path HKLM:\\x -N DefaultUserName -Va 'svc_x'0Set-ItemProperty HKLM:\\x -Name DefaultPassword -Value '${VALUE}'`;
    hides(row);
    expect(redactSecretText(row)).toContain("'svc_x'");
  });

  it("merges overlapping hits into one redaction without losing or repeating text", () => {
    // The reg query hit runs to the line end and holds both SetValue hits.
    const row = `    DefaultPassword    REG_SZ    a $k.SetValue('DefaultPassword','b') $k.SetValue('DefaultPassword','${VALUE}')`;
    expect(hides(row)).toBe(`    DefaultPassword    REG_SZ    ${PH}`);
  });
});

describe("redactSecretText — long inputs stay linear (#3040)", () => {
  it("reads one long data-first line and a script full of hashtables quickly", () => {
    const line = Array.from({ length: 3000 }, (_, i) => `ValueData=v${i} - ValueName=DefaultPassword`).join(
      " - ",
    );
    const script = Array.from({ length: 8000 }, (_, i) => `$h${i}=@{a=${i};b='x'}; Write-Host $h${i}`).join(
      "\n",
    );
    const t0 = performance.now();
    expect(redactSecretText(line)).not.toContain("ValueData=v1 ");
    redactSecretText(script);
    redactSecretText("@{".repeat(40000));
    expect(performance.now() - t0).toBeLessThan(5000);
  });
});

describe("full anonymizer — more registry credential shapes (#3040)", () => {
  const rows = [
    pretty({ ValueData: VALUE, ValueName: "DefaultPassword" }),
    `{"a":5}5"ValueName":"DefaultPassword","ValueData":"${VALUE}"}`,
    JSON.stringify({ TargetObject: WINLOGON, ValueData: VALUE, ValueName: "DefaultPassword" }),
    `ValueData=${VALUE} - ValueName=DefaultPassword - Type=REG_SZ`,
    `Set-ItemProperty '${WP}' DefaultPassword ${VALUE}`,
    `$k.SetValue('DefaultPassword','${VALUE}')`,
  ];
  for (const maskPublicIps of [true, false])
    it(`sends none of them in clear, and restore keeps them hidden (public masking ${maskPublicIps})`, () => {
      for (const row of rows) {
        const anon = createAnonymizer(
          { ...policy, maskPublicIps },
          { hosts: [], accounts: [], internalDomains: [] },
        );
        const out = anon.apply(row);
        expect(out).not.toContain(VALUE);
        expect(anon.restore(out)).not.toContain(VALUE);
      }
    });

  it("still tokenizes an address given as the data elsewhere in the row", () => {
    const anon = createAnonymizer(policy, { hosts: [], accounts: [], internalDomains: [] });
    const row = `sp HKLM:\\x DefaultPassword ${VALUE} ; contact ${EMAIL}`;
    const out = anon.apply(row);
    expect(out).not.toContain(VALUE);
    expect(out).not.toContain(EMAIL);
  });
});
