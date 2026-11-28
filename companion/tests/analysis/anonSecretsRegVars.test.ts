import { describe, it, expect } from "vitest";
import { redactSecretText, SECRET_PLACEHOLDER as PH } from "../../src/analysis/anonSecrets.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";
import { PS_QUOTE_PATTERNS } from "../../src/analysis/anonSecretPsQuote.js";
import { checkRegexSafety } from "../../src/analysis/regexSafety.js";

// #3054 — three PowerShell shapes left after #3051: a literal assigned to a variable and passed later,
// cmd-doubled quotes ("") inside an outer double-quoted command, and a backtick escape inside the value
// name. Every fixture value is built at runtime.
const join = (...parts: string[]) => parts.join("");
const VALUE = join("Hunt", "er2Value77");
const BT = "`";
const WP = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const WH = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const RUN = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const UPD = "C:\\u.exe";
const B64 = join("SQBFAFgAIAAo", "AE4AZQB3AC0ATwBi", "AGoAZQBjAHQA");
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
const hides = (row: string, ...secrets: string[]) => {
  const out = redactSecretText(row);
  for (const s of secrets.length ? secrets : [VALUE]) expect(out).not.toContain(s);
  expect(out).toContain(PH);
  return out;
};
const keeps = (row: string) => expect(redactSecretText(row)).toBe(row);

describe("redactSecretText — a literal assigned to a variable and passed as the value (#3054)", () => {
  it("hides the literal at its assignment for a credential name", () => {
    for (const row of [
      `$v = @'\n${VALUE}\n'@\nsp '${WP}' DefaultPassword $v`,
      `$v=@'\n${VALUE}\n'@; sp '${WP}' DefaultPassword $v`,
      `$v = @"\n${VALUE}\n"@\nSet-ItemProperty -Path '${WP}' -Name DefaultPassword -Value $v`,
      `$pw = '${VALUE}'; Set-ItemProperty -Path '${WP}' -Name DefaultPassword -Value $pw`,
      `$pw = "${VALUE}"\nsp '${WP}' DefaultPassword $pw`,
      `$pw = '${VALUE}'; [Microsoft.Win32.Registry]::SetValue('${WH}','DefaultPassword',$pw)`,
      `$pw = '${VALUE}'; $k.SetValue('DefaultPassword', $pw)`,
      `$pw = '${VALUE}'; $p=@{Path='${WP}';Name='DefaultPassword';Value=$pw}; sp @p`,
      // The first readable Value entry still counts when an earlier one is not a literal.
      `$p=@{Path='${WP}';Name='DefaultPassword';Value=(x);Value='${VALUE}'}; sp @p`,
      JSON.stringify({ ScriptBlockText: `$v = @'\n${VALUE}\n'@; sp '${WP}' DefaultPassword $v` }),
      JSON.stringify({ ScriptBlockText: `$pw = "${VALUE}"; sp '${WP}' DefaultPassword $pw` }),
      `$PW = '${VALUE}'; sp '${WP}' DefaultPassword $pw`,
      `$script:pw = '${VALUE}'; sp '${WP}' DefaultPassword $script:pw`,
      `\${pw} = '${VALUE}'; sp '${WP}' DefaultPassword \${pw}`,
      `[string]$pw = '${VALUE}'; sp '${WP}' DefaultPassword $pw`,
      `$pw = '${VALUE}'; sp '${WP}' DefaultPassword "$pw"`,
      `$pw = 12345678; sp '${WP}' DefaultPassword $pw`.replace("12345678", "8675309"),
    ])
      hides(row, row.includes("8675309") ? "8675309" : VALUE);
  });

  it("follows the nearest assignment before the use only", () => {
    const row = `$pw = '${UPD}'; $pw = '${VALUE}'; sp '${WP}' DefaultPassword $pw`;
    expect(hides(row)).toContain(UPD);
    const run = `$v = '${UPD}'; sp '${RUN}' Updater $v; $v = '${VALUE}'; sp '${WP}' DefaultPassword $v`;
    expect(hides(run)).toContain(UPD);
    // One variable feeding both a Run value and the password: the literal is the password.
    hides(`$v = '${VALUE}'; sp '${RUN}' Updater $v; sp '${WP}' DefaultPassword $v`);
  });

  it("keeps a variable passed to any other name, or not a whole variable, visible", () => {
    for (const row of [
      `$v = '${UPD}'; sp '${RUN}' Updater $v`,
      `$v = '1'; sp '${WP}' AutoAdminLogon $v`,
      `$v = '${UPD}'; sp '${RUN}' Updater $v; sp '${WP}' DefaultPassword $other`,
      `$pw = '${UPD}'; sp '${WP}' DefaultPassword $pw.x`,
      `$pw = '${UPD}'; sp '${WP}' DefaultPassword $pw[0]`,
      `$env:pw = '${UPD}'; sp '${WP}' DefaultPassword $env:pw`,
      `$pw = '${UPD}'; sp '${WP}' DefaultPassword '$pw'`,
      `sp '${WP}' DefaultPassword $pw; $pw = '${UPD}'`,
      `$pw = Get-Content x; sp '${WP}' DefaultPassword $pw`,
      `$pw = '${UPD}'; $pw = Get-Content x; sp '${WP}' DefaultPassword $pw`,
      `$pw += '${UPD}'; sp '${WP}' DefaultPassword $pw`,
    ])
      keeps(row);
  });

  it("does not follow an unclosed literal, nor one past the window", () => {
    keeps(`$pw = '${UPD} and more\nsp '${WP}' DefaultPassword $pw`.replace(`'${WP}'`, "HKLM:\\x"));
    keeps(`$pw = '${UPD}'; ${"Write-Host x; ".repeat(400)}sp '${WP}' DefaultPassword $pw`);
  });

  it("keeps an encoded-command cue in the literal for the CMD pass", () => {
    const out = hides(`$pw = 'x FromBase64String('${B64}')'; sp '${WP}' DefaultPassword $pw`, "x FromBase64");
    expect(out).toContain(B64);
  });
});

describe("redactSecretText — doubled quotes inside an outer double-quoted command (#3054)", () => {
  it('reads a ""…"" argument as one token', () => {
    for (const row of [
      `powershell -c "sp ""${WP}"" DefaultPassword ""${VALUE}"""`,
      `powershell -c "Set-ItemProperty -Path ""${WP}"" -Name DefaultPassword -Value ""${VALUE}"""`,
      `powershell -c "Set-ItemProperty -Path ""${WP}"" -Name DefaultPassword -Value ""${VALUE}""; Write-Host done"`,
      JSON.stringify({ CommandLine: `powershell -c "sp ""${WP}"" DefaultPassword ""${VALUE}"""` }),
    ])
      hides(row);
  });

  it("keeps the rest of the line and other names visible", () => {
    const out = hides(`powershell -c "sp ""${WP}"" DefaultPassword ""${VALUE}""" & echo done`);
    expect(out).toContain("& echo done");
    keeps(`powershell -c "sp ""${RUN}"" Updater ""${UPD}"""`);
    // A close glued to more text is not a doubled-quote argument: nothing more is read.
    keeps(`powershell -c "sp ""${WP}"" DefaultPassword ""${UPD}""x more"`);
  });

  it("leaves an encoded command after it to the CMD pass", () => {
    const anon = createAnonymizer(policy, { hosts: [], accounts: [], internalDomains: [] });
    const out = anon.apply(`powershell -c "sp ""${WP}"" DefaultPassword ""x""" & powershell -enc ${B64}`);
    expect(out).not.toContain(B64);
    expect(anon.restore(out)).toContain(B64);
  });
});

describe("redactSecretText — a backtick escape inside the value name (#3054)", () => {
  it("reads the name without its escape backticks", () => {
    for (const row of [
      `$k.SetValue("DefaultPassword${BT}","${VALUE}")`,
      `$k.SetValue("Default${BT}Password","${VALUE}")`,
      `[Microsoft.Win32.Registry]::SetValue("${WH}","Default${BT}Password","${VALUE}")`,
      `sp "${WP}" "Default${BT}Password" "${VALUE}"`,
      `Set-ItemProperty -Path "${WP}" -Name "Default${BT}Password" -Value "${VALUE}"`,
      `$p=@{Path="${WP}";Name="Default${BT}Password";Value="${VALUE}"}; sp @p`,
      JSON.stringify({ ScriptBlockText: `$k.SetValue("DefaultPassword${BT}","${VALUE}")` }),
    ])
      hides(row);
  });

  it("keeps other names, a special escape and a single-quoted name as written", () => {
    for (const row of [
      `$k.SetValue("Upd${BT}ater","${UPD}")`,
      `$k.SetValue("LimitBlank${BT}PasswordUse",1)`,
      `$k.SetValue('Default${BT}Password','${UPD}')`,
      `$k.SetValue("Default${BT}nPassword","${UPD}")`,
    ])
      keeps(row);
  });
});

describe("redactSecretText — the #3054 shapes stay linear", () => {
  it("uses only safe patterns", () => {
    for (const re of PS_QUOTE_PATTERNS) expect(checkRegexSafety(re.source, re.flags).ok).toBe(true);
  });

  it("reads many assignments, uses and doubled quotes quickly", () => {
    const rows = [
      `${"$pw = 'x'; ".repeat(10000)}sp HKLM:\\x DefaultPassword $pw`,
      `$pw = 'x'; ${"sp HKLM:\\x DefaultPassword $pw; ".repeat(2000)}`,
      `${"$pw = '".repeat(5000)}; ${"sp HKLM:\\x DefaultPassword $pw; ".repeat(1500)}`,
      `powershell -c "sp ${'""'.repeat(40000)}`,
      // Many separate hidden values: the span merge stays linear in their number.
      "sp HKLM:\\x DefaultPassword y; ".repeat(4000),
      `powershell -c "sp ""x"" DefaultPassword ${'""x'.repeat(30000)}`,
      `${'$k.SetValue("Default`Password",$pw);'.repeat(2500)}`,
    ];
    const t0 = performance.now();
    for (const row of rows) redactSecretText(row);
    expect(performance.now() - t0).toBeLessThan(5000);
  });
});

describe("full anonymizer — the #3054 shapes", () => {
  const rows = [
    `$v=@'\n${VALUE}\n'@; sp '${WP}' DefaultPassword $v`,
    `powershell -c "sp ""${WP}"" DefaultPassword ""${VALUE}"""`,
    `$k.SetValue("DefaultPassword${BT}","${VALUE}")`,
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
});
