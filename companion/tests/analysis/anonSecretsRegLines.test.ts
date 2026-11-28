import { describe, it, expect } from "vitest";
import { redactSecretText, SECRET_PLACEHOLDER as PH } from "../../src/analysis/anonSecrets.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";
import { PS_QUOTE_PATTERNS } from "../../src/analysis/anonSecretPsQuote.js";
import { REG_COMMAND_PATTERNS } from "../../src/analysis/anonSecretRegCommands.js";
import { checkRegexSafety } from "../../src/analysis/regexSafety.js";

// #3057 — five registry-credential shapes left after #3054: a command right after a JSON-escaped line
// break (the 4104 ScriptBlockText carrier), reg add with cmd-doubled quotes, reg add with a $variable,
// concatenated literals, and a here-string longer than the command window. Every fixture value is
// built at runtime.
const join = (...parts: string[]) => parts.join("");
const P1 = "Hunt";
const P2 = join("er2", "Value77");
const VALUE = P1 + P2;
const WP = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const WR = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const RUN = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const RUNR = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const UPD = "C:\\u.exe";
const B64 = join("SQBFAFgAIAAo", "AE4AZQB3AC0ATwBi", "AGoAZQBjAHQA");
const LONG = "x".repeat(1100);
const script = (s: string) => JSON.stringify({ ScriptBlockText: s });
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
  for (const s of secrets.length ? secrets : [VALUE, P2, "Value77"]) expect(out, row).not.toContain(s);
  expect(out).toContain(PH);
  return out;
};
const keeps = (row: string, ...kept: string[]) => {
  const out = redactSecretText(row);
  for (const k of kept) expect(out, row).toContain(k);
  return out;
};

describe("redactSecretText — a command after a JSON-escaped line break (#3057)", () => {
  it("reads sp, Set-/New-ItemProperty and reg add after \\n, \\r\\n or \\t", () => {
    for (const row of [
      script(`Write-Host a\nsp '${WP}' DefaultPassword '${VALUE}'`),
      script(`$a=1\nSet-ItemProperty -Path '${WP}' -Name DefaultPassword -Value '${VALUE}'`),
      script(`$a=1\r\nNew-ItemProperty -Path '${WP}' -Name DefaultPassword -Value '${VALUE}' -Force`),
      script(`$a=1\tsp '${WP}' DefaultPassword '${VALUE}'`),
      script(`echo a\nreg add "${WR}" /v DefaultPassword /d ${VALUE} /f`),
    ])
      hides(row);
  });

  it("reads the second command when the first one on the line before sets another value", () => {
    hides(script(`sp '${RUN}' Updater '${UPD}'\nsp '${WP}' DefaultPassword '${VALUE}'`));
    hides(script(`sp '${RUN}' Updater ${UPD}\nsp '${WP}' DefaultPassword ${VALUE}`));
    const out = hides(
      script(`reg add "${RUNR}" /v Updater /d ${UPD}\nreg add "${WR}" /v DefaultPassword /d ${VALUE}`),
    );
    expect(out).toContain("u.exe");
  });

  it("reads a hashtable written over JSON-escaped lines", () => {
    hides(script(`$p = @{\n  Path = '${WP}'\n  Name = 'DefaultPassword'\n  Value = '${VALUE}'\n}\nsp @p`));
  });

  it("keeps an escaped backslash, persistence data and an encoded command", () => {
    keeps(JSON.stringify({ P: `C:\\nsp x DefaultPassword yy` }), "yy");
    keeps(script(`Write-Host a\nsp '${RUN}' Updater '${UPD}'`), "u.exe");
    const out = redactSecretText(
      script(`Write-Host a\nsp '${WP}' DefaultPassword x; powershell -enc ${B64}`),
    );
    expect(out).toContain(B64);
    expect(out).toContain(PH);
  });

  it("keeps hiding a raw value or key that holds a backslash and a letter", () => {
    hides(`cmd /c "reg add HKLM\\x\\new /v DefaultPassword /d ${VALUE} /f"`);
    hides(`CommandLine: "reg add HKLM\\run\\tmp /v DefaultPassword /d ab\\nq${VALUE} /f"`, VALUE);
    hides(`"sp HKLM:\\temp\\nx DefaultPassword ${VALUE}\\rest"`, VALUE);
  });
});

describe("redactSecretText — reg add with doubled quotes or a variable (#3057)", () => {
  it("reads cmd-doubled quotes around the key and the data", () => {
    hides(`cmd /c "reg add ""${WR}"" /v DefaultPassword /t REG_SZ /d ""${VALUE}"" /f"`);
    hides(`cmd /c "reg add ""${WR}"" /v DefaultPassword /d ""${VALUE}"""`);
    hides(
      JSON.stringify({ CommandLine: `cmd /c "reg add ""${WR}"" /v DefaultPassword /d ""${VALUE}"" /f"` }),
    );
    keeps(`cmd /c "reg add ""${WR}"" /v DefaultPassword /d ""${VALUE}"" /f" & echo donex`, "donex");
    keeps(`cmd /c "reg add ""${RUNR}"" /v Updater /d ""${UPD}"" /f"`, "u.exe");
  });

  it("follows a $variable to the literal assigned to it", () => {
    hides(`$v="${VALUE}"; reg add HKLM\\x /v DefaultPassword /d $v`);
    hides(`$v = '${VALUE}'\nreg add "${WR}" /v DefaultPassword /t REG_SZ /d $v /f`);
    hides(`$v = '${VALUE}'; reg add "${WR}" /v DefaultPassword /d "$v" /f`);
    keeps(`$v = '${UPD}'; reg add "${RUNR}" /v Updater /d $v /f`, "u.exe");
    keeps(`$v = '${UPD}'; reg add "${WR}" /v DefaultPassword /d $w /f`, "u.exe");
    keeps(`$v = '${UPD}'; reg add "${WR}" /v DefaultPassword /d '$v' /f`, "u.exe");
  });
});

describe("redactSecretText — concatenated literals (#3057)", () => {
  it("hides every literal of the concatenation", () => {
    hides(`$pw = '${P1}' + '${P2}'; sp '${WP}' DefaultPassword $pw`);
    hides(
      `$pw = "${P1}" + "er2" + "Value77"; Set-ItemProperty -Path '${WP}' -Name DefaultPassword -Value $pw`,
    );
    hides(`[Microsoft.Win32.Registry]::SetValue('${WR}','DefaultPassword','${P1}' + '${P2}')`);
    hides(`$p=@{Path='${WP}';Name='DefaultPassword';Value='${P1}' + '${P2}'}; sp @p`);
    hides(script(`$pw = '${P1}' + '${P2}'\nsp '${WP}' DefaultPassword $pw`));
    hides(`$pw = '${P1}' + $x + '${P2}'; sp '${WP}' DefaultPassword $pw`);
  });

  it("keeps a concatenation set as another value, and an encoded command operand", () => {
    keeps(`$v = 'C:\\' + 'u.exe'; sp '${RUN}' Updater $v`, "u.exe");
    const out = redactSecretText(
      `$pw = 'x' + [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${B64}')); sp '${WP}' DefaultPassword $pw`,
    );
    expect(out).toContain(B64);
  });
});

describe("redactSecretText — a here-string longer than the command window (#3057)", () => {
  it("hides the whole here-string", () => {
    for (const row of [
      `$pw = @'\n${LONG}\n${VALUE}\n'@; sp '${WP}' DefaultPassword $pw`,
      `sp '${WP}' DefaultPassword @'\n${LONG}\n${VALUE}\n'@`,
      script(`$pw = @'\n${LONG}\n${VALUE}\n'@\nsp '${WP}' DefaultPassword $pw`),
      `$k.SetValue('DefaultPassword', @'\n${LONG}\n${VALUE}\n'@)`,
      `$p=@{Path='${WP}';Name='DefaultPassword';Value=@'\n${LONG}\n${VALUE}\n'@}; sp @p`,
    ])
      hides(row);
  });

  it("keeps the lines after it and a here-string set as another value", () => {
    keeps(`sp '${WP}' DefaultPassword @'\n${LONG}\n${VALUE}\n'@\nWrite-Host afterx`, "afterx");
    keeps(`sp '${RUN}' Updater @'\n${LONG}\n${UPD}\n'@`, "u.exe");
  });

  it("reads a command written inside a here-string set as another value", () => {
    hides(`sp '${RUN}' Updater @'\n${LONG}\nsp '${WP}' DefaultPassword '${VALUE}'\n'@`);
    hides(`sp '${RUN}' Updater @'\nsp '${WP}' DefaultPassword '${VALUE}'\n'@`);
  });
});

describe("redactSecretText — the #3057 shapes stay linear", () => {
  it("uses only safe patterns", () => {
    for (const re of [...PS_QUOTE_PATTERNS, ...REG_COMMAND_PATTERNS])
      expect(checkRegexSafety(re.source, re.flags).ok).toBe(true);
  });

  it("reads many line-break starts, here-string openers, concatenations and variables quickly", () => {
    const rows = [
      script("a\\nsp ".repeat(20000)),
      script(`${"x\nsp K DefaultPassword y".repeat(5000)}`),
      `${"sp K DefaultPassword @'\n".repeat(5000)}`,
      `${"$v = @'\n".repeat(5000)}${"sp K DefaultPassword $v; ".repeat(2000)}`,
      `$pw = ${"'a' + ".repeat(20000)}'b'; sp K DefaultPassword $pw`,
      `[Microsoft.Win32.Registry]::SetValue('K','DefaultPassword',${"'a' + $x + ".repeat(10000)}'b')`,
      `$v = 'x'; ${"reg add K /v DefaultPassword /d $v; ".repeat(4000)}`,
      `cmd /c "reg add ${'""'.repeat(40000)}`,
      `$v = @'\n${"y".repeat(16000)}\n'@\n${"sp K DefaultPassword $v; ".repeat(150)}\n`.repeat(4),
      script(`$p = @{${"\n Name = 'DefaultPassword'".repeat(5000)}}`),
    ];
    const t0 = performance.now();
    for (const row of rows) redactSecretText(row);
    expect(performance.now() - t0).toBeLessThan(5000);
  });
});

describe("full anonymizer — the #3057 shapes", () => {
  const rows = [
    script(`Write-Host a\nsp '${WP}' DefaultPassword '${VALUE}'`),
    `cmd /c "reg add ""${WR}"" /v DefaultPassword /d ""${VALUE}"" /f"`,
    `$v="${VALUE}"; reg add HKLM\\x /v DefaultPassword /d $v`,
    `$pw = '${P1}' + '${P2}'; sp '${WP}' DefaultPassword $pw`,
    `$pw = @'\n${LONG}\n${VALUE}\n'@; sp '${WP}' DefaultPassword $pw`,
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
        expect(out).not.toContain(P2);
        expect(anon.restore(out)).not.toContain(P2);
      }
    });
});
