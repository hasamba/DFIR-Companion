import { describe, it, expect } from "vitest";
import { redactSecretText, SECRET_PLACEHOLDER as PH } from "../../src/analysis/anonSecrets.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";
import { REG_FILE_PATTERNS } from "../../src/analysis/anonSecretRegFile.js";
import { PS_QUOTE_PATTERNS } from "../../src/analysis/anonSecretPsQuote.js";
import { checkRegexSafety } from "../../src/analysis/regexSafety.js";

// #3051 — the stored-credential registry shapes left after #3047: a FromBase64String blob quoted with
// '' inside a single-quoted value, the "" and backtick escapes of a double-quoted PowerShell value,
// here-strings, and .reg bodies inside a JSON string or written as hex. Every fixture value is built
// at runtime.
const join = (...parts: string[]) => parts.join("");
const VALUE = join("Hunt", "er2Value77");
const HEAD = "Hunt";
const TAIL = join("er2", "Value77");
const BT = "`";
const WP = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const WH = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const RUN = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
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

describe("redactSecretText — a '' quoted FromBase64String blob in the value (#3051)", () => {
  const value = `'x FromBase64String(''${B64}'')'`;
  it("hides the blob with the value, since the CMD pass cannot tokenize it", () => {
    for (const row of [
      `sp '${WP}' DefaultPassword ${value}`,
      `Set-ItemProperty -Path '${WP}' -Name DefaultPassword -Value ${value}`,
      `$p=@{Path='${WP}';Name='DefaultPassword';Value=${value}}; sp @p`,
      `[Microsoft.Win32.Registry]::SetValue('${WH}','DefaultPassword',${value})`,
      JSON.stringify({ ScriptBlockText: `sp '${WP}' DefaultPassword ${value}` }),
      `sp "${WP}" DefaultPassword "x FromBase64String(""${B64}"")"`,
      `sp "${WP}" DefaultPassword "x FromBase64String(${BT}"${B64}${BT}")"`,
    ])
      hides(row, B64);
  });

  it("still stops before a cue the CMD pass tokenizes", () => {
    expect(redactSecretText(`sp '${WP}' DefaultPassword 'x' FromBase64String('${B64}')`)).toContain(
      `FromBase64String('${B64}')`,
    );
    expect(redactSecretText(`sp '${WP}' DefaultPassword '${VALUE}'; powershell -enc ${B64}`)).toContain(
      `-enc ${B64}`,
    );
    expect(
      redactSecretText(
        `Set-ItemProperty -Path HKLM:\\x -Name DefaultPassword -Value 'v FromBase64String('${B64}')'`,
      ),
    ).toContain(`FromBase64String('${B64}')`);
  });

  it("gives the blob after a closed value its CMD token in the full anonymizer", () => {
    const anon = createAnonymizer(policy, { hosts: [], accounts: [], internalDomains: [] });
    const out = anon.apply(`sp '${WP}' DefaultPassword '${VALUE}' FromBase64String('${B64}')`);
    expect(out).toMatch(/FromBase64String\('ANON_CMD_\d+'\)/);
    expect(out).not.toContain(VALUE);
  });
});

describe("redactSecretText — double-quoted PowerShell escapes (#3051)", () => {
  it('hides the whole value across "" and a backtick quote', () => {
    for (const esc of [`"${HEAD}""${TAIL}"`, `"${HEAD}${BT}"${TAIL}"`]) {
      for (const row of [
        `Set-ItemProperty -Path "${WP}" -Name DefaultPassword -Value ${esc}`,
        `sp "${WP}" DefaultPassword ${esc}`,
        `Set-ItemProperty -Path "${WP}" -Name DefaultPassword -Value:${esc}`,
        `$p=@{Path="${WP}";Name="DefaultPassword";Value=${esc}}; sp @p`,
        `[Microsoft.Win32.Registry]::SetValue("${WH}","DefaultPassword",${esc})`,
        `$k.SetValue("DefaultPassword",${esc})`,
        JSON.stringify({ ScriptBlockText: `sp "${WP}" DefaultPassword ${esc}` }),
      ])
        expect(hides(row, TAIL)).not.toContain(HEAD);
    }
    hides(`sp "${WP}" DefaultPassword "${VALUE}${BT}""`);
    hides(`reg add "${WH}" /v DefaultPassword /d "${HEAD}""${TAIL}" /f`, TAIL);
  });

  it("ends the value at a quote after an even run of backticks", () => {
    const out = hides(`sp "${WP}" DefaultPassword "${HEAD}${BT}${BT}" ; echo ${TAIL}`, HEAD);
    expect(out).toContain(`echo ${TAIL}`);
  });

  it('does not read "" as an escape inside an outer quoted command, nor a backtick in reg add', () => {
    const nested = redactSecretText(`cmd /c "reg add K /v DefaultPassword /d "${VALUE}"" & echo "after"`);
    expect(nested).not.toContain(VALUE);
    expect(nested).toContain(`& echo "after"`);
    const cmd = redactSecretText(`reg add K /v DefaultPassword /d "${VALUE}${BT}" /f "Updater"`);
    expect(cmd).not.toContain(VALUE);
    expect(cmd).toContain(`/f "Updater"`);
  });

  it("never lets a stray escape move where the next command starts", () => {
    const row = join(
      `Set-ItemProperty -Path K -Name:DefaultPassword -Value:v, reg add K /v X /d "a${BT}" /f x, `,
      `Set-ItemProperty -Path "K" -Name DefaultPassword -Value "a${BT}"${TAIL}"`,
    );
    hides(row, TAIL);
  });

  it("never lets a stray escape shift a call's arguments or leave its hashtable", () => {
    hides(`[Microsoft.Win32.Registry]::SetValue("HKLM\\x${BT}","DefaultPassword","${VALUE}")`);
    hides(`$p=@{Path="K";Name="DefaultPassword";Value="${VALUE}${BT}"}; sp @p; echo "x"`);
    hides(`$p=@{Path="K${BT}";Name="DefaultPassword";Value="${VALUE}"}; sp @p`);
  });

  it("keeps the closed first part when the continuation never closes", () => {
    const out = hides(`sp "${WP}" DefaultPassword "${VALUE}${BT}" tail`);
    expect(out).toContain(`${PH}" tail`);
  });
});

describe("redactSecretText — PowerShell here-strings (#3051)", () => {
  it("hides the here-string content and keeps the script after it", () => {
    for (const [open, close] of [
      ["@'", "'@"],
      ['@"', '"@'],
    ]) {
      const here = `${open}\n${VALUE}\n${close}`;
      for (const row of [
        `Set-ItemProperty -Path '${WP}' -Name DefaultPassword -Value ${here}\nWrite-Host done`,
        `sp '${WP}' DefaultPassword ${here}\nWrite-Host done`,
        `$p=@{Path='${WP}';Name='DefaultPassword';Value=${here}}\nWrite-Host done`,
        `[Microsoft.Win32.Registry]::SetValue('${WH}','DefaultPassword',${here})\nWrite-Host done`,
      ])
        expect(hides(row)).toContain(`${PH}\n${close}`);
    }
    expect(hides(`sp '${WP}' DefaultPassword @'\r\n${VALUE}\r\n'@`)).toContain(`${PH}\r\n'@`);
    hides(`sp '${WP}' DefaultPassword @'\n${HEAD}\n${TAIL}\n'@`, HEAD, TAIL);
    hides(JSON.stringify({ ScriptBlockText: `sp '${WP}' DefaultPassword @'\n${VALUE}\n'@` }));
    hides(JSON.stringify({ ScriptBlockText: `sp '${WP}' DefaultPassword @"\r\n${VALUE}\r\n"@` }));
  });

  it("ends the command after the here-string, so the next line's command is read on its own", () => {
    const row = join(
      `sp '${WP}' DefaultPassword @"\n${HEAD}\n"@ ${BT}"1, `,
      `sp HKLM:\\x DefaultPassword "${TAIL} FromBase64String(""${B64}"")"`,
    );
    hides(row, HEAD, TAIL, B64);
  });

  it("hides the first line of an unterminated here-string only", () => {
    const out = hides(`sp '${WP}' DefaultPassword @'\n${VALUE}\nWrite-Host done`);
    expect(out).toContain(`${PH}\nWrite-Host done`);
  });

  it("leaves an empty here-string alone; a variable is followed to its assignment (#3054)", () => {
    const empty = `sp '${WP}' DefaultPassword @'\n'@`;
    expect(redactSecretText(empty)).toBe(empty);
    const variable = `$v = @'\nx\n'@\nsp '${WP}' DefaultPassword $v`;
    expect(redactSecretText(variable)).toBe(`$v = @'\n${PH}\n'@\nsp '${WP}' DefaultPassword $v`);
  });
});

describe("redactSecretText — .reg bodies (#3051)", () => {
  const body = (line: string, nl = "\n") =>
    `Windows Registry Editor Version 5.00${nl}${nl}[${WH}]${nl}${line}`;

  it("hides a credential value of a .reg body inside a JSON string", () => {
    hides(JSON.stringify({ Content: body(`"AutoAdminLogon"="1"\n"DefaultPassword"="${VALUE}"`) }));
    hides(JSON.stringify({ Content: body(`"DefaultPassword"="${VALUE}"`, "\r\n") }));
    hides(JSON.stringify({ Content: `[${WH}]\n"DefaultPassword"="${HEAD}\\"${TAIL}"` }), HEAD, TAIL);
    const out = hides(
      JSON.stringify({ Content: body(`"AutoAdminLogon"="1"\n"DefaultPassword"="${VALUE}"`) }),
    );
    expect(out).toContain('\\"AutoAdminLogon\\"=\\"1\\"');
  });

  it("hides the hex bytes of a credential value, across continuation lines", () => {
    const hex = "48,00,75,00,6e,00,74,00";
    hides(body(`"DefaultPassword"=hex(1):${hex}`), "48,00", "6e,00");
    hides(body(`"DefaultPassword"=hex(2):48,00,75,00,\\\n  6e,00,74,00\n"X"="1"`), "48,00", "6e,00");
    hides(body(`"DefaultPassword"=hex:${hex}`), "75,00");
    hides(JSON.stringify({ Content: body(`"DefaultPassword"=hex(1):48,00,\\\n  6e,00`) }), "48,00", "6e,00");
    const out = hides(
      body(`"DefaultPassword"=hex(2):48,00,\\\n  6e,00\n"AutoAdminLogon"="1"`),
      "48,00",
      "6e,00",
    );
    expect(out).toContain('"AutoAdminLogon"="1"');
  });

  it("keeps other values, other sections and a deleted value visible", () => {
    const two = hides(body(`"DefaultPassword"="${VALUE}"\n\n[${RUN}]\n"Updater"="C:\\\\u.exe"`));
    expect(two).toContain('"Updater"="C:\\\\u.exe"');
    const json = hides(
      JSON.stringify({ C: body(`"DefaultPassword"="${VALUE}"\n\n[${RUN}]\n"Updater"="C:\\\\u.exe"`) }),
    );
    expect(json).toContain("Updater");
    expect(json).toContain("u.exe");
    const deleted = body(`"DefaultPassword"=-`);
    expect(redactSecretText(deleted)).toBe(deleted);
    const otherHex = body(`"Updater"=hex(2):43,00,3a,00`);
    expect(redactSecretText(otherHex)).toBe(otherHex);
  });
});

describe("redactSecretText — the #3051 shapes stay linear", () => {
  it("uses only backtracking-safe patterns", () => {
    for (const re of [...REG_FILE_PATTERNS, ...PS_QUOTE_PATTERNS])
      expect(checkRegexSafety(re.source, re.flags).ok).toBe(true);
  });

  it("reads long quote, backtick, here-string, hex and section runs quickly", () => {
    const rows = [
      `sp HKLM:\\x DefaultPassword ${'"'.repeat(60000)}`,
      `sp HKLM:\\x DefaultPassword "${`${BT}"`.repeat(30000)}`,
      `sp HKLM:\\x DefaultPassword ${"@'\n".repeat(30000)}`,
      `Registry.SetValue('K','DefaultPassword',${"@'\n".repeat(20000)}`,
      `[${WH}]\n"DefaultPassword"=hex(1):${"00,".repeat(60000)}`,
      `[${WH}]\n"DefaultPassword"=hex(1):${"00,\\\n  ".repeat(30000)}`,
      Array.from({ length: 5000 }, () => `[${WH}]\n"DefaultPassword"=hex(1):00,`).join("\n"),
      `${'\\n\\"DefaultPassword\\"=\\"x'.repeat(20000)}`,
      `x FromBase64String(''${"FromBase64String(''".repeat(20000)}`,
    ];
    const t0 = performance.now();
    for (const row of rows) redactSecretText(row);
    expect(performance.now() - t0).toBeLessThan(5000);
  });
});

describe("full anonymizer — the #3051 shapes", () => {
  const rows: [string, string][] = [
    [`sp '${WP}' DefaultPassword 'x FromBase64String(''${B64}'')'`, B64],
    [`sp "${WP}" DefaultPassword "${HEAD}${BT}"${TAIL}"`, TAIL],
    [`sp "${WP}" DefaultPassword "${HEAD}""${TAIL}"`, TAIL],
    [`sp '${WP}' DefaultPassword @'\n${VALUE}\n'@`, VALUE],
    [JSON.stringify({ Content: `[${WH}]\n"DefaultPassword"="${VALUE}"` }), VALUE],
    [`[${WH}]\n"DefaultPassword"=hex(1):48,00,75,00`, "48,00,75,00"],
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
