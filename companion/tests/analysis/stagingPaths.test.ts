import { describe, expect, it } from "vitest";
import { isStagedCommandValue, isStagedPath, isVendorRootPath } from "../../src/analysis/stagingPaths.js";

// companion/src/analysis/stagingPaths.ts — the one definition of "this file sits somewhere a
// legitimately-installed binary does not".
//
// THE POINT OF THIS FILE IS THAT THE TWO MATCHERS CANNOT DISAGREE. Three copies of the staging-path
// idea had drifted apart before they were merged here, and then the merged version drifted again:
// the bare-path list was a second hand-typed literal, so perflogs and $Recycle.Bin were added to it
// and never reached the command-value matcher, while the file's own header comment promised the two
// could not diverge. The list is now derived rather than retyped, and the first block below is what
// holds that: every shared directory has to be recognised by BOTH matchers, so a directory added to
// one and not the other fails here instead of shipping as a silent detection gap.
const SHARED_DIRS: readonly { dir: string; command: string; bare: string }[] = [
  { dir: "temp", command: String.raw`C:\Temp\x.exe`, bare: String.raw`C:\Temp\x.exe` },
  { dir: "tmp", command: String.raw`C:\tmp\x.exe`, bare: String.raw`C:\tmp\x.exe` },
  {
    dir: "appdata\\local\\temp",
    command: String.raw`C:\Users\bob\AppData\Local\Temp\x.exe`,
    bare: String.raw`C:\Users\bob\AppData\Local\Temp\x.exe`,
  },
  {
    dir: "programdata",
    command: String.raw`C:\ProgramData\x.exe`,
    bare: String.raw`C:\ProgramData\x.exe`,
  },
  {
    dir: "public",
    command: String.raw`C:\Users\Public\x.exe`,
    bare: String.raw`C:\Users\Public\x.exe`,
  },
  {
    dir: "windows\\temp",
    command: String.raw`C:\Windows\Temp\x.exe`,
    bare: String.raw`C:\Windows\Temp\x.exe`,
  },
];

describe("staging directories are shared by both matchers", () => {
  for (const { dir, command, bare } of SHARED_DIRS) {
    it(`${dir} is staging for a command value and for a bare path`, () => {
      expect(isStagedCommandValue(command)).toBe(true);
      expect(isStagedPath(bare)).toBe(true);
    });
  }

  // Forward slashes are the reason the bare-path list is a separate expression at all. A file-stat
  // artifact hands over whichever separator the collector used.
  it("accepts either separator on a bare path", () => {
    expect(isStagedPath("C:/Users/bob/AppData/Local/Temp/x.exe")).toBe(true);
    expect(isStagedPath(String.raw`\\host\share\ProgramData\x.exe`)).toBe(true);
  });

  // These two are deliberately bare-path-only. Teaching the command-value matcher about them widens
  // what persistenceSniperImport flags, which is a detection change and needs its own test — this
  // one only pins where the asymmetry currently sits, so a future change to it is a decision rather
  // than an accident.
  it("keeps perflogs and $Recycle.Bin on the bare-path side only", () => {
    expect(isStagedPath(String.raw`C:\PerfLogs\x.exe`)).toBe(true);
    expect(isStagedPath(String.raw`C:\$Recycle.Bin\S-1-5-21\x.exe`)).toBe(true);
    expect(isStagedCommandValue(String.raw`C:\PerfLogs\x.exe`)).toBe(false);
  });

  // User-writable locations a dropped binary often sits in, which a command-line value would rarely
  // name. Bare-path side only, like the two above.
  it("treats a user's Downloads/Desktop/Documents as staging for a bare path", () => {
    expect(isStagedPath(String.raw`C:\Users\bob\Downloads\x.exe`)).toBe(true);
    expect(isStagedPath(String.raw`C:\Users\bob\Desktop\x.exe`)).toBe(true);
    expect(isStagedPath(String.raw`C:\Users\bob\Documents\x.exe`)).toBe(true);
  });
});

describe("isStagedCommandValue only claims the row's OWN target", () => {
  // "msiexec.exe /i C:\Windows\Temp\update.msi" runs msiexec, not the staged .msi. Flagging it was a
  // real false positive, so only a LEADING path or a QUOTED one anywhere counts.
  it("ignores an unquoted staged path sitting in an argument list", () => {
    expect(isStagedCommandValue(String.raw`msiexec.exe /i C:\Windows\Temp\update.msi`)).toBe(false);
  });

  it("claims a quoted staged path anywhere in the value", () => {
    expect(isStagedCommandValue(String.raw`rundll32.exe "C:\ProgramData\x.dll",stow`)).toBe(true);
  });

  // The file has to sit DIRECTLY in the staging directory. A deep vendor path below one must not
  // match — Defender's Platform\<ver>\MpCmdRun.exe was the case that made this rule.
  it("does not match a file nested below the staging directory", () => {
    expect(isStagedCommandValue(String.raw`C:\ProgramData\Vendor\Platform\1.2\MpCmdRun.exe`)).toBe(false);
  });

  // A bare \b matched an extension PREFIX inside a multi-dot filename: readme.hta.txt is a .txt
  // file, not an .hta.
  it("does not treat a multi-dot filename as its middle extension", () => {
    expect(isStagedCommandValue(String.raw`C:\Windows\Temp\readme.hta.txt`)).toBe(false);
  });

  // An allow-list of terminators silently dropped cmd.exe operators, so the guard rejects only what
  // is actually wrong: another dot, or a continuing word character.
  it("still matches when a cmd.exe operator follows the extension", () => {
    expect(isStagedCommandValue(String.raw`C:\Windows\Temp\evil.exe&calc.exe`)).toBe(true);
  });
});

describe("isVendorRootPath", () => {
  it("recognises the OS and Program Files install roots", () => {
    expect(isVendorRootPath(String.raw`C:\Program Files\Vendor\app.exe`)).toBe(true);
    expect(isVendorRootPath(String.raw`C:\Program Files (x86)\Vendor\app.exe`)).toBe(true);
    expect(isVendorRootPath(String.raw`C:\Windows\System32\svchost.exe`)).toBe(true);
  });

  // NOT the inverse of staging. C:\Tools is neither, and callers must treat that middle as neutral
  // rather than as evidence either way.
  it("leaves the ambiguous middle as neither staged nor vendor-owned", () => {
    const p = String.raw`C:\Tools\app.exe`;
    expect(isVendorRootPath(p)).toBe(false);
    expect(isStagedPath(p)).toBe(false);
  });
});
