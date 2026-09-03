import { describe, expect, it } from "vitest";
import { compileSigmaText, compileSigmaToVql, SIGMA_VQL_CATEGORIES } from "../../src/analysis/sigmaToVql.js";
import { parseSigmaRule } from "../../src/analysis/sigmaRule.js";
import type { SigmaRefusal } from "../../src/analysis/sigmaRuleTypes.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// Golden VQL is compared byte for byte. A change here is a deliberate, reviewed diff of what every
// analyst's hunt will run — never loosen these to `toContain` to make a refactor pass.

function vql(yaml: string): string {
  const r = compileSigmaText(yaml);
  if (!r.ok)
    throw new Error(
      "expected VQL, got refusals:\n" + r.refusals.map((x) => `${x.path}: ${x.message}`).join("\n"),
    );
  return r.vql;
}
function compiled(yaml: string) {
  const r = compileSigmaText(yaml);
  if (!r.ok)
    throw new Error(
      "expected VQL, got refusals:\n" + r.refusals.map((x) => `${x.path}: ${x.message}`).join("\n"),
    );
  return r;
}
function refusals(yaml: string): SigmaRefusal[] {
  const r = compileSigmaText(yaml);
  if (r.ok) throw new Error("expected refusals, got VQL:\n" + r.vql);
  return r.refusals;
}
// A compiled rule is one or more blank-line-separated sources; each names its stage in a LET.
const sourcesOf = (text: string): string[] => text.split(/\n\s*\n/);
// The WHERE clause of the FIRST source (for process_creation: the pslist() one).
const whereOf = (text: string): string => {
  const first = sourcesOf(text)[0];
  const i = first.indexOf("\nWHERE ");
  if (i < 0) throw new Error("no WHERE in:\n" + text);
  return first.slice(i + "\nWHERE ".length);
};
const stagesOf = (text: string): (string | undefined)[] =>
  sourcesOf(text).map((s) => /^LET (\w+) <= SELECT[^\n]*\nSELECT \* FROM \1\n/m.exec(s)?.[1]);
const sourceOf = (text: string, stage: string): string => {
  const s = sourcesOf(text).find((b) => b.includes(`\nLET ${stage} <= SELECT`));
  if (!s) throw new Error(`no ${stage} source in:\n` + text);
  return s;
};

const rule = (category: string, detection: string, condition = "sel", head = "title: T") =>
  `${head}\nlogsource:\n  category: ${category}\n  product: windows\ndetection:\n${detection}\n  condition: ${condition}\n`;
const proc = (fields: string, condition?: string, head?: string) =>
  rule("process_creation", `  sel:\n${fields}`, condition, head);
const net = (fields: string) => rule("network_connection", `  sel:\n${fields}`);
const file = (fields: string) => rule("file_event", `  sel:\n${fields}`);
const reg = (fields: string, category = "registry_set") => rule(category, `  sel:\n${fields}`);

describe("compileSigmaToVql — golden process_creation", () => {
  it("compiles Image|endswith to a pslist() stage and a case-insensitive anchored regex", () => {
    expect(sourceOf(vql(proc("    Image|endswith: '\\certutil.exe'")), "Procs")).toBe(
      [
        String.raw`-- Sigma "T" → pslist(): running processes only, not process history`,
        String.raw`-- Compiled by DFIR Companion from a Sigma rule; the same rule always yields this VQL`,
        String.raw`LET Procs <= SELECT Pid, Ppid, Name, Exe AS Image, CommandLine, Username AS User FROM pslist()`,
        String.raw`SELECT * FROM Procs`,
        String.raw`WHERE Image =~ "(?i)\\\\certutil\\.exe$"`,
      ].join("\n"),
    );
  });

  it("never emits a blank line, because the hunt launcher splits statements on blank lines", () => {
    const text = vql(
      proc("    Image|endswith: '\\a.exe'\n    ParentImage|endswith: '\\b.exe'\n    sha256: 'abc'"),
    );
    for (const source of sourcesOf(text)) {
      expect(source).not.toMatch(/\n\s*\n/);
      expect(source.split("\n").filter((l) => !l.startsWith("--")).length).toBeGreaterThanOrEqual(3);
    }
  });

  it("pairs the live pslist() source with the event-history source, in that order (#802)", () => {
    expect(stagesOf(vql(proc("    Image: x")))).toEqual(["Procs", "ProcEvents"]);
  });

  it("puts the rule id in the header when the rule has one", () => {
    expect(
      vql(proc("    Image: x", undefined, "title: T\nid: 0b0c5c3e-1d2e-4f5a-8b9c-0d1e2f3a4b5c")).split(
        "\n",
      )[0],
    ).toBe(
      String.raw`-- Sigma "T" (0b0c5c3e-1d2e-4f5a-8b9c-0d1e2f3a4b5c) → pslist(): running processes only, not process history`,
    );
  });

  it("adds the parent lookup stage only when a parent field is used", () => {
    const withParent = vql(proc("    ParentImage|endswith: '\\cmd.exe'"));
    expect(withParent).toContain(
      String.raw`LET ByPid <= memoize(query={ SELECT Pid, Exe, CommandLine FROM pslist() }, key="Pid")`,
    );
    expect(withParent).toContain(
      String.raw`get(item=ByPid, field=str(str=Ppid)).Exe AS ParentImage, get(item=ByPid, field=str(str=Ppid)).CommandLine AS ParentCommandLine FROM pslist()`,
    );
    expect(whereOf(withParent)).toBe(String.raw`ParentImage =~ "(?i)\\\\cmd\\.exe$"`);
    expect(vql(proc("    Image: x"))).not.toContain("ByPid");
  });

  it("adds the hash column only when a hash field is used, and routes sha256/md5/sha1 to their own member", () => {
    const text = vql(proc("    sha256: 'AbC'\n    md5: 'd41d8cd98f00b204e9800998ecf8427e'"));
    expect(text).toContain(String.raw`Username AS User, hash(path=Exe) AS Hashes FROM pslist()`);
    expect(whereOf(text)).toBe(
      String.raw`(Hashes.SHA256 =~ "(?i)^AbC$" AND Hashes.MD5 =~ "(?i)^d41d8cd98f00b204e9800998ecf8427e$")`,
    );
    expect(vql(proc("    Image: x"))).not.toContain("hash(");
  });

  it("matches a bare Hashes value against all three members, and an ALG=value against one", () => {
    expect(whereOf(vql(proc("    Hashes|contains: 'abc'")))).toBe(
      String.raw`(Hashes.MD5 =~ "(?i)abc" OR Hashes.SHA1 =~ "(?i)abc" OR Hashes.SHA256 =~ "(?i)abc")`,
    );
    expect(whereOf(vql(proc("    Hashes|contains: 'SHA256=abc'")))).toBe(
      String.raw`Hashes.SHA256 =~ "(?i)abc"`,
    );
  });
});

describe("compileSigmaToVql — golden network_connection", () => {
  it("compiles to a netstat() stage with Sigma-named columns", () => {
    expect(vql(net("    DestinationIp: '203.0.113.10'\n    DestinationPort: 4444"))).toBe(
      [
        String.raw`-- Sigma "T" → netstat(): open connections only, not connection history`,
        String.raw`-- Compiled by DFIR Companion from a Sigma rule; the same rule always yields this VQL`,
        String.raw`LET Conns <= SELECT Pid, Status, Laddr.IP AS SourceIp, Laddr.Port AS SourcePort, Raddr.IP AS DestinationIp, Raddr.Port AS DestinationPort FROM netstat()`,
        String.raw`SELECT * FROM Conns`,
        String.raw`WHERE (DestinationIp =~ "(?i)^203\\.0\\.113\\.10$" AND DestinationPort = 4444)`,
      ].join("\n"),
    );
  });

  it("compiles cidr to cidr_contains on an ip column", () => {
    expect(whereOf(vql(net("    DestinationIp|cidr:\n      - '10.0.0.0/8'\n      - '192.168.0.0/16'")))).toBe(
      String.raw`cidr_contains(ip=DestinationIp, ranges=["10.0.0.0/8", "192.168.0.0/16"])`,
    );
  });

  it("looks the process image up by Pid only when Image is used", () => {
    const text = vql(net("    Image|endswith: '\\svchost.exe'"));
    expect(text).toContain(
      String.raw`LET ByPid <= memoize(query={ SELECT Pid, Exe FROM pslist() }, key="Pid")`,
    );
    expect(text).toContain(
      String.raw`Raddr.Port AS DestinationPort, get(item=ByPid, field=str(str=Pid)).Exe AS Image FROM netstat()`,
    );
    expect(vql(net("    DestinationPort: 1"))).not.toContain("ByPid");
  });

  it("refuses DestinationHostname because netstat() has no hostname column", () => {
    expect(refusals(net("    DestinationHostname|contains: 'example.invalid'"))).toEqual([
      { path: "detection.sel.DestinationHostname|contains", message: expect.stringMatching(/hostname/i) },
    ]);
  });
});

describe("compileSigmaToVql — golden file_event", () => {
  it("derives the glob from an exact path and says nothing about walking the disk", () => {
    const r = compiled(file("    TargetFilename: 'C:\\Windows\\Temp\\x.ps1'"));
    expect(r.vql).toBe(
      [
        String.raw`-- Sigma "T" → glob(): files on disk now under C:/Windows/Temp/x.ps1`,
        String.raw`-- Compiled by DFIR Companion from a Sigma rule; the same rule always yields this VQL`,
        String.raw`LET Files <= SELECT OSPath AS TargetFilename, Size, Mtime FROM glob(globs=["C:/Windows/Temp/x.ps1"])`,
        String.raw`SELECT * FROM Files`,
        String.raw`WHERE TargetFilename =~ "(?i)^C:\\\\Windows\\\\Temp\\\\x\\.ps1$"`,
      ].join("\n"),
    );
    expect(r.coverage).toBe("glob(): files on disk now under C:/Windows/Temp/x.ps1");
  });

  it("turns startswith into a prefix glob, and contains/endswith into a whole-disk walk that the header admits", () => {
    expect(vql(file("    TargetFilename|startswith: 'C:\\Users\\'"))).toContain(
      String.raw`glob(globs=["C:/Users/**"])`,
    );
    const r = compiled(file("    TargetFilename|contains: 'payload.ps1'"));
    expect(r.vql).toContain(String.raw`glob(globs=["C:/**/*payload.ps1*"])`);
    expect(r.coverage).toBe(
      "glob(): files on disk now under C:/**/*payload.ps1*, which walks the whole disk",
    );
    expect(vql(file("    TargetFilename|endswith: '.hta'"))).toContain(
      String.raw`glob(globs=["C:/**/*.hta"])`,
    );
  });

  it("keeps Sigma wildcards as glob wildcards and as regex wildcards", () => {
    const text = vql(file("    TargetFilename: 'C:\\Users\\*\\AppData\\evil?.exe'"));
    expect(text).toContain(String.raw`glob(globs=["C:/Users/*/AppData/evil?.exe"])`);
    expect(whereOf(text)).toBe(
      String.raw`TargetFilename =~ "(?i)^C:\\\\Users\\\\.*\\\\AppData\\\\evil.\\.exe$"`,
    );
  });

  it("dedupes globs across values and keeps document order", () => {
    const text = vql(file("    TargetFilename|contains:\n      - 'a.ps1'\n      - 'b.ps1'\n      - 'a.ps1'"));
    expect(text).toContain(String.raw`glob(globs=["C:/**/*a.ps1*", "C:/**/*b.ps1*"])`);
  });
});

describe("compileSigmaToVql — golden registry", () => {
  it("expands the hive, globs the key, and matches the accessor's full hive name", () => {
    expect(vql(reg("    TargetObject: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*'"))).toBe(
      [
        String.raw`-- Sigma "T" → glob(accessor="registry"): registry keys and values as they are now under HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/*`,
        String.raw`-- Compiled by DFIR Companion from a Sigma rule; the same rule always yields this VQL`,
        String.raw`LET Keys <= SELECT OSPath AS TargetObject, Data.value AS Details, Mtime FROM glob(globs=["HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/*"], accessor="registry")`,
        String.raw`SELECT * FROM Keys`,
        String.raw`WHERE TargetObject =~ "(?i)^HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\.*$"`,
      ].join("\n"),
    );
  });

  it("maps HKCU to every user hive, in the glob and in the regex", () => {
    const text = vql(
      reg("    TargetObject|startswith: 'HKCU\\Software\\Classes\\ms-settings'", "registry_event"),
    );
    expect(text).toContain(
      String.raw`glob(globs=["HKEY_USERS/*/Software/Classes/ms-settings*", "HKEY_USERS/*/Software/Classes/ms-settings*/**"], accessor="registry")`,
    );
    expect(whereOf(text)).toBe(
      String.raw`TargetObject =~ "(?i)^HKEY_USERS\\\\[^\\\\]+\\\\Software\\\\Classes\\\\ms-settings"`,
    );
  });

  it("compiles Details against the value data", () => {
    expect(whereOf(vql(reg("    TargetObject: 'HKLM\\A'\n    Details|contains: 'powershell'")))).toBe(
      String.raw`(TargetObject =~ "(?i)^HKEY_LOCAL_MACHINE\\\\A$" AND Details =~ "(?i)powershell")`,
    );
  });

  it("refuses a TargetObject that is not rooted in a hive, or uses contains/endswith/re, because the hunt would walk the whole registry", () => {
    expect(refusals(reg("    TargetObject|contains: '\\CurrentVersion\\Run\\'"))[0]).toEqual({
      path: "detection.sel.TargetObject|contains",
      message: expect.stringMatching(/hive/i),
    });
    expect(refusals(reg("    TargetObject: 'SOFTWARE\\Run'"))[0].message).toMatch(/hive/i);
    expect(refusals(reg("    Details: 'x'"))[0].path).toBe("detection");
  });
});

describe("compileSigmaToVql — modifiers and values", () => {
  it("renders exact, contains, startswith and endswith as anchored case-insensitive regexes", () => {
    expect(whereOf(vql(proc("    Image: 'a'")))).toBe(String.raw`Image =~ "(?i)^a$"`);
    expect(whereOf(vql(proc("    Image|contains: 'a'")))).toBe(String.raw`Image =~ "(?i)a"`);
    expect(whereOf(vql(proc("    Image|startswith: 'a'")))).toBe(String.raw`Image =~ "(?i)^a"`);
    expect(whereOf(vql(proc("    Image|endswith: 'a'")))).toBe(String.raw`Image =~ "(?i)a$"`);
  });

  it("ORs a value list and ANDs it under |all", () => {
    expect(whereOf(vql(proc("    Image|contains:\n      - a\n      - b")))).toBe(
      String.raw`(Image =~ "(?i)a" OR Image =~ "(?i)b")`,
    );
    expect(whereOf(vql(proc("    Image|contains|all:\n      - a\n      - b")))).toBe(
      String.raw`(Image =~ "(?i)a" AND Image =~ "(?i)b")`,
    );
  });

  it("passes a re value through unchanged apart from VQL string escaping", () => {
    expect(whereOf(vql(proc(String.raw`    CommandLine|re: '(?i)-enc\s+[A-Za-z0-9+/=]{20,}'`)))).toBe(
      String.raw`CommandLine =~ "(?i)-enc\\s+[A-Za-z0-9+/=]{20,}"`,
    );
  });

  it("keeps an RE2 named group (?P<name>…) byte-identical for the endpoint (#810)", () => {
    expect(
      whereOf(vql(proc(String.raw`    CommandLine|re: '(?i)-enc\s+(?P<blob>[A-Za-z0-9+/=]{20,})'`))),
    ).toBe(String.raw`CommandLine =~ "(?i)-enc\\s+(?P<blob>[A-Za-z0-9+/=]{20,})"`);
  });

  it("compares numbers on number columns, with gt/gte/lt/lte and exact", () => {
    expect(whereOf(vql(net("    DestinationPort|gte: 1024\n    SourcePort|lt: 1024")))).toBe(
      String.raw`(DestinationPort >= 1024 AND SourcePort < 1024)`,
    );
    expect(whereOf(vql(proc("    ProcessId: 4")))).toBe("Pid = 4");
  });

  it("escapes every regex metacharacter in a Sigma value, and the quote and backslash for VQL", () => {
    const text = whereOf(vql(proc(String.raw`    CommandLine|contains: 'a"b\c(d).e+f'`)));
    expect(text).toBe(String.raw`CommandLine =~ "(?i)a\"b\\\\c\\(d\\)\\.e\\+f"`);
  });

  it("refuses type mismatches instead of coercing", () => {
    expect(refusals(net("    DestinationPort: 'abc'"))[0].message).toMatch(/number/i);
    expect(refusals(net("    DestinationPort|contains: 44"))[0].message).toMatch(/number/i);
    expect(refusals(proc("    Image|cidr: '10.0.0.0/8'"))[0].message).toMatch(/cidr|address/i);
    expect(refusals(net("    DestinationIp|gt: 1"))[0].message).toMatch(/number|compare/i);
    expect(refusals(proc("    Image: true"))[0].message).toMatch(/yes\/no|boolean/i);
  });

  it("refuses a value with a control character, and RE2-incompatible re constructs", () => {
    expect(refusals(proc('    Image: "a\\u0007b"'))[0].message).toMatch(/control/i);
    expect(refusals(proc("    Image|re: 'a(?=b)'"))[0].message).toMatch(/lookaround|RE2/i);
    expect(refusals(proc("    Image|re: '(a)\\1'"))[0].message).toMatch(/backreference|RE2/i);
  });
});

describe("compileSigmaToVql — condition", () => {
  const three = (condition: string) =>
    rule(
      "process_creation",
      "  sel_a:\n    Image: a\n  sel_b:\n    Image: b\n  filter:\n    User: SYSTEM",
      condition,
    );

  it("renders and / or / not with explicit parentheses", () => {
    expect(whereOf(vql(three("sel_a or sel_b and not filter")))).toBe(
      String.raw`(Image =~ "(?i)^a$" OR (Image =~ "(?i)^b$" AND NOT (User =~ "(?i)^SYSTEM$")))`,
    );
  });

  it("renders 1 of / all of as OR / AND over the resolved names", () => {
    expect(whereOf(vql(three("1 of sel_*")))).toBe(String.raw`(Image =~ "(?i)^a$" OR Image =~ "(?i)^b$")`);
    expect(whereOf(vql(three("all of sel_* and not filter")))).toBe(
      String.raw`((Image =~ "(?i)^a$" AND Image =~ "(?i)^b$") AND NOT (User =~ "(?i)^SYSTEM$"))`,
    );
  });

  it("renders a list-of-maps selection as an OR of ANDs", () => {
    expect(
      whereOf(vql(rule("process_creation", "  sel:\n    - Image: a\n      User: u\n    - Image: b"))),
    ).toBe(String.raw`((Image =~ "(?i)^a$" AND User =~ "(?i)^u$") OR Image =~ "(?i)^b$")`);
  });
});

describe("compileSigmaToVql — a selection the condition never names stays out of the hunt (#808)", () => {
  const two = (category: string, sel: string, unused: string, condition = "sel") =>
    rule(category, `  sel:\n${sel}\n  unused:\n${unused}`, condition);

  it("does not let an unused contains block turn a prefix hunt into a whole-disk walk", () => {
    const r = compiled(
      two(
        "file_event",
        "    TargetFilename|startswith: 'C:\\OnlyHere\\'",
        "    TargetFilename|contains: 'foo'",
      ),
    );
    expect(r.vql).toContain(String.raw`glob(globs=["C:/OnlyHere/**"])`);
    expect(r.vql).not.toContain("foo");
    expect(r.coverage).toBe("glob(): files on disk now under C:/OnlyHere/**");
    expect(whereOf(r.vql)).toBe(String.raw`TargetFilename =~ "(?i)^C:\\\\OnlyHere\\\\"`);
  });

  it("does not add the parent lookup stage for an unused parent field", () => {
    const r = vql(
      two("process_creation", "    Image|endswith: '\\cmd.exe'", "    ParentImage|endswith: '\\x.exe'"),
    );
    expect(r).not.toContain("ByPid");
    // The live source adds the parent columns only on demand; the event source always carries them.
    expect(sourceOf(r, "Procs")).not.toContain("ParentImage");
    expect(whereOf(sourceOf(r, "ProcEvents"))).not.toContain("ParentImage");
  });

  it("names the unused selection in the header, so the analyst sees it was left out", () => {
    const r = vql(
      two("process_creation", "    Image|endswith: '\\cmd.exe'", "    CommandLine|contains: 'x'"),
    );
    expect(r.split("\n")[2]).toBe("-- Not in the condition, so not in this hunt: unused");
    expect(vql(proc("    Image: x"))).not.toContain("Not in the condition");
  });

  it("still refuses a broken unused selection — nothing half-understood stays in the rule", () => {
    const r = refusals(two("process_creation", "    Image|endswith: '\\cmd.exe'", "    NoSuchField: 1"));
    expect(r.map((x) => x.path)).toEqual(["detection.unused.NoSuchField"]);
  });

  it("refuses a glob rule whose only path lives in an unused selection, because the hunt would have no root", () => {
    const r = refusals(two("registry_set", "    Details: 'x'", "    TargetObject: 'HKLM\\SOFTWARE\\a'"));
    expect(r).toEqual([{ path: "detection", message: expect.stringMatching(/no TargetObject value/) }]);
  });

  it("counts a selection reached through not / and / 1 of / all of as used", () => {
    const sel = "    Image|endswith: '\\cmd.exe'";
    const parent = "    ParentImage|endswith: '\\x.exe'";
    for (const cond of ["sel and not unused", "1 of them", "all of them", "sel or unused"]) {
      expect(vql(two("process_creation", sel, parent, cond))).toContain("ByPid");
    }
  });

  it("ignores an unused block another template could answer, instead of refusing it against the declared one", () => {
    const r = compiled(
      two("process_creation", "    Image|endswith: '\\cmd.exe'", "    TargetFilename|contains: 'x'"),
    );
    expect(r.vql).toContain("-- Not in the condition, so not in this hunt: unused");
    // No file source was added for it (the event source's own glob() over the log path stays).
    expect(stagesOf(r.vql)).toEqual(["Procs", "ProcEvents"]);
    expect(r.vql).not.toContain("LET Files");
    expect(r.coverage).toBe(
      "pslist(): running processes only, not process history; " +
        "Sysmon event 1, or Security 4688 where Sysmon is absent: process history as far back as the endpoint's event logs go",
    );
  });

  it("still refuses a broken unused selection in a mixed-category rule, where only the named blocks resolve", () => {
    const r = refusals(
      rule(
        "process_creation",
        "  sel_proc:\n    Image|endswith: '\\cmd.exe'\n  sel_net:\n    DestinationIp: '10.0.0.1'\n  unused:\n    NoSuchField: 1",
        "1 of sel_*",
      ),
    );
    expect(r.map((x) => x.path)).toEqual(["detection.unused.NoSuchField"]);
  });

  it("names the unused selection once per source in a mixed-category hunt", () => {
    const r = vql(
      rule(
        "process_creation",
        "  sel_proc:\n    Image|endswith: '\\cmd.exe'\n  sel_net:\n    DestinationIp: '10.0.0.1'\n  unused:\n    TargetFilename|contains: 'x'",
        "1 of sel_*",
      ),
    );
    expect(stagesOf(r)).toEqual(["Procs", "ProcEvents", "Conns"]);
    expect(r).not.toContain("LET Files");
    expect(r.match(/-- Not in the condition, so not in this hunt: unused/g)).toHaveLength(3);
  });
});

describe("compileSigmaToVql — refusals", () => {
  it("refuses a category outside the template set by name, listing the supported ones", () => {
    const r = refusals(rule("image_load", "  sel:\n    ImageLoaded: x"));
    expect(r).toEqual([{ path: "logsource.category", message: expect.stringContaining("image_load") }]);
    for (const c of SIGMA_VQL_CATEGORIES) expect(r[0].message).toContain(c);
    expect(
      refusals(
        "title: T\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image: x\n  condition: sel\n",
      )[0].path,
    ).toBe("logsource.category");
  });

  it("refuses a field the template has no column for, naming the fields it knows", () => {
    const r = refusals(proc("    TargetFilename: x"));
    expect(r).toEqual([{ path: "detection.sel.TargetFilename", message: expect.stringContaining("Image") }]);
    expect(r[0].message).toContain("CommandLine");
  });

  it("refuses a keywords selection, because there is no field to match", () => {
    expect(refusals(rule("process_creation", "  kw:\n    - mimikatz", "kw"))).toEqual([
      { path: "detection.kw", message: expect.stringMatching(/field/i) },
    ]);
  });

  it("reports every problem in one list, and parse refusals stop before compile refusals", () => {
    expect(
      refusals(proc("    TargetFilename: x\n    Image: true\n    DestinationHostname: y")).map((r) => r.path),
    ).toEqual(["detection.sel.TargetFilename", "detection.sel.Image", "detection.sel.DestinationHostname"]);
    const parseOnly = refusals(rule("image_load", "  sel:\n    Image|base64: x"));
    expect(parseOnly.map((r) => r.path)).toEqual(["detection.sel.Image|base64"]);
  });

  it("names every known field of every template in the refusal for an unknown one (no silent drop)", () => {
    const known: Record<string, string[]> = {
      process_creation: [
        "Image",
        "CommandLine",
        "ProcessId",
        "ParentProcessId",
        "User",
        "ParentImage",
        "ParentCommandLine",
        "Hashes",
        "sha256",
        "md5",
        "sha1",
      ],
      network_connection: ["DestinationIp", "DestinationPort", "SourceIp", "SourcePort", "Image"],
      file_event: ["TargetFilename"],
      registry_set: ["TargetObject", "Details"],
    };
    for (const [category, fields] of Object.entries(known)) {
      const r = refusals(rule(category, "  sel:\n    Nope: x"));
      for (const f of fields) expect(r[0].message, `${category} lists ${f}`).toContain(f);
    }
  });
});

describe("compileSigmaToVql — metadata and determinism", () => {
  it("carries title, id, level and the technique ids", () => {
    const r = compiled(
      proc(
        "    Image: x",
        undefined,
        "title: T\nid: abc\nlevel: high\ntags:\n  - attack.t1105\n  - attack.execution",
      ),
    );
    expect([r.title, r.id, r.level, r.mitreTechniques]).toEqual(["T", "abc", "high", ["T1105"]]);
  });

  it("keeps the header on one line whatever the title holds", () => {
    const r = compiled(proc("    Image: x", undefined, 'title: "a\\nb -- c \\"d\\""'));
    expect(r.vql.split("\n")[0]).toBe(
      String.raw`-- Sigma "a b -- c 'd'" → pslist(): running processes only, not process history`,
    );
  });

  it("gives identical bytes on two compiles, and when unrelated keys are reordered", () => {
    const a = proc("    Image: x", undefined, "title: T\nlevel: high\nstatus: test");
    const b = proc("    Image: x", undefined, "status: test\nlevel: high\ntitle: T");
    expect(vql(a)).toBe(vql(a));
    expect(vql(a)).toBe(vql(b));
  });

  it("compileSigmaToVql accepts a parsed rule directly", () => {
    const parsed = parseSigmaRule(proc("    Image: x"));
    if (!parsed.ok) throw new Error("parse failed");
    const r = compileSigmaToVql(parsed.rule);
    expect(r.ok && r.vql).toBe(vql(proc("    Image: x")));
  });
});

describe("compileSigmaToVql — round trip with the dashboard's Sigma draft export", () => {
  // The real findingSigmaYaml from public/js/dashboard-sigma-hunt.js, run in a vm the way the
  // browser runs it. baseName / pushUniq are the two page globals it reaches for.
  const api = loadDashboardModule<{ findingSigmaYaml: (f: unknown, c: unknown) => string }>(
    "dashboard-sigma-hunt.js",
    [],
    {
      baseName: (p: string) => String(p).split(/[\\/]/).pop() || String(p),
      pushUniq: (arr: string[], v: string) => {
        if (!arr.includes(v)) arr.push(v);
      },
    },
  );
  const finding = {
    id: "f-12",
    title: "Suspicious certutil download",
    description: "d",
    severity: "High",
    mitreTechniques: ["T1105"],
  };
  const ctx = {
    processes: ["C:\\Windows\\System32\\certutil.exe"],
    parent: "C:\\Windows\\System32\\cmd.exe",
    hashes: ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    ips: ["203.0.113.10"],
    domains: ["example.invalid"],
    urls: [],
    paths: ["C:\\Users\\Public\\payload.ps1"],
    host: "",
  };

  it("parses the draft, and refuses only the domain block — the one no template can answer — with the netstat hint", () => {
    // The draft is a process_creation rule that also carries network and file blocks (it is a
    // correct rule for a SIEM, where one event stream carries all of them). The IP and file blocks
    // would become their own sources (#802); the domain block cannot, because netstat() has no
    // hostname column. So the refusal names that block alone, with the fix, instead of blaming
    // pslist() for two blocks that compile fine elsewhere.
    const yaml = api.findingSigmaYaml(finding, ctx);
    expect(yaml).toContain("sel_network_domain");
    const r = compileSigmaText(yaml);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusals).toEqual([
      {
        path: "detection.sel_network_domain.DestinationHostname|contains",
        message: expect.stringMatching(/netstat\(\).*use DestinationIp/),
      },
    ]);
  });

  it("compiles the draft to three sources once the domain block is gone", () => {
    const yaml = api.findingSigmaYaml(finding, { ...ctx, domains: [] });
    const r = compileSigmaText(yaml);
    if (!r.ok) throw new Error(r.refusals.map((x) => `${x.path}: ${x.message}`).join("\n"));
    expect(stagesOf(r.vql)).toEqual(["Procs", "ProcEvents", "Conns", "Files"]);
  });

  it("compiles the draft's process, parent and hash blocks, and records the finding's technique", () => {
    const yaml = api.findingSigmaYaml(finding, { ...ctx, domains: [], urls: [], ips: [], paths: [] });
    const r = compileSigmaText(yaml);
    if (!r.ok) throw new Error(r.refusals.map((x) => `${x.path}: ${x.message}`).join("\n"));
    expect(r.mitreTechniques).toEqual(["T1105"]);
    expect(r.vql).toContain("hash(path=Exe) AS Hashes");
    expect(r.vql).toContain("AS ParentImage");
    const where = whereOf(r.vql);
    expect(where).toContain(String.raw`Image =~ "(?i)\\\\certutil\\.exe$"`);
    expect(where).toContain("Hashes.SHA256 =~");
  });
});

describe("compileSigmaToVql — mixed-category rules become several hunt sources (#802)", () => {
  const mixed = (condition: string, head = "title: T") =>
    [
      head,
      "logsource:",
      "  category: process_creation",
      "  product: windows",
      "detection:",
      "  sel_process:",
      String.raw`    Image|endswith: '\certutil.exe'`,
      "  sel_network:",
      "    DestinationIp: '203.0.113.10'",
      "  sel_file:",
      String.raw`    TargetFilename: 'C:\Users\Public\payload.ps1'`,
      `  condition: ${condition}`,
      "",
    ].join("\n");

  it("splits a top-level '1 of sel_*' into one blank-line-separated source per category", () => {
    const r = compiled(mixed("1 of sel_*"));
    expect(stagesOf(r.vql)).toEqual(["Procs", "ProcEvents", "Conns", "Files"]);
    const procWhere = String.raw`WHERE Image =~ "(?i)\\\\certutil\\.exe$"`;
    expect(sourceOf(r.vql, "Procs")).toContain(procWhere);
    expect(sourceOf(r.vql, "ProcEvents")).toContain(procWhere);
    expect(sourceOf(r.vql, "Conns")).toContain(String.raw`WHERE DestinationIp =~ "(?i)^203\\.0\\.113\\.10$"`);
    const fileWhere = String.raw`WHERE TargetFilename =~ "(?i)^C:\\\\Users\\\\Public\\\\payload\\.ps1$"`;
    expect(sourceOf(r.vql, "Files")).toContain(fileWhere);
    expect(r.coverage).toBe(
      "pslist(): running processes only, not process history; " +
        "Sysmon event 1, or Security 4688 where Sysmon is absent: process history as far back as the endpoint's event logs go; " +
        "netstat(): open connections only, not connection history; " +
        "glob(): files on disk now under C:/Users/Public/payload.ps1",
    );
    // The network and file blocks have no history source, so an empty result is still not negative
    // evidence for them: the hunt stays a snapshot (#803). Only a rule whose every block reads
    // history gives up that protection.
    expect(r.snapshot).toBe(true);
  });

  it("is a real miss only when every block has a history source", () => {
    const procOnly = rule(
      "process_creation",
      "  sel_a:\n    Image: a\n  sel_b:\n    CommandLine: b",
      "1 of sel_*",
    );
    expect(compiled(procOnly).snapshot).toBe(false);
    const withNet = rule(
      "process_creation",
      "  sel_a:\n    Image: a\n  sel_b:\n    DestinationPort: 443",
      "1 of sel_*",
    );
    expect(stagesOf(vql(withNet))).toEqual(["Procs", "ProcEvents", "Conns"]);
    expect(compiled(withNet).snapshot).toBe(true);
  });

  it("takes the same path for an explicit top-level 'or' of whole selections", () => {
    const r = compiled(mixed("sel_process or sel_network or sel_file"));
    expect(stagesOf(r.vql)).toEqual(["Procs", "ProcEvents", "Conns", "Files"]);
  });

  it("gives identical bytes on two compiles", () => {
    expect(vql(mixed("1 of sel_*"))).toBe(vql(mixed("1 of sel_*")));
  });

  it("never emits a source that itself contains a blank line", () => {
    for (const stmt of vql(mixed("1 of sel_*")).split(/\n\s*\n/)) expect(stmt).not.toMatch(/\n\s*\n/);
  });

  it("stays on the single-template refusal when the top condition ANDs across categories", () => {
    // sel_file is not in the condition and glob() could answer it, so it is not blamed (#808).
    const r = refusals(mixed("sel_process and sel_network"));
    expect(r).toEqual([
      { path: "detection.sel_network.DestinationIp", message: expect.stringContaining("pslist()") },
    ]);
    expect(refusals(mixed("sel_process and sel_network and sel_file"))).toEqual([
      { path: "detection.sel_network.DestinationIp", message: expect.stringContaining("pslist()") },
      { path: "detection.sel_file.TargetFilename", message: expect.stringContaining("pslist()") },
    ]);
  });

  it("stays on the single-template refusal when a 'not' reaches across categories", () => {
    const r = refusals(mixed("sel_process or not sel_network"));
    expect(r.some((x) => x.path === "detection.sel_network.DestinationIp")).toBe(true);
  });

  it("stays refused when one selection fits no template at all (a genuine capability gap)", () => {
    // DestinationHostname has no column on ANY template (netstat() has no hostname field), so this
    // rule can never fully resolve — the original per-field refusals stand, not a partial hunt.
    const yaml = [
      "title: T",
      "logsource:",
      "  category: process_creation",
      "  product: windows",
      "detection:",
      "  sel_process:",
      String.raw`    Image|endswith: '\certutil.exe'`,
      "  sel_hostname:",
      "    DestinationHostname|contains: 'example.invalid'",
      "  condition: 1 of sel_*",
      "",
    ].join("\n");
    const r = refusals(yaml);
    expect(r).toEqual([
      {
        path: "detection.sel_hostname.DestinationHostname|contains",
        message: expect.stringMatching(/netstat\(\) has no hostname column.*use DestinationIp/),
      },
    ]);
  });

  it("keeps a selection made only of process-context fields with its declared category", () => {
    // Image (like User and ProcessId) names the process BEHIND a file, registry or network event.
    // On its own it must not turn a file_event block into a pslist() hunt for a running process —
    // that is a different question than the rule asked. The glob() template has no Image column,
    // so the block refuses there, by name, and the rule stays refused.
    const yaml = [
      "title: T",
      "logsource:",
      "  category: file_event",
      "  product: windows",
      "detection:",
      "  sel_path:",
      String.raw`    TargetFilename: 'C:\Users\Public\payload.ps1'`,
      "  sel_proc:",
      String.raw`    Image|endswith: '\foo.exe'`,
      "  condition: 1 of sel_*",
      "",
    ].join("\n");
    const r = refusals(yaml);
    expect(r).toEqual([
      {
        path: "detection.sel_proc.Image|endswith",
        message: expect.stringMatching(/Image.*glob\(\)/),
      },
    ]);
  });

  it("moves a selection to another category when a field only that category answers anchors it", () => {
    // DestinationIp exists on netstat() alone, so this block is a connection block even though it
    // also names the Image; the netstat source gains the ByPid lookup to answer Image there.
    const yaml = [
      "title: T",
      "logsource:",
      "  category: process_creation",
      "  product: windows",
      "detection:",
      "  sel_cmd:",
      "    CommandLine|contains: 'urlcache'",
      "  sel_conn:",
      String.raw`    Image|endswith: '\certutil.exe'`,
      "    DestinationIp: '203.0.113.10'",
      "  condition: 1 of sel_*",
      "",
    ].join("\n");
    const text = vql(yaml);
    expect(stagesOf(text)).toEqual(["Procs", "ProcEvents", "Conns"]);
    const conns = sourceOf(text, "Conns");
    expect(conns).toContain('LET ByPid <= memoize(query={ SELECT Pid, Exe FROM pslist() }, key="Pid")');
    expect(conns).toContain(
      String.raw`WHERE (Image =~ "(?i)\\\\certutil\\.exe$" AND DestinationIp =~ "(?i)^203\\.0\\.113\\.10$")`,
    );
  });

  it("does not split when every selection already fits the declared category (no regression)", () => {
    const yaml = rule("process_creation", "  sel_a:\n    Image: a\n  sel_b:\n    Image: b", "1 of sel_*");
    const text = vql(yaml);
    // Only the category's own pair — no foreign source, one OR per source.
    expect(stagesOf(text)).toEqual(["Procs", "ProcEvents"]);
    expect(whereOf(sourceOf(text, "Procs"))).toBe(String.raw`(Image =~ "(?i)^a$" OR Image =~ "(?i)^b$")`);
    expect(whereOf(sourceOf(text, "ProcEvents"))).toBe(
      String.raw`(Image =~ "(?i)^a$" OR Image =~ "(?i)^b$")`,
    );
  });
});

describe("compileSigmaToVql — golden process events: Sysmon 1, else Security 4688 (#802)", () => {
  const events = (fields: string) => sourceOf(vql(proc(fields)), "ProcEvents");

  it("compiles the event-history source, byte for byte", () => {
    expect(events("    Image|endswith: '\\certutil.exe'")).toBe(
      [
        String.raw`-- Sigma "T" → Sysmon event 1, or Security 4688 where Sysmon is absent: process history as far back as the endpoint's event logs go`,
        String.raw`-- Compiled by DFIR Companion from a Sigma rule; the same rule always yields this VQL`,
        String.raw`LET SysmonLog <= "C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"`,
        String.raw`LET SecurityLog <= "C:/Windows/System32/winevt/Logs/Security.evtx"`,
        String.raw`LET SysmonEvents = SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, "Sysmon" AS Source, EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ProcessId AS ProcessId, EventData.ParentProcessId AS ParentProcessId, EventData.User AS User, EventData.ParentImage AS ParentImage, EventData.ParentCommandLine AS ParentCommandLine, EventData.Hashes AS Hashes, EventData.OriginalFileName AS OriginalFileName, EventData.IntegrityLevel AS IntegrityLevel, EventData.CurrentDirectory AS CurrentDirectory, EventData.Description AS Description, EventData.Product AS Product, EventData.Company AS Company FROM foreach(row={ SELECT OSPath FROM glob(globs=SysmonLog) }, query={ SELECT * FROM parse_evtx(filename=OSPath) WHERE System.EventID.Value = 1 })`,
        String.raw`LET SecurityEvents = SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, "Security" AS Source, EventData.NewProcessName AS Image, EventData.CommandLine AS CommandLine, int(int=EventData.NewProcessId) AS ProcessId, int(int=EventData.ProcessId) AS ParentProcessId, EventData.SubjectDomainName + "\\" + EventData.SubjectUserName AS User, EventData.ParentProcessName AS ParentImage, NULL AS ParentCommandLine, NULL AS Hashes, NULL AS OriginalFileName, NULL AS IntegrityLevel, NULL AS CurrentDirectory, NULL AS Description, NULL AS Product, NULL AS Company FROM foreach(row={ SELECT OSPath FROM glob(globs=SecurityLog) }, query={ SELECT * FROM parse_evtx(filename=OSPath) WHERE System.EventID.Value = 4688 })`,
        String.raw`LET HasSysmon <= SELECT count() AS N FROM SysmonEvents LIMIT 1`,
        String.raw`LET ProcEvents <= SELECT * FROM if(condition=HasSysmon[0].N > 0, then=SysmonEvents, else=SecurityEvents)`,
        String.raw`SELECT * FROM ProcEvents`,
        String.raw`WHERE Image =~ "(?i)\\\\certutil\\.exe$"`,
      ].join("\n"),
    );
  });

  it("matches sha256/md5/sha1/imphash against the Sysmon Hashes string by its tag", () => {
    expect(whereOf(events("    sha256: 'AbC'"))).toBe(String.raw`Hashes =~ "(?i)SHA256=AbC(,|$)"`);
    expect(whereOf(events("    md5|contains: 'abc'"))).toBe(String.raw`Hashes =~ "(?i)MD5=[^,]*abc"`);
    expect(whereOf(events("    imphash|startswith: 'abc'"))).toBe(String.raw`Hashes =~ "(?i)IMPHASH=abc"`);
    expect(whereOf(events("    sha1|endswith: 'abc'"))).toBe(String.raw`Hashes =~ "(?i)SHA1=[^,]*abc(,|$)"`);
  });

  it("treats Hashes itself as the Sysmon string, so the usual 'ALG=value' rule text matches as written", () => {
    expect(whereOf(events("    Hashes|contains: 'SHA256=abc'"))).toBe(String.raw`Hashes =~ "(?i)SHA256=abc"`);
  });

  it("drops the event source for a regex on a hash tag, because the tag prefix would break the regex's own anchors", () => {
    // pslist() still takes it: its Hashes.SHA256 member is the bare hex the regex was written for.
    const text = vql(proc("    sha256|re: '^[0-9a-f]{64}$'"));
    expect(stagesOf(text)).toEqual(["Procs"]);
    expect(whereOf(text)).toBe(String.raw`Hashes.SHA256 =~ "^[0-9a-f]{64}$"`);
    // imphash exists only on the event source, so there the rule refuses outright.
    expect(refusals(proc("    imphash|re: '^[0-9a-f]{32}$'"))).toHaveLength(1);
    expect(refusals(proc("    imphash|re: '^[0-9a-f]{32}$'"))[0].path).toBe("detection.sel.imphash|re");
  });

  const SYSMON_ONLY =
    "Sysmon event 1 only: the rule uses fields Security 4688 does not record, so an endpoint without Sysmon cannot answer it";

  it("runs only the event source for a field pslist() cannot answer, on the Sysmon branch alone, as a snapshot", () => {
    // 4688 has no hashes, parent command line or PE metadata; a rule on those fields cannot be
    // evaluated on a 4688-only endpoint, so its history covers only part of the fleet and its empty
    // result is not negative evidence (#803).
    for (const fields of [
      "    imphash: 'abc'",
      "    OriginalFileName: 'cmd.exe'",
      "    IntegrityLevel: 'High'",
    ]) {
      const r = compiled(proc(fields));
      expect(stagesOf(r.vql)).toEqual(["ProcEvents"]);
      expect(r.vql).toContain("LET ProcEvents <= SELECT * FROM SysmonEvents\n");
      expect(r.vql).not.toContain("else=SecurityEvents");
      expect(r.coverage).toBe(SYSMON_ONLY);
      expect(r.snapshot).toBe(true);
    }
  });

  it("keeps both branches, and the real miss, for fields both logs record", () => {
    for (const fields of [
      "    Image: x",
      "    CommandLine|contains: x",
      "    ParentImage: x",
      "    User: x",
    ]) {
      const r = compiled(proc(fields));
      expect(sourceOf(r.vql, "ProcEvents")).toContain("then=SysmonEvents, else=SecurityEvents");
      expect(r.snapshot).toBe(false);
    }
    // A hash beside the Image moves the whole source to the Sysmon branch.
    const r = compiled(proc("    Image: x\n    sha256: 'abc'"));
    expect(sourceOf(r.vql, "ProcEvents")).toContain("LET ProcEvents <= SELECT * FROM SysmonEvents\n");
    expect(r.coverage).toBe(`pslist(): running processes only, not process history; ${SYSMON_ONLY}`);
    expect(r.snapshot).toBe(true);
  });

  it("still refuses a field neither process source has", () => {
    const r = refusals(proc("    TargetFilename: 'x'"));
    expect(r.map((x) => x.path)).toEqual(["detection.sel.TargetFilename"]);
    expect(r[0].message).toMatch(/no column/);
  });

  it("is not a snapshot: the history source makes an empty result a real miss", () => {
    expect(compiled(proc("    Image: x")).snapshot).toBe(false);
    expect(compiled(proc("    CommandLine|contains: 'x'")).snapshot).toBe(false);
  });
});

describe("compileSigmaToVql — review fixes (#803)", () => {
  it("refuses a product other than Windows, because every template is a Windows plugin with Windows roots", () => {
    const linux =
      "title: T\nlogsource:\n  category: file_event\n  product: linux\ndetection:\n  sel:\n    TargetFilename|contains: 'x'\n  condition: sel\n";
    expect(refusals(linux)).toEqual([
      { path: "logsource.product", message: expect.stringMatching(/linux.*Windows|Windows.*linux/) },
    ]);
    expect(compileSigmaText(linux.replace("product: linux", "product: Windows")).ok).toBe(true);
    expect(compileSigmaText(linux.replace("  product: linux\n", "")).ok).toBe(true);
  });

  it("enumerates a prefix without a trailing separator as the same-component prefix AND its descendants", () => {
    const text = vql(file("    TargetFilename|startswith: 'C:\\Temp'"));
    expect(text).toContain(String.raw`glob(globs=["C:/Temp*", "C:/Temp*/**"])`);
    // A prefix that ends on a separator is a directory: one recursive glob, as before.
    expect(vql(file("    TargetFilename|startswith: 'C:\\Users\\'"))).toContain(
      String.raw`glob(globs=["C:/Users/**"])`,
    );
  });

  it("ANDs cidr ranges under |all instead of dropping the modifier", () => {
    expect(
      whereOf(vql(net("    DestinationIp|cidr|all:\n      - '10.0.0.0/8'\n      - '10.1.0.0/16'"))),
    ).toBe(
      String.raw`(cidr_contains(ip=DestinationIp, ranges=["10.0.0.0/8"]) AND cidr_contains(ip=DestinationIp, ranges=["10.1.0.0/16"]))`,
    );
    expect(whereOf(vql(net("    DestinationIp|cidr:\n      - '10.0.0.0/8'\n      - '10.1.0.0/16'")))).toBe(
      String.raw`cidr_contains(ip=DestinationIp, ranges=["10.0.0.0/8", "10.1.0.0/16"])`,
    );
  });

  it("says a live-only query is a snapshot, so the hunt loop never records its empty result as a miss", () => {
    for (const y of [
      net("    DestinationPort: 1"),
      file("    TargetFilename: 'C:\\x'"),
      reg("    TargetObject: 'HKLM\\A'"),
    ]) {
      expect(compiled(y).snapshot).toBe(true);
    }
    // process_creation reads event history too (#802), so it is the one category that is not.
    expect(compiled(proc("    Image: x")).snapshot).toBe(false);
  });
});

describe("compileSigmaToVql — review fixes (#806, #807)", () => {
  it("never assembles `WHERE ()`: an empty selection and a condition over no selection are refusals", () => {
    const head = "title: T\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n";
    for (const detection of [
      "  sel: {}\n  condition: sel\n",
      "  sel:\n    - {}\n  condition: sel\n",
      "  condition: 1 of them\n",
      "  condition: all of them\n",
    ]) {
      const r = compileSigmaText(head + detection);
      expect(r.ok, detection).toBe(false);
      if (!r.ok) expect(r.refusals.length, detection).toBeGreaterThan(0);
    }
  });

  it("refuses an empty field list handed to the compiler directly, at the selection's path", () => {
    const parsedRule = parseSigmaRule(proc("    Image: x"));
    if (!parsedRule.ok) throw new Error("fixture must parse");
    const rule = {
      ...parsedRule.rule,
      detection: {
        ...parsedRule.rule.detection,
        selections: [{ kind: "map" as const, name: "sel", fields: [] }],
      },
    };
    const r = compileSigmaToVql(rule);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusals).toEqual([{ path: "detection.sel", message: expect.stringMatching(/no fields/) }]);
    }
  });

  it("refuses a drive-rooted or UNC-rooted contains/endswith path, which a C:/** glob could never match (#807)", () => {
    for (const [key, value] of [
      ["TargetFilename|contains", "D:\\tools\\evil.log"],
      ["TargetFilename|endswith", "D:\\tools\\evil.log"],
      ["TargetFilename|contains", "C:\\tools\\evil.log"],
      ["TargetFilename|endswith", "\\\\fileserver\\share\\evil.log"],
    ]) {
      const r = refusals(file(`    ${key}: '${value}'`));
      expect(r, `${key}: ${value}`).toEqual([
        { path: `detection.sel.${key}`, message: expect.stringMatching(/rooted.*never appear.*startswith/) },
      ]);
    }
  });

  it("keeps the rooted forms that do work: startswith and an exact match on another drive", () => {
    expect(vql(file("    TargetFilename|startswith: 'D:\\tools'"))).toContain(
      String.raw`glob(globs=["D:/tools*", "D:/tools*/**"])`,
    );
    expect(vql(file("    TargetFilename: 'D:\\tools\\evil.log'"))).toContain(
      String.raw`glob(globs=["D:/tools/evil.log"])`,
    );
  });

  it("treats a fragment that opens on a separator as a component boundary, so C:\\Temp\\x.exe itself is found", () => {
    // Before: C:/**/*/Temp/x.exe, which needs one component between C: and Temp and so skips
    // C:/Temp/x.exe. `**` already matches zero or more components.
    expect(vql(file("    TargetFilename|endswith: '\\Temp\\x.exe'"))).toContain(
      String.raw`glob(globs=["C:/**/Temp/x.exe"])`,
    );
    expect(vql(file("    TargetFilename|contains: '\\Temp\\'"))).toContain(
      String.raw`glob(globs=["C:/**/Temp/*"])`,
    );
    // A bare name is unchanged: any folder, any prefix.
    expect(vql(file("    TargetFilename|endswith: '.hta'"))).toContain(
      String.raw`glob(globs=["C:/**/*.hta"])`,
    );
  });
});
