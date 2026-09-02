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
const whereOf = (text: string): string => {
  const i = text.indexOf("\nWHERE ");
  if (i < 0) throw new Error("no WHERE in:\n" + text);
  return text.slice(i + "\nWHERE ".length);
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
    expect(vql(proc("    Image|endswith: '\\certutil.exe'"))).toBe(
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
    expect(text).not.toMatch(/\n\s*\n/);
    expect(text.split("\n").filter((l) => !l.startsWith("--")).length).toBeGreaterThanOrEqual(3);
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
    const r = refusals(proc("    OriginalFileName: x"));
    expect(r).toEqual([
      { path: "detection.sel.OriginalFileName", message: expect.stringContaining("Image") },
    ]);
    expect(r[0].message).toContain("CommandLine");
  });

  it("refuses a keywords selection, because there is no field to match", () => {
    expect(refusals(rule("process_creation", "  kw:\n    - mimikatz", "kw"))).toEqual([
      { path: "detection.kw", message: expect.stringMatching(/field/i) },
    ]);
  });

  it("reports every problem in one list, and parse refusals stop before compile refusals", () => {
    expect(
      refusals(proc("    OriginalFileName: x\n    Image: true\n    DestinationHostname: y")).map(
        (r) => r.path,
      ),
    ).toEqual(["detection.sel.OriginalFileName", "detection.sel.Image", "detection.sel.DestinationHostname"]);
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

  it("parses the draft, and refuses exactly the three blocks whose fields pslist() cannot answer, by name", () => {
    // The draft is a process_creation rule that also carries network and file blocks (it is a
    // correct rule for a SIEM, where one event stream carries all of them). One template per
    // category means those blocks refuse here, each with its own line — never a silent drop.
    const yaml = api.findingSigmaYaml(finding, ctx);
    expect(yaml).toContain("sel_network_domain");
    const r = compileSigmaText(yaml);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusals.map((x) => x.path)).toEqual([
      "detection.sel_network_ip.DestinationIp",
      "detection.sel_network_domain.DestinationHostname|contains",
      "detection.sel_file_path.TargetFilename|contains",
    ]);
    expect(r.refusals[1].message).toMatch(/pslist\(\)/);
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

  it("says the compiled query is a live snapshot, so the hunt loop never records its empty result as a miss", () => {
    for (const y of [
      proc("    Image: x"),
      net("    DestinationPort: 1"),
      file("    TargetFilename: 'C:\\x'"),
      reg("    TargetObject: 'HKLM\\A'"),
    ]) {
      expect(compiled(y).snapshot).toBe(true);
    }
  });
});
