import { describe, it, expect } from "vitest";
import { vqlAllowed, canonicalVqlFingerprint } from "../../../../src/analysis/ai/watson/velo/vqlAllowed.js";
import { ALLOWED_CALLS, ALLOWED_ARTIFACTS } from "../../../../src/analysis/ai/watson/velo/vqlAllowlist.js";

const allowed = (vql: string): void => {
  const r = vqlAllowed(vql);
  expect(r, `expected allowed: ${vql}`).toEqual({ ok: true });
};

const blocked = (vql: string): string[] => {
  const r = vqlAllowed(vql);
  expect(r.ok, `expected blocked: ${vql}`).toBe(false);
  return r.ok ? [] : r.reasons;
};

describe("vqlAllowed — plain read-only VQL", () => {
  it("allows a plain plugin query", () => {
    allowed("SELECT * FROM pslist()");
  });

  it("allows keywords followed by a parenthesis", () => {
    allowed("SELECT Name, Pid FROM pslist() WHERE Pid IN (1, 2) AND (Name =~ 'svchost' OR NOT (Pid = 4))");
  });

  it("allows nested read-only functions and plugins", () => {
    allowed(
      "SELECT FullPath, lowcase(string=FullPath) AS Lower, format(format='%v', args=[Size]) FROM glob(globs='C:\\\\Users\\\\*\\\\Downloads\\\\*.exe')",
    );
  });

  it("allows an allowed artifact call", () => {
    allowed("SELECT * FROM Artifact.Windows.System.Pslist()");
    allowed("SELECT * FROM Artifact.Generic.Client.Info()");
  });

  it("allows calling a capitalised LET stored query, with and without parameters", () => {
    allowed("LET Procs = SELECT * FROM pslist()\nSELECT * FROM Procs");
    allowed("LET Procs <= SELECT * FROM pslist()\nSELECT * FROM Procs()");
    allowed("LET ProcOf(P) = SELECT * FROM pslist(pid=P)\nSELECT * FROM ProcOf(P=4)");
  });

  it("allows an identifier that merely contains a blocked name", () => {
    allowed("SELECT myexecvehelper, execve_count FROM pslist()");
  });

  it("allows a call that sits inside a comment", () => {
    allowed("-- execve(argv=['calc'])\nSELECT * FROM pslist()");
    allowed("// upload(file='x')\nSELECT * FROM pslist()");
    allowed("/* execve(argv=['calc']) */ SELECT * FROM pslist()");
  });

  it("allows a call name inside a string literal", () => {
    allowed("SELECT * FROM pslist() WHERE Name = 'execve(x)'");
    allowed("SELECT * FROM pslist() WHERE Name = '''it's execve()'''");
  });

  it("allows non-ASCII text inside a string literal", () => {
    allowed("SELECT * FROM pslist() WHERE Name = 'café'");
  });

  it("allows a local accessor given as a literal", () => {
    allowed("SELECT * FROM glob(globs='C:\\\\$MFT', accessor='ntfs')");
    allowed('SELECT * FROM stat(filename="C:\\\\x", accessor="file")');
  });

  it("allows a WMI query on a reviewed class (no namespace argument)", () => {
    allowed("SELECT * FROM wmi(query='SELECT * FROM Win32_Service')");
  });
});

describe("vqlAllowed — calls off the list", () => {
  it.each(["execve", "EXECVE", "ExecVe", "eXeCvE"])("blocks %s( in every case variant", (name) => {
    const reasons = blocked(`SELECT * FROM ${name}(argv=['calc'])`);
    expect(reasons.join(" ")).toContain(name);
  });

  it.each([
    "SELECT * FROM execve (argv=['calc'])",
    "SELECT * FROM execve\n(argv=['calc'])",
    "SELECT * FROM execve/**/(argv=['calc'])",
    "SELECT * FROM execve -- hidden\n(argv=['calc'])",
    "SELECT * FROM execve",
  ])("blocks a call however it is spaced: %s", (vql) => {
    expect(blocked(vql).join(" ")).toContain("execve");
  });

  it("names the whole identifier, not a substring", () => {
    const reasons = blocked("SELECT myexecvehelper(x=1) FROM pslist()");
    expect(reasons.join(" ")).toContain("myexecvehelper");
  });

  it.each([
    "upload",
    "upload_directory",
    "write_csv",
    "http_client",
    "collect_client",
    "hunt",
    "label",
    "rm",
    "copy",
    "mail",
    "killkillkill",
    "quarantine",
    "filter",
    "get",
  ])("blocks %s(", (name) => {
    blocked(`SELECT ${name}(x=1) FROM pslist()`);
  });

  it("blocks a call after a closing block comment", () => {
    blocked("/* note */ SELECT * FROM execve(argv=['calc'])");
  });

  it("does not nest block comments", () => {
    blocked("/* /* */ SELECT execve(argv=['x']) FROM info() */");
  });

  it("is not fooled by comment markers inside strings or string markers inside comments", () => {
    blocked("SELECT '--' , execve(argv=['x']) FROM info()");
    blocked("SELECT '/*' , execve(argv=['x']) FROM info() -- */");
    blocked("-- ' \nSELECT execve(argv=['x']) FROM info()");
    blocked("/* ' */ SELECT execve(argv=['x']) FROM info()");
  });

  it("blocks an artifact off the list, called or merely named", () => {
    expect(blocked("SELECT * FROM Artifact.Windows.System.CmdShell(Command='whoami')").join(" ")).toContain(
      "Windows.System.CmdShell",
    );
    blocked("LET X = Artifact.Windows.System.CmdShell\nSELECT * FROM info()");
  });

  it("blocks an artifact reference that is not a plain dotted name", () => {
    blocked("SELECT * FROM Artifact . Windows.System.Pslist()");
    blocked("SELECT * FROM Artifact['Windows.System.CmdShell']()");
    blocked("SELECT * FROM Artifact()");
  });

  it("blocks any other dotted call", () => {
    blocked("SELECT * FROM Foo.pslist()");
  });

  it("blocks dynamic invocation", () => {
    blocked("SELECT * FROM call_function(name='exe' + 'cve', args=dict(argv=['calc']))");
    blocked("SELECT * FROM query(query='SELECT * FROM ' + 'execve()')");
    blocked("SELECT eval(func=x) FROM info()");
    blocked("SELECT * FROM chain(a={SELECT * FROM info()})");
    blocked("SELECT * FROM foreach(row={SELECT * FROM pslist()}, query={SELECT * FROM info()})");
  });

  it("blocks calling the result of an expression", () => {
    blocked("SELECT (x)(argv=['calc']) FROM info()");
    blocked("SELECT 'execve'(argv=['calc']) FROM info()");
  });

  it("blocks a lambda string", () => {
    blocked("SELECT regex_replace(source=Name, re='a', replace_lambda='x=>x') FROM pslist()");
    blocked("SELECT * FROM pslist() WHERE Name = 'x=>execve()'");
  });
});

describe("vqlAllowed — lexical traps", () => {
  it("blocks a Unicode lookalike of a blocked call", () => {
    blocked("SELECT * FROM ехесve(argv=['calc'])");
  });

  it("blocks non-ASCII inside a comment", () => {
    blocked("-- ехесve\nSELECT * FROM pslist()");
  });

  it("blocks an unterminated string or block comment", () => {
    blocked("SELECT * FROM pslist() WHERE Name = 'x");
    blocked("SELECT * FROM pslist() /* trailing");
    blocked("SELECT * FROM pslist() WHERE Name = '''x");
  });

  it("blocks a backtick anywhere outside a string", () => {
    blocked("SELECT * FROM `execve`(argv=['calc'])");
    blocked("SELECT `Name` FROM pslist()");
  });

  it("blocks a string whose end depends on how backslashes are read", () => {
    blocked("SELECT * FROM glob(globs='C:\\Users\\' , x=execve(argv=['calc']), y='')");
  });

  it("blocks control characters", () => {
    blocked("SELECT * FROM pslist()\u0000");
  });
});

describe("vqlAllowed — LET definitions", () => {
  it("checks a LET body even when the name is never used", () => {
    blocked("LET Unused = SELECT * FROM execve(argv=['calc'])\nSELECT * FROM pslist()");
  });

  it("blocks calling a LET whose name could shadow a built-in", () => {
    blocked("LET execve = SELECT * FROM info()\nSELECT * FROM execve()");
    blocked("LET procs = SELECT * FROM pslist()\nSELECT * FROM procs");
  });

  it("blocks calling a LET that aliases a value instead of defining a query", () => {
    blocked("LET Alias = execve\nSELECT * FROM Alias(argv=['calc'])");
  });

  it("blocks a malformed LET", () => {
    blocked("LET = SELECT * FROM pslist()");
  });
});

describe("vqlAllowed — risky arguments", () => {
  it("blocks a network or unknown accessor", () => {
    blocked("SELECT * FROM glob(globs='*', accessor='smb')");
    blocked("SELECT * FROM read_file(filenames='x', accessor='s3')");
    blocked("SELECT * FROM glob(globs='*', accessor=format(format='%v', args='smb'))");
    blocked("SELECT * FROM glob(globs='*', accessor='fi' + 'le')");
  });

  it("blocks an upload argument to an allowed artifact", () => {
    blocked("SELECT * FROM Artifact.Windows.Search.FileFinder(SearchFilesGlob='C:\\\\x', Upload_File='Y')");
  });

  it("blocks a WMI namespace that is not a local root namespace", () => {
    blocked(
      "SELECT * FROM wmi(query='SELECT * FROM Win32_Service', namespace='\\\\\\\\host.example.com\\\\root')",
    );
  });
});

describe("allowlists", () => {
  it("never lists a call that runs, writes, sends or evaluates", () => {
    const forbidden = [
      "execve",
      "shell",
      "upload",
      "write_csv",
      "http_client",
      "collect_client",
      "query",
      "eval",
      "foreach",
      "chain",
      "call_function",
      "filter",
    ];
    for (const name of forbidden) expect(ALLOWED_CALLS).not.toContain(name);
    expect(ALLOWED_ARTIFACTS).not.toContain("Windows.System.CmdShell");
  });
});

describe("canonicalVqlFingerprint", () => {
  it("ignores comments, whitespace and keyword case", () => {
    const a = canonicalVqlFingerprint("SELECT * FROM pslist()");
    expect(a).not.toBe("");
    expect(canonicalVqlFingerprint("select *\n  from pslist() -- again")).toBe(a);
    expect(canonicalVqlFingerprint("/* x */ SELECT * FROM pslist()")).toBe(a);
  });

  it("keeps string contents and identifiers significant", () => {
    expect(canonicalVqlFingerprint("SELECT * FROM pslist() WHERE Name = 'a'")).not.toBe(
      canonicalVqlFingerprint("SELECT * FROM pslist() WHERE Name = 'b'"),
    );
  });

  it("is empty for VQL that does not tokenize", () => {
    expect(canonicalVqlFingerprint("SELECT 'x")).toBe("");
  });
});
