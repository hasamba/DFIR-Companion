import { describe, it, expect } from "vitest";
import { vqlAllowed } from "../../../../src/analysis/ai/watson/velo/vqlAllowed.js";
import { ALLOWED_ACCESSORS } from "../../../../src/analysis/ai/watson/velo/vqlAllowlist.js";

// Security review round 1 (Task 2): every bypass the reviewer found, plus the controller's rulings.

const allowed = (vql: string): void => {
  expect(vqlAllowed(vql), `expected allowed: ${vql}`).toEqual({ ok: true });
};
const blocked = (vql: string): void => {
  expect(vqlAllowed(vql).ok, `expected blocked: ${vql}`).toBe(false);
};

describe("CRITICAL 1 — delegate pathspecs and credential variables", () => {
  it("blocks the reviewer's raw_reg → smb delegate", () => {
    blocked(
      `LET SMB_CREDENTIALS = dict(host='u:p') SELECT * FROM read_file(filename='{"DelegateAccessor":"smb","DelegatePath":"host/s/x"}', accessor='raw_reg')`,
    );
  });

  it("no longer allows the raw_reg accessor", () => {
    expect(ALLOWED_ACCESSORS).not.toContain("raw_reg");
    blocked("SELECT * FROM read_file(filename='C:/x', accessor='raw_reg')");
  });

  it("blocks any string that names a delegate or opens a JSON object", () => {
    blocked(`SELECT * FROM read_file(filename='{"Path":"x"}', accessor='ntfs')`);
    blocked(`SELECT * FROM read_file(filename=' { "Path":"x"}')`);
    blocked("SELECT * FROM pslist() WHERE Name = 'my delegatepath'");
  });

  it.each([
    "SMB_CREDENTIALS",
    "s3_credentials",
    "SSH_PRIVATE_KEY_FILE",
    "Ssh_Hostname",
    "ANY_CREDENTIALS",
    "VELO_CONFIG",
    "MYCRED",
    "API_KEY",
    "AUTHTOKEN",
    "DBPASS",
    "TOPSECRET",
  ])("refuses LET %s, a config or credential variable", (name) => {
    blocked(`LET ${name} = dict(a=1)\nSELECT * FROM pslist()`);
  });
});

describe("IMPORTANT 2 — wmi", () => {
  it("allows a reviewed read-only class", () => {
    allowed("SELECT * FROM wmi(query='SELECT Name FROM Win32_Process')");
    allowed("SELECT * FROM wmi(query=\"SELECT * FROM win32_service WHERE State = 'Running'\")");
  });

  it("blocks a side-effecting class", () => {
    blocked(
      "SELECT * FROM wmi(query=\"SELECT * FROM Win32_PingStatus WHERE Address='x.attacker.example.com'\")",
    );
  });

  it("blocks a query that is not one plain literal SELECT", () => {
    blocked("SELECT * FROM wmi(query='SELECT * FROM ' + 'Win32_PingStatus')");
    blocked("SELECT * FROM wmi(query='ASSOCIATORS OF {Win32_Process}')");
    blocked("SELECT * FROM wmi(query='SELECT * FROM Win32_Process, Win32_PingStatus')");
    blocked("SELECT * FROM wmi()");
  });

  it("blocks any namespace argument", () => {
    blocked("SELECT * FROM wmi(query='SELECT * FROM Win32_Process', namespace='ROOT\\\\CIMV2')");
    blocked("SELECT * FROM wmi(query='x', namespace='\\\\\\\\remote\\\\root\\\\cimv2')");
  });
});

describe("IMPORTANT 3 — network paths", () => {
  it("blocks a path built at runtime", () => {
    blocked("SELECT * FROM glob(globs=format(format='%c%chost.example.com%cshare%c*', args=[92,92,92,92]))");
    blocked("SELECT * FROM glob(globs='C:/' + 'x')");
    blocked("LET P = 'C:/x'\nSELECT * FROM hash(path=P)");
    blocked("SELECT * FROM glob(globs='C:/*') WHERE hash(path=OSPath)");
  });

  it("allows literal paths and arrays of literal paths", () => {
    allowed("SELECT * FROM glob(globs='C:/Users/*/NTUSER.DAT')");
    allowed("SELECT * FROM glob(globs=['C:/a/*', 'C:/b/*'], root='C:/')");
    allowed("SELECT * FROM yara(rules='rule x { condition: true }', files='C:/x')");
  });

  it.each([
    "SELECT * FROM glob(globs='\\\\\\\\host.example.com\\\\share\\\\*')",
    "SELECT * FROM glob(globs='//host.example.com/share/*')",
    "SELECT * FROM glob(globs='  //host.example.com/share/*')",
    "SELECT * FROM glob(globs='\\\\\\\\?\\\\UNC\\\\host.example.com\\\\s')",
    "SELECT * FROM glob(globs='C:/x\\\\\\\\.\\\\unc\\\\h')",
    "SELECT * FROM glob(globs='smb://host.example.com/s')",
    "SELECT * FROM glob(globs='FILE:///x')",
    "SELECT * FROM pslist() WHERE Name = 'https://x.example.com'",
    "SELECT * FROM read_file(filenames=['C:/x', 'ftp://h.example.com/y'])",
    "SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(EvtxGlob='\\\\\\\\h\\\\c$\\\\*.evtx')",
  ])("blocks a network path: %s", (vql) => {
    blocked(vql);
  });

  it("requires every artifact argument to be a plain literal", () => {
    allowed(
      "SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(EvtxGlob='C:/Windows/System32/winevt/Logs/*.evtx')",
    );
    blocked("SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(EvtxGlob=format(format='%v', args='x'))");
    blocked("SELECT * FROM Artifact.Windows.Search.FileFinder(SearchFilesGlobTable=Procs)");
  });
});

describe("IMPORTANT 5 — positional arguments and string-compiled queries", () => {
  it("blocks positional arguments to any call", () => {
    blocked("SELECT regex_replace('a','b','c') FROM info()");
    blocked("SELECT * FROM pslist(4)");
    blocked("SELECT format(format='%v', 'x') FROM info()");
    blocked("SELECT * FROM pslist(pid=1,)");
  });

  it("blocks string values for query-like arguments", () => {
    blocked("SELECT * FROM if(condition=true, then='SELECT * FROM execve(argv=1)')");
    blocked("SELECT * FROM if(condition=true, then={SELECT * FROM info()}, else='SELECT 1 FROM info()')");
    blocked("SELECT enumerate(items='x') FROM info()");
    blocked("SELECT * FROM if(condition=true, then=format(format='SELECT * FROM info()'))");
  });

  it("allows subqueries and names for query-like arguments", () => {
    allowed("SELECT * FROM if(condition=true, then={SELECT * FROM info()})");
    allowed("LET Procs = SELECT * FROM pslist()\nSELECT * FROM if(condition=true, then=Procs)");
  });

  it("still allows an empty argument list and keyword parentheses", () => {
    allowed("SELECT * FROM pslist() WHERE Pid IN (1, 2) AND NOT (Pid = 4)");
  });
});

describe("ruling 6 — LET names", () => {
  it.each(["Pslist", "Glob", "Execve", "Upload_Directory", "Label", "Hunt"])(
    "refuses LET %s, which reuses an allowed or risky built-in name",
    (name) => {
      blocked(`LET ${name} = SELECT * FROM info()\nSELECT * FROM ${name}()`);
    },
  );
});

describe("reviewer probe cases stay blocked", () => {
  it.each([
    "SELECT * FROM pslist() /* c */ WHERE execve(argv=['x'])",
    "SELECT 'a\\'b', execve(argv=1), 'c' FROM pslist()",
    "SELECT * FROM exec\u200Bve(argv=1)",
    "LET X = execve SELECT * FROM X(argv=1)",
    "LET X = execve SELECT * FROM X",
    "LET X(a) = execve(argv=a) SELECT * FROM X(a=1)",
    "SELECT * FROM Artifact.Windows.Search.FileFinder(SearchFilesGlob='C:/x', Accessor='smb')",
    "SELECT * FROM pslist() WHERE { SELECT * FROM execve(argv=1) }",
    "SELECT * FROM if(condition=true, then={ SELECT * FROM shell(cmd='x') })",
    "SELECT * FROM sql(query='DROP TABLE x')",
    "SELECT * FROM pe(file='x')",
    "SELECT * FROM pslist() -- x\n, execve(argv=1)",
    "SELECT Artifact.Windows.System.CmdShell FROM info()",
    "SELECT * FROM Artifact.Windows.System.Pslist.CmdShell()",
    "SELECT * FROM info()->execve(argv=1)",
    "SELECT * FROM count(items={SELECT * FROM execve(argv=1)})",
    "SELECT * FROM if(condition=true, then=execve)",
    "SELECT * FROM FROM",
    "SELECT * FROM info() WHERE pslist.execve(argv=1)",
    "SELECT * FROM info() WHERE dict(a=1).a(x=1)",
    "SELECT * FROM info() WHERE [1](x=1)",
    "SELECT * FROM info() WHERE x(y=1)",
    "LET x = 1 SELECT * FROM x",
    "SELECT * FROM pslist(\x7f)",
    "SELECT * FROM info() WHERE 1 = 1 ;; SELECT * FROM execve(argv=1)",
  ])("%s", (vql) => {
    blocked(vql);
  });
});
