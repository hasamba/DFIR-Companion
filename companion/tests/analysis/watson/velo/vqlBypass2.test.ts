import { describe, it, expect } from "vitest";
import { vqlAllowed } from "../../../../src/analysis/ai/watson/velo/vqlAllowed.js";
import { WMI_CLASSES } from "../../../../src/analysis/ai/watson/velo/vqlAllowlist.js";

// Security re-review round 2 (Task 2): the reviewer's second probe set.

const B = "\\";
const allowed = (vql: string): void => {
  expect(vqlAllowed(vql), `expected allowed: ${vql}`).toEqual({ ok: true });
};
const blocked = (vql: string): void => {
  expect(vqlAllowed(vql).ok, `expected blocked: ${vql}`).toBe(false);
};

describe("1 — escapes other than \\\\ \\' \\\" \\n \\t \\r are refused", () => {
  it.each([
    `SELECT * FROM glob(globs="${B}x5c${B}x5chost.example.com${B}x5cshare${B}x5c*")`,
    `SELECT * FROM glob(globs='${B}u005c${B}u005chost.example.com/s/*')`,
    `SELECT * FROM read_file(filename="${B}x7b${B}"DelegateAccessor${B}":1}")`,
    `SELECT * FROM pslist() WHERE Name = '${B}0'`,
  ])("%s", (vql) => blocked(vql));

  it("still allows the plain escapes", () => {
    allowed(`SELECT * FROM glob(globs='C:${B}${B}Windows${B}${B}Temp${B}${B}*.ps1')`);
    allowed(`SELECT * FROM pslist() WHERE Name = "a${B}'b${B}n${B}t${B}r" OR Name = 'c${B}"d'`);
  });
});

describe("2 — network paths hidden inside a path literal", () => {
  it.each([
    "SELECT * FROM glob(globs='{C:/x,//host.example.com/share}/*')",
    `SELECT * FROM glob(globs='{C:${B}${B}x,${B}${B}${B}${B}host${B}${B}share}${B}${B}*')`,
    "SELECT * FROM glob(globs='C:/../..//host.example.com/share/*')",
    `SELECT * FROM glob(globs=' ${B}${B}${B}${B}host${B}${B}s')`,
    `SELECT * FROM stat(filename='${B}${B}${B}${B}?${B}${B}GLOBALROOT${B}${B}Device${B}${B}Mup${B}${B}host${B}${B}s')`,
    `SELECT * FROM glob(globs='C:/x${B}${B}${B}${B}host')`,
    "SELECT * FROM glob(globs='{C:/a,D:/b}/*')",
    "SELECT * FROM glob(globs=['C:/a', '//h/s'])",
    "SELECT * FROM glob(globs=['C:/a' , 'C:/b' ,])",
    "SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(VSSAnalysisAge='//h/s')",
    "SELECT * FROM Artifact.Windows.Search.FileFinder(SearchFilesGlob='C:/a//b')",
    "SELECT * FROM glob(globs='*', root=path_join(components=['','','h','s']))",
  ])("%s", (vql) => blocked(vql));

  it("still allows brace alternation without separators and ordinary paths", () => {
    allowed("SELECT * FROM glob(globs='C:/Users/*/{NTUSER,UsrClass}.DAT')");
    allowed("SELECT * FROM glob(globs=['C:/a/*', 'C:/b/*'])");
  });
});

describe("3 — yara include", () => {
  it("blocks include in yara rules", () => {
    blocked(`SELECT * FROM yara(rules='include "//h/s/r.yar" rule a {condition:true}', files='C:/x')`);
    blocked(`SELECT * FROM yara(rules='INCLUDE "C:/r.yar" rule a {condition:true}', files='C:/x')`);
  });

  it("still allows a self-contained rule", () => {
    allowed("SELECT * FROM yara(rules='rule a { strings: $s = \"evil\" condition: $s }', files='C:/x')");
  });
});

describe("4 — Win32_Product", () => {
  it("is off the WMI class list", () => {
    expect(WMI_CLASSES).not.toContain("Win32_Product");
    blocked("SELECT * FROM wmi(query='SELECT * FROM Win32_Product')");
  });
});

describe("probe 2 cases that must stay blocked", () => {
  it.each([
    "SELECT * FROM wmi(query='SELECT * FROM [Win32_PingStatus]')",
    "SELECT * FROM wmi(query='SELECT * FROM Win32_Process/**/WHERE 1')",
    `SELECT * FROM wmi(query='SELECT * FROM Win32_Process WHERE Name="x"', query='SELECT * FROM Win32_PingStatus')`,
    "SELECT * FROM WMI(query='SELECT * FROM Win32_PingStatus')",
    "SELECT * FROM wmi(query='SELECT Address FROM Win32_Process WHERE x=1 FROM Win32_PingStatus')",
    "SELECT * FROM Artifact.Windows.Search.FileFinder(SearchFilesGlobTable=format(format='%c%ch', args=[92,92]))",
    "SELECT * FROM Artifact.Windows.Search.FileFinder(Root=X)",
    "SELECT * FROM if(condition=true, then=({SELECT * FROM info()}))",
    "SELECT * FROM if(condition=true, Then='SELECT * FROM execve()')",
    "LET smb_credentials = dict(h='u:p') SELECT * FROM info()",
    "LET SmbCredentials = dict(h='u:p') SELECT * FROM info()",
    "SELECT * FROM Artifact.Generic.Client.Info(SMB_CREDENTIALS='x')",
    "LET PsList = SELECT * FROM info() SELECT * FROM PsList()",
    "SELECT * FROM glob (globs=format(format='%c', args=[92]))",
    "SELECT * FROM glob/**/(globs=X)",
    "SELECT * FROM hash(path='C:/x', accessor=Acc)",
    "SELECT * FROM glob(globs='http:x')",
    "SELECT * FROM glob(globs='HTTPS://h/x')",
  ])("%s", (vql) => blocked(vql));
});

describe("round 3 — mixed separator pairs", () => {
  it.each([
    `SELECT * FROM glob(globs='/${B}${B}host/s')`,
    `SELECT * FROM glob(globs='${B}${B}/host')`,
    `SELECT * FROM glob(globs='/${B}${B}?/UNC/h/s')`,
    `SELECT * FROM glob(globs='C:/x/${B}${B}/host')`,
    `SELECT * FROM pslist() WHERE Name = '/${B}${B}host/s'`,
    `SELECT * FROM Artifact.Windows.Search.FileFinder(SearchFilesGlob='C:/x${B}${B}/h')`,
    "SELECT * FROM glob(globs='C:/x/[/]host')",
    "SELECT * FROM glob(globs='[/][/]host/s/*')",
    "SELECT * FROM glob(root='/', globs='/host/s/*')",
    "SELECT * FROM Artifact.Windows.Search.FileFinder(SearchFilesGlob=['/', '/host/share/*'])",
    "SELECT * FROM glob(root='C:/', globs=['a/*', '/host/s'])",
  ])("%s", (vql) => blocked(vql));

  it("still allows ordinary paths", () => {
    allowed("SELECT * FROM glob(globs='C:/Windows/System32/*')");
    allowed("SELECT * FROM glob(root='C:/Windows', globs='/System32/*.dll')");
    allowed("SELECT * FROM glob(globs='C:/Windows/[Ss]ystem32/*')");
    allowed("SELECT * FROM glob(globs='C:/Users/*/{NTUSER,UsrClass}.DAT')");
  });
});
