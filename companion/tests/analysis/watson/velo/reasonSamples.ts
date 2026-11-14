import {
  ALREADY_RAN,
  HOST_NOT_IN_FLEET,
  STRING_REWRITTEN,
  sentTextAllowed,
} from "../../../../src/analysis/ai/watson/velo/launchCheck.js";
import { VQL_TOO_LONG } from "../../../../src/analysis/vqlInput.js";
import { unsafeVqlCharProblem } from "../../../../src/analysis/vqlStatements.js";

// One VQL per launch-check reason shape, plus the fixed reasons (shared by vqlRiskClass.test.ts and
// vqlReasonSte.test.ts, so every reason the checks produce is both classified and translated).

export const reasonsOf = (vql: string): string[] => {
  const r = sentTextAllowed(vql);
  return r.ok ? [] : r.reasons;
};

/** [VQL, a fragment of the reason it must produce, the expected class]. */
export const SAMPLES: Array<[string, string, "hard" | "risky"]> = [
  // HARD: the text the analyst sees could differ from what runs, or the check cannot tell what runs.
  ["SELECT * FROM pslist() ", "invisible control", "hard"],
  ["SELECT * FROM pslist()​", "invisible control", "hard"],
  ["SELECT * FROM pslist()\r\n", "invisible control", "hard"],
  ["SELECT '''x''' FROM pslist()", "triple-quoted", "hard"],
  ["SELECT * FROM pslist() -- hi", "comments are not allowed", "hard"],
  ["SELECT * FROM pslist() // hi", "comments are not allowed", "hard"],
  ["SELECT * FROM pslist() /* hi */", "comments are not allowed", "hard"],
  ["SELECT * FROM pslist() WHERE Name = 'a\n\nb'", "blank line", "hard"],
  ["SELECT * FROM pslist() WHERE Name = 'a\n--b'", "blank line", "hard"],
  ["SELECT * FROM pslist() WHERE Name = 'a", "unreadable VQL", "hard"],
  ["SELECT * FROM pslist() WHERE Name = é", "unreadable VQL", "hard"],
  ["SELECT * FROM `pslist`()", "unreadable VQL", "hard"],
  ["SELECT * FROM pslist(", "unbalanced brackets", "hard"],
  ["SELECT * FROM pslist(pid=1,)", "empty argument", "hard"],
  ["LET = 1 SELECT * FROM pslist()", "without a plain name", "hard"],
  ["LET X 1 SELECT * FROM pslist()", "is malformed", "hard"],
  ["SELECT * FROM 'x'", "FROM must name a plugin", "hard"],
  ["SELECT * FROM Artifact()", "Artifact must be followed directly", "hard"],
  ["SELECT * FROM (pslist)()", "result of an expression", "hard"],
  // RISKY: content the analyst can read and decide on.
  ["SELECT * FROM execve(argv=['calc'])", "execve", "risky"],
  ["SELECT * FROM shell(cmd='x')", "shell", "risky"],
  ["SELECT * FROM http_client(url='https://x')", "http_client", "risky"],
  ["SELECT * FROM somethingelse()", "somethingelse", "risky"],
  ["SELECT * FROM eval(func='x')", "dynamic invocation", "risky"],
  ["SELECT * FROM Artifact.Windows.Evil.Thing()", "artifact Windows.Evil.Thing", "risky"],
  ["SELECT * FROM foo.bar()", "dotted name", "risky"],
  ["SELECT * FROM pslist(1)", "positional argument", "risky"],
  ["LET pslist = SELECT * FROM info() SELECT * FROM pslist()", "reuses the name of a built-in", "risky"],
  ["LET SMB_CREDENTIALS = dict(a=1) SELECT * FROM pslist()", "config or credential", "risky"],
  ["LET lower = SELECT * FROM info() SELECT * FROM lower()", "no capital letter", "risky"],
  ["LET Val = 1 SELECT * FROM Val()", "does not define a query", "risky"],
  ["SELECT * FROM glob(globs='//host/share/*')", "network path", "risky"],
  ["SELECT * FROM glob(globs='/x/[/]')", "class holding a path separator", "risky"],
  ["SELECT * FROM glob(globs='/x/{a/b}')", "alternation holding a path separator", "risky"],
  ["SELECT * FROM glob(globs='/')", "bare separator", "risky"],
  ["SELECT * FROM glob(root='/', globs='/x')", "glob root ending", "risky"],
  ["SELECT * FROM pslist() WHERE Name = 'https://x'", "looks like a network path", "risky"],
  ["SELECT * FROM pslist() WHERE Name = 'delegate'", "delegate pathspec", "risky"],
  [`SELECT * FROM pslist() WHERE Name = '{"a":1}'`, "JSON pathspec", "risky"],
  ["SELECT * FROM pslist() WHERE Name = 'x=>y'", "lambda string", "risky"],
  ["SELECT * FROM if(condition=true, then='SELECT 1')", "must be a {subquery}", "risky"],
  ["SELECT * FROM glob(globs='/x', upload=true)", "uploads, dumps and lambdas", "risky"],
  ["SELECT * FROM read_file(filename='/x', accessor='smb')", "accessor must be", "risky"],
  ["SELECT * FROM pslist(namespace='x')", "namespace argument", "risky"],
  ["SELECT * FROM wmi(query='SELECT * FROM Win32_Evil')", "wmi class", "risky"],
  ["SELECT * FROM wmi(query=1)", "wmi needs one quoted", "risky"],
  ["SELECT * FROM Artifact.Generic.Client.Info(x=format(a=1))", "artifact argument", "risky"],
  ["SELECT * FROM yara(rules=format(a=1), files='/x')", "yara rules must be", "risky"],
  ["SELECT * FROM yara(rules='include \"x\"', files='/x')", "may not include", "risky"],
  ["SELECT * FROM read_file(filename=format(a=1))", "plain quoted path", "risky"],
  ["SELECT * FROM foo.Artifact.Windows()", "reaches an artifact through another name", "risky"],
  [
    "SELECT * FROM Artifact.Generic.Client.Info(SMB_CREDENTIALS='x')",
    "argument SMB_CREDENTIALS would set",
    "risky",
  ],
];

export const FIXED_REASONS: string[] = [
  "the VQL is empty",
  "unknown launch mode",
  VQL_TOO_LONG,
  "no runnable VQL",
  ALREADY_RAN,
  HOST_NOT_IN_FLEET,
  "host name matches more than one client in the case's Velociraptor fleet",
  "a fleet hunt does not take a host",
  "a carriage return in the VQL",
  STRING_REWRITTEN,
  unsafeVqlCharProblem("x\u{E0100}") ?? "",
];
