import { describe, expect, it } from "vitest";
import {
  ALREADY_RAN,
  HOST_NOT_IN_FLEET,
  STRING_REWRITTEN,
  sentTextAllowed,
} from "../../../../src/analysis/ai/watson/velo/launchCheck.js";
import {
  REASON_RULES,
  classifyReason,
  plainRisk,
  ruleFor,
  splitReasons,
} from "../../../../src/analysis/ai/watson/velo/vqlRiskClass.js";
import { VQL_TOO_LONG } from "../../../../src/analysis/vqlInput.js";
import { unsafeVqlCharProblem } from "../../../../src/analysis/vqlStatements.js";

// Task 9 (user request 2026-11-14): risky Watson VQL can be approved by the analyst. Every reason the
// launch check can produce is classified HARD (refused, no approval) or RISKY (approvable); a reason
// no rule names is HARD. This file enumerates one VQL per reason shape and asserts its class.

const reasonsOf = (vql: string): string[] => {
  const r = sentTextAllowed(vql);
  return r.ok ? [] : r.reasons;
};

/** [VQL, a fragment of the reason it must produce, the expected class]. */
const SAMPLES: Array<[string, string, "hard" | "risky"]> = [
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

describe("Watson launch reason classes (Task 9)", () => {
  it.each(SAMPLES)("%s → %s is %s", (vql, fragment, cls) => {
    const reasons = reasonsOf(vql);
    const hit = reasons.find((r) => r.includes(fragment));
    expect(hit, `no reason containing "${fragment}" in ${JSON.stringify(reasons)}`).toBeDefined();
    expect(ruleFor(hit!), `no rule names "${hit}"`).toBeDefined();
    expect(classifyReason(hit!)).toBe(cls);
  });

  it("every reason every sample produces is named by a rule (none falls to the default)", () => {
    const all = SAMPLES.flatMap(([vql]) => reasonsOf(vql));
    expect(all.length).toBeGreaterThan(SAMPLES.length - 1);
    expect(all.filter((r) => !ruleFor(r))).toEqual([]);
  });

  it.each([
    ["the VQL is empty", "hard"],
    ["unknown launch mode", "hard"],
    [VQL_TOO_LONG, "hard"],
    ["no runnable VQL", "hard"],
    [ALREADY_RAN, "hard"],
    [STRING_REWRITTEN, "hard"],
    [HOST_NOT_IN_FLEET, "hard"],
    ["host name matches more than one client in the case's Velociraptor fleet", "hard"],
    ["a fleet hunt does not take a host", "hard"],
    ["''' (a triple-quoted string) is not allowed", "hard"],
    ["a carriage return in the VQL", "hard"],
  ] as const)("the fixed reason %s is %s", (reason, cls) => {
    expect(ruleFor(reason)).toBeDefined();
    expect(classifyReason(reason)).toBe(cls);
  });

  it("every rule is matched by some produced or fixed reason (no dead or reworded rule)", () => {
    const fixed = [
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
    const all = [...fixed, ...SAMPLES.flatMap(([vql]) => reasonsOf(vql))];
    const dead = REASON_RULES.filter((r) => !all.some((x) => r.test.test(x))).map((r) => String(r.test));
    expect(dead).toEqual([]);
  });

  it("no plain reason shown on an approvable card says refused or must", () => {
    const risky = SAMPLES.flatMap(([vql]) => reasonsOf(vql)).filter((r) => classifyReason(r) === "risky");
    expect(risky.map(plainRisk).filter((p) => /\brefused\b|\bmust\b|\bneeds\b/.test(p))).toEqual([]);
  });

  it("an unclassified reason is HARD (fail closed)", () => {
    expect(ruleFor("something nobody wrote a rule for")).toBeUndefined();
    expect(classifyReason("something nobody wrote a rule for")).toBe("hard");
  });

  it("a risky-looking reason with HARD text appended does not become risky", () => {
    expect(classifyReason("the VQL calls execve, which is not on Watson's read-only list; comments")).toBe(
      "hard",
    );
  });

  it("splitReasons: any HARD reason makes the set HARD", () => {
    const s = splitReasons([
      "the VQL calls execve, which is not on Watson's read-only list",
      "comments are not allowed",
    ]);
    expect(s.hard).toEqual(["comments are not allowed"]);
    expect(s.risky).toHaveLength(1);
  });

  it("every rule declares its class", () => {
    for (const r of REASON_RULES) expect(["hard", "risky"]).toContain(r.cls);
  });

  it("maps common calls to plain English, others to the reviewed-list fallback", () => {
    expect(plainRisk("the VQL calls execve, which is not on Watson's read-only list")).toBe(
      "runs a program on the endpoint (execve)",
    );
    expect(plainRisk("the VQL calls http_client, which is not on Watson's read-only list")).toBe(
      "sends data over the network (http_client)",
    );
    expect(plainRisk("the VQL calls frobnicate, which is not on Watson's read-only list")).toBe(
      "uses frobnicate, which is not on the reviewed safe list",
    );
    expect(plainRisk("the VQL calls artifact Windows.Evil, which is not on Watson's read-only list")).toBe(
      "uses artifact Windows.Evil, which is not on the reviewed safe list",
    );
    expect(plainRisk("a string that looks like a network path")).toBe(
      "a string that looks like a network path",
    );
  });
});
