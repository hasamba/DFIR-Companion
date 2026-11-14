import { CALL_PLAIN } from "./vqlRiskClass.js";

// Task 10 fix round (user decision 2026-11-14: "the entire watson chat will be in asd-ste100"). The
// launch-check reasons stay byte-identical where they are stored and compared (risk.checks, the
// anchored rules of vqlRiskClass.ts). This module translates them for DISPLAY only: each reason the
// checks can produce becomes one to three ASD-STE100 sentences of 20 words or fewer. Technical names
// (calls, artifacts, arguments, LET names, Unicode code points) stay verbatim.

interface SteRule {
  test: RegExp;
  ste: (m: RegExpExecArray) => string;
}

const N = "[A-Za-z_][A-Za-z0-9_]*";
const D = `${N}(?:\\.${N})*`;
const re = (s: string): RegExp => new RegExp(`^${s}$`);
const fixed = (text: string) => (): string => text;

const callSte = (name: string): string =>
  CALL_PLAIN[name]
    ? `The query ${CALL_PLAIN[name]} (${name}).`
    : `The query uses ${name}. This name is not on the reviewed safe list.`;

const STE_RULES: readonly SteRule[] = [
  // Invalid launch.
  { test: re("the VQL is empty"), ste: fixed("The query is empty.") },
  { test: re("unknown launch mode"), ste: fixed("Watson does not know this launch mode.") },
  {
    test: re("vql is too long \\(limit (\\d+) bytes of UTF-8\\)"),
    ste: (m) => `The query is too long. The limit is ${m[1]} bytes of UTF-8.`,
  },
  { test: re("no runnable VQL"), ste: fixed("The query has no statement that can run.") },
  { test: re("this hunt already ran on the case"), ste: fixed("This hunt already ran on the case.") },
  {
    test: re("host not in the case's Velociraptor fleet"),
    ste: fixed("The host is not in the Velociraptor fleet of this case."),
  },
  {
    test: re("host name matches more than one client in the case's Velociraptor fleet"),
    ste: fixed("The host name matches more than one client in the Velociraptor fleet of this case."),
  },
  { test: re("a fleet hunt does not take a host"), ste: fixed("A fleet-wide hunt cannot have a host.") },
  // The checked text could differ from the text that runs.
  {
    test: re(
      "the VQL contains an invisible control or line-break character \\((U\\+[0-9A-F]{4,6})\\) that Velociraptor could read differently from what was checked; retype the query without it",
    ),
    ste: (m) =>
      `The query has a hidden control or line-break character (${m[1]}). Velociraptor can read it differently. Type the query again without it.`,
  },
  {
    test: re("''' \\(a triple-quoted string\\) is not allowed"),
    ste: fixed("Watson does not accept a triple-quoted string (''')."),
  },
  { test: re("a carriage return in the VQL"), ste: fixed("The query has a carriage return.") },
  {
    test: re("the duration rewrite would change a string literal"),
    ste: fixed("A change to a duration value would also change a string in the query."),
  },
  { test: re("comments are not allowed"), ste: fixed("Watson does not accept comments in the query.") },
  {
    test: re("a string literal holds a blank line or a line starting with --"),
    ste: fixed("A string in the query has a blank line or a line that starts with --."),
  },
  // The check cannot read the query or name what runs.
  { test: re("unreadable VQL: ([^;]+)"), ste: (m) => `Watson cannot read the query (${m[1]}).` },
  { test: re(`(${D})\\( has unbalanced brackets`), ste: (m) => `The brackets after ${m[1]} do not match.` },
  { test: re(`(${D}) has an empty argument`), ste: (m) => `The call to ${m[1]} has an empty argument.` },
  {
    test: re("a LET statement without a plain name"),
    ste: fixed("A LET statement does not have a plain name."),
  },
  { test: re(`LET (${N}) is malformed`), ste: (m) => `The LET statement for ${m[1]} is not correct.` },
  { test: re("FROM must name a plugin"), ste: fixed("FROM must have a plugin name after it.") },
  {
    test: re("Artifact must be followed directly by \\.<Name>"),
    ste: fixed("Artifact must have .<Name> directly after it."),
  },
  {
    test: re("the VQL calls the result of an expression"),
    ste: fixed("The query calls the result of an expression."),
  },
  // Calls and artifacts that are not on the reviewed list.
  {
    test: re(`the VQL calls artifact (${D}), which is not on Watson's read-only list`),
    ste: (m) => `The query uses artifact ${m[1]}. This artifact is not on the reviewed safe list.`,
  },
  { test: re(`the VQL calls (${N}), which is not on Watson's read-only list`), ste: (m) => callSte(m[1]) },
  {
    test: re(`the VQL calls (${D}), a dotted name that is not an allowed artifact`),
    ste: (m) => `The query uses ${m[1]}. This name is not an artifact on the reviewed safe list.`,
  },
  {
    test: re(`(${N}) is dynamic invocation \\(it evaluates a string or computed name as VQL\\)`),
    ste: (m) => `The query uses ${m[1]} to run text as VQL.`,
  },
  {
    test: re(`(${D}) reaches an artifact through another name`),
    ste: (m) => `The name ${m[1]} gets to an artifact through a different name.`,
  },
  // LET names.
  {
    test: re(`LET (${N}) reuses the name of a built-in`),
    ste: (m) => `LET ${m[1]} uses the name of a built-in function.`,
  },
  {
    test: re(`LET (${N}) would set a config or credential variable`),
    ste: (m) => `LET ${m[1]} sets a configuration or credential variable.`,
  },
  {
    test: re(`LET (${N}) is called but does not define a query`),
    ste: (m) => `The query calls LET ${m[1]}, but ${m[1]} does not define a query.`,
  },
  {
    test: re(`LET (${N}) is called but its name has no capital letter, so it could shadow a built-in`),
    ste: (m) =>
      `The query calls LET ${m[1]}. Its name has no capital letter, so it can hide a built-in function.`,
  },
  // Arguments.
  {
    test: re(`(${D}) has a positional argument \\(every argument must be name=value\\)`),
    ste: (m) => `The query gives an unnamed (positional) argument to ${m[1]}.`,
  },
  {
    test: re(`argument (${N}) is refused \\(uploads, dumps and lambdas\\)`),
    ste: (m) => `The query uses argument ${m[1]}. This argument can upload, dump or run a lambda.`,
  },
  {
    test: re("accessor must be one quoted local accessor \\([^()]*\\)"),
    ste: fixed("The query uses an accessor that is not on the reviewed local list."),
  },
  { test: re("a namespace argument is refused"), ste: fixed("The query uses a namespace argument.") },
  {
    test: re("wmi needs one quoted WQL SELECT from a reviewed read-only class"),
    ste: fixed("The WMI query is not one plain SELECT from a reviewed class."),
  },
  {
    test: re(`wmi class (${N}) is not on Watson's read-only list`),
    ste: (m) => `The query uses WMI class ${m[1]}. This class is not on the reviewed safe list.`,
  },
  {
    test: re(`argument (${N}) must be a \\{subquery\\} or a LET query name`),
    ste: (m) => `The query gives ${m[1]} as text. VQL can run this text as a query.`,
  },
  {
    test: re(`argument (${N}) would set a config or credential variable`),
    ste: (m) => `Argument ${m[1]} sets a configuration or credential variable.`,
  },
  {
    test: re(`artifact argument (${N}) must be a plain quoted value`),
    ste: (m) => `The query makes artifact argument ${m[1]} at run time.`,
  },
  {
    test: re("yara rules must be a plain quoted value"),
    ste: fixed("The query makes the yara rules at run time."),
  },
  { test: re("yara rules may not include other files"), ste: fixed("The yara rules include other files.") },
  {
    test: re(`(${D}) argument (${N}) must be a plain quoted path \\(no paths built at run time\\)`),
    ste: (m) => `The query makes the ${m[1]} ${m[2]} path at run time.`,
  },
  // Path and string literals.
  {
    test: re(`(${N}) holds two path separators in a row \\(a possible network path\\)`),
    ste: (m) => `The value ${m[1]} has two path separators together. This can be a network path.`,
  },
  {
    test: re(`(${N}) is a bare separator \\(it could join into a network path\\)`),
    ste: (m) => `The value ${m[1]} is only a path separator. It can join into a network path.`,
  },
  {
    test: re(`(${N}) has a \\[\\.\\.\\.\\] class holding a path separator`),
    ste: (m) => `The value ${m[1]} has a [...] class with a path separator.`,
  },
  {
    test: re(`(${N}) has a \\{…\\} alternation holding a path separator`),
    ste: (m) => `The value ${m[1]} has a {…} alternation with a path separator.`,
  },
  {
    test: re(
      "glob root ending in a separator joined to globs starting with one \\(a possible network path\\)",
    ),
    ste: fixed(
      "The glob root ends with a separator, and a glob starts with one. Together they can make a network path.",
    ),
  },
  {
    test: re("a lambda string \\(=>\\), which VQL evaluates as code"),
    ste: fixed("A string has a lambda (=>). VQL runs it as code."),
  },
  { test: re("a string naming a delegate pathspec"), ste: fixed("A string names a delegate pathspec.") },
  { test: re("a string holding a JSON pathspec"), ste: fixed("A string has a JSON pathspec.") },
  { test: re("a string that looks like a network path"), ste: fixed("A string looks like a network path.") },
];

const REASON_CODE_MAX = 120;

/** The generic line for a reason no rule names: an STE sentence plus the raw reason, quoted. */
export const steFallback = (reason: string): string =>
  `The safety check blocked this query. Reason code: "${reason.slice(0, REASON_CODE_MAX)}".`;

/** One launch-check reason as ASD-STE100 sentences, for display. The stored reason never changes. */
export function steReason(reason: string): string {
  for (const rule of STE_RULES) {
    const m = rule.test.exec(reason);
    if (m) return rule.ste(m);
  }
  return steFallback(reason);
}

/** Several reasons as one run of sentences. */
export const steReasons = (reasons: readonly string[]): string => reasons.map(steReason).join(" ");
