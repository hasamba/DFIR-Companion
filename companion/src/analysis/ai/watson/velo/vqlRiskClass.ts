// Which launch-check refusals an analyst may approve (Task 9, user request 2026-11-14: "if watson
// recommend a query we think its risky, the analyst should be able to approve it").
//
//   HARD  — still refused, no approval possible: anything where the text the analyst reads could
//           differ from what Velociraptor runs (hidden characters, ''', comments, a split inside a
//           string), anything the check cannot read or name (parse failures, a call on an
//           expression), and an invalid launch (empty, oversize, re-run, host problems).
//   RISKY — a content rule the analyst can read and decide on: a call, artifact, argument or string
//           that is not on the reviewed read-only list.
//
// Every reason the checks produce is named by one fully anchored rule below. A reason no rule names
// is HARD (fail closed), and so is a whole set that holds any HARD reason.

export type ReasonClass = "hard" | "risky";

export interface ReasonRule {
  test: RegExp;
  cls: ReasonClass;
  /** Plain English for the analyst's warning (risky only); the raw reason when absent. */
  plain?: (m: RegExpExecArray) => string;
}

const N = "[A-Za-z_][A-Za-z0-9_]*";
const D = `${N}(?:\\.${N})*`;
const re = (s: string): RegExp => new RegExp(`^${s}$`);

/** What a known call does, in plain words (the denied names of vqlAllowlist.ts). */
const CALL_PLAIN: Readonly<Record<string, string>> = {
  execve: "runs a program on the endpoint",
  shell: "runs a shell command on the endpoint",
  rm: "deletes files on the endpoint",
  copy: "copies files on the endpoint",
  mkdir: "creates folders on the endpoint",
  upload: "uploads files from the endpoint",
  upload_directory: "uploads a folder from the endpoint",
  write_csv: "writes a file",
  write_jsonl: "writes a file",
  write_file: "writes a file",
  mail: "sends email",
  http_client: "sends data over the network",
  elastic_upload: "sends data to Elasticsearch",
  splunk_upload: "sends data to Splunk",
  collect_client: "starts another collection",
  hunt: "starts another hunt",
  hunt_add: "adds clients to a hunt",
  artifact_set: "changes an artifact on the server",
  artifact_delete: "deletes an artifact on the server",
  user_create: "creates a Velociraptor user",
  user_delete: "deletes a Velociraptor user",
  server_set_metadata: "changes server metadata",
  client_set_metadata: "changes client metadata",
  label: "changes client labels",
  killkillkill: "restarts the Velociraptor client",
  quarantine: "quarantines the endpoint from the network",
  proc_dump: "dumps process memory",
};

const callPlain = (name: string): string =>
  CALL_PLAIN[name] ? `${CALL_PLAIN[name]} (${name})` : `uses ${name}, which is not on the reviewed safe list`;

export const REASON_RULES: readonly ReasonRule[] = [
  // ── HARD: invalid launch ───────────────────────────────────────────────────────────────
  { test: re("the VQL is empty"), cls: "hard" },
  { test: re("unknown launch mode"), cls: "hard" },
  { test: re("vql is too long \\(limit \\d+ bytes of UTF-8\\)"), cls: "hard" },
  { test: re("no runnable VQL"), cls: "hard" },
  { test: re("this hunt already ran on the case"), cls: "hard" },
  { test: re("host not in the case's Velociraptor fleet"), cls: "hard" },
  { test: re("host name matches more than one client in the case's Velociraptor fleet"), cls: "hard" },
  { test: re("a fleet hunt does not take a host"), cls: "hard" },
  // ── HARD: the checked text could differ from the run text ──────────────────────────────
  {
    test: re(
      "the VQL contains an invisible control or line-break character \\(U\\+[0-9A-F]{4}\\) that Velociraptor could read differently from what was checked; retype the query without it",
    ),
    cls: "hard",
  },
  { test: re("''' \\(a triple-quoted string\\) is not allowed"), cls: "hard" },
  { test: re("a carriage return in the VQL"), cls: "hard" },
  { test: re("comments are not allowed"), cls: "hard" },
  { test: re("a string literal holds a blank line or a line starting with --"), cls: "hard" },
  // ── HARD: the check cannot read it or cannot name what runs ────────────────────────────
  { test: re("unreadable VQL: [^;]+"), cls: "hard" },
  { test: re(`${D}\\( has unbalanced brackets`), cls: "hard" },
  { test: re(`${D} has an empty argument`), cls: "hard" },
  { test: re("a LET statement without a plain name"), cls: "hard" },
  { test: re(`LET ${N} is malformed`), cls: "hard" },
  { test: re("FROM must name a plugin"), cls: "hard" },
  { test: re("Artifact must be followed directly by \\.<Name>"), cls: "hard" },
  { test: re("the VQL calls the result of an expression"), cls: "hard" },
  // ── RISKY: calls and artifacts off the reviewed list ───────────────────────────────────
  {
    test: re(`the VQL calls artifact (${D}), which is not on Watson's read-only list`),
    cls: "risky",
    plain: (m) => `uses artifact ${m[1]}, which is not on the reviewed safe list`,
  },
  {
    test: re(`the VQL calls (${N}), which is not on Watson's read-only list`),
    cls: "risky",
    plain: (m) => callPlain(m[1]),
  },
  {
    test: re(`the VQL calls (${D}), a dotted name that is not an allowed artifact`),
    cls: "risky",
    plain: (m) => `uses ${m[1]}, which is not on the reviewed safe list`,
  },
  {
    test: re(`(${N}) is dynamic invocation \\(it evaluates a string or computed name as VQL\\)`),
    cls: "risky",
    plain: (m) => `evaluates text as VQL (${m[1]})`,
  },
  { test: re(`${D} reaches an artifact through another name`), cls: "risky" },
  // ── RISKY: LET names ───────────────────────────────────────────────────────────────────
  { test: re(`LET ${N} reuses the name of a built-in`), cls: "risky" },
  { test: re(`LET ${N} would set a config or credential variable`), cls: "risky" },
  { test: re(`LET ${N} is called but does not define a query`), cls: "risky" },
  {
    test: re(`LET ${N} is called but its name has no capital letter, so it could shadow a built-in`),
    cls: "risky",
  },
  // ── RISKY: arguments (plain words: the raw reasons say "refused" / "must be") ───────────
  {
    test: re(`(${D}) has a positional argument \\(every argument must be name=value\\)`),
    cls: "risky",
    plain: (m) => `passes an unnamed (positional) argument to ${m[1]}`,
  },
  {
    test: re(`argument (${N}) is refused \\(uploads, dumps and lambdas\\)`),
    cls: "risky",
    plain: (m) => `uses argument ${m[1]} (uploads, dumps or lambdas)`,
  },
  {
    test: re("accessor must be one quoted local accessor \\([^()]*\\)"),
    cls: "risky",
    plain: () => "uses an accessor that is not on the reviewed local list",
  },
  { test: re("a namespace argument is refused"), cls: "risky", plain: () => "uses a namespace argument" },
  {
    test: re("wmi needs one quoted WQL SELECT from a reviewed read-only class"),
    cls: "risky",
    plain: () => "runs a WMI query that is not one plain SELECT from a reviewed class",
  },
  {
    test: re(`wmi class (${N}) is not on Watson's read-only list`),
    cls: "risky",
    plain: (m) => `queries WMI class ${m[1]}, which is not on the reviewed safe list`,
  },
  {
    test: re(`argument (${N}) must be a \\{subquery\\} or a LET query name`),
    cls: "risky",
    plain: (m) => `passes ${m[1]} as text, which VQL may run as a query`,
  },
  { test: re(`argument ${N} would set a config or credential variable`), cls: "risky" },
  {
    test: re(`artifact argument (${N}) must be a plain quoted value`),
    cls: "risky",
    plain: (m) => `builds artifact argument ${m[1]} at run time`,
  },
  {
    test: re("yara rules must be a plain quoted value"),
    cls: "risky",
    plain: () => "builds yara rules at run time",
  },
  {
    test: re("yara rules may not include other files"),
    cls: "risky",
    plain: () => "yara rules include other files",
  },
  {
    test: re(`(${D}) argument (${N}) must be a plain quoted path \\(no paths built at run time\\)`),
    cls: "risky",
    plain: (m) => `builds the ${m[1]} ${m[2]} path at run time`,
  },
  // ── RISKY: path and string literals ────────────────────────────────────────────────────
  { test: re(`${N} holds two path separators in a row \\(a possible network path\\)`), cls: "risky" },
  { test: re(`${N} is a bare separator \\(it could join into a network path\\)`), cls: "risky" },
  { test: re(`${N} has a \\[\\.\\.\\.\\] class holding a path separator`), cls: "risky" },
  { test: re(`${N} has a \\{…\\} alternation holding a path separator`), cls: "risky" },
  {
    test: re(
      "glob root ending in a separator joined to globs starting with one \\(a possible network path\\)",
    ),
    cls: "risky",
  },
  { test: re("a lambda string \\(=>\\), which VQL evaluates as code"), cls: "risky" },
  { test: re("a string naming a delegate pathspec"), cls: "risky" },
  { test: re("a string holding a JSON pathspec"), cls: "risky" },
  { test: re("a string that looks like a network path"), cls: "risky" },
];

/** The rule that names this reason, or undefined (then it is HARD). */
export function ruleFor(reason: string): ReasonRule | undefined {
  return REASON_RULES.find((r) => r.test.test(reason));
}

export function classifyReason(reason: string): ReasonClass {
  return ruleFor(reason)?.cls ?? "hard";
}

/** The reasons split by class. Any HARD reason refuses the whole launch. */
export function splitReasons(reasons: readonly string[]): { hard: string[]; risky: string[] } {
  return {
    hard: reasons.filter((r) => classifyReason(r) === "hard"),
    risky: reasons.filter((r) => classifyReason(r) === "risky"),
  };
}

/** The reason in plain English for the analyst's warning. */
export function plainRisk(reason: string): string {
  const rule = ruleFor(reason);
  const m = rule?.plain ? rule.test.exec(reason) : null;
  return m && rule?.plain ? rule.plain(m) : reason;
}

/** The audit words for a risky launch an analyst accepted (Task 9 ruling 5). */
export function riskAcceptedText(r: { by: string; reasons: readonly string[] }): string {
  return `; approved by ${r.by} despite warning: ${r.reasons.join("; ")}`;
}
