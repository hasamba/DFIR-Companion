// Discovery / credential-access COMMANDS inside a logged PowerShell script block (#1531).
//
// On INC-2026-001 the 4104 block at 08:33:05 named every Phase-2 action the operator took —
// `nltest /dclist:`, `Get-ADDomain`, `Get-ADGroupMember "Domain Admins"`,
// `Get-GPResultantSetOfPolicy`, `ntdsutil … ifm`, a `\\.\pipe\` psexec_psh pipe — in five High rows
// the model read, and none of it became a finding or a technique. The same block's IP addresses DID
// (finding f13), because #1502 lifts them out of the 240-character prompt render as tags. The
// commands had no such path: they sit 120–350 characters into a 3.4 KB block, inside the cut.
//
// So this module does for commands what destinationFacts.ts does for destinations:
//   • `scriptCommandTechniques` gives the IMPORT grader (tradecraftRules.scriptBlockSignal) the
//     ATT&CK ids the existing tables miss, so the row carries them from the moment it lands;
//   • `renderScriptCommandTags` puts the literal commands and their ids on the prompt row as whole
//     tags, where the render's cut cannot reach them;
//   • `scriptCommandFacts` gives the deterministic finding pass (scriptBlockCommandFindings.ts) the
//     same reading, so a row whose commands no finding accounts for stops being invisible.
//
// WHAT A MATCH CLAIMS — and this bounds everything below. A 4104 record is the COMPILED TEXT of a
// script: a function body, a string array, a branch that never ran. The issue's own block says
// `executed=$false` and `blockedBy='Windows Defender'` about the ntdsutil attempt. So a match here
// is "this command is present in logged script content", never "this command ran", and nothing here
// raises a severity — discovery is tagged, never promoted, the rule reconTechniques.ts already
// follows.
//
// THREE GUARDS, each from a review of this design:
//   1. SCRIPT RECORDS ONLY (`isScriptRecord`). A process row's command line belongs to
//      reconTechniques; a detection rule's prose that merely quotes `tasklist` is not a script at
//      all. Titling either "in a PowerShell script block" would be a false claim.
//   2. NOT THE COLLECTOR (#1500). PersistenceSniper's own 4104 blocks call `Get-Process` and
//      `Invoke-Command`. A row the import attributed to the case's own collector is refused — by
//      `origin` AND by the footprint note, because gradeScriptAsCollector returns early on a
//      Critical row and that row carries the note but no origin.
//   3. CONTEXT WHERE THE COMMAND ALONE PROVES NOTHING. A named pipe is ordinary IPC and a shadow
//      copy is ordinary backup; each maps to a technique only with a corroborating token nearby.
//      Without it the command is still reported — as evidence text with no technique.
//
// PURE — no I/O. Not a prompt constant: the #378 eval change gate hashes analysis/ai/prompts/*.ts
// and .env.example, neither of which this is.

import type { ForensicEvent } from "./stateTypes.js";

/** One command family: the pattern, what it means, and how much one match on its own is worth. */
interface CommandRule {
  re: RegExp;
  ids: string[];
  /**
   * "high" — one match is specific enough to stand on its own (trust enumeration, an IFM dump).
   * "low" — ordinary administration when seen alone (`Get-Process`, `gpresult`); it tags the row
   * and contributes evidence, but never mints a finding by itself.
   */
  specificity: "high" | "low";
  /** When set, the ids are claimed only if this also matches within CONTEXT_WINDOW of the command. */
  context?: RegExp;
}

/** How far each side of a match a `context` token may sit — the same line, in practice. */
const CONTEXT_WINDOW = 120;
/** The prompt-tag budget, mirroring DESTINATION_TAGS_MAX: whole tags are dropped past it, never sliced. */
export const SCRIPT_COMMAND_TAGS_MAX = 220;
/** One command never eats the whole budget. */
const COMMAND_MAX = 60;
// Two DIFFERENT limits, and conflating them was a review finding: a row that matched eight ordinary
// discovery commands stopped the scan before the ntdsutil rule was ever evaluated, so the strongest
// command in the script decided nothing. DETECTION reads the whole bounded text; only the EVIDENCE
// rendered to a prompt or a finding is trimmed, high-specificity first.
/** Commands rendered as evidence — the row itself holds the rest. */
const MAX_COMMANDS_SHOWN = 8;
/** Hard stop on matches kept from one text, so a pathological block cannot grow unbounded. */
const MAX_MATCHES = 40;
/** A script block can run to tens of KB; scanning the head bounds the cost of a pathological row. */
const TEXT_SCAN = 20000;

// The table. Families reconTechniques.ts already covers keep IDENTICAL ids — they are here so the
// evidence names the literal command an analyst would grep for, and scriptBlockCommands.test.ts
// asserts the two agree, which is what keeps them from drifting apart.
const COMMAND_RULES: CommandRule[] = [
  // T1018 Remote System Discovery. `/dclist` LISTS domain controllers; it does not enumerate
  // trusts, and conflating the two was the first thing the plan review rejected.
  { re: /\bnltest\b[^\n]{0,80}\/(?:dclist|dsgetdc)\b[^\s'"]*/i, ids: ["T1018"], specificity: "low" },
  // T1482 Domain Trust Discovery — the trust switches themselves.
  {
    re: /\bnltest\b[^\n]{0,80}\/(?:domain_trusts|trusted_domains|all_trusts)\b[^\s'"]*/i,
    ids: ["T1482"],
    specificity: "high",
  },
  // T1482 again, from the AD cmdlets that read DOMAIN / FOREST configuration. Deliberately not
  // T1087.002: Get-ADDomain returns the domain's configuration, not its accounts.
  {
    re: /\bget-ad(?:domain|trust|forest)\b(?:\s+-\w+(?:\s+[^\s;|)'"]+)?)?/i,
    ids: ["T1482"],
    specificity: "low",
  },
  // T1087.002 Account Discovery: Domain Account.
  {
    re: /\bget-aduser\b(?:\s+-\w+(?:\s+[^\s;|)'"]+)?){0,2}|\bnet\s+user\b[^\n]{0,40}\/domain|\bdsquery\s+user\b(?:\s+[^\s;|)'"]+){0,3}|\[adsisearcher\]/i,
    ids: ["T1087.002"],
    specificity: "low",
  },
  // T1069.002 Permission Groups Discovery: Domain Groups. `Get-ADGroupMember` is the one the old
  // rule missed: `\bget-adgroup\b` needs a word boundary after "adgroup", and "Member" follows.
  {
    re: /\bget-adgroupmember\b(?:\s+"[^"\n]{0,40}"|\s+'[^'\n]{0,40}'|\s+[^\s;|)'"]{1,40})?|\bget-adgroup\b(?![a-z])|\bnet\s+(?:local)?group\b[^\n]{0,40}\/domain/i,
    ids: ["T1069.002"],
    specificity: "low",
  },
  // T1615 Group Policy Discovery.
  {
    re: /\b(?:get-gpresultantsetofpolicy|gpresult|get-gpo)\b(?:\s+[-\/]\w+(?:[:\s]+[^\s;|)'"]+)?){0,3}/i,
    ids: ["T1615"],
    specificity: "low",
  },
  // T1057 Process Discovery. Routine on its own — hence "low", and never a finding by itself.
  { re: /\bget-process\b(?:\s+-?\w+)?|\btasklist\b(?:\s+\/\w+)?/i, ids: ["T1057"], specificity: "low" },
  // T1003.003 OS Credential Dumping: NTDS — the IFM dump, which has no benign reading.
  {
    re: /\bntdsutil(?:\.exe)?(?=[\s'"])[^\n]{0,120}?\bifm\b(?:\s+[^\s;|)'"]{1,40}){0,4}/i,
    ids: ["T1003.003"],
    specificity: "high",
  },
  // A shadow copy is how every backup product works, so the technique is claimed only where the
  // surrounding text names the credential store the copy would be read for.
  {
    re: /\bvssadmin(?:\.exe)?\s+create\s+shadow\b(?:\s+[^\s;|)'"]{1,40}){0,3}|\bwmic\s+shadowcopy\s+call\s+create\b/i,
    ids: ["T1003.003"],
    specificity: "high",
    context: /ntds(?:\.dit)?|\\windows\\ntds|\\system32\\config\\(?:sam|system)|\bsam\b\s*(?:hive|copy)/i,
  },
  // A named pipe is ordinary IPC. SMB admin-share execution / lateral transfer is claimed only when
  // the span also names the remote-execution primitive that uses one.
  {
    re: /\\\\(?:\.|[\w.-]+)\\pipe\\[\w.$-]{1,40}/i,
    ids: ["T1021.002", "T1570"],
    specificity: "high",
    context: /psexec|psexec_psh|paexec|smbexec|svcctl|atsvc|admin\$|remote\s+service|service\s+creation/i,
  },
  // T1021.006 Remote Services: Windows Remote Management — an EXPLICIT remote target only.
  {
    // Enter-PSSession needs a target too: the switch form anywhere in its arguments, or a positional
    // host right after it. A bare `Enter-PSSession` (or one carrying only -Credential) opens nothing
    // and proves no remote host — the plan review caught that reading.
    re: /\benter-pssession\b[^\n]{0,60}?-(?:computername|connectionuri|vmname|containerid|hostname|session)\s+[^\s;|)'"{}]{1,40}|\benter-pssession\s+[^\s;|)'"{}-][^\s;|)'"{}]{0,40}|\b(?:invoke-command|new-pssession)\b[^\n]{0,60}?-computername\s+[^\s;|)'"{}]{1,40}|\bwinrs\b\s+-r:[^\s]{1,40}/i,
    ids: ["T1021.006"],
    specificity: "low",
  },
];

/** One command found in a script record: the literal text, and what it maps to (possibly nothing). */
export interface ScriptCommandMatch {
  /** The matched span, whitespace-collapsed, sanitised and clipped — what an analyst would grep for. */
  command: string;
  /** ATT&CK ids the match supports. [] when the rule needed context the row did not supply. */
  techniques: string[];
  specificity: "high" | "low";
}

const clean = (v: string): string =>
  v
    .replace(/[<>\u0000-\u001f]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();

const clip = (v: string): string => (v.length > COMMAND_MAX ? v.slice(0, COMMAND_MAX - 1) + "…" : v);

/** Up to CONTEXT_WINDOW characters each side of the match, cut at the line — the next line is not this one's. */
function around(text: string, at: number, len: number): string {
  const before =
    text
      .slice(Math.max(0, at - CONTEXT_WINDOW), at)
      .split(/[\r\n]/u)
      .pop() ?? "";
  const after = text.slice(at + len, at + len + CONTEXT_WINDOW).split(/[\r\n]/u)[0] ?? "";
  return `${before} ${after}`;
}

/**
 * Every command family the text names, in table order, deduped by the literal command. A rule whose
 * `context` is absent from the span still reports its command — with no techniques, because the
 * command alone does not support them.
 */
export function scriptCommandMatches(text: string): ScriptCommandMatch[] {
  const body = String(text ?? "").slice(0, TEXT_SCAN);
  if (!body) return [];
  const out: ScriptCommandMatch[] = [];
  const seen = new Set<string>();
  for (const rule of COMMAND_RULES) {
    // Global copy per rule so one text can report several distinct invocations of one family.
    const re = new RegExp(rule.re.source, rule.re.flags.includes("g") ? rule.re.flags : rule.re.flags + "g");
    for (const m of body.matchAll(re)) {
      const command = clip(clean(m[0]));
      if (!command) continue;
      const key = `${rule.ids.join(",")}\n${command.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      // The context window includes the MATCHED SPAN: `vssadmin create shadow … ntds.dit` states its
      // own context inside the match, and reading only around it would miss exactly that shape.
      const ok = !rule.context || rule.context.test(`${m[0]} ${around(body, m.index ?? 0, m[0].length)}`);
      out.push({
        command,
        techniques: ok ? [...rule.ids] : [],
        specificity: ok ? rule.specificity : "low",
      });
      if (out.length >= MAX_MATCHES) return out;
    }
  }
  return out;
}

/** The deduped ATT&CK ids a script text supports. Never a severity — see the header. */
export function scriptCommandTechniques(text: string): string[] {
  const ids = new Set<string>();
  for (const m of scriptCommandMatches(text)) for (const id of m.techniques) ids.add(id);
  return [...ids];
}

// The collector's own script blocks, the two ways an import marks them (#1500): the structured
// origin, and — on a Critical row, where gradeScriptAsCollector returns before setting either the
// Info grade or the origin — the footprint note it appends to the description.
const COLLECTOR_NOTE = /DFIR collector footprint/i;
export function isCollectorRow(e: Pick<ForensicEvent, "origin" | "description">): boolean {
  return e.origin === "collector" || COLLECTOR_NOTE.test(e.description ?? "");
}

// A row that positively IS a PowerShell script/module record: the rendered head the Windows mapper
// writes for 4104/4103, the field name the importers keep in the description, the trailer the engine
// puts after a script block, or a record id naming the PowerShell channel. Never `commandLine` — a
// process row's arguments are reconTechniques' work, and calling one "a script block" would be a
// false claim about where the evidence came from.
const SCRIPT_RECORD = /\(EID 410[34]\)|ScriptBlockText\s*=|ScriptBlock ID:|Script block logged/i;
const PS_CHANNEL = /powershell/i;
export function isScriptRecord(
  e: Pick<ForensicEvent, "description" | "message" | "sourceRecordId">,
): boolean {
  if (e.sourceRecordId && PS_CHANNEL.test(e.sourceRecordId)) return true;
  return SCRIPT_RECORD.test(e.description ?? "") || SCRIPT_RECORD.test((e.message ?? "").slice(0, TEXT_SCAN));
}

/** The script text a row carries: its full message when it kept one, plus the rendered description. */
export function scriptTextOf(e: Pick<ForensicEvent, "description" | "message">): string {
  const message = (e.message ?? "").slice(0, TEXT_SCAN);
  const description = e.description ?? "";
  return message ? `${description}\n${message}` : description;
}

/**
 * The commands a row's script text names — [] for a row that is not a script record, one the case's
 * own collector ran, or one that names nothing.
 */
export function scriptCommandFacts(e: ForensicEvent): ScriptCommandMatch[] {
  if (isCollectorRow(e) || !isScriptRecord(e)) return [];
  return scriptCommandMatches(scriptTextOf(e));
}

/**
 * The commands worth SHOWING, high-specificity first and otherwise in table order, capped at
 * MAX_COMMANDS_SHOWN. Detection has already read every match; this only decides what is printed.
 */
export function commandsToShow(facts: readonly ScriptCommandMatch[]): ScriptCommandMatch[] {
  const high = facts.filter((f) => f.specificity === "high");
  const low = facts.filter((f) => f.specificity !== "high");
  return [...high, ...low].slice(0, MAX_COMMANDS_SHOWN);
}

/**
 * The prompt row's whole tags: `<script-commands:…>` (the literal commands, `; `-separated) and
 * `<script-techniques:…>` (their ids). Named for what they are — commands PRESENT in logged script
 * content — so the model cannot read them as a process that ran. [] when the row names nothing.
 */
export function renderScriptCommandTags(e: ForensicEvent): string[] {
  const facts = scriptCommandFacts(e);
  if (!facts.length) return [];
  const ids = [...new Set(facts.flatMap((f) => f.techniques))];
  const commands: string[] = [];
  let used = "<script-commands:>".length;
  for (const f of commandsToShow(facts)) {
    const cost = f.command.length + (commands.length ? 2 : 0);
    if (used + cost > SCRIPT_COMMAND_TAGS_MAX) break;
    commands.push(f.command);
    used += cost;
  }
  const tags: string[] = [];
  if (commands.length) tags.push(`<script-commands:${commands.join("; ")}>`);
  if (ids.length) tags.push(`<script-techniques:${ids.join(",")}>`);
  return tags;
}
