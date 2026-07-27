import type { Finding, InvestigationState, Severity } from "./stateTypes.js";

// Two-way war-room slash-command bot (#235). IR happens in a Slack/Teams/Telegram war room; this
// module is the PURE core — the command parser, the caseId resolver, the read-only command
// formatters that turn case state into a slash-command response card, and the access-control
// predicates. The route (routes/slashCommand.ts) owns the inbound webhook handler (auth + rate
// limiting), the async result delivery, and per-channel case binding; this module is deterministic
// and unit-tested with no I/O.
//
// Slash commands supported (the issue's full set):
//   /dfir ask [caseId] <question>          → async (AI call) — the route handles this
//   /dfir findings [caseId]                → top 5 findings (severity + confidence + MITRE)
//   /dfir finding [caseId] <id>            → a single finding card
//   /dfir iocs [caseId] [flagged|malicious]→ top IOCs with verdicts
//   /dfir hunt [caseId] <technique>        → async (hand-off to the dashboard's hunt panel)
//   /dfir status [caseId]                  → case stats (events, findings, IOCs, questions)
//   /dfir synthesize [caseId]              → async (re-synthesis)
//   /dfir bind <caseId>                    → bind this channel to a default case
//   /dfir unbind                           → clear the channel binding
//   /dfir help                             → usage

export type SlashCommandName =
  | "ask"
  | "findings"
  | "finding"
  | "iocs"
  | "hunt"
  | "status"
  | "synthesize"
  | "bind"
  | "unbind"
  | "help";

export interface ParsedSlashCommand {
  name: SlashCommandName;
  // Everything after the command word, already split. The caseId CANNOT be picked out here: with a
  // bound channel `/dfir ask what was the initial access vector?` has no caseId at all, and "what"
  // is a syntactically valid caseId — only the route knows which case ids exist. resolveCommand()
  // makes that call once the route has looked the first token up.
  tokens: string[];
  raw: string;
}

export const SLASH_COMMAND_NAMES: readonly SlashCommandName[] = [
  "ask",
  "findings",
  "finding",
  "iocs",
  "hunt",
  "status",
  "synthesize",
  "bind",
  "unbind",
  "help",
];

// Parse a slash-command text string into a command name + its argument tokens. Tolerant of extra
// whitespace, of a leading "/" (Telegram sends the slash; Slack strips it), of the "/dfir" trigger
// word (some clients echo it back), and of Telegram's "@BotName" suffix on the command word
// (`/findings@DfirBot c1`, `/dfir@DfirBot findings c1`). Returns { name: "help" } for an
// empty/unrecognized input so the route always has something to respond with.
export function parseSlashCommand(text: string): ParsedSlashCommand {
  const raw = (text ?? "").trim();
  if (!raw) return { name: "help", tokens: [], raw: "" };
  const parts = (raw.startsWith("/") ? raw.slice(1) : raw).split(/\s+/).filter(Boolean);
  // Telegram appends "@BotName" to the command word when several bots share a group chat.
  if (parts[0]) parts[0] = parts[0].split("@")[0];
  // Drop the trigger word when the client echoes it ("/dfir findings c1").
  if (parts[0]?.toLowerCase() === "dfir") parts.shift();

  const name = parts[0]?.toLowerCase() as SlashCommandName;
  if (!SLASH_COMMAND_NAMES.includes(name)) return { name: "help", tokens: [], raw };
  return { name, tokens: parts.slice(1), raw };
}

// ── caseId resolution ───────────────────────────────────────────────────────────────────

export interface ChannelBinding {
  caseId: string;
  boundAt: string;
}

export interface ResolvedSlashCommand {
  name: SlashCommandName;
  caseId: string;                            // "" when the command takes none / none could be found
  arg: string;                               // the question / technique / finding id
  iocFilter?: "flagged" | "malicious";
  usedBinding: boolean;                      // true when the caseId came from the channel binding
  raw: string;
}

/**
 * Turn a parsed command into a resolved one: decide whether the first token is the caseId or part
 * of the argument, and fall back to the channel's bound case when it isn't.
 *
 * `firstTokenIsKnownCase` is the route's answer to "does a case with this id actually exist?" —
 * the one fact this module cannot know. Without it the parser has to guess positionally, and it
 * guesses wrong for every command that takes an argument: with a bound channel `/dfir iocs
 * malicious` silently queried a case called "malicious", and `/dfir ask what happened` a case
 * called "what". Both ids pass isValidCaseId, so nothing errored — the analyst just got an answer
 * about the wrong (empty) case.
 *
 * `bind` is deliberately exempt: its argument names the case to bind TO, so falling back to the
 * current binding would silently re-bind the channel to the case it is already bound to.
 */
export function resolveCommand(
  cmd: ParsedSlashCommand,
  binding: ChannelBinding | undefined,
  firstTokenIsKnownCase: boolean,
): ResolvedSlashCommand {
  const { name, tokens, raw } = cmd;
  const base = { name, arg: "", usedBinding: false, raw };

  if (name === "help" || name === "unbind") return { ...base, caseId: "" };
  if (name === "bind") return { ...base, caseId: (tokens[0] ?? "").trim() };

  let caseId: string;
  let rest: string[];
  let usedBinding = false;
  if (tokens.length > 0 && firstTokenIsKnownCase) {
    caseId = tokens[0];
    rest = tokens.slice(1);
  } else if (binding?.caseId) {
    caseId = binding.caseId;
    rest = tokens;
    usedBinding = true;
  } else {
    // No binding and the first token isn't a case we know: keep treating it as the caseId so the
    // error message names what the analyst actually typed.
    caseId = (tokens[0] ?? "").trim();
    rest = tokens.slice(1);
  }

  const filter = rest[0];
  return {
    name,
    caseId,
    arg: rest.join(" "),
    iocFilter: name === "iocs" && (filter === "flagged" || filter === "malicious") ? filter : undefined,
    usedBinding,
    raw,
  };
}

// ── Read-only command formatters ────────────────────────────────────────────────────────
// Each returns a { title, lines } card the route wraps in the platform's response envelope.
// Pure functions of InvestigationState.

export interface SlashCommandResponse {
  title: string;
  lines: string[];
}

const SEVERITY_ORDER: Record<Severity, number> = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };

function topFindings(state: InvestigationState, limit: number): Finding[] {
  return [...state.findings]
    .filter((f) => f.status !== "dismissed")
    .sort((a, b) => (SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]) || (b.confidence ?? 0) - (a.confidence ?? 0))
    .slice(0, limit);
}

export function formatFindingsCommand(state: InvestigationState, limit = 5): SlashCommandResponse {
  const top = topFindings(state, limit);
  if (top.length === 0) {
    return { title: `Top findings for ${state.caseId}`, lines: ["No findings yet — run a synthesis first."] };
  }
  const lines = top.map((f) => {
    const conf = f.confidence !== undefined ? ` conf ${f.confidence}%` : "";
    const mitre = f.mitreTechniques.length ? ` [${f.mitreTechniques.join(", ")}]` : "";
    return `${f.severity} · ${f.id}${conf}${mitre} — ${f.title}`;
  });
  return { title: `Top ${top.length} finding(s) for ${state.caseId}`, lines };
}

export function formatFindingCommand(state: InvestigationState, findingId: string): SlashCommandResponse {
  const wanted = findingId.trim();
  if (!wanted) {
    return { title: "Which finding?", lines: ["Usage: /dfir finding <id> — run /dfir findings to list them."] };
  }
  const f = state.findings.find((x) => x.id === wanted || x.semanticKey === wanted);
  if (!f) return { title: `Finding ${wanted} not found`, lines: [`Case ${state.caseId} has no finding with id/semanticKey "${wanted}".`] };
  const lines = [
    `Severity: ${f.severity}${f.confidence !== undefined ? ` (confidence ${f.confidence}%)` : ""}`,
    `Status: ${f.status}`,
    `MITRE: ${f.mitreTechniques.length ? f.mitreTechniques.join(", ") : "—"}`,
    `Related IOCs: ${f.relatedIocs.length || "none"}`,
    `Description: ${f.description}`,
    `First seen: ${f.firstSeen}`,
  ];
  return { title: `${f.id}: ${f.title}`, lines };
}

export function formatIocsCommand(
  state: InvestigationState,
  filter: "flagged" | "malicious" | undefined,
  limit = 10,
): SlashCommandResponse {
  let iocs = state.iocs;
  if (filter === "malicious") {
    iocs = iocs.filter((ioc) => (ioc.enrichments ?? []).some((e) => e.verdict === "malicious"));
  } else if (filter === "flagged") {
    iocs = iocs.filter((ioc) => (ioc.enrichments ?? []).some((e) => e.verdict === "malicious" || e.verdict === "suspicious"));
  }
  if (iocs.length === 0) {
    return { title: `IOCs for ${state.caseId}${filter ? ` (${filter})` : ""}`, lines: ["No IOCs match this filter."] };
  }
  const top = iocs.slice(0, limit);
  const lines = top.map((ioc) => {
    const verdicts = (ioc.enrichments ?? []).map((e) => `${e.source}:${e.verdict}`).join(", ");
    return `${ioc.type} · ${ioc.value}${verdicts ? ` — ${verdicts}` : ""}`;
  });
  return { title: `${iocs.length} IOC(s)${filter ? ` (${filter})` : ""} — showing top ${top.length} for ${state.caseId}`, lines };
}

export function formatStatusCommand(state: InvestigationState): SlashCommandResponse {
  const openFindings = state.findings.filter((f) => f.status === "open").length;
  const confirmed = state.findings.filter((f) => f.status === "confirmed").length;
  const maliciousIocs = state.iocs.filter((ioc) => (ioc.enrichments ?? []).some((e) => e.verdict === "malicious")).length;
  const openHypotheses = (state as { hypotheses?: unknown[] }).hypotheses;
  const lines = [
    `Events: ${state.forensicTimeline.length}`,
    `Findings: ${state.findings.length} (${openFindings} open, ${confirmed} confirmed)`,
    `IOCs: ${state.iocs.length} (${maliciousIocs} malicious)`,
    `Key questions: ${state.keyQuestions.length}`,
    `Next steps: ${state.nextSteps.length}`,
    `Last updated: ${state.updatedAt}`,
    ...(Array.isArray(openHypotheses) ? [`Open hypotheses: ${openHypotheses.length}`] : []),
  ];
  return { title: `Status for ${state.caseId}`, lines };
}

export function formatHelpCommand(): SlashCommandResponse {
  return {
    title: "DFIR Companion slash commands",
    lines: [
      "/dfir status [caseId] — case stats",
      "/dfir findings [caseId] — top 5 findings",
      "/dfir finding [caseId] <id> — a single finding card",
      "/dfir iocs [caseId] [flagged|malicious] — top IOCs",
      "/dfir ask [caseId] <question> — ask the AI (async)",
      "/dfir hunt [caseId] <technique> — note a technique to hunt; deploy it from the dashboard",
      "/dfir synthesize [caseId] — trigger re-synthesis (async)",
      "/dfir bind <caseId> — bind this channel to a default case",
      "/dfir unbind — clear the channel binding",
      "When a channel is bound, the caseId can be omitted from any command.",
    ],
  };
}

// ── Access control ──────────────────────────────────────────────────────────────────────
// Two separate axes that the first cut of this bot conflated:
//
//   PRIVILEGED — needs the operator's user-id allowlist. Spending AI budget (ask), triggering a
//   re-synthesis, filing a hunt, and REPOINTING THE CHANNEL AT A DIFFERENT CASE (bind). bind is in
//   here because it decides which case everyone else in the room can read.
//
//   ASYNC — takes longer than the 3s a chat platform waits, so the route ACKs and delivers the
//   result out of band. Nothing to do with permissions.

export const READ_ONLY_COMMANDS: readonly SlashCommandName[] = [
  "findings",
  "finding",
  "iocs",
  "status",
  "help",
  "unbind",
];

export const PRIVILEGED_COMMANDS: readonly SlashCommandName[] = ["ask", "hunt", "synthesize", "bind"];

export const ASYNC_COMMANDS: readonly SlashCommandName[] = ["ask", "hunt", "synthesize"];

export function isPrivilegedCommand(name: SlashCommandName): boolean {
  return PRIVILEGED_COMMANDS.includes(name);
}

export function isAsyncCommand(name: SlashCommandName): boolean {
  return ASYNC_COMMANDS.includes(name);
}

/** Is `userId` allowed to run this command? Privileged commands require the allowlist; when no
 *  allowlist is configured access is open (the default for a localhost tool). */
export function isAllowed(
  name: SlashCommandName,
  userId: string,
  actionAllowlist: readonly string[] | undefined,
): boolean {
  if (!isPrivilegedCommand(name)) return true;
  if (!actionAllowlist || actionAllowlist.length === 0) return true; // open access when unconfigured
  return actionAllowlist.includes(userId);
}

/**
 * Is `userId` allowed to read THIS case from THIS channel? Read-only commands take an explicit
 * caseId, so without this an ordinary chat member could read any case on the server just by naming
 * it. Policy: an operator who has configured an allowlist gets those responders full reach, and
 * confines everyone else to the case the channel is bound to. With no allowlist configured the
 * bot stays open, matching the rest of this localhost-first tool.
 *
 * Note this is about which case a chat member may READ. Password-protected cases are refused over
 * chat outright (the route checks) — a chat message carries no unlock.
 */
export function isCaseAccessAllowed(input: {
  userId: string;
  caseId: string;
  boundCaseId: string | undefined;
  actionAllowlist: readonly string[] | undefined;
}): boolean {
  const { userId, caseId, boundCaseId, actionAllowlist } = input;
  if (!actionAllowlist || actionAllowlist.length === 0) return true;
  if (actionAllowlist.includes(userId)) return true;
  return !!boundCaseId && caseId === boundCaseId;
}
