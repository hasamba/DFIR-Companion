import type { Finding, InvestigationState, IOC, Severity } from "./stateTypes.js";

// Two-way war-room slash-command bot (#235). IR happens in a Slack/Teams war room; this module
// is the PURE core — the command parser + the read-only command formatters that turn case state
// into a slash-command response card. The route (routes/slashCommand.ts) owns the inbound
// webhook handler (HMAC auth + rate limiting), the async response_url posting, and per-channel
// case binding; this module is deterministic and unit-tested with no I/O.
//
// Slash commands supported (the issue's full set):
//   /dfir ask <caseId> <question>          → async (AI call) — the route handles this; here it's a parse result
//   /dfir findings <caseId>                → top 5 findings (severity + confidence + MITRE)
//   /dfir finding <caseId> <id>            → a single finding card
//   /dfir iocs <caseId> [flagged|malicious]→ top IOCs with verdicts
//   /dfir hunt <caseId> <technique>        → async (deploy) — the route handles this
//   /dfir status <caseId>                  → case stats (events, findings, last synthesis, open hypotheses)
//   /dfir synthesize <caseId>              → async (re-synthesis) — the route handles this
//   /dfir bind <caseId>                    → bind this channel to a default case
//   /dfir unbind                           → clear the channel binding
//   /dfir help                              → usage

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
  caseId?: string;       // absent when the command doesn't take one (help, unbind) or when the
                         // channel is expected to supply a bound default (the route fills it)
  arg?: string;          // the question / technique / finding id / ioc filter
  iocFilter?: "flagged" | "malicious";
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

// Parse a slash-command text string into a structured command. Tolerant of extra whitespace and
// of a leading "/dfir" (Slack sends the bare args; Teams sometimes includes the trigger word).
// Returns { name: "help", raw } for an empty/unrecognized input so the route always has something
// to respond with.
export function parseSlashCommand(text: string): ParsedSlashCommand {
  const raw = (text ?? "").trim();
  if (!raw) return { name: "help", raw: "" };
  // Strip a leading "/dfir" if present (some clients echo the trigger word back).
  const stripped = raw.startsWith("/dfir ") ? raw.slice("/dfir ".length) : raw;
  const parts = stripped.split(/\s+/);
  const name = parts[0]?.toLowerCase() as SlashCommandName;
  if (!SLASH_COMMAND_NAMES.includes(name)) return { name: "help", raw };
  const rest = parts.slice(1);

  switch (name) {
    case "help":
    case "unbind":
      return { name, raw };
    case "bind":
      return { name, caseId: rest[0], raw };
    case "status":
    case "synthesize":
      return { name, caseId: rest[0], raw };
    case "findings":
      return { name, caseId: rest[0], raw };
    case "iocs": {
      const caseId = rest[0];
      const filter = rest[1];
      return {
        name,
        caseId,
        iocFilter: filter === "flagged" || filter === "malicious" ? filter : undefined,
        raw,
      };
    }
    case "finding":
    case "hunt":
    case "ask": {
      const caseId = rest[0];
      const arg = rest.slice(1).join(" ");
      return { name, caseId, arg, raw };
    }
    default:
      return { name: "help", raw };
  }
}

// ── Read-only command formatters ────────────────────────────────────────────────────────
// Each returns a { title, lines } card the route formats per-channel (Slack Block Kit / Teams
// MessageCard) and posts to response_url. Pure functions of InvestigationState.

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
  const f = state.findings.find((x) => x.id === findingId || x.semanticKey === findingId);
  if (!f) return { title: `Finding ${findingId} not found`, lines: [`Case ${state.caseId} has no finding with id/semanticKey "${findingId}".`] };
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
      "/dfir finding <caseId|bound> <id> — a single finding card",
      "/dfir iocs [caseId] [flagged|malicious] — top IOCs",
      "/dfir ask <caseId|bound> <question> — ask the AI (async)",
      "/dfir hunt <caseId|bound> <technique> — deploy a VQL hunt (async)",
      "/dfir synthesize [caseId] — trigger re-synthesis (async)",
      "/dfir bind <caseId> — bind this channel to a default case",
      "/dfir unbind — clear the channel binding",
      "When a channel is bound, the caseId can be omitted from any command.",
    ],
  };
}

// Per-channel case binding store: a channel can bind to a default case so subsequent commands
// omit the caseId. Stored in the notification config dir (a global, channel-level concern, not
// per-case) — the route module owns the persistence; this is just the shape.
export interface ChannelBinding {
  caseId: string;
  boundAt: string;
}

// Resolve the caseId for a parsed command: prefer the explicit caseId, fall back to the channel's
// bound default. Returns "" when neither is present (the route responds with a usage hint).
export function resolveCaseId(cmd: ParsedSlashCommand, binding: ChannelBinding | undefined): string {
  if (cmd.caseId && cmd.caseId.trim()) return cmd.caseId.trim();
  return binding?.caseId ?? "";
}

// Access control: a command kind is allowed for a user when the user is in the action allowlist
// (for action commands: hunt, synthesize, ask) OR when no allowlist is configured (open access,
// the default). Read-only commands (findings, finding, iocs, status, help, bind, unbind) are
// always allowed.
export const READ_ONLY_COMMANDS: readonly SlashCommandName[] = [
  "findings",
  "finding",
  "iocs",
  "status",
  "help",
  "bind",
  "unbind",
];

export const ACTION_COMMANDS: readonly SlashCommandName[] = ["ask", "hunt", "synthesize"];

export function isActionCommand(name: SlashCommandName): boolean {
  return ACTION_COMMANDS.includes(name);
}

export function isAllowed(
  name: SlashCommandName,
  userId: string,
  actionAllowlist: readonly string[] | undefined,
): boolean {
  if (!isActionCommand(name)) return true;
  if (!actionAllowlist || actionAllowlist.length === 0) return true; // open access when unconfigured
  return actionAllowlist.includes(userId);
}