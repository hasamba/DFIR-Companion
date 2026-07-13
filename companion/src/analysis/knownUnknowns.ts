// Known unknowns (#165 + investigation-guidance #9): the evidence we'd EXPECT in an intrusion but
// don't yet have — the gaps in the story. Synthesis and hunt suggestions report what the evidence
// shows; this surfaces what it DOESN'T, so the model treats the holes as open questions to
// investigate/hunt instead of glossing over them ("ransomware deployed but no initial-access vector
// identified", "lateral movement seen but no persistence", "a 3h window where every source went
// silent").
//
// #9 made this DIRECT collection instead of only naming a phase: it now returns STRUCTURED items
// (buildKnownUnknownItems) carrying, per uncovered kill-chain phase, a deterministic collection
// directive — WHICH log source / Velociraptor artifact on WHICH host would answer it (TACTIC_EVIDENCE
// + per-tactic host selection). The GET /cases/:id/known-unknowns route and the dashboard "Evidence
// gaps" panel render the same items the synthesis prompt does (renderKnownUnknowns), so the human and
// the model look at one list. Still PURE and OFFLINE — it consolidates signals the codebase already
// derives (gapDetect, tacticForTechniques over findings, adversaryEmulation, hostRanking,
// iocAnchors, evidenceGraph); no new detection, no AI, no I/O. Every line is a LEAD, not proof.

import type { CollectDirective, ForensicEvent, InvestigationState } from "./stateTypes.js";
import { detectTimelineGaps, type GapOptions } from "./gapDetect.js";
import { tacticForTechniques, type IrisTactic } from "../integrations/iris/mitreTactics.js";
import type { NextTechnique } from "./adversaryEmulation.js";
import { rankHosts } from "./hostRanking.js";
import { rankConnectiveIocs } from "./iocAnchors.js";
import { buildEvidenceGraph } from "./evidenceGraph.js";
import { byEventTime } from "./forensicSort.js";

// The kill-chain phases an intrusion usually touches. A case with real (Critical/High) findings that
// has NO finding covering one of these is a conspicuous gap worth calling out ("how did they get
// in?", "where's the persistence?"). Defense Evasion / Discovery / Collection are intentionally
// omitted — their absence is rarely a meaningful lead on its own.
const CORE_TACTICS: readonly IrisTactic[] = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Lateral Movement",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export interface KnownUnknownsOptions {
  gapOptions?: GapOptions;                      // forwarded to detectTimelineGaps
  nextTechniques?: readonly NextTechnique[];    // from adversaryEmulation — caller supplies (needs the offline dataset)
  maxGaps?: number;                             // cap on coverage-gap lines (default 3)
  maxNextTechniques?: number;                   // cap on likely-next-technique lines (default 5)
  max?: number;                                 // hard cap on TOTAL bullets in the rendered block (default 10)
}

const DEFAULT_MAX_GAPS = 3;
const DEFAULT_MAX_NEXT = 5;
const DEFAULT_MAX_TOTAL = 10;
const MAX_HOSTS_PER_TACTIC = 3;

export type KnownUnknownKind = "uncovered_tactic" | "silence_gap" | "likely_next_technique";

// One structured gap the case is missing. `collect` carries deterministic "where to look" directives
// (only for uncovered_tactic — silence gaps link to the existing Timeline Gaps panel, and likely-next
// techniques are predictive hunt priorities, not a specific collection).
export interface KnownUnknownItem {
  kind: KnownUnknownKind;
  label: string;                                          // the human sentence
  tactic?: IrisTactic;                                    // uncovered_tactic / likely_next_technique
  technique?: { id: string; name?: string };              // likely_next_technique
  window?: { start: string; end: string; durationLabel: string; complete: boolean };  // silence_gap
  collect: CollectDirective[];                            // deployable collection directives (may be empty)
}

// What log source / Velociraptor artifact would answer "did this kill-chain phase happen". The first
// entry is the PRIMARY (used to build the deploy directive); the rest enrich the human label. Artifact
// names are real Velociraptor built-ins (resolveCollectVql maps them; #8).
interface TacticEvidenceSpec { logSource: string; artifact?: string }
const TACTIC_EVIDENCE: Partial<Record<IrisTactic, readonly TacticEvidenceSpec[]>> = {
  "Initial Access": [
    { logSource: "mail-gateway / web-proxy logs + browser history", artifact: "Windows.Applications.Chrome.History" },
    { logSource: "VPN / RDP-gateway auth logs" },
  ],
  "Execution": [{ logSource: "Security.evtx 4688 + Sysmon EID 1 (process creation)", artifact: "Windows.EventLogs.Evtx" }],
  "Persistence": [{ logSource: "scheduled tasks / services / run keys / WMI subscriptions", artifact: "Windows.Persistence.PermanentWMIEvents" }],
  "Privilege Escalation": [{ logSource: "Security.evtx 4672/4673 + token/UAC events", artifact: "Windows.EventLogs.Evtx" }],
  "Lateral Movement": [{ logSource: "Security.evtx 4624 type-3/10 + 4648 (network/RDP logon)", artifact: "Windows.EventLogs.Evtx" }],
  "Command and Control": [{ logSource: "DNS + web-proxy logs for the connective IOCs", artifact: "Windows.Network.Netstat" }],
  "Exfiltration": [{ logSource: "SRUM network-usage + USN journal for staged archives", artifact: "Windows.Forensics.SRUM" }],
  "Impact": [{ logSource: "Security.evtx + VSS/backup-deletion + ransom-note artifacts", artifact: "Windows.EventLogs.Evtx" }],
};

function uniq(arr: readonly (string | undefined)[]): string[] {
  return [...new Set(arr.filter((s): s is string => !!s && s.trim().length > 0))];
}

function earliestAsset(scopedEvents: readonly ForensicEvent[]): string | undefined {
  const dated = [...scopedEvents].sort(byEventTime);
  return dated.find((e) => !!e.asset)?.asset;
}

// Host↔host endpoints of lateral_move edges (the pairs a pivot ran between). Host node ids are
// "host:<name>"; we read the node label to preserve the display case.
function lateralHosts(state: InvestigationState): string[] {
  const graph = buildEvidenceGraph(state);
  const labelById = new Map(graph.nodes.map((n) => [n.id, n.label] as const));
  const out: string[] = [];
  for (const e of graph.edges) {
    if (e.type !== "lateral_move") continue;
    for (const id of [e.source, e.target]) {
      const label = labelById.get(id);
      if (label) out.push(label);
    }
  }
  return uniq(out);
}

// Hosts touched by the case's connective (cross-host / multi-tool) IOCs — where a C2 channel would show.
function connectiveHosts(state: InvestigationState): string[] {
  const out: string[] = [];
  for (const a of rankConnectiveIocs(state, state.forensicTimeline, { max: 20 })) out.push(...a.hosts);
  return uniq(out);
}

// The hosts to point an uncovered-tactic collection at, tactic-specific where the case's own structure
// says where to look, else the top signal-carrying hosts. Always non-empty when the case has any host.
function targetHostsForTactic(tactic: IrisTactic, state: InvestigationState, scopedEvents: readonly ForensicEvent[], topHosts: readonly string[]): string[] {
  const fallback = topHosts.slice(0, MAX_HOSTS_PER_TACTIC);
  switch (tactic) {
    case "Initial Access":
      return uniq([earliestAsset(scopedEvents), ...topHosts]).slice(0, MAX_HOSTS_PER_TACTIC);
    case "Lateral Movement": {
      const l = lateralHosts(state);
      return (l.length ? l : fallback).slice(0, MAX_HOSTS_PER_TACTIC);
    }
    case "Command and Control": {
      const c = connectiveHosts(state);
      return (c.length ? c : fallback).slice(0, MAX_HOSTS_PER_TACTIC);
    }
    default:
      return fallback;
  }
}

// The deployable collection directives for one uncovered tactic: the primary artifact on each target
// host, expected-outcome set to the phase it would confirm. Empty when the tactic has no evidence spec
// or the case has no host to point at.
export function tacticCollectDirectives(tactic: IrisTactic, state: InvestigationState, scopedEvents: readonly ForensicEvent[], topHosts: readonly string[]): CollectDirective[] {
  const specs = TACTIC_EVIDENCE[tactic];
  if (!specs || !specs.length) return [];
  const primary = specs[0];
  const hosts = targetHostsForTactic(tactic, state, scopedEvents, topHosts);
  return hosts.map((host) => ({
    host,
    logSource: primary.logSource,
    ...(primary.artifact ? { artifact: primary.artifact } : {}),
    expectedOutcome: `evidence of ${tactic} (currently unexplained by any finding)`,
  }));
}

// The core kill-chain phases with NO covering finding — only once the case has a real (Critical/High)
// finding, so a low-signal case doesn't spuriously claim "missing initial access". Pure over state.
export function uncoveredCoreTactics(state: InvestigationState): IrisTactic[] {
  const serious = state.findings.some((f) => f.severity === "Critical" || f.severity === "High");
  if (!serious) return [];
  const covered = new Set<IrisTactic>();
  for (const f of state.findings) {
    const tac = tacticForTechniques(f.mitreTechniques ?? [], `${f.title} ${f.description}`);
    if (tac) covered.add(tac);
  }
  return CORE_TACTICS.filter((t) => !covered.has(t));
}

// A human label for one uncovered tactic, including its evidence hint (what to collect).
function uncoveredTacticLabel(tactic: IrisTactic): string {
  const specs = TACTIC_EVIDENCE[tactic];
  const where = specs?.map((s) => s.logSource).join("; ");
  return `No finding yet explains ${tactic}${where ? ` — collect ${where}` : ""}.`;
}

// The STRUCTURED known-unknowns for a case: uncovered kill-chain phases (each with a collection
// directive), silence gaps, and lookalike-actor likely-next techniques. Pure + offline.
export function buildKnownUnknownItems(
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
  opts: KnownUnknownsOptions = {},
): KnownUnknownItem[] {
  const items: KnownUnknownItem[] = [];
  const topHosts = rankHosts(state).topHosts;

  // 1. Uncovered ATT&CK phases — one item per phase, each carrying its collection directive.
  for (const tactic of uncoveredCoreTactics(state)) {
    items.push({
      kind: "uncovered_tactic",
      tactic,
      label: uncoveredTacticLabel(tactic),
      collect: tacticCollectDirectives(tactic, state, scopedEvents, topHosts),
    });
  }

  // 2. Coverage gaps — silent windows (complete = every source dark, the strongest log-tampering
  //    lead). No `collect` here: the dashboard links these to the existing Timeline Gaps panel, which
  //    already owns the shadow-artifact deploy UI.
  const gaps = detectTimelineGaps(scopedEvents, opts.gapOptions);
  const maxGaps = Math.max(0, opts.maxGaps ?? DEFAULT_MAX_GAPS);
  const orderedGaps = [...gaps.filter((g) => g.complete), ...gaps.filter((g) => !g.complete)].slice(0, maxGaps);
  for (const g of orderedGaps) {
    const who = g.complete ? "ALL sources silent" : `silent: ${g.silentSources.join(", ") || "some sources"}`;
    items.push({
      kind: "silence_gap",
      label: `No telemetry from ${g.startTimestamp} to ${g.endTimestamp} (${g.durationLabel}; ${who}) — collection gap or cleared logs?`,
      window: { start: g.startTimestamp, end: g.endTimestamp, durationLabel: g.durationLabel, complete: g.complete },
      collect: [],
    });
  }

  // 3. Likely-next techniques — what lookalike actors use that this case hasn't shown (predictive hunt
  //    priorities; statistical similarity, NOT attribution). Caller supplies them.
  const maxNext = Math.max(0, opts.maxNextTechniques ?? DEFAULT_MAX_NEXT);
  for (const nt of (opts.nextTechniques ?? []).slice(0, maxNext)) {
    items.push({
      kind: "likely_next_technique",
      tactic: nt.tactic as IrisTactic,
      technique: { id: nt.id, name: nt.name },
      label: `Not yet observed: ${nt.id}${nt.name ? ` (${nt.name})` : ""} [${nt.tactic}] — used by ${nt.groupCount} lookalike group(s).`,
      collect: [],
    });
  }

  return items;
}

// Render the known-unknowns items as the synthesis-prompt preamble block (or "" when none). Combines
// the per-tactic uncovered items into ONE bullet (the model reads phases as a set), keeps gaps + next
// as their own lines, and caps the total. This is what the prompt path used to build directly, so the
// human panel and the model see the same underlying items.
export function renderKnownUnknowns(items: readonly KnownUnknownItem[], max: number = DEFAULT_MAX_TOTAL): string {
  const bullets: string[] = [];

  const uncovered = items.filter((i) => i.kind === "uncovered_tactic").map((i) => i.tactic).filter(Boolean) as IrisTactic[];
  if (uncovered.length) bullets.push(`No finding yet explains these ATT&CK phases: ${uncovered.join(", ")}.`);

  for (const i of items) {
    if (i.kind === "silence_gap" || i.kind === "likely_next_technique") bullets.push(i.label);
  }

  if (!bullets.length) return "";
  const capped = bullets.slice(0, Math.max(0, max));
  return (
    "KNOWN UNKNOWNS / OPEN GAPS (evidence we'd expect in an intrusion but don't yet have — treat each " +
    "as an open question to investigate or hunt; an absence is a lead, not proof):\n" +
    capped.map((b) => `- ${b}`).join("\n") +
    "\n\n"
  );
}

// Backward-compatible text builder: structured items → prompt block. Existing callers keep working.
export function buildKnownUnknowns(
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
  opts: KnownUnknownsOptions = {},
): string {
  return renderKnownUnknowns(buildKnownUnknownItems(state, scopedEvents, opts), opts.max ?? DEFAULT_MAX_TOTAL);
}
