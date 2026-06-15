import { z } from "zod";
import type { ForensicEvent, InvestigationState, Severity } from "./stateTypes.js";

// Memory-forensics "Next-Step" agent (issue #101). The Companion already INGESTS Volatility 3 /
// Rekall output deterministically (`memoryImport.ts`) — process tree, network connections, malfind
// injected code, command lines, services, modules. Memory analysis is highly ITERATIVE: an analyst
// runs one plugin, spots an anomaly (svchost.exe without services.exe as parent, an unparented
// process, executable private memory, a beaconing connection), then runs the NEXT plugin to dig in.
// This is the "so what next" step for RAM: read the already-imported memory evidence, identify the
// anomalies, and suggest the EXACT next Volatility 3 command the analyst should run (e.g.
// `vol -f <image> windows.malfind --pid 1234`).
//
// The AI call lives in the pipeline (`suggestMemoryNextSteps`); this module holds the PURE,
// unit-tested pieces: the response schema (lenient `.catch` like responseSchema.ts so a slightly-off
// model reply still parses), the digest renderers that feed the model the memory evidence, the
// detector for which plugins have already been imported (so the agent suggests ones NOT yet run),
// and the sanitizer that drops useless suggestions and clamps field lengths.
//
// Suggestions are EPHEMERAL (generated on demand, shown for review) — like `ask`/`suggestHunts` they
// do NOT mutate InvestigationState. Per the Companion's post-detection principle this CONSUMES the
// memory tool's enumeration; it does not re-implement Volatility's analysis — it reasons over the
// imported rows and recommends the analyst's next command.

// The source tags `memoryImport.ts` stamps on the events it produces. An event is "memory evidence"
// when one of these is in its `sources`.
export const MEMORY_TOOLS: ReadonlySet<string> = new Set(["Volatility", "Rekall"]);

const severityEnum = z.enum(["Critical", "High", "Medium", "Low", "Info"]);

// One proposed next step. Every field is lenient so one off value never rejects the whole reply.
export const memoryNextStepSchema = z.object({
  anomaly: z.string().catch(""),             // the suspicious observation, e.g. "svchost.exe (PID 1234) has no services.exe parent"
  command: z.string().catch(""),             // the EXACT next Volatility 3 command, e.g. "vol -f <image> windows.malfind --pid 1234"
  plugin: z.string().catch(""),              // the Volatility 3 plugin it runs, e.g. "windows.malfind"
  rationale: z.string().catch(""),           // why this command + how to triage what it returns
  severity: severityEnum.catch("Medium"),    // priority of the underlying anomaly (drives display ordering)
  pid: z.string().catch(""),                 // the PID the step targets, if any (echoed for the analyst)
  mitreTechniques: z.array(z.string()).catch([]),
});

export type MemoryNextStep = z.infer<typeof memoryNextStepSchema>;

// The model returns { suggestions: [...] }. `.catch` at every level keeps a partial reply usable.
export const memoryNextStepResponseSchema = z.object({
  suggestions: z.array(memoryNextStepSchema).catch([]),
});

export type MemoryNextStepResponse = z.infer<typeof memoryNextStepResponseSchema>;

// Default cap on how many next steps to surface (override per case via DFIR_MEMORY_NEXTSTEP_MAX). A
// short, high-signal list beats a wall of near-duplicate commands the analyst won't run.
export const MEMORY_NEXTSTEP_MAX_DEFAULT = 8;

const MAX_COMMAND_LEN = 600;     // a runaway command is a sign of a confused model; keep it pasteable
const MAX_ANOMALY_LEN = 400;
const MAX_RATIONALE_LEN = 2000;
const MAX_PLUGIN_LEN = 80;
const MAX_PID_LEN = 20;

// Whether a forensic event came from a memory-forensics tool (Volatility / Rekall).
export function isMemoryEvent(e: Pick<ForensicEvent, "sources">): boolean {
  return (e.sources ?? []).some((s) => MEMORY_TOOLS.has(s));
}

// Whether the case has any imported memory evidence to reason about. With no Volatility/Rekall
// events there is nothing to analyse — the route returns [] without spending an AI call (and the
// dashboard hides the panel).
export function hasMemoryMaterial(state: InvestigationState): boolean {
  return (state.forensicTimeline ?? []).some(isMemoryEvent);
}

// `memoryImport.ts` writes descriptions as "<tool> <plugin>: …" (e.g. "Volatility pslist: …",
// "Rekall netscan: …"). Recover the plugin LABEL so we can tell the model which plugins were already
// imported — it should prefer suggesting plugins that have NOT been run yet where they would help.
const PLUGIN_LABEL_RE = /^(?:Volatility|Rekall)\s+([\w.]+):/;

export function memoryPluginsPresent(events: readonly ForensicEvent[]): string[] {
  const seen = new Set<string>();
  for (const e of events) {
    if (!isMemoryEvent(e)) continue;
    const m = PLUGIN_LABEL_RE.exec(e.description ?? "");
    if (m && m[1]) seen.add(m[1].toLowerCase());
  }
  return [...seen].sort();
}

// Render the memory evidence the model reasons over: just the Volatility/Rekall events, worst
// severity first then by the order given, each as "[sev] description". Capped for the token budget.
// The descriptions already carry the process tree (name/PID/PPID/parent), connections, malfind hits,
// and command lines, so the model has the structured signal without a second pass.
const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

export function renderMemoryEvidence(events: readonly ForensicEvent[], limit = 300): string {
  const mem = (events ?? []).filter(isMemoryEvent);
  if (!mem.length) return "(no memory evidence)";
  const ordered = [...mem].sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  return ordered
    .slice(0, limit)
    .map((e) => `[${e.severity}] ${(e.description ?? "").replace(/\s+/g, " ").trim().slice(0, 300)}`)
    .join("\n");
}

// Drop unusable suggestions and clamp fields. A step with no command or no anomaly is useless; a list
// longer than `max` is trimmed. Pure — deterministic, no I/O. Order is preserved (display sorting by
// severity happens in the dashboard).
export function sanitizeMemoryNextSteps(raw: readonly MemoryNextStep[] | undefined, max: number = MEMORY_NEXTSTEP_MAX_DEFAULT): MemoryNextStep[] {
  const out: MemoryNextStep[] = [];
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : MEMORY_NEXTSTEP_MAX_DEFAULT;
  for (const s of raw ?? []) {
    const command = String(s?.command ?? "").replace(/\s+/g, " ").trim();
    const anomaly = String(s?.anomaly ?? "").trim();
    if (!command || !anomaly) continue;       // no command or no observation → nothing to act on
    out.push({
      anomaly: anomaly.slice(0, MAX_ANOMALY_LEN),
      command: command.slice(0, MAX_COMMAND_LEN),
      plugin: String(s?.plugin ?? "").trim().slice(0, MAX_PLUGIN_LEN),
      rationale: String(s?.rationale ?? "").trim().slice(0, MAX_RATIONALE_LEN),
      severity: s?.severity ?? "Medium",
      pid: String(s?.pid ?? "").trim().slice(0, MAX_PID_LEN),
      mitreTechniques: dedupeStrings((s?.mitreTechniques ?? []).map((t) => String(t).trim()).filter(Boolean)).slice(0, 20),
    });
    if (out.length >= cap) break;
  }
  return out;
}

function dedupeStrings(arr: string[]): string[] {
  return [...new Set(arr)];
}

// Severity rank for display ordering (Critical first). Exposed so the dashboard stays consistent
// with the rest of the app's severity ordering.
export const MEMORY_NEXTSTEP_SEVERITY_RANK = SEV_RANK;
