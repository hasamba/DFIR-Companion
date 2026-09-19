import { createHash } from "node:crypto";
import { z } from "zod";
import type { Finding, ForensicEvent, Severity } from "./stateTypes.js";
import { tacticForTechniques, type IrisTactic } from "./mitreTactics.js";

// Per-finding analyst tasks (#1418). A Critical/High finding used to become a playbook card that
// restated the finding ("Investigate & remediate: <title>" over the description, verbatim). This
// module owns the task shape the card is built from instead: an imperative title, numbered steps
// that name the evidence, and a "done when" line. Two producers, one consumer:
//   - ai/findingTaskPass.ts writes one after synthesis (sanitized here, persisted by
//     findingTaskStore.ts);
//   - fallbackFindingTask() builds a deterministic one when the AI wrote none — an old case, a
//     backfilled finding, a provider outage;
//   - playbook.ts renders either into the card via renderFindingTaskDescription().
// Pure: no I/O, no store access. Everything the fallback needs (hosts, collect directives) is
// passed IN by the caller, so this file does not reach into workflow/ (an intel → workflow import
// would be a new ledger violation).

export interface FindingTask {
  title: string;
  steps: string[];
  doneWhen: string;
}

export interface StoredFindingTask extends FindingTask {
  // sha1 of severity|title|description at the time the task was written. A re-synthesis that leaves
  // the finding unchanged spends nothing on it; one that rewords it gets a fresh task.
  sourceHash: string;
  writtenAt: string;
  engine: "ai";
}

export const FINDING_TASK_TITLE_MAX = 160;
export const FINDING_TASK_STEP_MAX = 400;
export const FINDING_TASK_STEPS_MAX = 4;
const WHY_MAX = 200;

const clean = (s: string, max: number): string =>
  s
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .replace(/\s*\n\s*/g, " ")
    .trim()
    .slice(0, max);

export const findingTaskSchema = z.object({
  title: z.string(),
  steps: z.array(z.string()),
  doneWhen: z.string(),
});

export const storedFindingTaskSchema = findingTaskSchema.extend({
  sourceHash: z.string(),
  writtenAt: z.string(),
  engine: z.literal("ai"),
});

// The model's raw response row — lenient on purpose; sanitizeFindingTasks decides what survives.
export const rawFindingTaskSchema = z.object({
  findingId: z.string(),
  title: z.string().catch(""),
  steps: z.array(z.string()).catch([]),
  doneWhen: z.string().catch(""),
});
export type RawFindingTask = z.infer<typeof rawFindingTaskSchema>;

export function findingSourceHash(f: Finding): string {
  return createHash("sha1").update(`${f.severity}|${f.title}|${f.description}`).digest("hex");
}

// Keep a task only for a finding the prompt offered, with a non-empty title and at least one real
// step. Text is trimmed, control characters stripped, over-long fields truncated rather than
// dropped, and the first row wins when the model repeats a finding id.
export function sanitizeFindingTasks(
  rows: readonly RawFindingTask[],
  offered: ReadonlySet<string>,
): Record<string, FindingTask> {
  const out: Record<string, FindingTask> = {};
  for (const row of rows) {
    if (!offered.has(row.findingId) || out[row.findingId]) continue;
    const title = clean(row.title, FINDING_TASK_TITLE_MAX);
    const steps = row.steps
      .map((s) => clean(s, FINDING_TASK_STEP_MAX))
      .filter(Boolean)
      .slice(0, FINDING_TASK_STEPS_MAX);
    const doneWhen = clean(row.doneWhen, FINDING_TASK_STEP_MAX);
    if (!title || !steps.length) continue;
    out[row.findingId] = { title, steps, doneWhen };
  }
  return out;
}

// Distinct hosts of the finding's cited events, in citation order. Case-insensitive dedup keeps
// the first spelling seen.
export function findingEvidenceHosts(f: Finding, events: readonly ForensicEvent[]): string[] {
  const byId = new Map(events.map((e) => [e.id, e] as const));
  const seen = new Set<string>();
  const hosts: string[] = [];
  for (const id of f.relatedEventIds ?? []) {
    const host = byId.get(id)?.asset?.trim();
    if (!host || seen.has(host.toLowerCase())) continue;
    seen.add(host.toLowerCase());
    hosts.push(host);
  }
  return hosts;
}

// Tactic-specific investigation focus, keyed by the finding's dominant ATT&CK tactic. Shared with
// the IR-template phases in playbook.ts.
export const TACTIC_FOCUS: Record<IrisTactic, string> = {
  "Initial Access":
    "Identify the delivery mechanism (phishing, exposed service, valid account) and confirm patient zero.",
  Execution:
    "Trace the parent→child process chain and command lines; establish what ran and under which account.",
  Persistence:
    "Enumerate autoruns, services, scheduled tasks, and WMI subscriptions the adversary left behind.",
  "Privilege Escalation": "Determine how elevation was achieved and which accounts gained higher privileges.",
  "Defense Evasion":
    "Check for cleared logs, disabled security tooling, and masqueraded or obfuscated binaries.",
  "Credential Access": "Identify which credentials were accessed or dumped and rotate them immediately.",
  Discovery: "Review what the adversary enumerated to gauge their knowledge of the environment.",
  "Lateral Movement": "Map which hosts were reached and via what protocol and credentials.",
  Collection: "Determine what data was staged for exfiltration and from where.",
  "Command and Control": "Identify and block the C2 infrastructure; hunt for additional beacons.",
  Exfiltration: "Quantify what data left the environment and through which channel.",
  Impact:
    "Assess the damage (encryption / destruction / disruption) and prioritize recovery of affected systems.",
};

// Generic per-phase IR guidance (NIST SP 800-61 / SANS phases). Used by the IR-template mode in
// playbook.ts and, for `contain`, by the Critical fallback below.
export const PHASE_GUIDANCE = {
  contain:
    "Isolate the affected host(s) from the network (capture volatile evidence first), block the related indicators at the firewall/EDR, and disable any implicated accounts or sessions.",
  investigate:
    "Scope the activity: confirm the entry vector, build the timeline, and determine blast radius (which hosts, accounts, and data are involved). Pull supporting artifacts and correlate across tools.",
  eradicate:
    "Remove the threat: terminate malicious processes, delete dropped artifacts, remove persistence (services / scheduled tasks / run keys / WMI), and reset compromised credentials. Close the exploited vector.",
  recover:
    "Restore affected systems from known-good backups, re-enable services, validate integrity, and add detections/monitoring so a recurrence of these techniques is caught.",
} as const;

// The imperative the fallback title opens with, per tactic. The finding's own title follows the
// colon so the card still reads as the finding the analyst saw in the Findings panel.
const TACTIC_IMPERATIVE: Record<IrisTactic, string> = {
  "Initial Access": "Confirm the entry point and patient zero",
  Execution: "Confirm execution and trace the process chain",
  Persistence: "Enumerate and remove the persistence",
  "Privilege Escalation": "Confirm the elevation and which accounts gained it",
  "Defense Evasion": "Confirm what was tampered with and restore visibility",
  "Credential Access": "Confirm the credential theft and rotate what was exposed",
  Discovery: "Confirm the reconnaissance and what it revealed",
  "Lateral Movement": "Map the hosts reached and how",
  Collection: "Confirm what was staged and from where",
  "Command and Control": "Identify and block the C2",
  Exfiltration: "Quantify what left and through which channel",
  Impact: "Assess the damage and prioritize recovery",
};
const DEFAULT_IMPERATIVE = "Confirm and scope";
const SHORT_TITLE_MAX = 100;

export interface FallbackInput {
  // Hosts of the finding's cited events (findingEvidenceHosts), first-cited first.
  hosts: readonly string[];
  // "collect <what> from <host>" lines the caller already rendered from the tactic's collect
  // directives (playbook.ts owns that workflow/ import; this module stays in intel/).
  collectLines: readonly string[];
}

function shortTitle(title: string): string {
  const t = title.trim();
  return t.length <= SHORT_TITLE_MAX ? t : `${t.slice(0, SHORT_TITLE_MAX - 1).trimEnd()}…`;
}

function dateOnly(iso: string): string {
  return /^\d{4}-\d{2}-\d{2}/.test(iso) ? iso.slice(0, 10) : iso;
}

function containsAt(severity: Severity): boolean {
  return severity === "Critical";
}

// Deterministic task for a finding the AI wrote none for. Never the finding description: the first
// step names the evidence hosts and the time to look at, the next names what to collect where, then
// the tactic focus, then (Critical only) containment.
export function fallbackFindingTask(f: Finding, input: FallbackInput): FindingTask {
  const tactic = tacticForTechniques(f.mitreTechniques ?? [], f.description ?? "");
  const imperative = (tactic && TACTIC_IMPERATIVE[tactic]) || DEFAULT_IMPERATIVE;
  const when = f.firstSeen ? ` around ${dateOnly(f.firstSeen)}` : "";
  const where = input.hosts.length ? ` on ${input.hosts.slice(0, 3).join(", ")}` : "";
  const steps: string[] = [
    `Confirm the activity${where}${when}: pull the cited events' source artifacts and the process/logon context ±15 minutes.`,
  ];
  for (const line of input.collectLines.slice(0, 2)) {
    if (line.trim()) steps.push(line.charAt(0).toUpperCase() + line.slice(1));
  }
  if (tactic && TACTIC_FOCUS[tactic]) steps.push(TACTIC_FOCUS[tactic]);
  if (containsAt(f.severity)) steps.push(`Contain: ${PHASE_GUIDANCE.contain}`);
  const doneWhen = containsAt(f.severity)
    ? "Activity confirmed or refuted on each named host; supporting event ids attached to the finding; containment actions logged."
    : "Activity confirmed or refuted on each named host; supporting event ids attached to the finding.";
  return {
    title: `${imperative}: ${shortTitle(f.title)}`,
    steps: steps.slice(0, FINDING_TASK_STEPS_MAX),
    doneWhen,
  };
}

export interface RenderOptions {
  // Folded next-step notes → numbered "Also:" steps after the task's own.
  extraSteps?: readonly string[];
  // Rabbit-hole caveat, placed before "Done when" so it is read before the analyst acts.
  rabbitNote?: string;
  // The finding description; only its first sentence (≤ 200 chars) survives, as the last line.
  why?: string;
}

function firstSentence(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  const m = /^(.+?[.!?])(\s|$)/.exec(flat);
  const s = m ? m[1] : flat;
  return s.length <= WHY_MAX ? s : `${s.slice(0, WHY_MAX - 1).trimEnd()}…`;
}

// The playbook card body: steps first, "Done when" next, one-line "Why" last.
export function renderFindingTaskDescription(task: FindingTask, opts: RenderOptions = {}): string {
  const lines: string[] = [];
  let n = 0;
  for (const s of task.steps) lines.push(`${++n}. ${s}`);
  for (const s of opts.extraSteps ?? []) lines.push(`${++n}. Also: ${s}`);
  if (opts.rabbitNote) lines.push(opts.rabbitNote);
  if (task.doneWhen) lines.push(`Done when: ${task.doneWhen}`);
  if (opts.why?.trim()) lines.push(`Why: ${firstSentence(opts.why)}`);
  return lines.join("\n");
}
