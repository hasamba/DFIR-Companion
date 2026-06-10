import { z } from "zod";
import type { Finding, InvestigationState, Severity, StepPriority } from "./stateTypes.js";
import { tacticForTechniques, type IrisTactic } from "../integrations/iris/mitreTactics.js";

// Playbook tracking (issue #36, Phase 1). Turns the AI's "next steps" and the
// high-severity findings into a trackable checklist of remediation/investigation
// TASKS the analyst can move through (todo → in-progress → done/skipped), annotate
// with an assignee + due date, reorder, and add custom items to. Persisted per case
// in `state/playbook.json` (PlaybookStore) — NOT in InvestigationState, so synthesis
// never wipes analyst progress (like comments/tags/notebook). The derivation here is
// pure and deterministic so it can be re-run on every read/synthesis idempotently:
// an auto-task's id IS its source key, so re-deriving REFRESHES its text but PRESERVES
// the analyst's status/assignee/due-date/notes/order.

export const PLAYBOOK_STATUSES = ["todo", "in_progress", "done", "skipped"] as const;
export type PlaybookStatus = (typeof PLAYBOOK_STATUSES)[number];

export const PLAYBOOK_SOURCES = ["next_step", "finding", "custom"] as const;
export type PlaybookSource = (typeof PLAYBOOK_SOURCES)[number];

const STEP_PRIORITIES = ["critical", "high", "medium", "low"] as const;

export const playbookTaskSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string().catch(""),
  status: z.enum(PLAYBOOK_STATUSES).catch("todo" as PlaybookStatus),
  priority: z.enum(STEP_PRIORITIES).catch("medium" as StepPriority),
  source: z.enum(PLAYBOOK_SOURCES).catch("custom" as PlaybookSource),
  sourceKey: z.string().optional(),       // stable derive key (absent for custom tasks)
  relatedFindingId: z.string().optional(),
  assignee: z.string().optional(),
  dueDate: z.string().optional(),         // free-form date, e.g. "2026-06-15"
  notes: z.string().optional(),
  order: z.number().catch(0),
  createdAt: z.string(),
  updatedAt: z.string(),
});

export type PlaybookTask = z.infer<typeof playbookTaskSchema>;
export const playbookSchema = z.array(playbookTaskSchema).catch([]);

// A candidate task derived from case state (before it's merged into the stored list).
export interface DerivedTaskSeed {
  title: string;
  description: string;
  priority: StepPriority;
  source: "next_step" | "finding";
  sourceKey: string;
  relatedFindingId?: string;
}

const PRIORITY_FROM_SEVERITY: Record<Severity, StepPriority> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
  Info: "low",
};

function normalizePriority(p: string): StepPriority {
  const v = String(p).toLowerCase();
  return (STEP_PRIORITIES as readonly string[]).includes(v) ? (v as StepPriority) : "medium";
}

// ── Severity-based response templates (Phase 2, opt-in) ──────────────────────
// A Critical finding expands into the full incident-response cycle; a High finding into the
// investigation-first subset. The guidance is tailored to the finding's dominant ATT&CK tactic
// (the "MITRE remediation advice" — derived from the already-mapped technique→tactic table).

export const IR_PHASES = ["contain", "investigate", "eradicate", "recover"] as const;
export type IrPhase = (typeof IR_PHASES)[number];

const PHASE_LABEL: Record<IrPhase, string> = {
  contain: "Contain", investigate: "Investigate", eradicate: "Eradicate", recover: "Recover",
};

// Generic per-phase IR guidance (NIST SP 800-61 / SANS phases).
const PHASE_GUIDANCE: Record<IrPhase, string> = {
  contain: "Isolate the affected host(s) from the network (capture volatile evidence first), block the related indicators at the firewall/EDR, and disable any implicated accounts or sessions.",
  investigate: "Scope the activity: confirm the entry vector, build the timeline, and determine blast radius (which hosts, accounts, and data are involved). Pull supporting artifacts and correlate across tools.",
  eradicate: "Remove the threat: terminate malicious processes, delete dropped artifacts, remove persistence (services / scheduled tasks / run keys / WMI), and reset compromised credentials. Close the exploited vector.",
  recover: "Restore affected systems from known-good backups, re-enable services, validate integrity, and add detections/monitoring so a recurrence of these techniques is caught.",
};

// Tactic-specific investigation focus, keyed by the finding's dominant ATT&CK tactic.
const TACTIC_FOCUS: Record<IrisTactic, string> = {
  "Initial Access": "Identify the delivery mechanism (phishing, exposed service, valid account) and confirm patient zero.",
  "Execution": "Trace the parent→child process chain and command lines; establish what ran and under which account.",
  "Persistence": "Enumerate autoruns, services, scheduled tasks, and WMI subscriptions the adversary left behind.",
  "Privilege Escalation": "Determine how elevation was achieved and which accounts gained higher privileges.",
  "Defense Evasion": "Check for cleared logs, disabled security tooling, and masqueraded or obfuscated binaries.",
  "Credential Access": "Identify which credentials were accessed or dumped and rotate them immediately.",
  "Discovery": "Review what the adversary enumerated to gauge their knowledge of the environment.",
  "Lateral Movement": "Map which hosts were reached and via what protocol and credentials.",
  "Collection": "Determine what data was staged for exfiltration and from where.",
  "Command and Control": "Identify and block the C2 infrastructure; hunt for additional beacons.",
  "Exfiltration": "Quantify what data left the environment and through which channel.",
  "Impact": "Assess the damage (encryption / destruction / disruption) and prioritize recovery of affected systems.",
};

// Which IR phases each severity expands into. Critical → full cycle; High → investigate + contain.
const PHASES_BY_SEVERITY: Partial<Record<Severity, readonly IrPhase[]>> = {
  Critical: IR_PHASES,
  High: ["investigate", "contain"],
};

function mitreSummary(techniques: readonly string[]): string {
  const ids = techniques.filter(Boolean);
  if (!ids.length) return "";
  const tactic = tacticForTechniques(ids);
  return ` ATT&CK: ${ids.join(", ")}${tactic ? ` (${tactic})` : ""}.`;
}

// Expand one Critical/High finding into ordered IR-phase task seeds. Each phase keeps a stable
// sourceKey (`finding:<id>:<phase>`) so re-derivation stays idempotent.
function buildFindingTemplateSeeds(f: Finding): DerivedTaskSeed[] {
  const priority = PRIORITY_FROM_SEVERITY[f.severity] ?? "medium";
  const phases = PHASES_BY_SEVERITY[f.severity];
  if (!phases) return [];
  const tactic = tacticForTechniques(f.mitreTechniques ?? [], f.description ?? "");
  const mitre = mitreSummary(f.mitreTechniques ?? []);
  return phases.map((phase) => {
    let description = PHASE_GUIDANCE[phase];
    if (phase === "investigate") {
      if (tactic && TACTIC_FOCUS[tactic]) description += ` Focus: ${TACTIC_FOCUS[tactic]}`;
      description += mitre;
    }
    return {
      title: `${PHASE_LABEL[phase]}: ${f.title}`,
      description,
      priority,
      source: "finding" as const,
      sourceKey: `finding:${f.id}:${phase}`,
      relatedFindingId: f.id,
    };
  });
}

// Sort: by analyst-controlled `order`, then by creation time as a stable tiebreaker.
export function sortPlaybookTasks(tasks: PlaybookTask[]): PlaybookTask[] {
  return [...tasks].sort((a, b) => (a.order - b.order) || a.createdAt.localeCompare(b.createdAt));
}

export interface DeriveOptions {
  // When true, each Critical/High finding expands into a severity-based IR template
  // (Contain/Investigate/Eradicate/Recover) instead of a single "investigate & remediate" task.
  // Opt-in per case (Phase 2) so the playbook isn't flooded by default.
  useTemplates?: boolean;
}

// Derive the candidate task list from the synthesized case state:
//  - every AI next step → one task (priority carried through), and
//  - every NON-dismissed Critical/High finding → either a single "investigate & remediate" task
//    (default) or, when `useTemplates` is on, the severity-based IR template phases.
// Lower-severity findings stay out to avoid flooding. Each seed has a STABLE sourceKey so
// re-derivation is idempotent.
export function derivePlaybookTasks(state: InvestigationState, opts: DeriveOptions = {}): DerivedTaskSeed[] {
  const seeds: DerivedTaskSeed[] = [];
  for (const s of state.nextSteps ?? []) {
    const desc = [s.rationale, s.pointer ? `Where / what to collect: ${s.pointer}` : ""]
      .filter(Boolean)
      .join("\n\n");
    seeds.push({
      title: s.action,
      description: desc,
      priority: normalizePriority(s.priority),
      source: "next_step",
      sourceKey: `next_step:${s.id}`,
    });
  }
  for (const f of state.findings ?? []) {
    if (f.status === "dismissed") continue;
    const priority = PRIORITY_FROM_SEVERITY[f.severity] ?? "medium";
    if (priority !== "critical" && priority !== "high") continue;
    if (opts.useTemplates) {
      seeds.push(...buildFindingTemplateSeeds(f));
    } else {
      seeds.push({
        title: `Investigate & remediate: ${f.title}`,
        description: f.description,
        priority,
        source: "finding",
        sourceKey: `finding:${f.id}`,
        relatedFindingId: f.id,
      });
    }
  }
  return seeds;
}

export interface MergeResult {
  tasks: PlaybookTask[];
  changed: boolean;
}

// A pristine auto-task is one the analyst hasn't engaged with — still `todo`, no assignee,
// due date, or notes. Such a task may be safely pruned when its seed disappears; anything the
// analyst touched is kept.
function isPristineAuto(t: PlaybookTask): boolean {
  return t.source !== "custom" && !!t.sourceKey && t.status === "todo" && !t.assignee && !t.dueDate && !t.notes;
}

// Merge freshly-derived seeds into the existing stored tasks. An auto-task is keyed by
// its sourceKey (which is also its id). For a seed that already exists we REFRESH the
// title/description/priority/finding-link (synthesis may have reworded it) but PRESERVE
// the analyst's status/assignee/dueDate/notes/order. A seed with no existing task is
// appended as a fresh `todo`. An existing auto-task whose seed disappeared (finding
// dismissed, next step gone, or a template-mode switch changed the keys) is DROPPED only if
// it's pristine; a touched auto-task and every custom task are always kept. Pure +
// deterministic: pass `now` in so there's no clock dependency.
export function mergePlaybook(existing: PlaybookTask[], seeds: DerivedTaskSeed[], now: string): MergeResult {
  const result = existing.map((t) => ({ ...t }));
  const byId = new Map(result.map((t) => [t.id, t] as const));
  let changed = false;
  let maxOrder = result.reduce((m, t) => Math.max(m, t.order), -1);

  for (const seed of seeds) {
    const id = seed.sourceKey;
    const cur = byId.get(id);
    if (cur) {
      const findingChanged = (cur.relatedFindingId ?? "") !== (seed.relatedFindingId ?? "");
      if (cur.title !== seed.title || cur.description !== seed.description || cur.priority !== seed.priority || findingChanged) {
        const idx = result.findIndex((t) => t.id === id);
        result[idx] = {
          ...result[idx],
          title: seed.title,
          description: seed.description,
          priority: seed.priority,
          ...(seed.relatedFindingId ? { relatedFindingId: seed.relatedFindingId } : {}),
          updatedAt: now,
        };
        changed = true;
      }
    } else {
      maxOrder += 1;
      const task: PlaybookTask = {
        id,
        title: seed.title,
        description: seed.description,
        status: "todo",
        priority: seed.priority,
        source: seed.source,
        sourceKey: seed.sourceKey,
        ...(seed.relatedFindingId ? { relatedFindingId: seed.relatedFindingId } : {}),
        order: maxOrder,
        createdAt: now,
        updatedAt: now,
      };
      result.push(task);
      byId.set(id, task);
      changed = true;
    }
  }

  // Prune pristine auto-tasks whose seed is no longer derived.
  const seedKeys = new Set(seeds.map((s) => s.sourceKey));
  const pruned = result.filter((t) => {
    if (t.sourceKey && !seedKeys.has(t.sourceKey) && isPristineAuto(t)) {
      changed = true;
      return false;
    }
    return true;
  });
  return { tasks: pruned, changed };
}

export interface PlaybookStats {
  total: number;
  done: number;
  skipped: number;
  open: number;            // todo + in_progress (still needs action)
  inProgress: number;
  completionPct: number;   // done / total, rounded
}

export function playbookStats(tasks: PlaybookTask[]): PlaybookStats {
  const total = tasks.length;
  const done = tasks.filter((t) => t.status === "done").length;
  const skipped = tasks.filter((t) => t.status === "skipped").length;
  const inProgress = tasks.filter((t) => t.status === "in_progress").length;
  const open = total - done - skipped;
  const completionPct = total ? Math.round((done / total) * 100) : 0;
  return { total, done, skipped, open, inProgress, completionPct };
}
