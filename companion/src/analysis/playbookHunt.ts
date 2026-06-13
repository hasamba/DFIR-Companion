import { z } from "zod";
import type { InvestigationState, Severity } from "./stateTypes.js";
import type { PlaybookTask } from "./playbook.js";

// AI-suggested Velociraptor hunts for the case's PLAYBOOK tasks (issue #70). The sibling #57
// `huntSuggest.ts` proposes fleet hunts from the case FINDINGS; this is the per-playbook-task
// analog, and ENDPOINT-AWARE: the model writes one CLIENT-side VQL hunt for each task that is
// about endpoints, and the deploy MODE is decided deterministically here from the case's REAL
// observed endpoints — a task tied to exactly ONE endpoint becomes a single-client COLLECTION on
// that host; anything spanning multiple/unknown hosts becomes a fleet HUNT.
//
// Division of labor (so a hallucinated hostname can never trigger a dead collection):
//  - the AI classifies each task `endpointRelated`, writes the `vql`/`rationale`, and ECHOES the
//    host it inferred (chosen from the known-endpoints list the prompt provides), and
//  - this module (pure, unit-tested) derives the endpoints a task actually touches, validates the
//    AI's host against the observed ones, and finalizes `{ mode, targetHost }`.
//
// Suggestions are EPHEMERAL (generated on demand, reviewed, then deployed) — like `suggestHunts`
// they do NOT mutate InvestigationState. Deploy reuses `launchHunt` (POST /velociraptor/hunt) for a
// fleet hunt, or `collectFromHost` (POST /velociraptor/collect-host) for a single-endpoint collection.

const severityEnum = z.enum(["Critical", "High", "Medium", "Low", "Info"]);

// One raw suggestion from the model. Every field is lenient (`.catch`) so one off value never
// rejects the whole reply (mirrors `huntSuggestionSchema` and `responseSchema.ts`).
export const playbookHuntSuggestionSchema = z.object({
  taskId: z.string().catch(""),              // the playbook task this hunt is for (echoed from the list)
  endpointRelated: z.boolean().catch(false), // the model's judgment — false → dropped by the sanitizer
  title: z.string().catch(""),               // short hunt name
  rationale: z.string().catch(""),           // why: which task triggered it + what the query looks for + how to triage hits
  vql: z.string().catch(""),                 // a single CLIENT-side Velociraptor VQL statement
  targetHost: z.string().catch(""),          // the ONE host the model scoped it to (from the known list), "" = fleet-wide
  severity: severityEnum.catch("Medium"),    // priority of the underlying threat (drives display ordering)
  mitreTechniques: z.array(z.string()).catch([]),
});

export type RawPlaybookHuntSuggestion = z.infer<typeof playbookHuntSuggestionSchema>;

// The model returns { suggestions: [...] }. `.catch` at every level keeps a partial reply usable.
export const playbookHuntResponseSchema = z.object({
  suggestions: z.array(playbookHuntSuggestionSchema).catch([]),
});

export type PlaybookHuntResponse = z.infer<typeof playbookHuntResponseSchema>;

export type HuntMode = "hunt" | "collection";

// The finalized, sanitized suggestion the route + dashboard consume — the deterministic deploy MODE
// (and the validated target host for a collection) attached to the model's content.
export interface PlaybookHuntSuggestion {
  taskId: string;
  title: string;
  rationale: string;
  vql: string;
  severity: Severity;
  mitreTechniques: string[];
  mode: HuntMode;
  targetHost?: string;       // a real, observed host — present ONLY when mode === "collection"
}

// Default cap on suggestions per generation (override via DFIR_PBHUNT_SUGGEST_MAX).
export const PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT = 8;

const MAX_VQL_LEN = 4000;
const MAX_TITLE_LEN = 200;
const MAX_RATIONALE_LEN = 2000;

// A task is "open" (worth hunting for) when it's still actionable — done/skipped are excluded.
function isOpenTask(t: PlaybookTask): boolean {
  return t.status !== "done" && t.status !== "skipped";
}

// The distinct HOST endpoints observed in the case — each event's `asset` (the affected host),
// case-folded so "ALClient07" and "alclient07" collapse to one. These are the ONLY values that may
// become a collection target (accounts are NOT Velociraptor client hostnames, so they're excluded).
export function knownEndpoints(state: InvestigationState): string[] {
  const seen = new Map<string, string>();   // lowercased → first-seen canonical casing
  for (const e of state.forensicTimeline ?? []) {
    const host = (e.asset ?? "").trim();
    if (!host) continue;
    const key = host.toLowerCase();
    if (!seen.has(key)) seen.set(key, host);
  }
  return [...seen.values()];
}

const HOST_TOKEN_RE = /[A-Za-z0-9._-]+/g;

// Whether `host` is named in free text as a standalone token (boundary-aware so "PC1" does not
// false-match inside "PC10"). Handles short-name ⇄ FQDN both ways: a known "web01" matches a
// "web01.corp.local" mention and vice-versa. Case-insensitive.
function hostMentioned(text: string, host: string): boolean {
  const h = host.toLowerCase();
  if (h.length < 2) return false;
  const tokens = (text || "").toLowerCase().match(HOST_TOKEN_RE);
  if (!tokens) return false;
  for (const t of tokens) {
    if (t === h) return true;
    if (t.startsWith(h + ".")) return true;   // host is the leading label of an FQDN token
    if (h.startsWith(t + ".")) return true;   // token is the leading label of the host's FQDN
  }
  return false;
}

// The host endpoints a single playbook task touches: (a) the `asset` of every forensic event linked
// to the task's finding, plus (b) any KNOWN endpoint named in the task's title/description. Findings
// carry no `asset` (only events do, via `relatedFindingIds`), so the event-join is the only sound
// host source; `next_step`/`custom` tasks (no `relatedFindingId`) fall back to name-matching.
export function deriveTaskEndpoints(state: InvestigationState, task: PlaybookTask): string[] {
  const out = new Map<string, string>();
  const addHost = (h: string | undefined): void => {
    const v = (h ?? "").trim();
    if (!v) return;
    const k = v.toLowerCase();
    if (!out.has(k)) out.set(k, v);
  };

  if (task.relatedFindingId) {
    for (const e of state.forensicTimeline ?? []) {
      if (e.relatedFindingIds?.includes(task.relatedFindingId)) addHost(e.asset);
    }
  }

  const text = `${task.title} ${task.description ?? ""}`;
  for (const host of knownEndpoints(state)) {
    if (hostMentioned(text, host)) addHost(host);
  }

  return [...out.values()];
}

// Precompute the endpoints for each task once (keyed by task id) — fed to both the prompt renderer
// and the sanitizer so the mode decision matches the context the model saw.
export function buildTaskEndpointsMap(state: InvestigationState, tasks: readonly PlaybookTask[]): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const t of tasks) map.set(t.id, deriveTaskEndpoints(state, t));
  return map;
}

// Decide hunt vs collection for one suggestion, deterministically:
//  (a) the model's `targetHost` IF it matches a real observed endpoint (canonical casing kept), else
//  (b) the task's single derived endpoint when there is exactly one, else
//  (c) a fleet hunt.
// SAFETY CLAMP: an unmatched/hallucinated targetHost never becomes a collection — only ever-observed
// hosts can be a collection target (so a dead `collect_client` on a non-existent host can't happen).
export function resolveHuntMode(
  rawTargetHost: string,
  taskEndpoints: readonly string[],
  known: readonly string[],
): { mode: HuntMode; targetHost?: string } {
  const knownByLc = new Map(known.map((h) => [h.toLowerCase(), h] as const));
  const wanted = (rawTargetHost ?? "").trim().toLowerCase();
  if (wanted && knownByLc.has(wanted)) return { mode: "collection", targetHost: knownByLc.get(wanted)! };
  if (taskEndpoints.length === 1) return { mode: "collection", targetHost: taskEndpoints[0] };
  return { mode: "hunt" };
}

function dedupeStrings(arr: string[]): string[] {
  return [...new Set(arr)];
}

// Drop unusable suggestions (non-endpoint, or no VQL/title), clamp field lengths, and attach the
// deterministic deploy mode. Pure — no I/O. Order is preserved (display sorting is the dashboard's).
export function sanitizePlaybookHuntSuggestions(
  raw: readonly RawPlaybookHuntSuggestion[] | undefined,
  endpointsByTaskId: Map<string, string[]>,
  known: readonly string[],
  max: number = PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT,
): PlaybookHuntSuggestion[] {
  const out: PlaybookHuntSuggestion[] = [];
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT;
  for (const s of raw ?? []) {
    if (!s?.endpointRelated) continue;              // the issue's core rule — only endpoint tasks get a hunt
    const vql = String(s?.vql ?? "").trim();
    const title = String(s?.title ?? "").trim();
    if (!vql || !title) continue;                   // no query or no name → nothing to deploy
    const taskId = String(s?.taskId ?? "").trim();
    const taskEndpoints = endpointsByTaskId.get(taskId) ?? [];
    const { mode, targetHost } = resolveHuntMode(String(s?.targetHost ?? ""), taskEndpoints, known);
    out.push({
      taskId,
      title: title.slice(0, MAX_TITLE_LEN),
      rationale: String(s?.rationale ?? "").trim().slice(0, MAX_RATIONALE_LEN),
      vql: vql.slice(0, MAX_VQL_LEN),
      severity: s?.severity ?? "Medium",
      mitreTechniques: dedupeStrings((s?.mitreTechniques ?? []).map((t) => String(t).trim()).filter(Boolean)).slice(0, 20),
      mode,
      ...(targetHost ? { targetHost } : {}),
    });
    if (out.length >= cap) break;
  }
  return out;
}

// Render the OPEN playbook tasks for the model, each annotated with the endpoints it's already known
// to touch (so the model classifies endpoint-relatedness with evidence and picks a REAL targetHost
// instead of inventing one). Done/skipped tasks are excluded. Capped description for the budget.
export function renderPlaybookHuntTasks(tasks: readonly PlaybookTask[], endpointsByTaskId: Map<string, string[]>): string {
  const open = (tasks ?? []).filter(isOpenTask);
  if (!open.length) return "(no open playbook tasks)";
  return open
    .map((t) => {
      const eps = endpointsByTaskId.get(t.id) ?? [];
      const epText = eps.length ? ` [endpoints: ${eps.join(", ")}]` : " [endpoints: none derived]";
      const desc = (t.description ?? "").replace(/\s+/g, " ").trim().slice(0, 240);
      return `[${t.id}] [${t.priority}] ${t.title}${epText}${desc ? ` — ${desc}` : ""}`;
    })
    .join("\n");
}

// The case's known endpoints, for the prompt — the model must pick a `targetHost` only from this list.
export function renderKnownEndpoints(known: readonly string[]): string {
  return known.length ? known.join(", ") : "(no endpoints observed in this case)";
}

// A server can define hundreds of CLIENT artifacts; the full list (alphabetical, so the `Windows.*`
// ones sort LAST) would bloat the prompt and a naive cap would drop the most useful ones. Rank by DFIR
// relevance so a small cap keeps the high-value artifacts. Admin/Server/Demo/Reporting are never
// endpoint hunts → dropped.
function artifactRelevanceRank(name: string): number {
  if (/^(Admin|Server|Demo|Reporting|Notebooks|Github)\./i.test(name)) return 99;   // dropped
  if (/^Windows\./i.test(name)) return 0;
  if (/^DetectRaptor\./i.test(name)) return 1;
  if (/^Custom\./i.test(name)) return 2;
  if (/^(Generic|Exchange|Elastic)\./i.test(name)) return 3;
  return 5;   // Linux./MacOS./other — kept, lower priority (most cases are Windows; raw plugins cover the rest)
}

// Render the Velociraptor server's available CLIENT artifact names for the prompt — the model may
// reference an `Artifact.<Name>()` ONLY if <Name> is here; anything else won't exist on the server and
// the hunt/collection fails to compile. Deduped, relevance-ranked, and capped (DFIR_PBHUNT_MAX_ARTIFACTS)
// so the high-value artifacts survive a small cap and the prompt stays lean.
export function renderAvailableArtifacts(names: readonly string[], max = 150): string {
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : 150;
  const seen = new Set<string>();
  const ranked: Array<{ name: string; rank: number; i: number }> = [];
  for (const n of names ?? []) {
    const v = String(n ?? "").trim();
    if (!v || seen.has(v)) continue;
    seen.add(v);
    const rank = artifactRelevanceRank(v);
    if (rank >= 99) continue;   // never an endpoint hunt
    ranked.push({ name: v, rank, i: ranked.length });
  }
  ranked.sort((a, b) => (a.rank - b.rank) || (a.i - b.i));   // by relevance, stable within a rank
  const out = ranked.slice(0, cap).map((r) => r.name);
  return out.length ? out.join(", ") : "(artifact list unavailable — use raw VQL plugins only)";
}

// Whether the case has enough signal to ask the model for playbook hunts: at least one OPEN task,
// plus some material to write VQL from (a live finding or a forensic event). Returns false on an
// empty/closed playbook so the route returns [] without spending an AI call.
export function hasPlaybookHuntMaterial(state: InvestigationState, tasks: readonly PlaybookTask[]): boolean {
  const hasOpen = (tasks ?? []).some(isOpenTask);
  if (!hasOpen) return false;
  const liveFindings = (state.findings ?? []).some((f) => f.status !== "dismissed");
  return liveFindings || (state.forensicTimeline ?? []).length > 0;
}

// Severity rank for display ordering (Critical first) — exposed for the dashboard so playbook-hunt
// ordering stays consistent with the rest of the app.
export const PLAYBOOK_HUNT_SEVERITY_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

// ── Persistence + staleness (suggestions survive a page refresh) ─────────────────────────────
// Suggestions are generated on demand but PERSISTED per case so they don't vanish on reload. A
// suggestion stays valid only while its TASK is unchanged: we fingerprint the task's text at
// generation time, and on read drop any suggestion whose task was reworded (synthesis re-wrote it) or
// deleted — the analyst regenerates those. The fingerprint is intentionally task-only (title +
// description): a suggestion sticks even as the rest of the case evolves, matching the analyst's
// mental model of "this hunt is for THIS task".

export interface PersistedPlaybookHunts {
  generatedAt: string;                       // when the analyst last generated (ISO)
  suggestions: PlaybookHuntSuggestion[];     // each carries its taskId
  taskHashes: Record<string, string>;        // taskId → task fingerprint at generation time
}

export const EMPTY_PERSISTED_HUNTS: PersistedPlaybookHunts = { generatedAt: "", suggestions: [], taskHashes: {} };

// Deterministic FNV-1a fingerprint of the task fields that drive a suggestion (title + description,
// whitespace-normalized). A change here means the task was edited/reworded → its hunt is stale.
export function taskFingerprint(task: { title?: string; description?: string }): string {
  const norm = `${String(task?.title ?? "").replace(/\s+/g, " ").trim()} ${String(task?.description ?? "").replace(/\s+/g, " ").trim()}`;
  let h = 0x811c9dc5;
  for (let i = 0; i < norm.length; i++) {
    h ^= norm.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

// The fingerprint map to persist alongside freshly-generated suggestions — one entry per task that
// has a suggestion, hashed from the tasks the model actually saw.
export function buildHuntTaskHashes(suggestions: readonly PlaybookHuntSuggestion[], tasks: readonly PlaybookTask[]): Record<string, string> {
  const byId = new Map(tasks.map((t) => [t.id, t] as const));
  const out: Record<string, string> = {};
  for (const s of suggestions) {
    const t = byId.get(s.taskId);
    if (t) out[s.taskId] = taskFingerprint(t);
  }
  return out;
}

// Keep the persisted suggestions whose task STILL EXISTS and is UNCHANGED since generation; the rest
// are stale (task reworded or deleted) and dropped. `taskHashes` carries the fingerprint of EVERY
// evaluated task that is still unchanged — including ones the AI evaluated but produced no hunt for
// (non-endpoint tasks) — so a later generate can SKIP them (incremental, never re-doing covered work).
// Returns the filtered set + `changed` so the caller can write-back the pruned store. Pure.
export function selectFreshHunts(persisted: PersistedPlaybookHunts | undefined, tasks: readonly PlaybookTask[]): { suggestions: PlaybookHuntSuggestion[]; taskHashes: Record<string, string>; changed: boolean } {
  const byId = new Map(tasks.map((t) => [t.id, t] as const));
  const allSug = persisted?.suggestions ?? [];
  const storedHashes = persisted?.taskHashes ?? {};
  const suggestions: PlaybookHuntSuggestion[] = [];
  for (const s of allSug) {
    const t = byId.get(s.taskId);
    if (t && storedHashes[s.taskId] === taskFingerprint(t)) suggestions.push(s);   // task unchanged → keep
  }
  const taskHashes: Record<string, string> = {};
  for (const [taskId, hash] of Object.entries(storedHashes)) {
    const t = byId.get(taskId);
    if (t && taskFingerprint(t) === hash) taskHashes[taskId] = hash;               // evaluated + unchanged → keep marker
  }
  const changed = suggestions.length !== allSug.length || Object.keys(taskHashes).length !== Object.keys(storedHashes).length;
  return { suggestions, taskHashes, changed };
}

// Which OPEN tasks still need a hunt generated: NEW tasks (never evaluated) or CHANGED tasks (their
// fingerprint differs from when last evaluated). Tasks already evaluated and unchanged are skipped, so
// pressing Generate after adding one task only sends THAT task to the model and never regenerates the
// hunts that already exist. Pure.
export function pendingHuntTasks(tasks: readonly PlaybookTask[], evaluatedHashes: Record<string, string>): PlaybookTask[] {
  return (tasks ?? []).filter((t) => isOpenTask(t) && evaluatedHashes[t.id] !== taskFingerprint(t));
}

// Merge freshly-generated suggestions with the kept (unchanged) ones, and stamp the fingerprint of
// every task evaluated THIS round (the pending ones) so the next generate skips them. Pure.
export function mergePersistedHunts(
  fresh: { suggestions: PlaybookHuntSuggestion[]; taskHashes: Record<string, string> },
  newSuggestions: readonly PlaybookHuntSuggestion[],
  pendingTasks: readonly PlaybookTask[],
  generatedAt: string,
): PersistedPlaybookHunts {
  const taskHashes = { ...fresh.taskHashes };
  for (const t of pendingTasks) taskHashes[t.id] = taskFingerprint(t);
  return { generatedAt, suggestions: [...fresh.suggestions, ...newSuggestions], taskHashes };
}
