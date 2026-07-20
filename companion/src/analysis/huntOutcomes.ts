// Hunt feedback loop (issue #157) — the PURE, unit-tested core of the per-case hunting profile.
//
// Hunt suggestions used to be generated open-loop: the model proposed VQL fleet/playbook hunts, the
// analyst deployed some, and the NEXT round of suggestions had no idea which already ran or what they
// found. This module records each deployed hunt's OUTCOME (did it surface new evidence + counts) so
// the loop can close: suggestions skip a query that already ran, and pivot on what a productive hunt
// surfaced. The state is persisted by `HuntOutcomeStore` (`state/hunt-outcomes.json`); this file holds
// only the deterministic, I/O-free pieces (record/fill/render/profile) so they're tested in isolation.
//
// Signal sources (server-wired): BUNDLE hunts already auto-collect through `importVeloHuntResults`,
// which computes addedEvents/addedIocs — that's the real hit/miss delta (→ fillOutcome). Suggested
// FLEET / PLAYBOOK / TECHNIQUE hunts record what VQL ran at deploy time (→ recordDeploy) and are
// filled if/when the analyst collects their results into the case. The VQL fingerprint is the dedup
// key that guarantees a deployed hunt is never re-proposed.

import type { HuntRunDiff } from "./huntRunDiff.js";

export type HuntOutcomeSource = "fleet" | "playbook" | "technique" | "bundle";
export type HuntOutcomeStatus = "deployed" | "collected";

// One recorded hunt. `vqlFingerprint`/`vqlPreview` are empty for bundles (artifact lists, not a single
// VQL). The collected-only fields (foundEvidence/added*/resultSummary/collectedAt) are filled when the
// hunt's results are imported. All fields optional past the deploy-time core so a partial/older file
// loads cleanly.
export interface HuntOutcome {
  id: string;                 // stable: the Velociraptor huntId when known, else `${fingerprint}:${deployedAt}`
  source: HuntOutcomeSource;
  title: string;
  vqlFingerprint: string;     // FNV-1a of the normalized VQL; "" for bundles
  vqlPreview: string;         // short normalized VQL snippet (profile + prompt); "" for bundles
  mitreTechniques: string[];
  huntId?: string;            // Velociraptor hunt id when known (links to a VeloHuntJob for collection)
  deployedAt: string;         // ISO
  status: HuntOutcomeStatus;
  foundEvidence?: boolean;    // collected: did the hunt return ANY rows / add any new events or IOCs
  // ACH-style hypotheses (investigation-guidance #14): the hypothesis this hunt was deployed to test, so
  // a hunt that comes back empty counts as a MISS against it (→ eventual `exhausted`). Optional — most
  // hunts aren't tied to a specific hypothesis and fall back to technique-overlap matching.
  relatedHypothesisId?: string;
  resultRows?: number;        // collected: total rows the hunt returned (what the analyst sees) — a snapshot, not cumulative
  addedEvents?: number;       // collected: events NEW to the case after dedup (cumulative across re-collects)
  addedIocs?: number;         // collected: IOCs new to the case (cumulative)
  resultSummary?: string;     // collected: compact, e.g. "10 results, +1 new event" / "no results"
  collectedAt?: string;       // collected: ISO
  // Run-to-run diff (#80): what's new/gone vs this hunt's PREVIOUS run of the same VQL fingerprint (a
  // re-deploy of a recurring/scheduled hunt), as opposed to addedEvents/addedIocs above which are
  // cumulative against the whole CASE. Set by the caller (server.ts, via HuntRunSnapshotStore) since
  // computing it needs I/O; absent when this fingerprint has no prior run to diff against yet, or for
  // bundles (no fingerprint to key a run history on).
  runDiff?: HuntRunDiff;
}

// Cap retained outcomes per case (newest first) so the side file stays small; override per case with
// DFIR_HUNT_OUTCOME_MAX. Generous enough to span a whole investigation's hunts.
export const HUNT_OUTCOME_MAX_DEFAULT = 50;

const MAX_TITLE_LEN = 200;
const MAX_VQL_PREVIEW_LEN = 300;

// Whitespace-normalize a VQL statement so two formattings of the same query fingerprint identically
// (mirrors playbookHunt.ts's task normalization). NOT lowercased — VQL artifact names are case-sensitive.
export function normalizeVql(vql: string): string {
  return String(vql ?? "").replace(/\s+/g, " ").trim();
}

// Deterministic FNV-1a fingerprint of the normalized VQL — the dedup/exclude key. Empty input → "" so
// a missing/bundle VQL never collides with a real one.
export function vqlFingerprint(vql: string): string {
  const norm = normalizeVql(vql);
  if (!norm) return "";
  let h = 0x811c9dc5;
  for (let i = 0; i < norm.length; i++) {
    h ^= norm.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

function dedupeStrings(arr: string[]): string[] {
  return [...new Set(arr)];
}

function capMax(max: number): number {
  return Number.isFinite(max) && max > 0 ? Math.floor(max) : HUNT_OUTCOME_MAX_DEFAULT;
}

// What the caller supplies when a hunt is deployed. `vql` is omitted/"" for bundles.
export interface HuntDeployInput {
  source: HuntOutcomeSource;
  title: string;
  vql?: string;
  mitreTechniques?: string[];
  huntId?: string;
  relatedHypothesisId?: string;  // ACH (#14): the hypothesis this hunt tests, when deployed from one
  deployedAt: string;         // ISO (the route stamps it — keeps this module time-free)
}

// Record a freshly-deployed hunt (status "deployed"), prepended and capped (newest first). Upsert by
// id — re-deploying the same huntId / same fingerprint+time replaces the entry rather than duplicating.
// Pure: returns a new array, never mutates the input.
export function recordDeploy(
  outcomes: readonly HuntOutcome[],
  input: HuntDeployInput,
  max: number = HUNT_OUTCOME_MAX_DEFAULT,
): HuntOutcome[] {
  const fp = vqlFingerprint(input.vql ?? "");
  const huntId = String(input.huntId ?? "").trim();
  const id = huntId || `${fp || "bundle"}:${input.deployedAt}`;
  const entry: HuntOutcome = {
    id,
    source: input.source,
    title: String(input.title ?? "").trim().slice(0, MAX_TITLE_LEN),
    vqlFingerprint: fp,
    vqlPreview: input.vql ? normalizeVql(input.vql).slice(0, MAX_VQL_PREVIEW_LEN) : "",
    mitreTechniques: dedupeStrings((input.mitreTechniques ?? []).map((t) => String(t).trim()).filter(Boolean)).slice(0, 20),
    ...(huntId ? { huntId } : {}),
    ...(input.relatedHypothesisId ? { relatedHypothesisId: String(input.relatedHypothesisId).trim() } : {}),
    deployedAt: input.deployedAt,
    status: "deployed",
  };
  const rest = outcomes.filter((o) => o.id !== id);
  return [entry, ...rest].slice(0, capMax(max));
}

// The collection result for a deployed hunt — what the server computes after reading + importing the
// hunt's rows. `resultRows` is the TOTAL rows the hunt returned (what the analyst sees in the table);
// `addedEvents`/`addedIocs` are what was NEW to the case after dedup (a hunt that only re-confirms
// already-known artifacts returns rows but adds 0 new events — still a hit, not a miss).
export interface HuntCollectResult {
  resultRows?: number;
  addedEvents: number;
  addedIocs: number;
  collectedAt: string;        // ISO
  runDiff?: HuntRunDiff;      // #80: this run vs the fingerprint's previous run, when one was computed
}

// Compact human summary of a collected hunt. Leads with the rows the hunt RETURNED (the count that
// matches the results table), then the delta NEW to the case so "10 results, +1 new event" reads
// clearly instead of a bare "+1 event" that looks wrong next to 10 rows.
function summarizeResult(resultRows: number, addedEvents: number, addedIocs: number): string {
  const parts: string[] = [];
  if (resultRows > 0) parts.push(`${resultRows} result${resultRows === 1 ? "" : "s"}`);
  if (addedEvents > 0) parts.push(`+${addedEvents} new event${addedEvents === 1 ? "" : "s"}`);
  if (addedIocs > 0) parts.push(`+${addedIocs} new IOC${addedIocs === 1 ? "" : "s"}`);
  if (parts.length) return parts.join(", ");
  return (resultRows > 0 || addedEvents > 0 || addedIocs > 0) ? "new evidence" : "no results";
}

// Mark the outcome(s) matching `huntId` as collected, deriving foundEvidence + the summary. counts that
// are CUMULATIVE deltas (addedEvents/addedIocs) ACCUMULATE across collects; resultRows is a SNAPSHOT
// total so it takes the MAX (a later re-collect reads ALL current rows, not an increment). NON-
// DOWNGRADING: a hit is never flipped back to a miss — fleet-hunt results trickle in, so the analyst
// re-collects to pull stragglers, and a re-collect of already-imported rows yields a 0 event-delta
// (dedup); without this that second collect would wrongly overwrite a real "hit". No-op (returns a
// copy) when huntId is blank or no entry matches. Pure.
export function fillOutcome(
  outcomes: readonly HuntOutcome[],
  huntId: string,
  result: HuntCollectResult,
): HuntOutcome[] {
  const hid = String(huntId ?? "").trim();
  if (!hid) return [...outcomes];
  const deltaEvents = Math.max(0, Math.floor(result.addedEvents || 0));
  const deltaIocs = Math.max(0, Math.floor(result.addedIocs || 0));
  const newRows = Math.max(0, Math.floor(result.resultRows || 0));
  return outcomes.map((o) => {
    if (o.huntId !== hid) return o;
    const addedEvents = (o.addedEvents || 0) + deltaEvents;   // cumulative across re-collects (re-reads dedup to 0)
    const addedIocs = (o.addedIocs || 0) + deltaIocs;
    const resultRows = Math.max(o.resultRows || 0, newRows);  // snapshot total — keep the largest seen
    const found = o.foundEvidence === true || resultRows > 0 || addedEvents > 0 || addedIocs > 0;   // returned rows = hit; a hit stays a hit
    return {
      ...o,
      status: "collected" as const,
      foundEvidence: found,
      resultRows,
      addedEvents,
      addedIocs,
      resultSummary: summarizeResult(resultRows, addedEvents, addedIocs),
      collectedAt: result.collectedAt,
      runDiff: result.runDiff ?? o.runDiff,   // keep the last-computed diff when this collect didn't recompute one
    };
  });
}

// The set of VQL fingerprints already deployed — the deterministic exclusion list for new suggestions
// (a hunt the analyst already deployed is never shown again). Bundles (no fingerprint) don't contribute.
export function deployedFingerprints(outcomes: readonly HuntOutcome[]): Set<string> {
  const out = new Set<string>();
  for (const o of outcomes ?? []) if (o.vqlFingerprint) out.add(o.vqlFingerprint);
  return out;
}

// The "PRIOR HUNTS" prompt context block fed to suggestHunts/suggestPlaybookHunts/suggestTechniqueHunts.
// Lenient/optional like the other context blocks: "" when there are no outcomes, else a block ending in
// a blank line so it concatenates cleanly ahead of the rest of the user prompt.
export function renderPriorHuntsBlock(outcomes: readonly HuntOutcome[], limit = 30): string {
  const list = (outcomes ?? []).slice(0, Math.max(0, Math.floor(limit)));
  if (!list.length) return "";
  const lines = list.map((o) => {
    const tech = o.mitreTechniques?.length ? `  (${o.mitreTechniques.join(", ")})` : "";
    const result =
      o.status === "collected"
        ? o.resultSummary || (o.foundEvidence ? "new evidence" : "no new evidence")
        : "results not yet collected";
    return `- [${o.status}] "${o.title}" — ${result}${tech}`;
  });
  return (
    `PRIOR HUNTS (already run in this case — do NOT re-propose a hunt that ran and found nothing; ` +
    `propose follow-ups that pivot on what a productive hunt surfaced):\n${lines.join("\n")}\n\n`
  );
}

// The per-case hunting profile for the dashboard: headline tallies + the raw outcomes (newest first).
export interface HuntingProfile {
  total: number;
  hit: number;        // collected AND found new evidence
  missed: number;     // collected AND found nothing
  pending: number;    // deployed but not yet collected
  hunts: HuntOutcome[];
  pivotProductivity: PivotProductivity[];   // #72: aggregate hit-rate by pivot class
}

export function buildHuntingProfile(outcomes: readonly HuntOutcome[]): HuntingProfile {
  const hunts = [...(outcomes ?? [])];
  let hit = 0;
  let missed = 0;
  let pending = 0;
  for (const o of hunts) {
    if (o.status !== "collected") pending++;
    else if (o.foundEvidence) hit++;
    else missed++;
  }
  return { total: hunts.length, hit, missed, pending, hunts, pivotProductivity: buildPivotProductivity(hunts) };
}

// Aggregate productivity by PIVOT CLASS (issue #72). Per-hunt outcomes already feed the "PRIOR HUNTS"
// prompt block above, but that's a flat per-hunt list — it doesn't tell the model which KIND of pivot
// (a hash, a process name, a filesystem path, a network indicator, a registry key) has actually been
// paying off in this case, so a run of unproductive process-name hunts keeps getting repeated in a
// different shape. This classifies each outcome's pivot class from its VQL (the plugin/field names are
// a reliable tell — `glob`/`path` for filesystem, `pslist`/`CommandLine` for process, `hash`/`md5` for
// hashes, `netstat`/`dns`/`domain` for network, `registry`/`hklm` for the registry) and tallies hit/
// miss/pending per class so the model can bias toward classes that have found evidence.
export type PivotType = "hash" | "process" | "path" | "network" | "registry" | "other";

const PIVOT_TYPE_PATTERNS: ReadonlyArray<{ type: PivotType; re: RegExp }> = [
  { type: "hash", re: /\b(md5|sha1|sha256|sha-1|sha-256|hash)\b/i },
  { type: "registry", re: /\b(registry|reg_key|hkcu|hklm|hkey_)/i },
  { type: "network", re: /\b(netstat|connections?|dns|domain|url|http|network)\b/i },
  { type: "process", re: /\b(pslist|process|commandline|parentname|proc(ess)?tree)\b/i },
  { type: "path", re: /\b(glob|filename|filepath|path)\b/i },
];

// Classify one outcome's pivot class from its VQL preview (falls back to the title — bundles carry no
// VQL). Pure, order-sensitive (first pattern to match wins — hash/registry/network are checked before
// the broader process/path patterns since e.g. a hash lookup often also globs a directory).
export function classifyPivotType(outcome: HuntOutcome): PivotType {
  const text = `${outcome.vqlPreview || ""} ${outcome.title || ""}`;
  for (const { type, re } of PIVOT_TYPE_PATTERNS) if (re.test(text)) return type;
  return "other";
}

export interface PivotProductivity {
  type: PivotType;
  total: number;
  hit: number;
  missed: number;
  pending: number;
}

// Tally hit/missed/pending per pivot class, sorted MOST-productive first (highest hit-rate among
// collected outcomes, ties broken by volume). Classes with no collected outcomes yet (rate undefined)
// sort last, ahead of nothing. Only classes with at least one outcome are returned. Pure.
export function buildPivotProductivity(outcomes: readonly HuntOutcome[]): PivotProductivity[] {
  const order: PivotType[] = ["hash", "process", "path", "network", "registry", "other"];
  const tally = new Map<PivotType, PivotProductivity>(order.map((type) => [type, { type, total: 0, hit: 0, missed: 0, pending: 0 }]));
  for (const o of outcomes ?? []) {
    const entry = tally.get(classifyPivotType(o))!;
    entry.total++;
    if (o.status !== "collected") entry.pending++;
    else if (o.foundEvidence) entry.hit++;
    else entry.missed++;
  }
  return order
    .map((type) => tally.get(type)!)
    .filter((p) => p.total > 0)
    .sort((a, b) => {
      const rateA = a.hit + a.missed > 0 ? a.hit / (a.hit + a.missed) : -1;
      const rateB = b.hit + b.missed > 0 ? b.hit / (b.hit + b.missed) : -1;
      return rateB - rateA || b.total - a.total;
    });
}

// The "HUNT PRODUCTIVITY" prompt block fed alongside `renderPriorHuntsBlock` to the hunt-suggestion
// prompts — the aggregate signal that lets the model bias toward pivot classes that have historically
// found evidence in THIS case, not just avoid re-running an exact prior query. "" when there isn't
// enough collected history yet (nothing to bias on) so the prompt stays lean on a fresh case.
export function renderHuntProductivityBlock(outcomes: readonly HuntOutcome[]): string {
  const stats = buildPivotProductivity(outcomes).filter((p) => p.hit + p.missed > 0);
  if (!stats.length) return "";
  const lines = stats.map((p) => {
    const collected = p.hit + p.missed;
    const rate = Math.round((p.hit / collected) * 100);
    const pendingNote = p.pending ? `, ${p.pending} pending` : "";
    return `- ${p.type}: ${p.hit}/${collected} hunts found evidence (${rate}%)${pendingNote}`;
  });
  return (
    `HUNT PRODUCTIVITY BY PIVOT CLASS (this case's history — favor pivot classes below with a high hit ` +
    `rate; deprioritize classes that keep coming back empty unless a new lead specifically calls for them):\n` +
    `${lines.join("\n")}\n\n`
  );
}
