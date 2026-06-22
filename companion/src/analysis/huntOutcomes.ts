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
  foundEvidence?: boolean;    // collected: did it add any new events or IOCs
  addedEvents?: number;       // collected
  addedIocs?: number;         // collected
  resultSummary?: string;     // collected: compact, e.g. "+12 events, +3 IOCs" / "no new evidence"
  collectedAt?: string;       // collected: ISO
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
    deployedAt: input.deployedAt,
    status: "deployed",
  };
  const rest = outcomes.filter((o) => o.id !== id);
  return [entry, ...rest].slice(0, capMax(max));
}

// The collection result for a deployed hunt — the import delta the server already computes.
export interface HuntCollectResult {
  addedEvents: number;
  addedIocs: number;
  collectedAt: string;        // ISO
}

// Compact human summary of a collected hunt's delta.
function summarizeResult(found: boolean, addedEvents: number, addedIocs: number): string {
  if (!found) return "no new evidence";
  const parts: string[] = [];
  if (addedEvents > 0) parts.push(`+${addedEvents} event${addedEvents === 1 ? "" : "s"}`);
  if (addedIocs > 0) parts.push(`+${addedIocs} IOC${addedIocs === 1 ? "" : "s"}`);
  return parts.length ? parts.join(", ") : "new evidence";
}

// Mark the outcome(s) matching `huntId` as collected, deriving foundEvidence + the summary from the
// import delta. CUMULATIVE + NON-DOWNGRADING: counts ACCUMULATE across collects and a hit is never
// flipped back to a miss. This matters because fleet-hunt results trickle in — the analyst re-collects
// to pull stragglers, and a re-collect of already-imported rows yields a 0 delta (dedup); without this,
// that second collect would wrongly overwrite a real "hit" with "no new evidence". No-op (returns a
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
  return outcomes.map((o) => {
    if (o.huntId !== hid) return o;
    const addedEvents = (o.addedEvents || 0) + deltaEvents;   // cumulative across re-collects (re-reads dedup to 0)
    const addedIocs = (o.addedIocs || 0) + deltaIocs;
    const found = o.foundEvidence === true || addedEvents > 0 || addedIocs > 0;   // a hit stays a hit
    return {
      ...o,
      status: "collected" as const,
      foundEvidence: found,
      addedEvents,
      addedIocs,
      resultSummary: summarizeResult(found, addedEvents, addedIocs),
      collectedAt: result.collectedAt,
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
  return { total: hunts.length, hit, missed, pending, hunts };
}
