import type { ForensicEvent, InvestigationState, LabIntelRecord } from "./stateTypes.js";

// Sandbox detonations as intelligence about a SAMPLE, attached to the incident events that carry
// its hash (#932 item 5). Read the EvidenceOrigin comment in stateTypes.ts for why lab rows are kept
// out of the forensic timeline altogether; this module is the other half — how the model still
// learns what the sample does, at the place and time the sample was actually observed.
//
// Everything here is derived data. The registry (InvestigationState.labIntel) is written once per
// import; `event.labIntel` is cleared and recomputed from it on every merge, so nothing here is ever
// a claim of its own that could go stale or be copied onto the wrong row.

// The source labels the sandbox importer stamps and the exact description prefixes it emits. Owned
// HERE, in the timeline tier, and imported by the importer — so the classifier below and the
// emitter can never drift apart, and the boundary checker stays happy (timeline may not import
// ingest). Change a prefix here and every emitted row changes with it.
export const SANDBOX_SOURCES: ReadonlySet<string> = new Set(["CAPEv2", "Falcon Sandbox"]);
export const SANDBOX_PREFIX = {
  capeVerdict: "CAPE sandbox:",
  capeSignature: "CAPE signature:",
  falconVerdict: "Falcon Sandbox:",
  falconSignature: "Falcon signature:",
} as const;
export const SANDBOX_DESCRIPTION_PREFIXES: readonly string[] = Object.values(SANDBOX_PREFIX);

const SHA256 = /^[0-9a-f]{64}$/;

// The only sha256 that may act as a join key. Trimmed, lowercased, exactly 64 hex — anything else
// (an md5, a truncated digest, a placeholder token) is "" and matches nothing. A field NAMED sha256
// is not an identity until its value is one.
export function normalizeSha256(raw: unknown): string {
  const v = String(raw ?? "")
    .trim()
    .toLowerCase();
  return SHA256.test(v) ? v : "";
}

// Report-derived text that ends up inside a prompt tag. Every other structured tag clips its value;
// this one must ALSO strip the tag delimiters and control characters, because a family or signature
// name is attacker-influenced input (the sample chose its own strings and the sandbox echoed them)
// and a "<" or a newline inside a tag can forge a second tag or instruction-like text. Applied at
// ingestion, so the stored record is already safe and small, and again at render as belt and braces.
const MAX_FAMILY = 48;
const MAX_SIGNATURE = 32;
const MAX_SIGNATURES = 5;
const MAX_TAG = 240;
export function cleanTagText(raw: unknown, max: number): string {
  const s = String(raw ?? "")
    .replace(/[<>\x00-\x1f\x7f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

// `source` and `runId` are IDENTITY (half the registry key) and are only trimmed — sanitising them
// here would fold "run<1" and "run>1" into one key and silently drop a detonation. They are cleaned
// at render, where they are display text. Family and signatures are display text only, so they are
// cleaned once here and the stored record is already safe and small.
function cleanRecord(raw: LabIntelRecord, sha256: string): LabIntelRecord {
  return {
    ...raw,
    sha256,
    source: String(raw.source ?? "").trim(),
    runId: String(raw.runId ?? "").trim(),
    family: cleanTagText(raw.family, MAX_FAMILY),
    signatures: raw.signatures
      .map((x) => cleanTagText(x, MAX_SIGNATURE))
      .filter(Boolean)
      .slice(0, MAX_SIGNATURES),
  };
}

const keyOf = (r: LabIntelRecord): string => `${r.sha256}|${r.source}|${r.runId}`;

// Union by (sha256, source, runId); a later record for the same key replaces the earlier one. Output
// order is deterministic (by key) so two imports in either order produce the same registry. A record
// whose sha256 does not normalise is dropped: with no identity there is nothing to attach it to.
export function upsertLabIntel(
  current: readonly LabIntelRecord[] | undefined,
  incoming: readonly LabIntelRecord[],
): LabIntelRecord[] {
  const byKey = new Map<string, LabIntelRecord>();
  for (const r of current ?? []) byKey.set(keyOf(r), r);
  for (const raw of incoming) {
    const sha256 = normalizeSha256(raw.sha256);
    if (!sha256) continue;
    const r = cleanRecord(raw, sha256);
    byKey.set(keyOf(r), r);
  }
  return [...byKey.values()].sort((a, b) => keyOf(a).localeCompare(keyOf(b)));
}

const VERDICT_RANK: Record<LabIntelRecord["verdict"], number> = { malicious: 0, suspicious: 1, unknown: 2 };
const DISPLAY_CAP = 3;

// Which detonations to show for one sample when there are many. Newest first, because the latest
// run is the current assessment; worst verdict first on a time tie, so a benign rerun never hides a
// malicious one; capped, with the overflow counted so the tag can say "+N more" rather than silently
// omit. NOT sorted by runId — "sb10" sorts before "sb2" lexically and means nothing temporally.
export function selectLabIntelForDisplay(records: readonly LabIntelRecord[]): {
  shown: LabIntelRecord[];
  omitted: number;
} {
  const sorted = [...records].sort(
    (a, b) =>
      epoch(b.detonatedAt) - epoch(a.detonatedAt) ||
      VERDICT_RANK[a.verdict] - VERDICT_RANK[b.verdict] ||
      keyOf(a).localeCompare(keyOf(b)),
  );
  return { shown: sorted.slice(0, DISPLAY_CAP), omitted: Math.max(0, sorted.length - DISPLAY_CAP) };
}

function epoch(iso: string): number {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : 0;
}

// Attach each sample's detonations to the incident events that carry its hash. Pure. Lab rows are
// never annotated (a sandbox row annotating itself would be circular), a stale annotation whose
// record is gone is cleared, and an event with no match is returned as the SAME object so a merge
// with no registry costs nothing.
export function annotateSightingsWithLabIntel(state: InvestigationState): InvestigationState {
  const registry = state.labIntel ?? [];
  const hasStale = state.forensicTimeline.some((e) => e.labIntel !== undefined);
  if (registry.length === 0 && !hasStale) return state;
  const bySha = new Map<string, LabIntelRecord[]>();
  for (const r of registry) (bySha.get(r.sha256) ?? bySha.set(r.sha256, []).get(r.sha256)!).push(r);
  let changed = false;
  const forensicTimeline = state.forensicTimeline.map((e) => {
    const matches = isLabProduced(e) ? undefined : bySha.get(normalizeSha256(e.sha256));
    if (!matches?.length) {
      if (e.labIntel === undefined) return e;
      changed = true;
      const { labIntel: _dropped, ...rest } = e;
      return rest;
    }
    changed = true;
    return { ...e, labIntel: matches };
  });
  return changed ? { ...state, forensicTimeline } : state;
}

// The compact tag the model reads beside <host:…> and <proc:…>. One entry per shown detonation:
// source, verdict, family, the sandbox's own score, and up to two signature names — enough to say
// "this sample is Emotet and injects" without pasting a report. Empty when there is nothing.
export function labIntelTag(records: readonly LabIntelRecord[] | undefined): string {
  if (!records?.length) return "";
  const { shown, omitted } = selectLabIntelForDisplay(records);
  const parts = shown.map((r) => {
    const sigs = r.signatures
      .slice(0, 2)
      .map((x) => cleanTagText(x, MAX_SIGNATURE))
      .join(",");
    return [cleanTagText(r.source, 24), r.verdict, cleanTagText(r.family, MAX_FAMILY), String(r.score), sigs]
      .filter(Boolean)
      .join(" ");
  });
  const body = `${parts.join("; ")}${omitted ? ` +${omitted} more` : ""}`;
  return ` <sandbox:${body.length > MAX_TAG ? body.slice(0, MAX_TAG - 1) + "…" : body}>`;
}

// Is this row sandbox-produced? The importer now says so with `origin`. Rows persisted before that
// field existed are recognised only when BOTH hold: every source is a sandbox provider, and the
// description opens with one of the importer's own prefixes. A row whose sources also name a host
// tool has already been merged with a host observation — that is contaminated evidence, and
// demoting it would hide the real event, so it is deliberately NOT reclassified here.
export function isLabProduced(e: Pick<ForensicEvent, "origin" | "sources" | "description">): boolean {
  if (e.origin === "lab") return true;
  const sources = (e.sources ?? []).filter((s) => s && s !== "unknown source");
  if (sources.length === 0 || !sources.every((s) => SANDBOX_SOURCES.has(s))) return false;
  return SANDBOX_DESCRIPTION_PREFIXES.some((p) => e.description.startsWith(p));
}
