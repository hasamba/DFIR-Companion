// Detection-burst grouping for the SYNTHESIS PROMPT ONLY (spec 2026-07-21). The typical import is
// Velociraptor output from artifacts that already carry a verdict — Hayabusa, DetectRaptor, YARA — so
// the forensic timeline is mostly graded detections, and the same Sigma rule fires hundreds of times.
// Each occurrence used to consume one of the 300 prompt seats, so the model read the same sentence
// hundreds of times while genuinely distinct detections never reached it.
//
// This collapses occurrences of the SAME activity pattern at the SAME severity, within `gapSeconds` of
// each other, into ONE representative row carrying the count, the host spread and the time span. It is
// derived on read and PURE: no case state is touched, nothing is persisted, and the representative is
// a copy — the analyst's timeline, event ids, severities and findings are unaffected.
//
// Deliberate boundaries:
//   * Groups never span severities, so "every Critical/High is an anchor" stays exact.
//   * Grouping crosses hosts on purpose — one rule firing on six hosts IS the lateral-movement signal,
//     and it stays explicit on the rendered line instead of being flattened away.
//   * Undated events have no position on the time axis, so they are never grouped.
//   * The gap default is 1 hour, NOT burstDetect's DEFAULT_GAP_SECONDS (300). Five minutes is right for
//     detecting attack phases across a whole timeline, but here it would shatter a rule firing every
//     ten minutes into six entries.
//
// KNOWN LIMITATION: the pattern fingerprint comes from prevalence.ts's patternKey, which normalizes
// bare numbers to <n> so "robocopy C:\data\1" and "…\2" collapse to one shape. Two DIFFERENT detections
// whose descriptions differ ONLY by a number therefore merge into a single group. Real Sigma/YARA rule
// titles carry words, so this does not bite in practice, and using the same fingerprint everywhere keeps
// grouping consistent with the prevalence/rarity baseline. See the matching test in synthGroup.test.ts.

import type { ForensicEvent, Severity } from "./stateTypes.js";
import { patternKey, commandShape } from "./prevalence.js";
import { byEventTime } from "./forensicSort.js";

export const DEFAULT_GROUP_GAP_SECONDS = 3600;   // 1 hour between occurrences starts a new burst
export const DEFAULT_GROUP_MIN_REPEATS = 4;      // below this, collapsing costs detail and saves nothing
export const DEFAULT_MAX_HOSTS_NAMED = 4;        // how many host names the rendered line spells out

export interface DetectionGroup {
  key: string;                    // "<severity>|<patternKey>" — the bucket this burst came from
  representative: ForensicEvent;  // the EARLIEST member; its id anchors the prompt row
  memberIds: string[];            // every event this group represents (incl. the representative)
  count: number;                  // memberIds.length
  hosts: string[];                // distinct assets, first-seen order
  first: string;                  // earliest member timestamp (ISO)
  last: string;                   // latest member timestamp (ISO)
  severity: Severity;             // shared by every member (groups never span severities)
}

export interface GroupOptions {
  gapSeconds?: number;
  minRepeats?: number;
}

export interface CollapsedPrompt {
  events: ForensicEvent[];                             // representatives + ungrouped events, input order
  groupById: Map<string, DetectionGroup>;              // representative event id → its group
  memberIdsByRepresentative: Map<string, string[]>;    // representative event id → every id it covers
}

// Minimum length for an extracted rule header to be trusted (guards against a stray "[x] y: z").
const DETECTION_MIN_HEAD = 10;

/**
 * Extract the RULE IDENTITY from a detection-style description, or null when the description is not in
 * that format. Detection importers render:
 *
 *     "<Tool> [<Artifact>] <Detector>: <RuleName> - <per-event detail>"
 *
 * e.g. "Velociraptor [Windows.Detection.Sigma] Sigma: Encoded PowerShell - Computer: ws-01 User: alice".
 * The head identifies WHICH rule fired; the tail is per-event detail (host, user, path) that differs on
 * every hit. Fingerprinting the whole description therefore shatters one rule into one pattern per host —
 * measured on a real Velociraptor+Sigma case, 1,089 events produced 367 patterns instead of ~116.
 *
 * This is deliberately a HEURISTIC with a strict fallback: a description that does not carry both an
 * "[Artifact]" bracket and a "<Detector>: " separator returns null and keeps the existing fingerprint.
 * The failure mode is therefore "grouped less", never "grouped wrongly" — important because this couples
 * to an importer's rendering format, the same fragility that makes the login graph break silently when
 * mapWindows changes its description layout.
 */
export function detectionRuleHead(description: string | undefined): string | null {
  const desc = String(description ?? "");
  if (!/\[[^\]]+\]/.test(desc)) return null;   // needs the "[Artifact]" bracket
  if (!desc.includes(": ")) return null;        // needs the "<Detector>: <RuleName>" separator
  const cut = desc.indexOf(" - ");
  const head = (cut > 0 ? desc.slice(0, cut) : desc).trim();
  return head.length >= DETECTION_MIN_HEAD ? head : null;
}

// The bucket key for one event. Mirrors prevalence.patternKey's hierarchy but inserts rule identity
// between the content hash and the generic description shape: a file hash is still the strongest
// identity (two distinct malware samples matched by one YARA rule must NOT merge into a single row),
// and anything that is not a detection falls through to the shared fingerprint unchanged.
function groupPatternKey(e: ForensicEvent): string {
  const hash = (e.sha256 ?? e.md5 ?? "").trim().toLowerCase();
  if (hash) return `hash:${hash}`;
  const head = detectionRuleHead(e.description);
  if (head) return `rule:${commandShape(head)}`;
  return patternKey(e);
}

function eventMs(e: ForensicEvent): number {
  return Date.parse(e.timestamp);
}

function isDated(e: ForensicEvent): boolean {
  return !Number.isNaN(eventMs(e));
}

function toGroup(key: string, run: readonly ForensicEvent[]): DetectionGroup {
  const first = run[0];
  const last = run[run.length - 1];
  const hosts: string[] = [];
  const seen = new Set<string>();
  for (const e of run) {
    const asset = (e.asset ?? "").trim();
    if (!asset || seen.has(asset.toLowerCase())) continue;
    seen.add(asset.toLowerCase());
    hosts.push(asset);
  }
  return {
    key,
    representative: first,
    memberIds: run.map((e) => e.id),
    count: run.length,
    hosts,
    first: first.timestamp,
    last: last.timestamp,
    severity: first.severity,
  };
}

/**
 * Group repeated detections into bursts. Buckets by (severity, activity pattern), sorts each bucket
 * chronologically, and starts a new burst whenever consecutive occurrences are more than `gapSeconds`
 * apart. Bursts shorter than `minRepeats` are not emitted — their events stay individual rows.
 * Pure and deterministic; the input array is never mutated.
 */
export function groupDetections(
  events: readonly ForensicEvent[],
  opts: GroupOptions = {},
): DetectionGroup[] {
  const gapMs = Math.max(0, (opts.gapSeconds ?? DEFAULT_GROUP_GAP_SECONDS) * 1000);
  const minRepeats = Math.max(2, opts.minRepeats ?? DEFAULT_GROUP_MIN_REPEATS);

  const buckets = new Map<string, ForensicEvent[]>();
  for (const e of events) {
    if (!isDated(e)) continue;                 // undated: no position on the time axis, never grouped
    const pk = groupPatternKey(e);
    if (!pk) continue;                          // no stable pattern (empty description, no hash/process)
    const key = `${e.severity}|${pk}`;
    const list = buckets.get(key);
    if (list) list.push(e);
    else buckets.set(key, [e]);
  }

  const out: DetectionGroup[] = [];
  for (const [key, list] of buckets) {
    const sorted = [...list].sort(byEventTime);
    let run: ForensicEvent[] = [];
    const flush = (): void => {
      if (run.length >= minRepeats) out.push(toGroup(key, run));
      run = [];
    };
    for (const e of sorted) {
      if (run.length && eventMs(e) - eventMs(run[run.length - 1]) > gapMs) flush();
      run.push(e);
    }
    flush();
  }
  return out.sort((a, b) => a.first.localeCompare(b.first) || a.key.localeCompare(b.key));
}

/**
 * Collapse a scoped event list into the rows that should be rendered into the prompt: one
 * representative per burst (carrying `count` + `endTimestamp`, matching the aggregation convention
 * ForensicEvent already documents) plus every event that was not grouped, in the caller's original
 * order. The representative is a COPY — source events are never mutated.
 */
export function collapseForPrompt(
  events: readonly ForensicEvent[],
  opts: GroupOptions = {},
): CollapsedPrompt {
  const groups = groupDetections(events, opts);
  const groupById = new Map<string, DetectionGroup>();
  const memberIdsByRepresentative = new Map<string, string[]>();
  const claimed = new Set<string>();
  for (const g of groups) {
    groupById.set(g.representative.id, g);
    memberIdsByRepresentative.set(g.representative.id, g.memberIds);
    for (const id of g.memberIds) claimed.add(id);
  }

  const out: ForensicEvent[] = [];
  for (const e of events) {
    const g = groupById.get(e.id);
    if (g) {
      out.push({ ...e, count: g.count, endTimestamp: g.last });
      continue;
    }
    if (claimed.has(e.id)) continue;            // a non-representative member — covered by its group
    out.push(e);
  }
  return { events: out, groupById, memberIdsByRepresentative };
}

/**
 * The suffix appended to a grouped row in the prompt, e.g.
 * " ⟨grouped: 412× identical detection on 6 hosts (dc-01, ws-14, ws-15, +3 more) between … and …⟩".
 */
export function renderGroupSuffix(g: DetectionGroup, maxHostsNamed = DEFAULT_MAX_HOSTS_NAMED): string {
  const cap = Math.max(1, maxHostsNamed);
  const named = g.hosts.slice(0, cap).join(", ");
  const more = g.hosts.length > cap ? `, +${g.hosts.length - cap} more` : "";
  const where = g.hosts.length
    ? ` on ${g.hosts.length} host${g.hosts.length === 1 ? "" : "s"} (${named}${more})`
    : "";
  const span = g.last && g.last !== g.first ? ` between ${g.first} and ${g.last}` : "";
  return ` ⟨grouped: ${g.count}× identical detection${where}${span}⟩`;
}

/** Grouping is ON unless explicitly disabled, so existing deployments get the fix without config. */
export function groupingEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return !/^(0|false|off|no)$/i.test((env.DFIR_SYNTH_GROUP ?? "").trim());
}

/** Read the tunables from the environment, falling back to the defaults on absent/invalid values. */
export function groupEnvOptions(env: NodeJS.ProcessEnv = process.env): Required<GroupOptions> {
  const gap = Number(env.DFIR_SYNTH_GROUP_GAP_SECONDS);
  const min = Number(env.DFIR_SYNTH_GROUP_MIN_REPEATS);
  return {
    gapSeconds: Number.isFinite(gap) && gap > 0 ? gap : DEFAULT_GROUP_GAP_SECONDS,
    minRepeats: Number.isFinite(min) && min >= 2 ? min : DEFAULT_GROUP_MIN_REPEATS,
  };
}
