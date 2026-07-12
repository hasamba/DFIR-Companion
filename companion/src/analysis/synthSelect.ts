import type { ForensicEvent, InvestigationState, Severity } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";
import { buildAttackPhases } from "./burstDetect.js";
import { buildAssetGraph } from "./assetGraph.js";
import { extractCveIds, matchKevEntries, buildKevDigest, type KevCatalog } from "./kev.js";
import { rankConnectiveIocs, buildConnectiveIocDigest, shortHost, isKnownHostAsset, classifyVerdict, iocHasBehavioralEvent } from "./iocAnchors.js";
import { rankHosts, buildSignalConcentrationDigest } from "./hostRanking.js";

const SEV_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

// How many of the earliest events to always keep (initial-access context).
const EARLIEST_KEEP = 15;

// The window around a Critical/High "anchor" within which same-host events are pulled in as CONTEXT —
// the low-graded "what happened right before/after on this host" chain that carries the real story
// (fairhaven's sqlcmd→tar→curl-PUT, halcyon's robocopy/7z) but never won a seat under even-spread.
const ANCHOR_WINDOW_MS = 15 * 60 * 1000;
const PER_ANCHOR_CONTEXT_CAP = 6;

// Reserved fractions of the post-guaranteed budget for each behavioral class, so a burst of mis-graded
// High noise can't starve the corroborated/technique-tagged evidence. Filled in order, each capped, so
// an over-supplied earlier class can't consume a later class's share; unused capacity rolls to spread.
const BUDGET_ANCHOR_CONTEXT = 0.40;
const BUDGET_CORROBORATED = 0.25;
const BUDGET_TECHNIQUE = 0.15;

// Why an event earned a synthesis seat. "anchor" = Critical/High verdict; "earliest" = initial-access
// context; the rest are the behavioral fills. Exposed (via the annotated selection) so the dashboard
// can show the analyst what CLASSES of evidence the model actually saw.
export type SelectionClass =
  | "anchor"
  | "earliest"
  | "anchor_context"
  | "corroborated"
  | "technique"
  | "spread";

export interface AnnotatedSelection {
  events: ForensicEvent[];                       // chosen events, CHRONOLOGICAL (the model reads a story)
  classOf: Map<string, SelectionClass>;          // event id → the class that claimed it (strongest wins)
  counts: Record<SelectionClass, number>;        // per-class tally of the final selection
  omitted: number;                               // scoped events NOT selected (still in the case)
}

function emptyCounts(): Record<SelectionClass, number> {
  return { anchor: 0, earliest: 0, anchor_context: 0, corroborated: 0, technique: 0, spread: 0 };
}

function eventMs(e: ForensicEvent): number | null {
  const t = Date.parse(e.timestamp);
  return Number.isNaN(t) ? null : t;
}

function sameAsset(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return false;
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

// Process/command-line-bearing events are the highest-value context around an anchor (they show what
// ran), so they're preferred when an anchor has more nearby events than the per-anchor cap.
function isProcessLike(e: ForensicEvent): boolean {
  if (e.processName || e.parentName || e.action === "execute") return true;
  return /\b(cmd|powershell|pwsh|bash|sh|wscript|cscript|rundll32|regsvr32|mshta|\.exe|\.ps1|\.dll|-enc|-e[nc]{0,2} |http)\b/i.test(e.description ?? "");
}

// The same-host events within ±ANCHOR_WINDOW of each anchor, best-first per anchor (process-like, then
// nearest in time), interleaved ROUND-ROBIN across anchors so a single busy anchor can't hog the whole
// context budget. Already-claimed events (anchors, earliest) are skipped by the caller's fill guard.
function anchorContextCandidates(
  byTime: ForensicEvent[],
  anchors: ForensicEvent[],
  claimed: ReadonlySet<string>,
): ForensicEvent[] {
  const perAnchor: ForensicEvent[][] = [];
  for (const a of anchors) {
    const am = eventMs(a);
    if (am === null || !a.asset) continue;
    const near = byTime.filter((e) => {
      if (e.id === a.id || claimed.has(e.id)) return false;
      if (!sameAsset(e.asset, a.asset)) return false;
      const em = eventMs(e);
      return em !== null && Math.abs(em - am) <= ANCHOR_WINDOW_MS;
    });
    near.sort((x, y) => {
      const px = isProcessLike(x) ? 0 : 1;
      const py = isProcessLike(y) ? 0 : 1;
      if (px !== py) return px - py;
      return Math.abs((eventMs(x) as number) - am) - Math.abs((eventMs(y) as number) - am);
    });
    if (near.length) perAnchor.push(near.slice(0, PER_ANCHOR_CONTEXT_CAP));
  }
  // Round-robin flatten, de-duped (a context event near two anchors appears once).
  const out: ForensicEvent[] = [];
  const seen = new Set<string>();
  for (let i = 0; ; i++) {
    let progressed = false;
    for (const list of perAnchor) {
      if (i < list.length) {
        progressed = true;
        const e = list[i];
        if (!seen.has(e.id)) { seen.add(e.id); out.push(e); }
      }
    }
    if (!progressed) break;
  }
  return out;
}

// Pick the events that best inform synthesis when the timeline exceeds the prompt budget. Severity-only
// / even-spread selection buried the kill chain: the true attack steps often graded Low/Info while
// mis-graded noise filled the cap. This keeps the GUARANTEED classes (all Critical/High anchors + the
// earliest initial-access events) and then fills with reserved per-class budgets — same-host context
// around each anchor, cross-source-corroborated events, and ATT&CK-technique-tagged events — before an
// even/whole-burst spread. Returns CHRONOLOGICAL order so the model reads the attack as a story.
export function selectSynthesisEventsAnnotated(events: ForensicEvent[], max: number): AnnotatedSelection {
  const byTime = [...events].sort(byEventTime);
  if (events.length <= max || max <= 0) {
    return { events: byTime, classOf: new Map(), counts: emptyCounts(), omitted: 0 };
  }

  const classOf = new Map<string, SelectionClass>();
  const claim = (id: string, c: SelectionClass): void => { if (!classOf.has(id)) classOf.set(id, c); };
  const capacityLeft = (): number => max - classOf.size;

  // GUARANTEED 1: anchors — every Critical/High event (the verdict-bearing rows).
  for (const e of events) if (e.severity === "Critical" || e.severity === "High") claim(e.id, "anchor");

  // Overflow: anchors alone exceed the budget → keep the severest, then earliest, chronological.
  if (classOf.size > max) {
    const anchorEvents = byTime.filter((e) => classOf.get(e.id) === "anchor");
    const trimmed = [...anchorEvents]
      .sort((a, b) => (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || byEventTime(a, b))
      .slice(0, max)
      .sort(byEventTime);
    const counts = emptyCounts();
    counts.anchor = trimmed.length;
    return { events: trimmed, classOf: new Map(trimmed.map((e) => [e.id, "anchor" as const])), counts, omitted: events.length - trimmed.length };
  }

  // GUARANTEED 2: earliest events — initial-access context (guarded against the cap).
  for (const e of byTime.slice(0, EARLIEST_KEEP)) {
    if (capacityLeft() <= 0) break;
    claim(e.id, "earliest");
  }

  const remaining = Math.max(0, max - classOf.size);
  const fill = (candidates: ForensicEvent[], cap: number, cls: SelectionClass): void => {
    let added = 0;
    for (const e of candidates) {
      if (added >= cap || capacityLeft() <= 0) break;
      if (classOf.has(e.id)) continue;
      classOf.set(e.id, cls);
      added++;
    }
  };

  // RESERVED FILL 1: same-host context around each anchor.
  const anchors = events.filter((e) => classOf.get(e.id) === "anchor");
  fill(anchorContextCandidates(byTime, anchors, new Set(classOf.keys())), Math.floor(remaining * BUDGET_ANCHOR_CONTEXT), "anchor_context");

  // RESERVED FILL 2: cross-source-corroborated events (correlate.ts already merged their sources).
  fill(byTime.filter((e) => !classOf.has(e.id) && (e.sources?.length ?? 0) >= 2), Math.floor(remaining * BUDGET_CORROBORATED), "corroborated");

  // RESERVED FILL 3: ATT&CK-technique-tagged events regardless of severity (behavioral signal).
  fill(byTime.filter((e) => !classOf.has(e.id) && (e.mitreTechniques?.length ?? 0) > 0), Math.floor(remaining * BUDGET_TECHNIQUE), "technique");

  // SPREAD remainder: keep whole activity bursts (burstDetect phases) rather than shredding clusters
  // with an even sample; whatever budget is left after whole bursts is filled by an even time-spread.
  if (capacityLeft() > 0) {
    const byId = new Map(byTime.map((e) => [e.id, e] as const));
    const phases = buildAttackPhases(events);
    const phaseRank = (p: { maxSeverity: Severity }): number => SEV_RANK[p.maxSeverity] ?? 9;
    for (const p of [...phases].sort((a, b) => phaseRank(a) - phaseRank(b))) {
      const pending = p.eventIds.map((id) => byId.get(id)).filter((e): e is ForensicEvent => !!e && !classOf.has(e.id));
      if (!pending.length) continue;
      if (pending.length <= capacityLeft()) {                    // keep the whole burst, or skip it whole
        for (const e of pending) classOf.set(e.id, "spread");
      }
      if (capacityLeft() <= 0) break;
    }
  }
  if (capacityLeft() > 0) {                                       // residual even time-spread of what's left
    const rest = byTime.filter((e) => !classOf.has(e.id));
    const slots = capacityLeft();
    if (rest.length <= slots) {
      rest.forEach((e) => classOf.set(e.id, "spread"));
    } else {
      const step = rest.length / slots;
      for (let i = 0; i < slots; i++) classOf.set(rest[Math.min(rest.length - 1, Math.floor(i * step))].id, "spread");
    }
  }

  const selected = byTime.filter((e) => classOf.has(e.id));
  const counts = emptyCounts();
  for (const e of selected) counts[classOf.get(e.id) as SelectionClass]++;
  return { events: selected, classOf, counts, omitted: events.length - selected.length };
}

// Backwards-compatible wrapper: the chosen events in chronological order. All existing callers use this;
// the reserved-budget improvement flows through them automatically.
export function selectSynthesisEvents(events: ForensicEvent[], max: number): ForensicEvent[] {
  return selectSynthesisEventsAnnotated(events, max).events;
}

// A compact context digest for the synthesis prompt: the compromised assets (host/account
// and the IoCs seen on each), third-party threat-intel verdicts, and — when a KEV catalog is
// loaded — CVEs from the timeline/IOCs that CISA confirms are actively exploited in the wild
// (a strong initial-access signal). Returns "" when there's nothing to add, so it costs no
// tokens on a bare case.
export function buildSynthesisContext(
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
  kevCatalog?: KevCatalog,
): string {
  const graph = buildAssetGraph({ ...state, forensicTimeline: scopedEvents });
  const iocVal = new Map(graph.iocs.map((i) => [i.id, i.value] as const));
  // The case's own host assets — a verdict on one of these (shared internal infra the model would
  // otherwise trust at face value) needs a flag, not silent inclusion. See iocAnchors.ts.
  const hostNames = new Set(graph.assets.filter((a) => a.type === "host").map((a) => shortHost(a.name)));

  const assetLines = graph.assets.filter((a) => a.compromised).slice(0, 25).map((a) => {
    const iocs = a.iocIds.map((id) => iocVal.get(id) || id).slice(0, 8).join(", ");
    return `- ${a.name} (${a.type})${iocs ? ` ← ${iocs}` : ""}`;
  });

  // Threat-intel verdicts, classified by trust (investigation-guidance #7): a single stale provider
  // verdict on the case's OWN infra flowed unchecked into a Critical finding (northpeak). Each verdict
  // is tagged [corroborated] (2+ providers, or intel+behavioral evidence) vs [lone-intel] (single
  // provider — a LEAD, not a compromise), and CONFLICTED verdicts (own-host/internal address) are moved
  // to their own "do not treat as confirmed" block so the model can't read them as external C2.
  const trustedVerdicts: string[] = [];
  const conflictVerdicts: string[] = [];
  for (const i of state.iocs) {
    const hit = (i.enrichments ?? []).find((x) => x.verdict === "malicious")
      ?? (i.enrichments ?? []).find((x) => x.verdict === "suspicious");
    if (!hit) continue;
    const cls = classifyVerdict(i, { hasBehavioralEvent: iocHasBehavioralEvent(i.value, scopedEvents), hostNames });
    if (cls === "none") continue;
    const base = `${i.value} = ${hit.verdict}${hit.source ? ` (${hit.source}${hit.score ? ` ${hit.score}` : ""})` : ""}`;
    if (cls === "conflicted") {
      conflictVerdicts.push(`- ${base} ⚠ CONFLICT: also one of this case's OWN host assets or an internal address — this verdict is most likely stale/wrong; do NOT treat it as confirmed malicious or as external C2`);
    } else {
      trustedVerdicts.push(`- ${base} [${cls}]`);
    }
    if (trustedVerdicts.length + conflictVerdicts.length >= 25) break;
  }

  // KEV correlation: scan the scoped events + IOC values for CVE ids and cross-reference
  // against the loaded catalog. Only fires when a catalog is provided (opt-in, store starts
  // empty) so it never costs tokens on unconfigured deployments.
  let kevBlock = "";
  if (kevCatalog && kevCatalog.size > 0) {
    const cveIds = new Set<string>();
    for (const e of scopedEvents) extractCveIds(e.description).forEach((id) => cveIds.add(id));
    for (const ioc of state.iocs) extractCveIds(ioc.value).forEach((id) => cveIds.add(id));
    const kevMatches = matchKevEntries([...cveIds], kevCatalog);
    kevBlock = buildKevDigest(kevMatches);
  }

  // Connective indicators (#200): rank IOCs by cross-host / multi-tool reach so the model anchors
  // on the attack's backbone (a C2 seen on multiple hosts by multiple tools) instead of the flat
  // list. Leads the digest — it's the highest-signal context.
  const connectiveBlock = buildConnectiveIocDigest(rankConnectiveIocs(state, scopedEvents));

  // Signal concentration (#202): tell the model which host(s) carry the suspicious activity so an
  // automatic run over a noisy multi-host timeline doesn't anchor its narrative on a benign host.
  const concentrationBlock = buildSignalConcentrationDigest(rankHosts({ ...state, forensicTimeline: scopedEvents }));

  let block = "";
  if (concentrationBlock) block += concentrationBlock;
  if (connectiveBlock) block += connectiveBlock;
  if (assetLines.length) block += `COMPROMISED ASSETS (host/account ← IoCs seen on it):\n${assetLines.join("\n")}\n\n`;
  if (trustedVerdicts.length) block += `THREAT-INTEL VERDICTS (third-party — [corroborated] = 2+ providers or intel PLUS behavioral evidence; [lone-intel] = a single provider with no corroborating activity, treat as a LEAD, not a confirmed compromise):\n${trustedVerdicts.join("\n")}\n\n`;
  if (conflictVerdicts.length) block += `INTEL CONFLICTS (do NOT treat as confirmed — a verdict on the case's OWN infrastructure or an internal address, most likely stale/incorrect third-party data):\n${conflictVerdicts.join("\n")}\n\n`;
  if (kevBlock) block += kevBlock;
  return block;
}
