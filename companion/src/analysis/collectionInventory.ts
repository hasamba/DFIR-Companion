import { canonicalHostName, resolveHost, type HostAliasIndex } from "./hostAlias.js";
import {
  collectedEvidenceClasses,
  DETECTION_FEED_RE,
  EVIDENCE_CLASSES,
  SNAPSHOT_SOURCE_RE,
  type EvidenceClass,
} from "./refutationGate.js";
import type { ForensicEvent } from "./stateTypes.js";
import type { VeloHuntJob } from "./veloHuntStore.js";

type HuntReachedClient = NonNullable<VeloHuntJob["reachedClients"]>[number];

/**
 * What this case actually holds, per source and per host (#1588) — built in code, never by the model.
 *
 * The synthesis used to answer "What was the impact?" with "no confirmed data encryption was
 * observed" on a ransomware simulation that encrypted files. The case held Sigma/Chainsaw hits built
 * on Sysmon, no raw Sysmon events and no file listing of the victim folder: nothing that COULD have
 * shown the encryption. A negative answer is only as good as the evidence that could have falsified
 * it, and the model cannot tell a detection feed's silence from the artifact's.
 *
 * Built from the FORENSIC timeline (in-window, BEFORE the false-positive filter — a row marked benign
 * still proves its source was collected) and from Velociraptor hunt METADATA. Never from super-
 * timeline rows or counts: the AI must not read the super-timeline (CLAUDE.md §7), and a summary of
 * it is a reading of it.
 *
 * Coverage follows refutationGate.ts: detection feeds and point-in-time snapshots are not coverage.
 * One addition: a raw EVTX row counts for the class its record type names, so raw Sysmon collected
 * through the generic Windows.EventLogs.Evtx artifact is recognised — the artifact name alone says
 * nothing about Sysmon.
 */

/** Where each class of evidence can be collected. The ONE table the prompt and the backstop share. */
export const CLASS_COLLECTION: Record<EvidenceClass, { artifact: string; logSource: string }> = {
  execution: {
    artifact: "Windows.EventLogs.Evtx",
    logSource:
      "Microsoft-Windows-Sysmon/Operational EID 1 (or Security 4688), plus Windows.Forensics.Prefetch",
  },
  "file-activity": {
    artifact: "Windows.EventLogs.Evtx",
    logSource:
      "Microsoft-Windows-Sysmon/Operational EID 11/23, or Windows.Search.FileFinder / Windows.NTFS.MFT over the affected folders",
  },
  network: {
    artifact: "Windows.EventLogs.Evtx",
    logSource: "Microsoft-Windows-Sysmon/Operational EID 3, or firewall/proxy logs for the incident window",
  },
  persistence: {
    artifact: "Windows.Sysinternals.Autoruns",
    logSource: "Autoruns, Windows.System.TaskScheduler, System 7045",
  },
};

/** The record types a raw EVTX row can vouch for. */
const CATEGORY_CLASS: Partial<Record<string, EvidenceClass>> = {
  process: "execution",
  file: "file-activity",
  network: "network",
  registry: "persistence",
  service: "persistence",
  task: "persistence",
};

const norm = (s: string): string => s.toLowerCase().replace(/[\s_-]+/g, "");

export type SourceKind = "detections" | "snapshot" | "raw";

export interface SourceLine {
  name: string;
  kind: SourceKind;
  rows: number;
}

export interface ClearedLog {
  host: string; // canonical host, "" when the row names none
  channel: string; // "Security", "System", … or "" when the row does not say which log
  at: string; // the LATEST clear on that host+channel — the effective cutoff
  count: number;
}

export type HuntArtifactState = "empty" | "truncated" | "failed" | "archive-only" | "running";

export interface HuntArtifactLine {
  artifact: string;
  state: HuntArtifactState;
  detail: string;
  /** No label filter: the hunt went to every enrolled client, so its result speaks for every host. */
  fleetWide: boolean;
  /**
   * An empty result limited by a time window or a result filter (#1604): "nothing in the window" or
   * "nothing matched", not "the artifact holds nothing". It can qualify an answer, never settle one.
   */
  bounded: boolean;
  /**
   * The hosts (canonical, lowercase) an unbounded empty speaks for: those whose hunt flow finished
   * without error and that run this artifact's OS (#1625). [] on every other line.
   */
  reached: string[];
}

export interface CollectionInventory {
  /** Evidence classes collected raw, per canonical host. */
  byHost: Map<string, Set<EvidenceClass>>;
  /** Hosts with any in-window activity, canonical, sorted. */
  hosts: string[];
  sources: SourceLine[];
  cleared: ClearedLog[];
  hunts: HuntArtifactLine[];
}

export function sourceName(e: ForensicEvent): string {
  return e.artifactName || e.sources?.[0] || "";
}

export function sourceKind(name: string): SourceKind {
  const n = norm(name);
  if (DETECTION_FEED_RE.test(n)) return "detections";
  if (SNAPSHOT_SOURCE_RE.test(n)) return "snapshot";
  return "raw";
}

/** Classes one row vouches for: the name-based rules, plus a raw EVTX row's own record type. */
function rowClasses(e: ForensicEvent): EvidenceClass[] {
  const named = [...collectedEvidenceClasses([e])];
  const isFeed = [...(e.sources ?? []), e.artifactName ?? ""].some((s) => s && sourceKind(s) !== "raw");
  if (isFeed || !e.sourceRecordId?.startsWith("evtx:")) return named;
  const byType = CATEGORY_CLASS[e.canonical?.event.category ?? ""];
  return byType && !named.includes(byType) ? [...named, byType] : named;
}

const CLEAR_TEXT_RE =
  /\b(?:security\s+audit\s+log\s+(?:was\s+)?cleared|event\s+log\s+(?:was\s+)?cleared|log\s+file\s+was\s+cleared|(?:security|system|application)\s+log\s+(?:was\s+)?cleared)\b/i;
const CHANNEL_IN_TEXT_RE =
  /\bthe\s+([A-Za-z][\w\- /]{1,60}?)\s+log\s+file\s+was\s+cleared|\bchannel\s*[:=]\s*"?([\w\- /]+)"?/i;

/**
 * A row that RECORDS a clear — the 1102/104 record, or a rule hit on it. Not any T1070.001 row:
 * Prefetch showing wevtutil.exe ran proves an execution, not which log was emptied.
 */
function clearedChannel(e: ForensicEvent): string | null {
  const text = `${e.description} ${e.message ?? ""}`;
  if (!CLEAR_TEXT_RE.test(text)) return null;
  if (/security\s+(audit\s+)?log/i.test(text)) return "Security";
  const m = CHANNEL_IN_TEXT_RE.exec(text);
  const named = (m?.[1] ?? m?.[2] ?? "").trim();
  if (named) return named.replace(/^\w/, (c) => c.toUpperCase());
  if (/\bsystem\s+log\b/i.test(text)) return "System";
  if (/\bapplication\s+log\b/i.test(text)) return "Application";
  return "";
}

function clearedLogs(events: readonly ForensicEvent[], host: (e: ForensicEvent) => string): ClearedLog[] {
  const byKey = new Map<string, ClearedLog>();
  for (const e of events) {
    const channel = clearedChannel(e);
    if (channel === null || !e.timestamp) continue;
    const h = host(e);
    const key = `${h}|${channel.toLowerCase()}`;
    const prev = byKey.get(key);
    byKey.set(key, {
      host: h,
      channel,
      at: prev && prev.at > e.timestamp ? prev.at : e.timestamp,
      count: (prev?.count ?? 0) + 1,
    });
  }
  return [...byKey.values()].sort(
    (a, b) => a.host.localeCompare(b.host) || a.channel.localeCompare(b.channel),
  );
}

const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

/**
 * velo-hunt.json is read without a schema, and hunt metadata is supplemental: a malformed job is
 * dropped, never allowed to fail the synthesis that reads it (#1588 review).
 */
export function sanitizeHuntJobs(jobs: readonly unknown[]): VeloHuntJob[] {
  const out: VeloHuntJob[] = [];
  for (const raw of jobs) {
    if (!raw || typeof raw !== "object") continue;
    const j = raw as Partial<VeloHuntJob>;
    if (typeof j.huntId !== "string" || typeof j.status !== "string") continue;
    const named = (v: unknown) =>
      (Array.isArray(v) ? v : []).filter(
        (x): x is { name: string } => !!x && typeof (x as { name?: unknown }).name === "string",
      );
    out.push({
      ...(j as VeloHuntJob),
      artifacts: strings(j.artifacts),
      emptyArtifacts: strings(j.emptyArtifacts),
      skippedArtifacts: named(j.skippedArtifacts).map((x) => ({
        name: x.name,
        error: String((x as { error?: unknown }).error ?? ""),
      })),
      truncatedArtifacts: named(j.truncatedArtifacts).map((x) => {
        const t = x as { name: string; kept?: unknown; total?: unknown };
        return { name: t.name, kept: Number(t.kept) || 0, total: Number(t.total) || 0 };
      }),
    });
  }
  return out;
}

const record = (v: unknown): Record<string, unknown> =>
  v && typeof v === "object" ? (v as Record<string, unknown>) : {};

/** The window a time-scoped hunt was launched with, as far as its (schema-less) record says. */
function windowText(ts: Record<string, unknown>): string {
  const at = (v: unknown, none: string) => (typeof v === "string" && v ? v : none);
  return `analyst window ${at(ts.start, "?")} → ${at(ts.end, "open")}`;
}

/**
 * What the hunt stats say beyond the per-host list (#1612), as text only: "" when every scheduled
 * client finished without error or the counts are missing. The stats cannot see a client that never
 * checked in, so they never decide settlement — the per-host list does (#1625).
 */
function countsNote(job: VeloHuntJob): string {
  const c = record(job.clientCounts);
  const ok = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0;
  const [scheduled, completed, errors] = [c.scheduled, c.completed, c.errors];
  if (!ok(scheduled) || !ok(completed) || !ok(errors)) return "";
  if (completed === scheduled && errors === 0) return "";
  return `; only ${completed} of ${scheduled} scheduled client(s) finished${errors ? `, ${errors} with errors` : ""}`;
}

/** velo-hunt.json is read without a schema: a list that is not an array is unknown (#1625). */
function reachedClientsOf(job: VeloHuntJob): HuntReachedClient[] | undefined {
  const raw: unknown = job.reachedClients;
  if (!Array.isArray(raw)) return undefined;
  const str = (v: unknown): string => (typeof v === "string" ? v.trim() : "");
  return raw.flatMap((c) => {
    const r = record(c);
    const clientId = str(r.clientId);
    return clientId
      ? [{ clientId, hostname: str(r.hostname), fqdn: str(r.fqdn), os: str(r.os).toLowerCase() }]
      : [];
  });
}

/** A Windows./Linux./MacOS. artifact runs only on that OS; a clean flow elsewhere skipped it. */
const ARTIFACT_OS: readonly (readonly [RegExp, string])[] = [
  [/^windows\./i, "windows"],
  [/^linux\./i, "linux"],
  [/^macos\./i, "darwin"],
];
const runsOn = (artifact: string, os: string): boolean => {
  const need = ARTIFACT_OS.find(([re]) => re.test(artifact))?.[1];
  return !need || need === os;
};

/**
 * The canonical host of a reached client. The client id is the stable identity: when the alias index
 * knows it, that alone decides. Otherwise the recorded hostname and FQDN, as full names only.
 */
function clientHosts(c: HuntReachedClient, aliasIndex?: HostAliasIndex): string[] {
  const byId = aliasIndex?.canonicalOf.get(canonicalHostName(c.clientId));
  if (byId) return [byId];
  const resolve = (n: string) => (aliasIndex ? resolveHost(aliasIndex, n) : canonicalHostName(n));
  return [c.hostname, c.fqdn].filter(Boolean).map(resolve);
}

/**
 * Why this hunt's silence for one artifact is bounded (#1604), or "" when it speaks for the whole
 * artifact. velo-hunt.json is read without a schema and sanitizeHuntJobs spreads these fields raw.
 * The time bound is per artifact: only the artifacts that took the window are bounded. A job written
 * before the names were recorded only counts them, so every artifact of it counts as possibly bounded.
 * A window that reached no artifact bounds nothing — `degraded` means the metadata was unknown, not
 * that a window was applied.
 */
function silenceBound(job: VeloHuntJob, artifact: string): string {
  const parts: string[] = [];
  if (job.timeScope && typeof job.timeScope === "object") {
    const ts = record(job.timeScope);
    if (Array.isArray(ts.scopedArtifactNames)) {
      if (strings(ts.scopedArtifactNames).includes(artifact))
        parts.push(`time-bounded collection (${windowText(ts)})`);
    } else if (Number(ts.scopedArtifacts) > 0)
      parts.push(`possibly time-bounded (${windowText(ts)}; which artifacts took it is not recorded)`);
  }
  const filter = record(job.filters)[artifact];
  if (typeof filter === "string" && filter.trim()) parts.push("result filter applied");
  if (!reachedClientsOf(job))
    parts.push("which hosts the hunt finished on is not recorded (collected before it was tracked)");
  return parts.join("; ");
}

/**
 * A hunt restricted by label (either way) or by OS reached only part of the fleet, and the job does not
 * say which hosts: its result speaks for none of them. Settlement is case-wide, so an OS-targeted empty
 * must not settle a class for a host of another OS that the hunt never reached.
 */
const isFleetWide = (job: VeloHuntJob): boolean =>
  !job.target?.includeLabels?.length && !job.target?.excludeLabels?.length && !job.target?.os;

const canSettle = (l: HuntArtifactLine): boolean => l.fleetWide && !l.bounded;

/** Which of two lines for one artifact+state to keep: the one that can settle, then fleet-wide, then stable. */
function preferred(a: HuntArtifactLine, b: HuntArtifactLine): HuntArtifactLine {
  if (canSettle(a) !== canSettle(b)) return canSettle(a) ? a : b;
  if (a.fleetWide !== b.fleetWide) return a.fleetWide ? a : b;
  return a.detail <= b.detail ? a : b;
}

const MAX_REACHED_NAMES = 10;

/** The text of an empty that settles on the hosts it names, and on no other. */
function reachedDetail(reached: readonly string[], note: string, hunts: number): string {
  const shown = reached.slice(0, MAX_REACHED_NAMES).join(", ");
  const more = reached.length > MAX_REACHED_NAMES ? ` +${reached.length - MAX_REACHED_NAMES} more` : "";
  const across = hunts > 1 ? ` across ${hunts} hunts` : "";
  return (
    `returned no rows on ${shown}${more} — every host whose flow finished without error${across}${note}; ` +
    "silence on any other host is not absence"
  );
}

/** Two empties that can both settle speak together for every host either reached. */
function mergeLines(a: HuntArtifactLine, b: HuntArtifactLine, hunts: number): HuntArtifactLine {
  if (!(a.state === "empty" && canSettle(a) && canSettle(b))) return preferred(a, b);
  const reached = [...new Set([...a.reached, ...b.reached])].sort();
  return { ...a, reached, detail: reachedDetail(reached, "", hunts) };
}

/** An empty artifact's line: bounded silence, or silence on the hosts the hunt finished on (#1625). */
function emptyLine(job: VeloHuntJob, artifact: string, aliasIndex?: HostAliasIndex) {
  const bound = silenceBound(job, artifact);
  const bounded = (why: string) => ({
    detail: `returned no rows — ${why}; silence outside those bounds is not absence`,
    bounded: true,
    reached: [] as string[],
  });
  if (bound) return bounded(bound);
  const clients = (reachedClientsOf(job) ?? []).filter((c) => runsOn(artifact, c.os));
  const reached = [...new Set(clients.flatMap((c) => clientHosts(c, aliasIndex)))].sort();
  if (!reached.length) return bounded("the hunt finished cleanly on no client that runs this artifact");
  return { detail: reachedDetail(reached, countsNote(job), 1), bounded: false, reached };
}

/** Hunt metadata is supplemental: only imported jobs say anything, and only per artifact. */
function huntLines(
  jobs: readonly VeloHuntJob[],
  inTimeline: ReadonlySet<string>,
  aliasIndex?: HostAliasIndex,
): HuntArtifactLine[] {
  const out = new Map<string, HuntArtifactLine>();
  const hunts = new Map<string, number>();
  for (const job of jobs) {
    const fleetWide = isFleetWide(job);
    const put = (
      artifact: string,
      state: HuntArtifactState,
      detail: string,
      bounded = false,
      reached: string[] = [],
    ) => {
      const key = `${artifact}|${state}`;
      const line = { artifact, state, detail, fleetWide, bounded, reached };
      const prev = out.get(key);
      const settling = canSettle(line) ? 1 : 0;
      hunts.set(key, (hunts.get(key) ?? 0) + settling);
      out.set(key, prev ? mergeLines(prev, line, hunts.get(key) ?? 0) : line);
    };
    if (job.status === "running" || job.status === "collecting") {
      for (const a of job.artifacts) put(a, "running", "still running");
      continue;
    }
    if (job.status !== "imported") continue;
    const empty = new Set(job.emptyArtifacts ?? []);
    const failed = new Set((job.skippedArtifacts ?? []).map((s) => s.name));
    const truncated = new Map((job.truncatedArtifacts ?? []).map((t) => [t.name, t]));
    for (const a of job.artifacts) {
      const t = truncated.get(a);
      if (failed.has(a)) put(a, "failed", "fetch failed");
      else if (empty.has(a)) {
        const e = emptyLine(job, a, aliasIndex);
        put(a, "empty", e.detail, e.bounded, e.reached);
      } else if (t) put(a, "truncated", `partial — kept ${t.kept} of ${t.total}`);
      else if (job.superTimelineOnly || !inTimeline.has(a)) put(a, "archive-only", "in the archive only");
    }
  }
  return [...out.values()].sort(
    (a, b) => a.artifact.localeCompare(b.artifact) || a.state.localeCompare(b.state),
  );
}

export function buildCollectionInventory(input: {
  events: readonly ForensicEvent[];
  hunts?: readonly VeloHuntJob[];
  aliasIndex?: HostAliasIndex;
}): CollectionInventory {
  const host = (e: ForensicEvent): string => {
    const raw = (e.asset ?? "").trim();
    return raw && input.aliasIndex ? resolveHost(input.aliasIndex, raw) : raw;
  };
  const byHost = new Map<string, Set<EvidenceClass>>();
  const rows = new Map<string, number>();
  for (const e of input.events) {
    const h = host(e);
    if (h) {
      const set = byHost.get(h) ?? new Set<EvidenceClass>();
      for (const c of rowClasses(e)) set.add(c);
      byHost.set(h, set);
    }
    const name = sourceName(e);
    if (name) rows.set(name, (rows.get(name) ?? 0) + 1);
  }
  const sources = [...rows.entries()]
    .map(([name, n]) => ({ name, kind: sourceKind(name), rows: n }))
    .sort((a, b) => b.rows - a.rows || a.name.localeCompare(b.name));
  const inTimeline = new Set(input.events.map((e) => e.artifactName).filter((a): a is string => !!a));
  return {
    byHost,
    hosts: [...byHost.keys()].sort(),
    sources,
    cleared: clearedLogs(input.events, host),
    hunts: huntLines(input.hunts ?? [], inTimeline, input.aliasIndex),
  };
}

/** Classes collected raw on EVERY one of these hosts — an absence across hosts needs all of them. */
export function coveredOnAll(inv: CollectionInventory, hosts: readonly string[]): Set<EvidenceClass> {
  const list = hosts.length ? hosts : inv.hosts;
  let acc: Set<EvidenceClass> | null = null;
  for (const h of list) {
    const got = inv.byHost.get(h) ?? new Set<EvidenceClass>();
    const prev: Set<EvidenceClass> | null = acc;
    acc = prev ? new Set([...prev].filter((c: EvidenceClass) => got.has(c))) : new Set(got);
  }
  return acc ?? new Set();
}

/**
 * The artifacts whose clean, zero-row result can settle a class — each collects ONE kind of record.
 * Windows.EventLogs.Evtx is deliberately absent: it collects whichever channels its parameters named,
 * and the metadata does not say which, so its silence cannot settle execution, file or network.
 */
const CLASS_SETTLING_ARTIFACTS: Record<EvidenceClass, readonly string[]> = {
  execution: ["Windows.Forensics.Prefetch"],
  "file-activity": ["Windows.Search.FileFinder", "Windows.NTFS.MFT"],
  network: [],
  persistence: ["Windows.Sysinternals.Autoruns", "Windows.System.TaskScheduler"],
};

/**
 * Classes a clean zero-row FLEET-WIDE hunt settles on THIS host: evidence of absence, which
 * re-collecting would only repeat. A label-filtered hunt names no hosts, so it settles nothing; a
 * time-scoped or result-filtered empty is bounded silence, so it settles nothing either (#1604). An
 * empty speaks only for the hosts whose flow finished without error (#1625): a client that never
 * checked in was never scheduled, so the hunt says nothing about it.
 */
export function emptySettledClasses(inv: CollectionInventory, host: string): Set<EvidenceClass> {
  const h = canonicalHostName(host);
  const empty = new Set(
    inv.hunts
      .filter((l) => l.state === "empty" && canSettle(l) && !!h && l.reached.includes(h))
      .map((l) => l.artifact),
  );
  return new Set(EVIDENCE_CLASSES.filter((c) => CLASS_SETTLING_ARTIFACTS[c].some((a) => empty.has(a))));
}

const MAX_SOURCE_LINES = 12;
const MAX_HUNT_LINES = 12;

/** Stable input for the skip-hash: hunt metadata can change what the inventory says with no new row. */
export function inventorySignature(hunts: readonly VeloHuntJob[]): string {
  const one = (j: VeloHuntJob): string =>
    JSON.stringify([
      j.huntId,
      j.status,
      [...j.artifacts].sort(),
      [...(j.emptyArtifacts ?? [])].sort(),
      (j.skippedArtifacts ?? []).map((s) => s.name).sort(),
      (j.truncatedArtifacts ?? []).map((t) => `${t.name}:${t.kept}/${t.total}`).sort(),
      !!j.superTimelineOnly,
      // What decides fleet-wide and bounded (#1604) — a change there changes what the inventory says.
      JSON.stringify(j.target ?? null),
      JSON.stringify(j.timeScope ?? null),
      Object.entries(record(j.filters))
        .filter(([, f]) => typeof f === "string" && f.trim())
        .map(([name]) => name)
        .sort(),
      JSON.stringify(j.clientCounts ?? null), // shown in the text (#1612)
      // Which hosts an empty speaks for (#1625); an unknown list (null) differs from an empty one ([]).
      JSON.stringify(
        reachedClientsOf(j)
          ?.map((c) => [c.clientId, c.hostname, c.fqdn, c.os])
          .sort((a, b) => a[0].localeCompare(b[0])) ?? null,
      ),
    ]);
  return hunts.map(one).sort().join("\n");
}

export function renderCollectionInventory(inv: CollectionInventory): string {
  if (!inv.hosts.length && !inv.sources.length && !inv.hunts.length) return "";
  const lines: string[] = [];
  const missingAnywhere = new Set<EvidenceClass>();
  for (const h of inv.hosts) {
    const got = inv.byHost.get(h) ?? new Set<EvidenceClass>();
    const have = EVIDENCE_CLASSES.filter((c) => got.has(c));
    const lack = EVIDENCE_CLASSES.filter((c) => !got.has(c));
    for (const c of lack) missingAnywhere.add(c);
    lines.push(
      `- ${h}: collected raw: ${have.length ? have.join(", ") : "none"}; no raw collection found: ${lack.length ? lack.join(", ") : "none"}`,
    );
  }
  if (missingAnywhere.size)
    lines.push(
      `- Where to collect: ${EVIDENCE_CLASSES.filter((c) => missingAnywhere.has(c))
        .map((c) => `${c} → ${CLASS_COLLECTION[c].artifact} (${CLASS_COLLECTION[c].logSource})`)
        .join("; ")}`,
    );
  for (const c of inv.cleared) {
    const where = c.host ? ` on ${c.host}` : "";
    const what = c.channel ? `${c.channel} log` : "An event log (channel not recorded)";
    lines.push(
      `- Cleared: ${what}${where} at ${c.at}${c.count > 1 ? ` (cleared ${c.count}×; latest shown)` : ""}`,
    );
  }
  if (inv.sources.length) {
    const shown = inv.sources.slice(0, MAX_SOURCE_LINES).map((s) => `${s.name} (${s.kind}) ${s.rows}`);
    const more = inv.sources.length - shown.length;
    lines.push(
      `- Sources in the forensic timeline: ${shown.join(" · ")}${more > 0 ? ` · +${more} more` : ""}`,
    );
  }
  const hunts = inv.hunts.slice(0, MAX_HUNT_LINES);
  if (hunts.length)
    lines.push(`- Recent Velociraptor hunts: ${hunts.map((h) => `${h.artifact} — ${h.detail}`).join("; ")}`);
  return (
    "COLLECTION INVENTORY (built in code from what this case holds; detection feeds and point-in-time snapshots are not collection):\n" +
    lines.join("\n") +
    "\n" +
    NEGATIVE_ANSWER_RULES
  );
}

export const NEGATIVE_ANSWER_RULES = [
  "Rules for negative answers:",
  "- An answer, uncertainty or finding that says an activity was NOT observed must name the artifact that could have shown it.",
  '- If the inventory shows no raw collection for that evidence on the host in question (detections only, archive only, or a cleared log), the answer is not settled: set the question\'s status to "partial" and give a collect object naming the Velociraptor artifact above. At most ONE next step per missing artifact and host.',
  "- If the evidence is in the archive only, the step is to search the archive and promote the rows, not to collect again.",
  "- Do not suggest collecting a log the inventory lists as cleared for the period before the clear; suggest a log that was not cleared.",
  '- No generic "collect more" steps: a collection step must serve a negative answer that depends on missing evidence, or a cleared log.',
].join("\n");
