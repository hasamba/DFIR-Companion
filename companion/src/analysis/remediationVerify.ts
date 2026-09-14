import { randomUUID } from "node:crypto";
import type { ForensicEvent } from "./stateTypes.js";
import { canonicalHostName, resolveHost, type HostAliasIndex } from "./hostAlias.js";
import { alignedEpoch } from "./clockSkew.js";
import {
  boundaryWindow,
  TELEMETRY_FAMILIES,
  type CoverageState,
  type RemediationBoundary,
  type RemediationReceipt,
  type TelemetryFamily,
} from "./remediationBoundary.js";
import { classifyHit, familyOf, relevantFamilies, tripleOf, type HitClass } from "./remediationShapes.js";

// VERIFY (#969): deterministic, analyst-triggered, and FACTS ONLY. Given the boundary and the rows
// of both stores inside its window, it says which rows name the artifact on that host (exact or
// weak, by rule), what each row IS (remediationShapes.ts), and how much telemetry of each family
// the case holds for the host in the window. It never emits a negative verdict, never changes a
// row, never mints a finding. The receipt it returns holds counts, ids and the read's own facts —
// never a row's text or envelope (the forensic / super-timeline boundary, ARCHITECTURE.md).
//
// Coverage is EXPLICIT: a family is `covered` only when its rows inside the window reach a floor
// AND span most of the elapsed window; one process row in a week is `partial`, and a
// `checked-not-observed` recorded against a partial or absent relevant family needs the analyst's
// override note (remediationBoundary.ts). Per-event import time does not exist, so a late import
// of old history reads as a hit; the facts say so rather than pretending otherwise.

export const HITS_IN_RESPONSE_MAX = 200;
export const VERIFY_ROW_BUDGET = 200_000;
/** Distinct super-timeline host spellings read for the spelling resolution; past this the read is truncated. */
export const HOSTS_READ_MAX = 5_000;
/** A family is covered with at least this many rows in the window … */
export const COVERED_ROWS_MIN = 10;
/** … whose span reaches this share of the elapsed window. */
export const COVERED_SPAN_SHARE = 0.9;

export type HitStrength = "exact" | "weak";

export interface VerifyHit {
  id: string;
  store: "forensic" | "super";
  timestamp: string;
  source: string;
  strength: HitStrength;
  matchedOn: string;
  cls: HitClass;
  classNote?: string;
  triple: string;
  description: string;
  /** With alignment on: the row sits on the other side of the boundary once corrected. */
  changesSideWhenAligned?: boolean;
}

export interface VerifyFacts {
  boundaryId: string;
  spellings: string[];
  window: { from: string; to: string; open: boolean };
  hits: VerifyHit[];
  hitTotal: number;
  hitsByClass: Record<string, number>;
  coverage: RemediationReceipt["coverage"];
  families: RemediationReceipt["families"];
  coverageGapped: boolean;
  truncated: boolean;
  truncatedBy?: string;
  undated: number;
  retentionNote?: string;
  lateImportNote: string;
  clock: RemediationReceipt["clock"] & { boundaryAligned?: string };
  inconsistent: boolean;
  receipt: RemediationReceipt;
  sentence: string;
}

export interface VerifyInput {
  boundary: RemediationBoundary;
  now: string;
  /** Every forensic-timeline row (all time; the host and window filters run here). */
  forensic: readonly ForensicEvent[];
  /** Super-timeline rows inside the window, as read (undated included), plus whether the read stopped. */
  superRows: readonly ForensicEvent[];
  superTruncated: boolean;
  superMeta: {
    rows: number;
    generation: number;
    hosts: string[];
    hostsTruncated: boolean;
    atCap: boolean;
  };
  superMetaAfter: { rows: number; generation: number };
  forensicMeta: { rows: number; updatedAt: string };
  /** The forensic store as read again after the scan; a change marks the receipt inconsistent. */
  forensicMetaAfter: { rows: number; updatedAt: string };
  aliasIndex?: HostAliasIndex;
  /** Present only when alignment is enabled and has offsets. */
  offsets?: ReadonlyMap<string, number>;
  lastImportedAt: string;
}

// ───────────────────────────── hosts ─────────────────────────────

/**
 * The RAW spellings the stores hold for the typed host: equal canonical names, plus the spellings
 * a fleet pairing or an analyst merge links (only when the alias index resolves them to one
 * machine). Never a spelling the case does not hold; never a short-label guess.
 */
export function resolveSpellings(typed: string, known: readonly string[], index?: HostAliasIndex): string[] {
  const want = canonicalHostName(typed);
  // Two spellings are one machine through the index only when BOTH are spellings the index
  // knows (a fleet record or an analyst merge named them) and they resolve to one canonical name.
  const linked = (c: string): boolean =>
    !!index &&
    index.canonicalOf.has(c) &&
    index.canonicalOf.has(want) &&
    resolveHost(index, c) === resolveHost(index, want);
  const out = new Set<string>();
  for (const raw of known) {
    if (!raw) continue;
    const c = canonicalHostName(raw);
    if (c === want || linked(c)) out.add(raw);
  }
  return [...out].sort();
}

// ───────────────────────────── matching ─────────────────────────────

const normPath = (p: string): string =>
  p
    .trim()
    .replace(/^\\\\\?\\/, "")
    .replace(/\//g, "\\")
    .replace(/^"+|"+$/g, "")
    .toLowerCase();
const baseOf = (p: string): string => p.slice(Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/")) + 1);

/** Path-bearing tokens of a command line: quoted strings and whitespace-separated words with a separator. */
export function commandLinePaths(cmd: string): string[] {
  const out: string[] = [];
  const re = /"([^"]+)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(cmd.slice(0, 4096))) !== null) {
    const tok = m[1] ?? m[2];
    if (/[\\/]/.test(tok)) out.push(tok);
  }
  return out;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const tokenIn = (text: string, value: string): boolean =>
  new RegExp(`(?<![A-Za-z0-9._-])${escapeRe(value)}(?![A-Za-z0-9._-])`, "i").test(text);

interface Match {
  strength: HitStrength;
  on: string;
}

function accountParts(name: string): { domain: string; user: string } {
  const s = name.trim().toLowerCase();
  const at = s.indexOf("@");
  if (at > 0) return { domain: s.slice(at + 1), user: s.slice(0, at) };
  const bs = s.indexOf("\\");
  if (bs > 0) return { domain: s.slice(0, bs), user: s.slice(bs + 1) };
  return { domain: "", user: s };
}

export function matchArtifact(e: ForensicEvent, kind: string, value: string): Match | null {
  const c = e.canonical;
  switch (kind) {
    case "path": {
      const want = normPath(value);
      const candidates: [string, string | undefined][] = [
        ["path", e.path],
        ["file.path", c?.file?.path],
        ["process.executable", c?.process?.executable],
      ];
      for (const [on, raw] of candidates) {
        if (!raw) continue;
        const have = normPath(raw);
        if (have === want) return { strength: "exact", on };
      }
      for (const tok of commandLinePaths(e.commandLine ?? c?.process?.commandLine ?? "")) {
        if (normPath(tok) === want) return { strength: "exact", on: "commandLine" };
      }
      const wantBase = baseOf(want);
      for (const [on, raw] of candidates) {
        if (raw && baseOf(normPath(raw)) === wantBase)
          return { strength: "weak", on: `${on} (basename only)` };
      }
      for (const tok of commandLinePaths(e.commandLine ?? c?.process?.commandLine ?? "")) {
        if (baseOf(normPath(tok)) === wantBase)
          return { strength: "weak", on: "commandLine (basename only)" };
      }
      // A Sysmon file event names the created file only in its rendered text (the row's `path`
      // is the creating process's image): the full path in the description is a weak match.
      if (normPath(e.description).includes(want)) return { strength: "weak", on: "description" };
      return null;
    }
    case "hash": {
      const want = value.toLowerCase();
      const have = [e.sha256, e.md5, c?.file?.sha256, c?.file?.md5].map((h) => h?.toLowerCase());
      const at = have.findIndex((h) => h === want);
      if (at < 0) return null;
      return { strength: "exact", on: ["sha256", "md5", "file.sha256", "file.md5"][at] };
    }
    case "account": {
      const want = accountParts(value);
      const names = [
        ["account.name", c?.account?.name],
        ["actor", c?.actor?.kind === "account" ? c.actor.name : undefined],
      ] as const;
      // Every candidate is read: an exact (user + domain) match anywhere wins; else a candidate
      // with the user and no domain on one side is weak; a candidate under another domain is
      // another principal and counts for nothing.
      let weak: Match | null = null;
      for (const [on, raw] of names) {
        if (!raw) continue;
        const have = accountParts(raw);
        if (have.user !== want.user) continue;
        if (have.domain && want.domain) {
          if (have.domain === want.domain) return { strength: "exact", on };
          continue;
        }
        weak ??= { strength: "weak", on: `${on} (domain not recorded on one side)` };
      }
      return weak;
    }
    case "ip":
    case "domain": {
      const want = value.toLowerCase();
      const addrs: [string, string | undefined][] = [
        ["dstIp", e.dstIp],
        ["srcIp", e.srcIp],
        ["network.destination", c?.network?.destination?.address],
        ["network.source", c?.network?.source?.address],
      ];
      for (const [on, raw] of addrs) if (raw && raw.toLowerCase() === want) return { strength: "exact", on };
      const dnsNames = (c?.dns as { query?: string; answers?: string[] } | undefined) ?? {};
      if (dnsNames.query?.toLowerCase() === want) return { strength: "exact", on: "dns.query" };
      if ((dnsNames.answers ?? []).some((a) => a.toLowerCase() === want))
        return { strength: "exact", on: "dns.answer" };
      return tokenIn(e.description, value) ? { strength: "weak", on: "description" } : null;
    }
    case "service":
    case "task":
    case "regkey": {
      const want = value.toLowerCase();
      const field =
        kind === "service" ? c?.service?.name : kind === "task" ? c?.task?.name : c?.registry?.key;
      if (field && field.toLowerCase() === want) return { strength: "exact", on: `${kind}.name` };
      return tokenIn(e.description, value) ? { strength: "weak", on: "description" } : null;
    }
    default:
      return null;
  }
}

// ───────────────────────────── the verify ─────────────────────────────

const ms = (iso: string | undefined): number | null => {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};

export function verifyBoundary(input: VerifyInput): VerifyFacts {
  const { boundary, now } = input;
  const win = boundaryWindow(boundary, now);
  const known = [...new Set([...input.forensic.map((e) => e.asset ?? ""), ...input.superMeta.hosts])];
  const spellings = resolveSpellings(boundary.host, known, input.aliasIndex);
  const spellingSet = new Set(spellings);
  const onHost = (e: ForensicEvent) => !!e.asset && spellingSet.has(e.asset);

  // Union by id, the forensic copy winning.
  const rows = new Map<string, { store: "forensic" | "super"; e: ForensicEvent }>();
  let undated = 0;
  const inWindow = (e: ForensicEvent): boolean | null => {
    const t = ms(e.timestamp);
    if (t === null) return null;
    return t > win.fromMs && t <= win.toMs;
  };
  for (const e of input.superRows) {
    if (!onHost(e)) continue;
    const w = inWindow(e);
    if (w === null) {
      undated += 1;
      continue;
    }
    if (w) rows.set(e.id, { store: "super", e });
  }
  const anyOnHost = new Set<TelemetryFamily>();
  for (const e of input.forensic) {
    if (!onHost(e)) continue;
    const fam = familyOf(e);
    if (fam) anyOnHost.add(fam);
    const w = inWindow(e);
    if (w === null) {
      undated += 1;
      continue;
    }
    if (w) rows.set(e.id, { store: "forensic", e });
  }

  // Coverage per store/source, and per family.
  const cov = new Map<
    string,
    { store: "forensic" | "super"; source: string; rows: number; earliest: number; latest: number }
  >();
  const fam = new Map<TelemetryFamily, { rows: number; earliest: number; latest: number }>();
  for (const { store, e } of rows.values()) {
    const t = ms(e.timestamp)!;
    for (const source of e.sources?.length ? e.sources : ["(unnamed source)"]) {
      const key = `${store}|${source}`;
      const c = cov.get(key) ?? cov.set(key, { store, source, rows: 0, earliest: t, latest: t }).get(key)!;
      c.rows += 1;
      c.earliest = Math.min(c.earliest, t);
      c.latest = Math.max(c.latest, t);
    }
    const f = familyOf(e);
    if (f) {
      const c = fam.get(f) ?? fam.set(f, { rows: 0, earliest: t, latest: t }).get(f)!;
      c.rows += 1;
      c.earliest = Math.min(c.earliest, t);
      c.latest = Math.max(c.latest, t);
    }
  }
  const elapsed = Math.max(1, win.toMs - win.fromMs);
  const relevant = new Set(relevantFamilies(boundary.artifact.kind));
  const families = TELEMETRY_FAMILIES.map((family) => {
    const c = fam.get(family);
    const rowsIn = c?.rows ?? 0;
    const spanMs = c ? c.latest - c.earliest : 0;
    const state: CoverageState =
      rowsIn === 0
        ? "absent"
        : rowsIn >= COVERED_ROWS_MIN && spanMs >= COVERED_SPAN_SHARE * elapsed
          ? "covered"
          : "partial";
    return {
      family,
      relevant: relevant.has(family),
      anyRowsOnHost: anyOnHost.has(family) || rowsIn > 0,
      rowsInWindow: rowsIn,
      spanMs,
      state,
    };
  });
  const coverageGapped = families.some((f) => f.relevant && f.state !== "covered");

  // Hits.
  const boundaryMs = win.fromMs;
  const hits: VerifyHit[] = [];
  for (const { store, e } of [...rows.values()].sort(
    (a, b) => ms(a.e.timestamp)! - ms(b.e.timestamp)! || a.e.id.localeCompare(b.e.id),
  )) {
    const m = matchArtifact(e, boundary.artifact.kind, boundary.artifact.value);
    if (!m) continue;
    const { cls, note } = classifyHit(e, boundaryMs);
    const hit: VerifyHit = {
      id: e.id,
      store,
      timestamp: e.timestamp,
      source: (e.sources ?? []).join(", "),
      strength: m.strength,
      matchedOn: m.on,
      cls,
      ...(note ? { classNote: note } : {}),
      triple: tripleOf(e),
      description: e.description.slice(0, 300),
    };
    if (input.offsets) {
      const aligned = alignedEpoch(e, input.offsets);
      if (aligned !== undefined && aligned <= boundaryMs) hit.changesSideWhenAligned = true;
    }
    hits.push(hit);
  }
  const hitsByClass: Record<string, number> = {};
  for (const h of hits) hitsByClass[h.cls] = (hitsByClass[h.cls] ?? 0) + 1;

  const truncated = input.superTruncated || input.superMeta.hostsTruncated;
  const inconsistent =
    input.superMeta.generation !== input.superMetaAfter.generation ||
    input.superMeta.rows !== input.superMetaAfter.rows ||
    input.forensicMeta.rows !== input.forensicMetaAfter.rows ||
    input.forensicMeta.updatedAt !== input.forensicMetaAfter.updatedAt;
  const offsetMs = input.offsets?.get(hostKeyOf(boundary.host));
  const window = {
    from: new Date(win.fromMs).toISOString(),
    to: new Date(win.toMs).toISOString(),
    open: win.open,
  };
  const lateImportNote =
    "Rows carry no import time: a row imported after the boundary was declared cannot be told from one present before it, so a late import of old history reads as a hit." +
    (input.lastImportedAt ? ` The last import ran at ${input.lastImportedAt}.` : "");
  const receipt: RemediationReceipt = {
    id: `rr-${randomUUID().slice(0, 12)}`,
    at: now,
    boundary: {
      host: boundary.host,
      artifact: boundary.artifact,
      remediatedAt: boundary.remediatedAt,
      windowHours: boundary.windowHours,
    },
    spellings,
    window,
    coverage: [...cov.values()]
      .sort((a, b) => a.store.localeCompare(b.store) || a.source.localeCompare(b.source))
      .map((c) => ({
        ...c,
        earliest: new Date(c.earliest).toISOString(),
        latest: new Date(c.latest).toISOString(),
      })),
    families,
    hitTotal: hits.length,
    hitsByClass,
    // Forensic ids only: a raw row's id is persisted when the analyst attaches it, not because a
    // verify saw it (the boundary rule); raw hits are a count here.
    hitIds: hits
      .filter((h) => h.store === "forensic")
      .slice(0, HITS_IN_RESPONSE_MAX)
      .map((h) => h.id),
    superHitTotal: hits.filter((h) => h.store === "super").length,
    truncated,
    ...(truncated
      ? {
          truncatedBy: input.superMeta.hostsTruncated
            ? `the case holds more distinct host spellings than the ${HOSTS_READ_MAX} read`
            : `the super-timeline read stopped at the ${VERIFY_ROW_BUDGET}-row budget`,
        }
      : {}),
    undated,
    coverageGapped,
    ...(input.superMeta.atCap
      ? { retentionNote: "the super-timeline is at its retention cap: older rows may have been evicted" }
      : {}),
    lateImportNote,
    clock: { alignment: input.offsets ? "on" : "off", ...(offsetMs !== undefined ? { offsetMs } : {}) },
    highWater: {
      forensic: input.forensicMetaAfter,
      super: { rows: input.superMetaAfter.rows, generation: input.superMetaAfter.generation },
    },
    inconsistent,
  };
  return {
    boundaryId: boundary.id,
    spellings,
    window,
    hits: hits.slice(0, HITS_IN_RESPONSE_MAX),
    hitTotal: hits.length,
    hitsByClass,
    coverage: receipt.coverage,
    families,
    coverageGapped,
    truncated,
    ...(receipt.truncatedBy ? { truncatedBy: receipt.truncatedBy } : {}),
    undated,
    ...(receipt.retentionNote ? { retentionNote: receipt.retentionNote } : {}),
    lateImportNote,
    clock: {
      ...receipt.clock,
      ...(offsetMs !== undefined ? { boundaryAligned: new Date(boundaryMs + offsetMs).toISOString() } : {}),
    },
    inconsistent,
    receipt,
    sentence: "The check lists what was seen and what was covered. Only you can say the foothold is gone.",
  };
}

// The alignment feature keys offsets by short host (clockSkew.ts hostKey); read as it keys them.
function hostKeyOf(asset: string): string {
  return canonicalHostName(asset).split(".")[0];
}

/** A receipt is stale when either store's high-water mark moved since it was written. */
export function receiptIsStale(
  r: RemediationReceipt,
  current: { forensic: { rows: number; updatedAt: string }; super: { rows: number; generation: number } },
): boolean {
  return (
    r.highWater.forensic.rows !== current.forensic.rows ||
    r.highWater.forensic.updatedAt !== current.forensic.updatedAt ||
    r.highWater.super.rows !== current.super.rows ||
    r.highWater.super.generation !== current.super.generation
  );
}
