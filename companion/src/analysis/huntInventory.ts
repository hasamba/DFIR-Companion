import { huntItemKey, type HuntEvidence, type HuntFields } from "./huntArtifactFields.js";
import type { HostKey } from "./huntHostKey.js";
import { EMPTY_IDENTITY_COVERAGE, observeIdentity, type IdentityCoverage } from "./huntItemCoverage.js";

/**
 * The per-case hunt inventory (#2670): every distinct program / autorun / download a hunt import
 * added, with the hosts it was seen on. Recorded AT THE IMPORT SEAM from the import's own rows, before
 * the forensic gate moves the Info rows to the super-timeline — so rarity, "new since last hunt" and
 * the client's confirm list are computed from this record and never from a read of the raw record.
 * PURE: every function returns a new inventory.
 *
 * Bounded: at most INVENTORY_MAX_ITEMS items and INVENTORY_MAX_HOSTS hosts per item. A full item keeps
 * counting (`hostOverflow`) so a count is never silently low, and a full inventory says so (`full`).
 */
export const INVENTORY_MAX_ITEMS = 20_000;
export const INVENTORY_MAX_HOSTS = 5_000;
export const MAX_VALUES = 20;
/** Task names per autorun item (#2748): per-host or per-user named tasks can exceed MAX_VALUES. */
export const MAX_ENTRIES = 200;

export type InventoryFamily = "program" | "installed" | "autorun" | "download";

export interface InventoryHost {
  hostname: string;
  basis: HostKey["basis"];
  firstSeen: string;
}

/** The SHA1 and signer coverage fields (#2731) are documented in huntItemCoverage.ts. */
export interface InventoryItem extends IdentityCoverage {
  key: string;
  family: InventoryFamily;
  program: string;
  pathPattern: string;
  /** Distinct evidence labels seen (execution / presence / …), so the report stays honest. */
  evidence: HuntEvidence[];
  publishers: string[]; // UNVERIFIED text — describes, never approves
  sha256: string[];
  /**
   * Hosts with NO hashed observation of this item yet. A hash approval covers the item only when this
   * is empty: one host's approved SHA256 says nothing about a host seen only through a hash-less row.
   * Absent on an item stored before it was recorded — completeness unknown, so never approved.
   */
  unhashedHosts?: string[];
  /** A distinct SHA256 was dropped by the MAX_VALUES cap: the hash list is incomplete. */
  hashesCapped?: boolean;
  md5: string[];
  sourceUrls: string[];
  /**
   * (#2748) Old identities of the rows folded into this autorun item — the scheduled task files a
   * task item was keyed on before it was keyed on the program it runs. A Not-allowed mark matches them.
   * `entriesCapped`: a distinct entry was dropped by the MAX_ENTRIES cap.
   */
  entries?: { program: string; pathPattern: string }[];
  entriesCapped?: true;
  /**
   * (#2732) The Velociraptor artifacts this item was reported by, so a partial artifact blocks rarity
   * for its own items only. Absent on an item stored before it was recorded: unknown, never graded
   * while any artifact is partial. `artifactsIncomplete`: a row named no artifact, or the cap dropped one.
   */
  artifacts?: string[];
  artifactsIncomplete?: true;
  hosts: Record<string, InventoryHost>;
  hostOverflow: number;
  firstSeen: string;
  lastSeen: string;
}

export interface HuntInventory {
  version: 1;
  items: Record<string, InventoryItem>;
  full: boolean;
  updatedAt: string;
}

export const EMPTY_INVENTORY: HuntInventory = { version: 1, items: {}, full: false, updatedAt: "" };

export interface InventoryObservation {
  fields: HuntFields;
  host: HostKey;
  at: string;
  /** The artifact that emitted the row (`artifactName`), when it named one (#2732). */
  artifact?: string;
}

const familyOf = (e: HuntEvidence): InventoryFamily =>
  e === "execution" || e === "presence" ? "program" : e;

const addValue = (list: readonly string[], v: string | undefined): string[] =>
  !v || list.includes(v) || list.length >= MAX_VALUES ? [...list] : [...list, v];

/** The item's old entry identities with this observation's one added (#2748); capped, and says so. */
function entryList(
  base: InventoryItem,
  e: HuntFields["entry"],
): Pick<InventoryItem, "entries" | "entriesCapped"> {
  const list = base.entries ?? [];
  const keep = {
    ...(list.length ? { entries: list } : {}),
    ...(base.entriesCapped ? { entriesCapped: true as const } : {}),
  };
  if (!e || list.some((x) => x.program === e.program && x.pathPattern === e.pathPattern)) return keep;
  if (list.length >= MAX_ENTRIES) return { ...keep, entriesCapped: true };
  return { ...keep, entries: [...list, e] };
}

/** The item's artifact list with this observation's one added (#2732); a legacy item stays unknown. */
function artifactList(
  base: InventoryItem,
  artifact: string | undefined,
): Pick<InventoryItem, "artifacts" | "artifactsIncomplete"> {
  if (!base.artifacts) return {};
  const keep = {
    artifacts: base.artifacts,
    ...(base.artifactsIncomplete ? { artifactsIncomplete: true as const } : {}),
  };
  if (!artifact) return { ...keep, artifactsIncomplete: true };
  if (base.artifacts.includes(artifact)) return keep;
  if (base.artifacts.length >= MAX_VALUES) return { ...keep, artifactsIncomplete: true };
  return { ...keep, artifacts: [...base.artifacts, artifact] };
}

const earlier = (a: string, b: string): string => (!a ? b : !b ? a : a < b ? a : b);
const later = (a: string, b: string): string => (a > b ? a : b);

/**
 * Per-host hash coverage: a host leaves `unhashedHosts` at its first hashed observation and joins it
 * when first seen without a hash. A legacy item (no list) stays unknown: it is never approved.
 */
function hashCoverage(
  base: InventoryItem,
  o: InventoryObservation,
  knownHost: boolean,
): Pick<InventoryItem, "unhashedHosts" | "hashesCapped"> {
  const sha = o.fields.sha256;
  const capped =
    base.hashesCapped !== false || (!!sha && !base.sha256.includes(sha) && base.sha256.length >= MAX_VALUES);
  if (!base.unhashedHosts) return { hashesCapped: capped };
  const list = base.unhashedHosts;
  const unhashedHosts = sha
    ? list.filter((k) => k !== o.host.key)
    : knownHost || list.includes(o.host.key) || list.length >= INVENTORY_MAX_HOSTS // overflow: hostOverflow says so
      ? [...list]
      : [...list, o.host.key];
  return { unhashedHosts, hashesCapped: capped };
}

function observe(item: InventoryItem | undefined, o: InventoryObservation): InventoryItem {
  const f = o.fields;
  const base: InventoryItem = item ?? {
    key: huntItemKey(f),
    family: familyOf(f.evidence),
    program: f.program,
    pathPattern: f.pathPattern,
    evidence: [],
    publishers: [],
    sha256: [],
    unhashedHosts: [],
    hashesCapped: false,
    ...EMPTY_IDENTITY_COVERAGE,
    md5: [],
    sourceUrls: [],
    artifacts: [],
    hosts: {},
    hostOverflow: 0,
    firstSeen: o.at,
    lastSeen: o.at,
  };
  const known = base.hosts[o.host.key];
  const roomForHost = Object.keys(base.hosts).length < INVENTORY_MAX_HOSTS;
  const hosts = known
    ? { ...base.hosts, [o.host.key]: { ...known, firstSeen: earlier(known.firstSeen, o.at) } }
    : roomForHost
      ? { ...base.hosts, [o.host.key]: { hostname: o.host.hostname, basis: o.host.basis, firstSeen: o.at } }
      : base.hosts;
  return {
    ...base,
    evidence: base.evidence.includes(f.evidence) ? base.evidence : [...base.evidence, f.evidence],
    publishers: addValue(base.publishers, f.publisher),
    sha256: addValue(base.sha256, f.sha256),
    ...hashCoverage(base, o, known !== undefined),
    ...observeIdentity(base, f, {
      hostKey: o.host.key,
      knownHost: known !== undefined,
      maxHosts: INVENTORY_MAX_HOSTS,
    }),
    md5: addValue(base.md5, f.md5),
    sourceUrls: addValue(base.sourceUrls, f.sourceUrl),
    ...entryList(base, f.entry),
    ...artifactList(base, o.artifact?.trim() || undefined),
    hosts,
    hostOverflow: (base.hostOverflow ?? 0) + (!known && !roomForHost ? 1 : 0),
    firstSeen: earlier(base.firstSeen, o.at),
    lastSeen: later(base.lastSeen, o.at),
  };
}

/** The inventory with this import's observations folded in. */
export function recordObservations(
  inv: HuntInventory,
  obs: readonly InventoryObservation[],
  now: string,
): HuntInventory {
  if (!obs.length) return inv;
  const items: Record<string, InventoryItem> = { ...inv.items };
  let full = inv.full;
  let count = Object.keys(items).length;
  for (const o of obs) {
    const key = huntItemKey(o.fields);
    const cur = items[key];
    if (!cur && count >= INVENTORY_MAX_ITEMS) {
      full = true;
      continue;
    }
    if (!cur) count++;
    items[key] = observe(cur, o);
  }
  return { version: 1, items, full, updatedAt: now };
}

/** A readable one-line name for an item: "7z.exe in \tools". */
export function itemLabel(item: Pick<InventoryItem, "program" | "pathPattern" | "family">): string {
  const where = item.pathPattern ? ` in ${item.pathPattern}` : "";
  const what =
    item.family === "installed" ? "installed program " : item.family === "autorun" ? "autorun " : "";
  return `${what}${item.program}${where}`;
}

/** How many of an item's hosts are in `answered` (stable client keys). */
export function answeringHostCount(item: InventoryItem, answered: ReadonlySet<string>): number {
  return Object.keys(item.hosts).filter((k) => answered.has(k)).length;
}
