import { huntItemKey, type HuntEvidence, type HuntFields } from "./huntArtifactFields.js";
import type { HostKey } from "./huntHostKey.js";

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
const MAX_VALUES = 20;

export type InventoryFamily = "program" | "installed" | "autorun" | "download";

export interface InventoryHost {
  hostname: string;
  basis: HostKey["basis"];
  firstSeen: string;
}

export interface InventoryItem {
  key: string;
  family: InventoryFamily;
  program: string;
  pathPattern: string;
  /** Distinct evidence labels seen (execution / presence / …), so the report stays honest. */
  evidence: HuntEvidence[];
  publishers: string[]; // UNVERIFIED text — describes, never approves
  sha256: string[];
  md5: string[];
  sourceUrls: string[];
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
}

const familyOf = (e: HuntEvidence): InventoryFamily =>
  e === "execution" || e === "presence" ? "program" : e;

const addValue = (list: readonly string[], v: string | undefined): string[] =>
  !v || list.includes(v) || list.length >= MAX_VALUES ? [...list] : [...list, v];

const earlier = (a: string, b: string): string => (!a ? b : !b ? a : a < b ? a : b);
const later = (a: string, b: string): string => (a > b ? a : b);

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
    md5: [],
    sourceUrls: [],
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
    md5: addValue(base.md5, f.md5),
    sourceUrls: addValue(base.sourceUrls, f.sourceUrl),
    hosts,
    hostOverflow: base.hostOverflow + (!known && !roomForHost ? 1 : 0),
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
