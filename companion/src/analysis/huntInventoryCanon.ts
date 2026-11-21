import { expandKnownFolder } from "./huntKnownFolders.js";
import {
  INVENTORY_MAX_HOSTS,
  MAX_ENTRIES,
  MAX_VALUES,
  type HuntInventory,
  type InventoryHost,
  type InventoryItem,
} from "./huntInventory.js";

/**
 * Canonical item keys for a STORED hunt inventory (#2750). An inventory recorded before UserAssist
 * known-folder GUID paths were normalised keeps items keyed `program|foo.exe|{guid}\foo`; new imports
 * add `program|foo.exe|\program files\foo` for the same program, so the two would coexist and the
 * stale one could still grade rare on a fraction of the hosts. On load, every item's path pattern is
 * re-normalised the way huntArtifactFields does it now, and items that land on one key are merged.
 * PURE, and idempotent: an inventory already in canonical form comes back unchanged (`changed: false`).
 *
 * A merge never makes an item MORE approvable than its parts: a host counts as hashed (or signed, or
 * SHA1-covered) when either part saw it so, a value list absent on either part (stored before it was
 * tracked) stays absent, caps and sticky flags are OR-ed, and the host cap still holds.
 */
export function canonicalPathPattern(pattern: string): string {
  return expandKnownFolder(pattern);
}

const keyOf = (item: Pick<InventoryItem, "family" | "program" | "pathPattern">): string =>
  `${item.family}|${item.program}|${item.pathPattern}`;

const earlier = (a: string, b: string): string => (!a ? b : !b ? a : a < b ? a : b);
const later = (a: string, b: string): string => (a > b ? a : b);

function union(a: readonly string[], b: readonly string[], max: number): { list: string[]; capped: boolean } {
  const list = [...a];
  let capped = false;
  for (const v of b) {
    if (list.includes(v)) continue;
    if (list.length >= max) capped = true;
    else list.push(v);
  }
  return { list, capped };
}

/** Hosts missing a value in the merged item: missing in every part that saw the host. Absent stays absent. */
function missingHosts(
  a: InventoryItem,
  b: InventoryItem,
  pick: (i: InventoryItem) => readonly string[] | undefined,
): string[] | undefined {
  const la = pick(a);
  const lb = pick(b);
  if (!la || !lb) return undefined;
  const covered = (i: InventoryItem, l: readonly string[], h: string) => h in i.hosts && !l.includes(h);
  return [...new Set([...la, ...lb])].filter((h) => !covered(a, la, h) && !covered(b, lb, h));
}

/** A value list and its cap flag; a part without the list (legacy) leaves the merged item capped. */
function valueList(
  a: readonly string[] | undefined,
  b: readonly string[] | undefined,
  capA: boolean | undefined,
  capB: boolean | undefined,
): { list: string[]; capped: boolean } {
  const u = union(a ?? [], b ?? [], MAX_VALUES);
  const legacy = (l: readonly string[] | undefined, c: boolean | undefined) => !l || c !== false;
  return { list: u.list, capped: u.capped || legacy(a, capA) || legacy(b, capB) };
}

function mergeHosts(
  a: InventoryItem,
  b: InventoryItem,
): { hosts: Record<string, InventoryHost>; dropped: number } {
  const hosts: Record<string, InventoryHost> = { ...a.hosts };
  let count = Object.keys(hosts).length;
  let dropped = 0;
  for (const [k, h] of Object.entries(b.hosts)) {
    const cur = hosts[k];
    if (cur) hosts[k] = { ...cur, firstSeen: earlier(cur.firstSeen, h.firstSeen) };
    else if (count < INVENTORY_MAX_HOSTS) {
      hosts[k] = h;
      count++;
    } else dropped++;
  }
  return { hosts, dropped };
}

function mergeEntries(a: InventoryItem, b: InventoryItem): Pick<InventoryItem, "entries" | "entriesCapped"> {
  const list = [...(a.entries ?? [])];
  let capped = !!a.entriesCapped || !!b.entriesCapped;
  for (const e of b.entries ?? []) {
    if (list.some((x) => x.program === e.program && x.pathPattern === e.pathPattern)) continue;
    if (list.length >= MAX_ENTRIES) capped = true;
    else list.push(e);
  }
  return { ...(list.length ? { entries: list } : {}), ...(capped ? { entriesCapped: true as const } : {}) };
}

function mergeArtifacts(
  a: InventoryItem,
  b: InventoryItem,
): Pick<InventoryItem, "artifacts" | "artifactsIncomplete"> {
  if (!a.artifacts || !b.artifacts) return {};
  const u = union(a.artifacts, b.artifacts, MAX_VALUES);
  const incomplete = u.capped || !!a.artifactsIncomplete || !!b.artifactsIncomplete;
  return { artifacts: u.list, ...(incomplete ? { artifactsIncomplete: true as const } : {}) };
}

const flag = (on: boolean) => (on ? (true as const) : undefined);

/** Two items with the same canonical key as one; `a` is the canonical-form item when there is one. */
export function mergeInventoryItems(a: InventoryItem, b: InventoryItem): InventoryItem {
  const { hosts, dropped } = mergeHosts(a, b);
  const sha256 = union(a.sha256, b.sha256, MAX_VALUES);
  const sha1 = valueList(a.sha1, b.sha1, a.sha1Capped, b.sha1Capped);
  const signers = valueList(a.signers, b.signers, a.signersCapped, b.signersCapped);
  const sticky = {
    sha1OverLimit: flag(!!a.sha1OverLimit || !!b.sha1OverLimit),
    sha1NoSize: flag(!!a.sha1NoSize || !!b.sha1NoSize),
    signatureUnverified: flag(!!a.signatureUnverified || !!b.signatureUnverified),
    identityConflict: flag(!!a.identityConflict || !!b.identityConflict),
  };
  const merged: InventoryItem = {
    ...a,
    evidence: [...new Set([...a.evidence, ...b.evidence])],
    publishers: union(a.publishers, b.publishers, MAX_VALUES).list,
    sha256: sha256.list,
    unhashedHosts: missingHosts(a, b, (i) => i.unhashedHosts),
    hashesCapped: sha256.capped || a.hashesCapped !== false || b.hashesCapped !== false,
    sha1: sha1.list,
    noSha1Hosts: missingHosts(a, b, (i) => i.noSha1Hosts),
    sha1Capped: sha1.capped,
    signers: signers.list,
    unsignedHosts: missingHosts(a, b, (i) => i.unsignedHosts),
    signersCapped: signers.capped,
    ...sticky,
    md5: union(a.md5, b.md5, MAX_VALUES).list,
    sourceUrls: union(a.sourceUrls, b.sourceUrls, MAX_VALUES).list,
    hosts,
    hostOverflow: a.hostOverflow + b.hostOverflow + dropped,
    firstSeen: earlier(a.firstSeen, b.firstSeen),
    lastSeen: later(a.lastSeen, b.lastSeen),
  };
  const { entries: _e, entriesCapped: _ec, artifacts: _a, artifactsIncomplete: _ai, ...rest } = merged;
  const clean = Object.fromEntries(Object.entries(rest).filter(([, v]) => v !== undefined));
  return { ...(clean as Omit<InventoryItem, "entries">), ...mergeEntries(a, b), ...mergeArtifacts(a, b) };
}

/** The item with its path pattern (and its old entry identities) canonical, or the same item. */
function canonicalItem(item: InventoryItem): InventoryItem {
  if (!item || typeof item !== "object" || typeof item.pathPattern !== "string") return item;
  const pathPattern = canonicalPathPattern(item.pathPattern);
  const entries = (Array.isArray(item.entries) ? item.entries : undefined)?.map((e) => ({
    ...e,
    pathPattern: canonicalPathPattern(e.pathPattern),
  }));
  const entriesChanged = !!entries?.some((e, i) => e.pathPattern !== item.entries?.[i].pathPattern);
  if (pathPattern === item.pathPattern && !entriesChanged) return item;
  const next = { ...item, pathPattern, ...(entries ? { entries } : {}) };
  return { ...next, key: pathPattern === item.pathPattern ? item.key : keyOf(next) };
}

/** The inventory with every item on its canonical key, colliding items merged. */
export function canonicalizeInventory(inv: HuntInventory): { inventory: HuntInventory; changed: boolean } {
  const items: Record<string, InventoryItem> = {};
  let changed = false;
  const entries = Object.entries(inv.items);
  // Items already canonical go first, so a merge keeps the canonical item's own fields as its base.
  const ordered = [
    ...entries.filter(([, v]) => canonicalItem(v) === v),
    ...entries.filter(([, v]) => canonicalItem(v) !== v),
  ];
  for (const [k, raw] of ordered) {
    const item = canonicalItem(raw);
    const key = item === raw ? k : item.key;
    if (item !== raw) changed = true;
    const cur = items[key];
    items[key] = cur ? mergeInventoryItems(cur, item) : item;
  }
  return changed ? { inventory: { ...inv, items }, changed } : { inventory: inv, changed };
}
