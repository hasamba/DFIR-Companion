// macOS Background Task Management login-item parser (#933 item 8, importer half, #1013). Two
// real, confirmed generations, schema-verified live against mnrkbys/bgiparser's own parse_btm()
// (Apache-2.0, cloned and read live): legacy (macOS <= 12, backgrounditems.btm) — a dict with
// `version === 2`, items at `backgroundItems.allContainers[*].internalItems[0].bookmark.data`; and
// modern (macOS 13+, BackgroundItems-v*.btm) — a 2-element array whose first element carries
// `version >= 3`, items at element[1].store.itemsByUserIdentifier[userUuid][*]. bgiparser's own
// code confirms exactly four modern per-item fields (type, modificationDate,
// executableModificationDate, sha256) plus the bookmark/lightweightRequirement byte fields; every
// OTHER present key is carried through as disclosed, unconfirmed rawFields rather than asserted
// into a guessed schema. See RECOMMENDATION-12.md for the full research trail.

import { createHash } from "node:crypto";
import { boundedAggKey } from "./aggKey.js";
import { parseBplist } from "./bplistReader.js";
import { resolveKeyedArchive, type ResolvedValue } from "./nsKeyedArchiver.js";
import {
  parseBookmark,
  bookmarkGet,
  kBookmarkPath,
  kBookmarkCNIDPath,
  kBookmarkVolumeName,
  kBookmarkVolumeUUID,
  kBookmarkVolumeIsRoot,
  kBookmarkFileCreationDate,
  kBookmarkWasFileReference,
  kBookmarkDisplayName,
} from "./cfurlBookmarkReader.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import {
  MAC_LOGIN_ITEM_BASIS,
  MAX_FIELD_LEN,
  MAX_PATH_DEPTH,
  MAX_RAW_FIELDS,
} from "./canonicalMacLoginItemTarget.js";
import type { MappedEvent, SiemEvent } from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";

export const MAX_ITEMS_SCANNED = 5_000; // report-wide — BTM files are small in real data

export interface MacLoginItemOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface MacLoginItemResult {
  events: SiemEvent[];
  iocs: [];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformedItems: number;
  sourceFormat: "btm-legacy" | "btm-modern";
}

function clip(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max);
}

function isMap(v: ResolvedValue | undefined): v is Map<string, ResolvedValue> {
  return v instanceof Map;
}

function asNumber(v: ResolvedValue | undefined): number | undefined {
  if (typeof v === "number") return Number.isFinite(v) ? v : undefined;
  if (typeof v === "bigint") return Number.isSafeInteger(Number(v)) ? Number(v) : undefined;
  return undefined;
}

function asDate(v: ResolvedValue | undefined): string | undefined {
  return v instanceof Date ? v.toISOString() : undefined;
}

function asBuffer(v: ResolvedValue | undefined): Buffer | undefined {
  return Buffer.isBuffer(v) ? v : undefined;
}

function stringifyRaw(v: ResolvedValue): string {
  if (v === null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "bigint" || typeof v === "boolean") return String(v);
  if (v instanceof Date) return v.toISOString();
  if (Buffer.isBuffer(v)) return v.toString("hex");
  if (Array.isArray(v)) return "[array]";
  if (v instanceof Map) return "[dict]";
  return "[object]";
}

interface BookmarkFacts {
  targetPathComponents?: string[];
  targetCnidPath?: string[];
  volumeName?: string;
  volumeUuid?: string;
  volumeIsRoot?: boolean;
  fileCreationDate?: string;
  wasFileReference?: boolean;
  displayName?: string;
  decodeStatus: "decoded" | "malformed" | "absent";
}

function decodeBookmark(bytes: Buffer | undefined): BookmarkFacts {
  if (!bytes) return { decodeStatus: "absent" };
  try {
    const bm = parseBookmark(bytes);
    const pathRaw = bookmarkGet(bm, kBookmarkPath);
    const cnidRaw = bookmarkGet(bm, kBookmarkCNIDPath);
    const targetPathComponents = Array.isArray(pathRaw)
      ? pathRaw
          .filter((p): p is string => typeof p === "string")
          .slice(0, MAX_PATH_DEPTH)
          .map((p) => clip(p, MAX_FIELD_LEN))
      : undefined;
    const targetCnidPath = Array.isArray(cnidRaw)
      ? cnidRaw
          .filter((c): c is number | bigint => typeof c === "number" || typeof c === "bigint")
          .slice(0, MAX_PATH_DEPTH)
          .map((c) => String(c))
      : undefined;
    const volumeNameRaw = bookmarkGet(bm, kBookmarkVolumeName);
    const volumeUuidRaw = bookmarkGet(bm, kBookmarkVolumeUUID);
    const displayNameRaw = bookmarkGet(bm, kBookmarkDisplayName);
    const creationRaw = bookmarkGet(bm, kBookmarkFileCreationDate);
    return {
      ...(targetPathComponents ? { targetPathComponents } : {}),
      ...(targetCnidPath ? { targetCnidPath } : {}),
      ...(typeof volumeNameRaw === "string" ? { volumeName: clip(volumeNameRaw, MAX_FIELD_LEN) } : {}),
      ...(typeof volumeUuidRaw === "string" ? { volumeUuid: clip(volumeUuidRaw, MAX_FIELD_LEN) } : {}),
      ...(typeof bookmarkGet(bm, kBookmarkVolumeIsRoot) === "boolean"
        ? { volumeIsRoot: bookmarkGet(bm, kBookmarkVolumeIsRoot) as boolean }
        : {}),
      ...(creationRaw instanceof Date ? { fileCreationDate: creationRaw.toISOString() } : {}),
      ...(typeof bookmarkGet(bm, kBookmarkWasFileReference) === "boolean"
        ? { wasFileReference: bookmarkGet(bm, kBookmarkWasFileReference) as boolean }
        : {}),
      ...(typeof displayNameRaw === "string" ? { displayName: clip(displayNameRaw, MAX_FIELD_LEN) } : {}),
      decodeStatus: "decoded" as const,
    };
  } catch {
    return { decodeStatus: "malformed" };
  }
}

interface RawItem {
  sourceFormat: "btm-legacy" | "btm-modern";
  userUuid?: string;
  locator: string;
  itemType?: number;
  modificationDate?: string;
  executableModificationDate?: string;
  sha256?: string;
  rawFields: Record<string, string>;
  bookmarkBytes?: Buffer;
}

function collectLegacyItems(root: Map<string, ResolvedValue>): RawItem[] {
  const items: RawItem[] = [];
  const backgroundItems = root.get("backgroundItems");
  const allContainers = isMap(backgroundItems) ? backgroundItems.get("allContainers") : undefined;
  if (!Array.isArray(allContainers)) return items;
  allContainers.forEach((container, i) => {
    if (!isMap(container)) return;
    const internalItems = container.get("internalItems");
    if (!Array.isArray(internalItems) || internalItems.length === 0) return;
    const first = internalItems[0];
    if (!isMap(first)) return;
    const bookmark = first.get("bookmark");
    const data = isMap(bookmark) ? bookmark.get("data") : undefined;
    items.push({
      sourceFormat: "btm-legacy",
      locator: `container:${i}`,
      rawFields: {},
      bookmarkBytes: asBuffer(data),
    });
  });
  return items;
}

function collectModernItems(root: ResolvedValue[]): RawItem[] {
  const items: RawItem[] = [];
  const store = isMap(root[1]) ? root[1].get("store") : undefined;
  const byUser = isMap(store) ? store.get("itemsByUserIdentifier") : undefined;
  if (!isMap(byUser)) return items;
  for (const [uuid, list] of byUser) {
    if (!Array.isArray(list)) continue;
    list.forEach((item, i) => {
      if (!isMap(item)) return;
      const rawFields: Record<string, string> = {};
      let fieldCount = 0;
      for (const [k, v] of item) {
        if (
          k === "type" ||
          k === "modificationDate" ||
          k === "executableModificationDate" ||
          k === "sha256"
        ) {
          continue;
        }
        if (k === "bookmark" || k === "lightweightRequirement") continue; // bytes-bearing, handled separately
        if (fieldCount >= MAX_RAW_FIELDS) break;
        rawFields[clip(k, 60)] = clip(stringifyRaw(v), MAX_FIELD_LEN);
        fieldCount += 1;
      }
      const sha = asBuffer(item.get("sha256"));
      items.push({
        sourceFormat: "btm-modern",
        userUuid: clip(uuid, MAX_FIELD_LEN),
        locator: `${uuid}:${i}`,
        itemType: asNumber(item.get("type")),
        modificationDate: asDate(item.get("modificationDate")),
        executableModificationDate: asDate(item.get("executableModificationDate")),
        ...(sha ? { sha256: sha.toString("hex") } : {}),
        rawFields,
        bookmarkBytes: asBuffer(item.get("bookmark")),
      });
    });
  }
  return items;
}

function mapItem(item: RawItem, reportFingerprint: string): MappedEvent {
  const facts = decodeBookmark(item.bookmarkBytes);
  const bookmarkDigest = item.bookmarkBytes
    ? createHash("sha256").update(item.bookmarkBytes).digest("hex").slice(0, 16)
    : "none";
  const findingId = createHash("sha256")
    .update(
      JSON.stringify([
        item.sourceFormat,
        item.userUuid ?? "",
        item.locator,
        item.itemType ?? "",
        item.modificationDate ?? "",
        bookmarkDigest,
      ]),
    )
    .digest("hex");
  const aggKey = boundedAggKey(`mac-login-item|${reportFingerprint}|${findingId}`);

  const reportTag = `; report ${reportFingerprint.slice(0, 16)}, item ${findingId.slice(0, 12)}`;
  const pathLabel = facts.targetPathComponents?.length
    ? `/${facts.targetPathComponents.join("/")}`
    : facts.decodeStatus === "malformed"
      ? "(bookmark malformed)"
      : "(no bookmark)";
  const body = clip(
    `macOS login item (${item.sourceFormat}): ${pathLabel} — a decoded configuration record, ` +
      `never evidence of execution`,
    600 - reportTag.length,
  );
  const description = `${body}${reportTag}`;

  return {
    timestamp: "",
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["bookmark-decoder"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "mac-login-item", action: "reported" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "bookmark-decoder", locator: `item:${findingId.slice(0, 16)}` }] },
      producer: {
        importer: "mac-login-item",
        parserVersion: "1",
        mappingVersion: "mac-login-item-target-v1",
      },
      macLoginItem: {
        tool: "bookmark-decoder",
        sourceFormat: item.sourceFormat,
        ...(item.userUuid ? { userUuid: item.userUuid } : {}),
        ...(item.itemType !== undefined ? { itemType: item.itemType } : {}),
        ...(item.modificationDate ? { modificationDate: item.modificationDate } : {}),
        ...(item.executableModificationDate
          ? { executableModificationDate: item.executableModificationDate }
          : {}),
        ...(item.sha256 ? { sha256: item.sha256 } : {}),
        ...(Object.keys(item.rawFields).length ? { rawFields: item.rawFields } : {}),
        ...(facts.targetPathComponents ? { targetPathComponents: facts.targetPathComponents } : {}),
        ...(facts.targetCnidPath ? { targetCnidPath: facts.targetCnidPath } : {}),
        ...(facts.volumeName ? { volumeName: facts.volumeName } : {}),
        ...(facts.volumeUuid ? { volumeUuid: facts.volumeUuid } : {}),
        ...(facts.volumeIsRoot !== undefined ? { volumeIsRoot: facts.volumeIsRoot } : {}),
        ...(facts.fileCreationDate ? { fileCreationDate: facts.fileCreationDate } : {}),
        ...(facts.wasFileReference !== undefined ? { wasFileReference: facts.wasFileReference } : {}),
        ...(facts.displayName ? { displayName: facts.displayName } : {}),
        bookmarkDecodeStatus: facts.decodeStatus,
        targetEvidence: "stored-bookmark-metadata",
        reportFingerprint,
        mappingVersion: "mac-login-item-target-v1",
        basis: MAC_LOGIN_ITEM_BASIS,
      },
    }),
  };
}

export function parseMacLoginItemBtm(
  bytes: Buffer,
  opts: MacLoginItemOptions = {},
): MacLoginItemResult | null {
  let root: ResolvedValue;
  try {
    const parsed = resolveKeyedArchive(parseBplist(bytes));
    if (!parsed) return null;
    const r = parsed.roots.get("root");
    if (r === undefined) return null;
    root = r;
  } catch {
    return null;
  }

  let items: RawItem[] = [];
  let sourceFormat: "btm-legacy" | "btm-modern";
  if (isMap(root) && asNumber(root.get("version")) === 2) {
    sourceFormat = "btm-legacy";
    items = collectLegacyItems(root);
  } else if (
    Array.isArray(root) &&
    root.length >= 2 &&
    isMap(root[0]) &&
    (asNumber(root[0].get("version")) ?? 0) >= 3
  ) {
    sourceFormat = "btm-modern";
    items = collectModernItems(root);
  } else {
    return null; // neither confirmed BTM shape matched -- never a blind fallback
  }

  const reportFingerprint = createHash("sha256").update(bytes).digest("hex");
  const mapped: MappedEvent[] = [];
  let total = 0;
  const malformedItems = 0;
  for (const item of items) {
    if (total >= MAX_ITEMS_SCANNED) break;
    total += 1;
    mapped.push(mapItem(item, reportFingerprint));
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_ITEMS_SCANNED,
  });

  return {
    events,
    iocs: [],
    total,
    kept: events.length,
    dropped: malformedItems,
    groups,
    format: sourceFormat === "btm-legacy" ? "MacBtmLegacy" : "MacBtmModern",
    malformedItems,
    sourceFormat,
  };
}
