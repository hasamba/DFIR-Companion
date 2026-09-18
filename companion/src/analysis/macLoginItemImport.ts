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
// #1301 adds the two pre-BTM containers: `SessionLoginItems.sfl2` (a keyed archive whose root is a
// dict with `items[]` of {Name, uuid, Bookmark, CustomItemProperties} — shape read from mac_apt's
// ReadSFL2Plist and macMRU-Parser's ParseSFL2) and the classic `com.apple.loginitems.plist` (a PLAIN
// bplist, `SessionItems.CustomListItems[]` of {Name, Alias} — mac_apt's process_loginitems_plist),
// whose `Alias` bytes are either a classic Alias Manager record (aliasRecordReader.ts) or, on
// later systems, a CFURL bookmark; the two are told apart by structure, never by the first four
// bytes. The filename gate in macBinaryDetect.ts is what keeps an MRU `.sfl2` (same container) out
// of here — the parser cannot tell a RecentDocuments list from a login-item list by shape.

import { createHash } from "node:crypto";
import { boundedAggKey } from "./aggKey.js";
import { BplistUid, parseBplist, type BplistValue } from "./bplistReader.js";
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
import { looksLikeAliasRecord, parseAliasRecord } from "./aliasRecordReader.js";
import {
  MAC_LOGIN_ITEM_ALIAS_BASIS,
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
  /** Items kept (never dropped -- see mapItem) whose own bookmark data failed to decode; disclosed
   * separately from malformedItems/dropped, which stay 0 because no item is ever discarded here. */
  malformedBookmarks: number;
  sourceFormat: SourceFormat;
}

type SourceFormat = "btm-legacy" | "btm-modern" | "sfl2" | "loginitems-plist";
const FORMAT_LABEL: Record<SourceFormat, string> = {
  "btm-legacy": "MacBtmLegacy",
  "btm-modern": "MacBtmModern",
  sfl2: "MacSfl2",
  "loginitems-plist": "MacLoginItemsPlist",
};

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
  recordKind?: "cfurl-bookmark" | "alias-record";
  targetPathComponents?: string[];
  targetCnidPath?: string[];
  volumeName?: string;
  volumeUuid?: string;
  volumeIsRoot?: boolean;
  fileCreationDate?: string;
  wasFileReference?: boolean;
  displayName?: string;
  decodeStatus: "decoded" | "malformed" | "absent";
  tocTruncated?: boolean;
  aliasVersion?: 2 | 3;
  aliasKind?: number;
  targetCnid?: string;
  folderCnid?: string;
  volumeCreationDate?: string;
  posixMountPoint?: string;
  aliasUnknownTags?: number[];
  /** A carbon (colon-separated) path when the record has no POSIX path — shown as stored, never split. */
  carbonPath?: string;
  /** Extra disclosed facts an alias record carries (appinfo, recsize, fs/disk type, codes). */
  aliasRaw?: Record<string, string>;
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
      ...(bm.tocChainTruncated ? { tocTruncated: true } : {}),
      recordKind: "cfurl-bookmark" as const,
    };
  } catch {
    return { decodeStatus: "malformed", recordKind: "cfurl-bookmark" };
  }
}

function pathComponents(posix: string): string[] {
  return posix
    .split("/")
    .filter((c) => c.length > 0)
    .slice(0, MAX_PATH_DEPTH)
    .map((c) => clip(c, MAX_FIELD_LEN));
}

function decodeAlias(bytes: Buffer): BookmarkFacts {
  try {
    const a = parseAliasRecord(bytes);
    const aliasRaw: Record<string, string> = { aliasAppinfo: a.appinfo, aliasRecsize: String(a.recsize) };
    if (a.fsType) aliasRaw.aliasFsType = a.fsType;
    if (a.diskType !== undefined) aliasRaw.aliasDiskType = String(a.diskType);
    if (a.creatorCode) aliasRaw.aliasCreatorCode = a.creatorCode;
    if (a.typeCode) aliasRaw.aliasTypeCode = a.typeCode;
    if (a.levelsFrom !== undefined) aliasRaw.aliasLevelsFrom = String(a.levelsFrom);
    if (a.levelsTo !== undefined) aliasRaw.aliasLevelsTo = String(a.levelsTo);
    if (a.volumeAttributes !== undefined) aliasRaw.aliasVolumeAttributes = String(a.volumeAttributes);
    if (a.folderName) aliasRaw.aliasFolderName = clip(a.folderName, MAX_FIELD_LEN);
    if (a.pascalFilename && a.pascalFilename !== a.targetFilename)
      aliasRaw.aliasPascalFilename = clip(a.pascalFilename, MAX_FIELD_LEN);
    if (a.userHomePrefixLen !== undefined) aliasRaw.aliasUserHomePrefixLen = String(a.userHomePrefixLen);
    return {
      recordKind: "alias-record",
      decodeStatus: "decoded",
      aliasVersion: a.version,
      aliasKind: a.kind,
      ...(a.posixPath ? { targetPathComponents: pathComponents(a.posixPath) } : {}),
      ...(a.cnidPath ? { targetCnidPath: a.cnidPath.slice(0, MAX_PATH_DEPTH).map((c) => String(c)) } : {}),
      ...(a.targetCnid !== undefined ? { targetCnid: String(a.targetCnid) } : {}),
      ...(a.folderCnid !== undefined ? { folderCnid: String(a.folderCnid) } : {}),
      ...(a.volumeName ? { volumeName: clip(a.volumeName, MAX_FIELD_LEN) } : {}),
      ...(a.volumeCreationDate ? { volumeCreationDate: a.volumeCreationDate } : {}),
      ...(a.targetCreationDate ? { fileCreationDate: a.targetCreationDate } : {}),
      ...(a.targetFilename ? { displayName: clip(a.targetFilename, MAX_FIELD_LEN) } : {}),
      ...(a.posixMountPoint ? { posixMountPoint: clip(a.posixMountPoint, MAX_FIELD_LEN) } : {}),
      ...(a.carbonPath ? { carbonPath: clip(a.carbonPath, MAX_FIELD_LEN) } : {}),
      ...(a.unknownTags.length ? { aliasUnknownTags: a.unknownTags.slice(0, 64) } : {}),
      aliasRaw,
    };
  } catch {
    return { decodeStatus: "malformed", recordKind: "alias-record" };
  }
}

/**
 * The classic plist's `Alias` key holds either a classic Alias Manager record or (later systems) a
 * CFURL bookmark. Dispatch is by STRUCTURE — the alias header's version and recsize — never by the
 * first four bytes, which are a caller-set `appinfo` code that may legally read "alis" (#1301
 * design review finding 2). Undecidable bytes are malformed, never guessed.
 */
function decodeAliasOrBookmark(bytes: Buffer | undefined): BookmarkFacts {
  if (!bytes) return { decodeStatus: "absent" };
  if (looksLikeAliasRecord(bytes)) return decodeAlias(bytes);
  const magic = bytes.length >= 4 ? bytes.toString("ascii", 0, 4) : "";
  if (magic === "book" || magic === "alis") return decodeBookmark(bytes);
  return { decodeStatus: "malformed", recordKind: "alias-record" };
}

interface RawItem {
  sourceFormat: SourceFormat;
  itemName?: string;
  userUuid?: string;
  locator: string;
  itemType?: number;
  modificationDate?: string;
  executableModificationDate?: string;
  sha256?: string;
  rawFields: Record<string, string>;
  bookmarkBytes?: Buffer;
  /** Set for the classic plist: the `Alias` bytes, decoded by structure (alias record or bookmark). */
  aliasBytes?: Buffer;
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

/** Copies every entry of `m` not in `skip` into `rawFields` under `prefix`, one level deep, bounded. */
function rawFieldsFrom(
  m: Map<string, ResolvedValue>,
  skip: ReadonlySet<string>,
  prefix: string,
  rawFields: Record<string, string>,
): void {
  for (const [k, v] of m) {
    if (skip.has(k)) continue;
    if (Object.keys(rawFields).length >= MAX_RAW_FIELDS) break;
    if (k === "CustomItemProperties" && isMap(v)) {
      rawFieldsFrom(v, new Set(), `${prefix}CustomItemProperties.`, rawFields);
      continue;
    }
    rawFields[clip(`${prefix}${k}`, 60)] = clip(stringifyRaw(v), MAX_FIELD_LEN);
  }
}

const SFL2_TYPED_KEYS: ReadonlySet<string> = new Set(["Name", "Bookmark"]);

function collectSfl2Items(root: Map<string, ResolvedValue>): RawItem[] {
  const items: RawItem[] = [];
  const list = root.get("items");
  if (!Array.isArray(list)) return items;
  list.forEach((item, i) => {
    if (!isMap(item)) return;
    const rawFields: Record<string, string> = {};
    rawFieldsFrom(item, SFL2_TYPED_KEYS, "", rawFields);
    const name = item.get("Name");
    items.push({
      sourceFormat: "sfl2",
      locator: `sfl2:${i}`,
      ...(typeof name === "string" ? { itemName: clip(name, MAX_FIELD_LEN) } : {}),
      rawFields,
      bookmarkBytes: asBuffer(item.get("Bookmark")),
    });
  });
  return items;
}

const LOGINITEMS_TYPED_KEYS: ReadonlySet<string> = new Set(["Name", "Alias"]);

/** The classic plain-plist container: SessionItems.CustomListItems[] of {Name, Alias}. */
function collectLoginItemsPlistItems(root: Map<string, ResolvedValue>): RawItem[] | null {
  const session = root.get("SessionItems");
  const list = isMap(session) ? session.get("CustomListItems") : undefined;
  if (!Array.isArray(list)) return null;
  const items: RawItem[] = [];
  list.forEach((item, i) => {
    if (!isMap(item)) return;
    const rawFields: Record<string, string> = {};
    rawFieldsFrom(item, LOGINITEMS_TYPED_KEYS, "", rawFields);
    const name = item.get("Name");
    items.push({
      sourceFormat: "loginitems-plist",
      locator: `sessionitem:${i}`,
      ...(typeof name === "string" ? { itemName: clip(name, MAX_FIELD_LEN) } : {}),
      rawFields,
      aliasBytes: asBuffer(item.get("Alias")),
    });
  });
  return items;
}

/** A plain (non-keyed-archive) bplist resolves to the same Map/array shapes the archive resolver emits. */
function plainValue(v: BplistValue, depth = 0): ResolvedValue {
  if (depth > MAX_PLAIN_DEPTH) return null;
  if (v instanceof BplistUid) return null;
  if (Array.isArray(v)) return v.map((e) => plainValue(e, depth + 1));
  if (v instanceof Map) {
    const out = new Map<string, ResolvedValue>();
    for (const [k, val] of v) if (typeof k === "string") out.set(k, plainValue(val, depth + 1));
    return out;
  }
  return v;
}
const MAX_PLAIN_DEPTH = 16;

function mapItem(
  item: RawItem,
  reportFingerprint: string,
): { event: MappedEvent; bookmarkMalformed: boolean } {
  const facts = item.aliasBytes ? decodeAliasOrBookmark(item.aliasBytes) : decodeBookmark(item.bookmarkBytes);
  const targetBytes = item.aliasBytes ?? item.bookmarkBytes;
  // The FULL digest, never a clipped slice — a clipped digest fed into an identity hash risks
  // colliding two content-distinct bookmarks that happen to share the same short prefix (the
  // standing "hash unclipped raw values" lesson from item 11, per Ollama code review finding).
  const bookmarkDigest = targetBytes ? createHash("sha256").update(targetBytes).digest("hex") : "none";
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
  const isAlias = facts.recordKind === "alias-record";
  const pathLabel = facts.targetPathComponents?.length
    ? `/${facts.targetPathComponents.join("/")}`
    : facts.carbonPath
      ? `(carbon path ${facts.carbonPath})`
      : facts.decodeStatus === "decoded" && facts.displayName
        ? `(alias: ${facts.displayName}${facts.volumeName ? ` on ${facts.volumeName}` : ""})`
        : facts.decodeStatus === "malformed"
          ? isAlias
            ? "(alias record malformed)"
            : "(bookmark malformed)"
          : "(no bookmark)";
  const nameLabel = item.itemName ? ` "${item.itemName}"` : "";
  const body = clip(
    `macOS login item (${item.sourceFormat})${nameLabel}: ${pathLabel} — a decoded configuration record, ` +
      `never evidence of execution`,
    600 - reportTag.length,
  );
  const isV1 = item.sourceFormat === "btm-legacy" || item.sourceFormat === "btm-modern";
  const rawFields = { ...item.rawFields, ...(facts.aliasRaw ?? {}) };
  const description = `${body}${reportTag}`;

  const event: MappedEvent = {
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
        ...(item.itemName ? { itemName: item.itemName } : {}),
        ...(item.userUuid ? { userUuid: item.userUuid } : {}),
        ...(item.itemType !== undefined ? { itemType: item.itemType } : {}),
        ...(item.modificationDate ? { modificationDate: item.modificationDate } : {}),
        ...(item.executableModificationDate
          ? { executableModificationDate: item.executableModificationDate }
          : {}),
        ...(item.sha256 ? { sha256: item.sha256 } : {}),
        ...(Object.keys(rawFields).length ? { rawFields } : {}),
        ...(facts.targetPathComponents ? { targetPathComponents: facts.targetPathComponents } : {}),
        ...(facts.targetCnidPath ? { targetCnidPath: facts.targetCnidPath } : {}),
        ...(facts.volumeName ? { volumeName: facts.volumeName } : {}),
        ...(facts.volumeUuid ? { volumeUuid: facts.volumeUuid } : {}),
        ...(facts.volumeIsRoot !== undefined ? { volumeIsRoot: facts.volumeIsRoot } : {}),
        ...(facts.fileCreationDate ? { fileCreationDate: facts.fileCreationDate } : {}),
        ...(facts.wasFileReference !== undefined ? { wasFileReference: facts.wasFileReference } : {}),
        ...(facts.displayName ? { displayName: facts.displayName } : {}),
        bookmarkDecodeStatus: facts.decodeStatus,
        ...(facts.tocTruncated ? { bookmarkTocTruncated: true } : {}),
        ...(!isV1 && facts.recordKind ? { targetRecordKind: facts.recordKind } : {}),
        ...(facts.aliasVersion ? { aliasVersion: facts.aliasVersion } : {}),
        ...(facts.aliasKind !== undefined ? { aliasKind: facts.aliasKind } : {}),
        ...(facts.targetCnid ? { targetCnid: facts.targetCnid } : {}),
        ...(facts.folderCnid ? { folderCnid: facts.folderCnid } : {}),
        ...(facts.volumeCreationDate ? { volumeCreationDate: facts.volumeCreationDate } : {}),
        ...(facts.posixMountPoint ? { posixMountPoint: facts.posixMountPoint } : {}),
        ...(facts.aliasUnknownTags ? { aliasUnknownTags: facts.aliasUnknownTags } : {}),
        targetEvidence: isAlias ? "stored-alias-metadata" : "stored-bookmark-metadata",
        reportFingerprint,
        mappingVersion: isV1 ? "mac-login-item-target-v1" : "mac-login-item-target-v2",
        basis: isAlias ? MAC_LOGIN_ITEM_ALIAS_BASIS : MAC_LOGIN_ITEM_BASIS,
      },
    }),
  };
  return { event, bookmarkMalformed: facts.decodeStatus === "malformed" };
}

export function parseMacLoginItemBtm(
  bytes: Buffer,
  opts: MacLoginItemOptions = {},
): MacLoginItemResult | null {
  // Cheap, exception-free check first: if the bytes don't even carry the real bplist00 magic,
  // this is simply the wrong format -- return null the same way every other importer's "not this
  // format" path does. Anything that fails PAST this point is a genuine parse/structural/budget
  // problem with what IS a real bplist, and must propagate as a real error rather than being
  // silently folded into the same "not recognized" signal (Ollama code review finding: budget-
  // exceeded and bounds errors were previously indistinguishable from "wrong format" and surfaced
  // as a misleading 400 rather than the real failure).
  if (bytes.length < 8 || bytes.toString("ascii", 0, 8) !== "bplist00") return null;

  const plist = parseBplist(bytes);
  const parsed = resolveKeyedArchive(plist);
  let items: RawItem[] = [];
  let sourceFormat: SourceFormat;
  if (!parsed) {
    // Not a keyed archive: the only plain-plist shape accepted is the classic loginitems plist.
    const plain = plainValue(plist);
    const collected = isMap(plain) ? collectLoginItemsPlistItems(plain) : null;
    if (!collected) return null;
    sourceFormat = "loginitems-plist";
    items = collected;
  } else {
    const r = parsed.roots.get("root");
    if (r === undefined) return null;
    const root: ResolvedValue = r;
    // The legacy guard excludes a root carrying `items` so an sfl2 that happens to store
    // `version: 2` is not claimed here and silently emptied (#1301 design review finding 8).
    if (isMap(root) && asNumber(root.get("version")) === 2 && !Array.isArray(root.get("items"))) {
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
    } else if (isMap(root) && Array.isArray(root.get("items"))) {
      sourceFormat = "sfl2";
      items = collectSfl2Items(root);
    } else {
      return null; // no confirmed shape matched -- never a blind fallback
    }
  }

  const reportFingerprint = createHash("sha256").update(bytes).digest("hex");
  const mapped: MappedEvent[] = [];
  let total = 0;
  const malformedItems = 0; // no item is ever discarded here -- see malformedBookmarks instead
  let malformedBookmarks = 0;
  for (const item of items) {
    if (total >= MAX_ITEMS_SCANNED) break;
    total += 1;
    const { event, bookmarkMalformed } = mapItem(item, reportFingerprint);
    if (bookmarkMalformed) malformedBookmarks += 1;
    mapped.push(event);
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
    format: FORMAT_LABEL[sourceFormat],
    malformedItems,
    malformedBookmarks,
    sourceFormat,
  };
}
