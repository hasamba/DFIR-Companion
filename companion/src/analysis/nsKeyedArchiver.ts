// Resolves an NSKeyedArchiver-convention bplist (a dict with $archiver/$version/$top/$objects) into
// a plain object graph, substituting every UID reference with the object it names. Schema verified
// live against ydkhatri/nska_deserialize's own _recurse_safely()/_recurse_create_plist() (cycle
// handling: a UID re-entered while still on the active resolution stack is a genuine cycle, not a
// permanent memo) and cclgroupltd/ccl-bplist's own Foundation-container conventions (NSDictionary
// via NS.keys+NS.objects, NSArray/NSSet via NS.objects, NSData via NS.data, NSDate via NS.time,
// NSString via NS.string). #933 item 8 (importer half, #1013). See RECOMMENDATION-12.md.

import { BplistUid, type BplistValue } from "./bplistReader.js";

export const MAX_REFERENCE_EDGES = 500_000;
export const MAX_RESOLVE_DEPTH = 64;

export class NsKeyedArchiverError extends Error {}

export interface CycleMarker {
  cycle: true;
  uid: number;
}

export type ResolvedValue =
  | null
  | boolean
  | bigint
  | number
  | Date
  | Buffer
  | string
  | ResolvedValue[]
  | Map<string, ResolvedValue>
  | { unknownClass: string; raw: Map<string, ResolvedValue> }
  | CycleMarker;

export interface KeyedArchiveResult {
  roots: Map<string, ResolvedValue>;
}

function isCycle(v: ResolvedValue): v is CycleMarker {
  return typeof v === "object" && v !== null && "cycle" in v;
}

class Resolver {
  edges = 0;
  resolving = new Set<number>();

  constructor(private readonly objects: BplistValue[]) {}

  private bumpEdge(): void {
    this.edges += 1;
    if (this.edges > MAX_REFERENCE_EDGES) throw new NsKeyedArchiverError("reference-edge budget exceeded");
  }

  private classNameOf(dict: Map<BplistValue, BplistValue>): string | undefined {
    const classRef = dict.get("$class");
    if (!(classRef instanceof BplistUid)) return undefined;
    const classObj = this.objects[classRef.value];
    if (!(classObj instanceof Map)) return undefined;
    const name = classObj.get("$classname");
    return typeof name === "string" ? name : undefined;
  }

  resolve(value: BplistValue, depth: number): ResolvedValue {
    if (depth > MAX_RESOLVE_DEPTH) throw new NsKeyedArchiverError("resolve-depth budget exceeded");
    this.bumpEdge();

    if (value instanceof BplistUid) {
      const idx = value.value;
      if (idx < 0 || idx >= this.objects.length) throw new NsKeyedArchiverError("UID out of range");
      if (this.resolving.has(idx)) return { cycle: true, uid: idx };
      this.resolving.add(idx);
      try {
        return this.resolve(this.objects[idx], depth + 1);
      } finally {
        this.resolving.delete(idx);
      }
    }

    const v = value;
    if (v === "$null") return null;
    if (v === null) return null;
    if (typeof v === "boolean") return v;
    if (typeof v === "bigint") return v;
    if (typeof v === "number") return v;
    if (typeof v === "string") return v;
    if (v instanceof Date) return v;
    if (Buffer.isBuffer(v)) return v;

    if (Array.isArray(v)) {
      return v.map((el) => this.resolve(el, depth + 1));
    }
    const dict: Map<BplistValue, BplistValue> = v;

    // A dict: check for a recognized Foundation container by $classname before falling back to a
    // plain resolved map.
    const className = this.classNameOf(dict);
    if (className) {
      if (className === "NSData" || className === "NSMutableData") {
        const data = dict.get("NS.data");
        const resolved = data !== undefined ? this.resolve(data, depth + 1) : null;
        if (Buffer.isBuffer(resolved)) return resolved;
        return { unknownClass: className, raw: this.resolveDictBody(dict, depth) };
      }
      if (className === "NSString" || className === "NSMutableString") {
        const str = dict.get("NS.string");
        const resolved = str !== undefined ? this.resolve(str, depth + 1) : null;
        if (typeof resolved === "string") return resolved;
        return { unknownClass: className, raw: this.resolveDictBody(dict, depth) };
      }
      if (className === "NSDate") {
        const time = dict.get("NS.time");
        const resolved = time !== undefined ? this.resolve(time, depth + 1) : null;
        if (typeof resolved === "number" || typeof resolved === "bigint") {
          const secs = typeof resolved === "bigint" ? Number(resolved) : resolved;
          const date = new Date(Date.UTC(2001, 0, 1) + secs * 1000);
          // secs can be finite (or a huge bigint) and still produce an out-of-range Invalid Date —
          // reject it here rather than let it flow into the resolved object graph, where it would
          // silently degrade to null on JSON.stringify or throw for any later .toISOString() (#1190).
          if (Number.isNaN(date.getTime()))
            throw new NsKeyedArchiverError("date value out of representable range");
          return date;
        }
        return { unknownClass: className, raw: this.resolveDictBody(dict, depth) };
      }
      if (
        className === "NSArray" ||
        className === "NSMutableArray" ||
        className === "NSSet" ||
        className === "NSMutableSet"
      ) {
        const objs = dict.get("NS.objects");
        const resolved = objs !== undefined ? this.resolve(objs, depth + 1) : null;
        if (Array.isArray(resolved)) return resolved;
        return { unknownClass: className, raw: this.resolveDictBody(dict, depth) };
      }
      if (className === "NSDictionary" || className === "NSMutableDictionary") {
        const keys = dict.get("NS.keys");
        const objs = dict.get("NS.objects");
        const rKeys = keys !== undefined ? this.resolve(keys, depth + 1) : null;
        const rObjs = objs !== undefined ? this.resolve(objs, depth + 1) : null;
        if (Array.isArray(rKeys) && Array.isArray(rObjs) && rKeys.length === rObjs.length) {
          const out = new Map<string, ResolvedValue>();
          for (let i = 0; i < rKeys.length; i++) {
            const k = rKeys[i];
            if (typeof k === "string" && !isCycle(rObjs[i])) out.set(k, rObjs[i]);
          }
          return out;
        }
        return { unknownClass: className, raw: this.resolveDictBody(dict, depth) };
      }
      // A known-but-unrecognized class: preserved as a tagged, un-interpreted record — never
      // guessed at (the design's own corrected lesson from the design-review rejection).
      return { unknownClass: className, raw: this.resolveDictBody(dict, depth) };
    }

    // A plain (non-NS-object) dict — resolve every entry generically.
    return this.resolveDictBody(dict, depth);
  }

  private resolveDictBody(dict: Map<BplistValue, BplistValue>, depth: number): Map<string, ResolvedValue> {
    const out = new Map<string, ResolvedValue>();
    for (const [k, v] of dict) {
      if (k === "$class") continue;
      const key = typeof k === "string" ? k : this.resolve(k, depth + 1);
      if (typeof key !== "string") continue; // a non-string key can't be carried into this map shape
      out.set(key, this.resolve(v, depth + 1));
    }
    return out;
  }
}

export function resolveKeyedArchive(root: BplistValue): KeyedArchiveResult | null {
  if (!(root instanceof Map)) return null;
  const archiver = root.get("$archiver");
  if (archiver !== "NSKeyedArchiver" && archiver !== "NRKeyedArchiver") return null;
  const objectsRaw = root.get("$objects");
  const topRaw = root.get("$top");
  if (!Array.isArray(objectsRaw) || !(topRaw instanceof Map)) return null;

  const resolver = new Resolver(objectsRaw);
  const roots = new Map<string, ResolvedValue>();
  for (const [name, ref] of topRaw) {
    if (typeof name !== "string") continue;
    roots.set(name, resolver.resolve(ref, 0));
  }
  return { roots };
}
