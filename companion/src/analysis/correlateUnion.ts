// The guarded union-find behind correlate.ts, and the enumeration that feeds it (#1476, #1483).
//
// Every component carries the set of STRUCTURED paths, the set of EXECUTION identities (see
// chainSignature.ts executionIdentity) and the set of LOG RECORD identities (sourceRecordId) its
// members recorded. A union that would put two different paths, two different launches, or two
// different log records into one row is refused — at the union, not pairwise in one step, so the
// refusal holds transitively: an execution cannot reach a second execution through a file-write
// row they both touch, a file cannot reach a second file through a hash-only hit, and two records
// of the SAME command a second apart (a repeated launch) stay two rows even when each record was
// read by two parsers.
//
// Before this, four renamed copies of one binary (one hash, four paths, no pid) became one row that
// named one of them, and three launches of one binary 1 s apart (same path, three command lines)
// became one row — the other files and launches simply left the forensic timeline.
//
// A fourth fact is the ACT a typed row records (#1557): a file write and a process start are two
// facts about one binary — who dropped it, and what it ran — so a component holding one never takes
// in the other, whatever path, hash or pid they share, and no untyped row can bridge the two.
//
// Three more facts are the PEER a network connection reached (#1922): destination address, port and
// protocol, each its own fact. A Sysmon EID 3 burst from one image — mDNS multicasts and one TCP
// connection to a C2 server — shares the image path, and an Amcache row of that image within 2 s
// corroborated each connection pairwise; the union is transitive, so every connection became one row
// and the multicast text won. A row with no peer (Amcache, Prefetch, MFT) still joins one connection.
// They stay separate facts so a reading that knows only the address (a Hayabusa row) still merges
// with one that knows all three (a Chainsaw reading of the same record, #688).
//
// A member with no structured path, or no command line, constrains nothing and joins freely; a
// pathless hash-only hit that could belong to either of two files stays on its own (that ambiguity
// is real, and picking one would be the guess this refuses to make).
//
// The guard is MONOTONE: a component only gains facts, so a refused pair stays refused and a
// compatible pair can only become incompatible. #1476 therefore compared every pair of a bucket
// (a chain anchored on one member left same-path pairs behind a refusal un-compared), which made a
// hash bucket of n rows cost n²/2 unions — 20k file-write rows of one binary on one host took 5–19
// s on the event loop, on every merge and every synthesis (#1483). unionEligible below reaches the
// same end state without the cross product: no two distinct components remain compatible while an
// eligible pair of their members exists.

/** The facts a merged row must never contradict, read once per event by the caller. */
export interface UnionFacts {
  path?: string;
  exec?: string;
  record?: string;
  /** "file-write" or "process-start" for a typed row; unset when the row's act is not one of them (#1557). */
  act?: string;
  /** The destination address of a network connection, lowercased (#1922). */
  dstAddr?: string;
  /** The destination port, as a decimal string (#1922). */
  dstPort?: string;
  /** The transport protocol, lowercased (#1922). */
  proto?: string;
}

/** The structural slice of an event the peer facts are read from — no import edge on stateTypes. */
export interface NetworkPeerSource {
  canonical?: { network?: { destination?: { address?: string; port?: number }; protocol?: string } };
  dstIp?: string;
  port?: number;
}

const IANA_PROTOCOL_NAMES: Readonly<Record<string, string>> = {
  "1": "icmp",
  "6": "tcp",
  "17": "udp",
  "58": "ipv6-icmp",
};

/** The destination of a network connection as three union facts; each is undefined when absent (#1922). */
export function networkPeerFacts(e: NetworkPeerSource): Pick<UnionFacts, "dstAddr" | "dstPort" | "proto"> {
  const net = e.canonical?.network;
  // An IPv4-mapped IPv6 address and an IANA protocol number name the same peer as their plain forms,
  // so two parsers' readings of one record never split on spelling.
  const addr = (net?.destination?.address ?? e.dstIp ?? "")
    .trim()
    .toLowerCase()
    .replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/, "");
  const port = net?.destination?.port ?? e.port;
  const rawProto = (net?.protocol ?? "").trim().toLowerCase();
  const proto = IANA_PROTOCOL_NAMES[rawProto] ?? rawProto;
  return {
    dstAddr: addr || undefined,
    dstPort: typeof port === "number" && Number.isFinite(port) ? String(port) : undefined,
    proto: proto || undefined,
  };
}

/** How many facts a component carries — the length of every `facts()` tuple. */
const FACT_KEYS = ["path", "exec", "record", "act", "dstAddr", "dstPort", "proto"] as const;
const FACT_COUNT = FACT_KEYS.length;
type Facts = string[];

/** Union attempts and candidate probes, for the tests that pin the cost (#1483). */
export interface UnionStats {
  unions: number;
  probes: number;
}

export class DSU {
  private parent: number[];
  /** Per fact position (FACT_KEYS), per member: the values its component recorded. */
  private sets: Array<Array<Set<string> | undefined>>;
  /** Every union() call, refused or not. */
  unions = 0;
  constructor(facts: readonly UnionFacts[]) {
    this.parent = facts.map((_, i) => i);
    this.sets = FACT_KEYS.map((k) =>
      facts.map((f) => {
        const v = f[k];
        return v ? new Set([v]) : undefined;
      }),
    );
  }
  find(x: number): number {
    let i = x;
    while (this.parent[i] !== i) {
      this.parent[i] = this.parent[this.parent[i]];
      i = this.parent[i];
    }
    return i;
  }
  /** True when the two components agree on every fact both of them record. */
  compatible(a: number, b: number): boolean {
    const ra = this.find(a),
      rb = this.find(b);
    if (ra === rb) return true;
    return this.sets.every((s) => agree(s[ra], s[rb]));
  }
  /** Merge when compatible; returns whether the two now share a component. */
  union(a: number, b: number): boolean {
    this.unions++;
    const ra = this.find(a),
      rb = this.find(b);
    if (ra === rb) return true;
    if (!this.compatible(ra, rb)) return false;
    const keep = Math.min(ra, rb),
      drop = Math.max(ra, rb);
    this.parent[drop] = keep;
    for (const s of this.sets) s[keep] = mergeSets(s[keep], s[drop]);
    return true;
  }
  /** The component's current facts, "" where it recorded nothing. Every set is a singleton (agree). */
  facts(x: number): Facts {
    const r = this.find(x);
    return this.sets.map((s) => single(s[r]));
  }
}

// Two recorded fact sets agree when either side recorded nothing, or both recorded the same one
// thing. A component that already holds two distinct values can only have got them through a member
// that recorded neither (impossible by construction) — so "same single value" is the whole test.
function agree(a: Set<string> | undefined, b: Set<string> | undefined): boolean {
  if (!a || !b) return true;
  if (a.size !== b.size) return false;
  for (const v of a) if (!b.has(v)) return false;
  return true;
}

function mergeSets(a: Set<string> | undefined, b: Set<string> | undefined): Set<string> | undefined {
  if (!a) return b;
  if (!b) return a;
  return new Set([...a, ...b]);
}

function single(s: Set<string> | undefined): string {
  if (!s) return "";
  for (const v of s) return v;
  return "";
}

/** One member of a bucket walk: the event index and its immutable eligibility signature. */
export interface EligibleMember {
  i: number;
  /** Everything the pairwise predicate reads that a union cannot change (class, structured, sources). */
  sig: string;
}

interface Bucket {
  order: number;
  sig: string;
  facts: Facts;
  /** Live component roots, first-appearance order; compacted after every pairing. */
  roots: number[];
}

const FACT_SEP = "\u0000";

/**
 * Union every eligible, compatible pair among `members` without enumerating the pairs.
 *
 * `eligible(sigA, sigB)` is the pairwise predicate that no union can change (same correlation
 * class; for the path step also "one side structured" and "the sources corroborate"). It must be
 * symmetric. The DSU guard supplies the rest and is re-checked at every union.
 *
 * Members are bucketed by (component facts at entry, signature). Inside a bucket every pair is
 * compatible (same facts) and equally eligible, so a self-eligible bucket chains into one component
 * in |bucket| unions; a bucket that is not self-eligible (one tool's rows on one path) keeps its
 * members apart until a member of another bucket bridges them — exactly what the cross product did
 * transitively. Across buckets, the candidates are found through a per-fact index (a fixed value
 * matches only itself or a blank), so two buckets whose facts already disagree are never probed;
 * every live root of one is unioned with every live root of the other, and both are compacted
 * afterwards, so a bucket that has collapsed to one component costs one union per later pairing.
 *
 * Cost: O(n + Σ over eligible bucket pairs of their live roots). Every real shape measured for
 * #1483 is O(n). Residual: many distinct source-set signatures on one fixed triple probe each other
 * (Θ(K²) over the distinct tool combinations), and a wildcard-only bucket probes every bucket.
 *
 * Where a wildcard member could join more than one component, the walk's `order` breaks the tie
 * the way the enumeration it replaced did: "forward" (the hash step's cross product) gives it to
 * the earliest compatible member; "nearest" (the path step's time-sorted walk, each row against
 * the ones before it, latest first) to the latest earlier one.
 */
export function unionEligible(
  members: readonly EligibleMember[],
  dsu: DSU,
  eligible: (a: string, b: string) => boolean,
  order: "forward" | "nearest" = "forward",
  stats?: UnionStats,
): void {
  const before = dsu.unions;
  try {
    if (members.length < 2) return;
    const buckets = buildBuckets(members, dsu);
    // Chain each self-eligible bucket into one component.
    for (const b of buckets) {
      if (b.roots.length < 2 || !eligible(b.sig, b.sig)) continue;
      for (let k = 1; k < b.roots.length; k++) dsu.union(b.roots[0], b.roots[k]);
      b.roots = [dsu.find(b.roots[0])];
    }
    if (buckets.length < 2) return;
    const index = indexByFact(buckets);
    for (const a of buckets) {
      const found = candidates(a, buckets, index);
      // Each unordered pair once. "forward" visits the pairs as a cross product does — every later
      // bucket of the earliest first; "nearest" as the replaced time-sorted walk did — each bucket
      // against the ones before it, latest first — so a wildcard joins the same neighbour it used to.
      if (order === "forward") {
        for (const b of found) {
          if (b.order <= a.order) continue;
          if (stats) stats.probes++;
          if (!factsAgree(a.facts, b.facts) || !eligible(a.sig, b.sig)) continue;
          pairBuckets(a, b, dsu);
        }
      } else {
        for (let k = found.length - 1; k >= 0; k--) {
          const b = found[k];
          if (b.order >= a.order) continue;
          if (stats) stats.probes++;
          if (!factsAgree(a.facts, b.facts) || !eligible(a.sig, b.sig)) continue;
          pairBuckets(b, a, dsu);
        }
      }
    }
  } finally {
    if (stats) stats.unions += dsu.unions - before;
  }
}

function buildBuckets(members: readonly EligibleMember[], dsu: DSU): Bucket[] {
  const byKey = new Map<string, { bucket: Bucket; seen: Set<number> }>();
  for (const m of members) {
    const root = dsu.find(m.i);
    const facts = dsu.facts(root);
    const key = `${facts.join(FACT_SEP)}${FACT_SEP}${m.sig}`;
    let entry = byKey.get(key);
    if (!entry) {
      entry = { bucket: { order: byKey.size, sig: m.sig, facts, roots: [] }, seen: new Set() };
      byKey.set(key, entry);
    }
    if (!entry.seen.has(root)) {
      entry.seen.add(root);
      entry.bucket.roots.push(root);
    }
  }
  return [...byKey.values()].map((e) => e.bucket);
}

// For each fact position, the buckets holding each value — "" is the blank a fixed value also matches.
function indexByFact(buckets: Bucket[]): Array<Map<string, Bucket[]>> {
  const index: Array<Map<string, Bucket[]>> = Array.from({ length: FACT_COUNT }, () => new Map());
  for (const b of buckets)
    for (let f = 0; f < FACT_COUNT; f++) {
      const m = index[f];
      const v = b.facts[f];
      (m.get(v) ?? m.set(v, []).get(v)!).push(b);
    }
  return index;
}

// The buckets that could still be compatible with `a`: for each fact `a` recorded, only those holding
// the same value or a blank. The shortest such list is scanned; a bucket that recorded nothing has no
// list to narrow by and scans every bucket.
function candidates(a: Bucket, all: Bucket[], index: Array<Map<string, Bucket[]>>): Bucket[] {
  let bestSame: Bucket[] | undefined;
  let bestBlank: Bucket[] = [];
  for (let f = 0; f < FACT_COUNT; f++) {
    const v = a.facts[f];
    if (!v) continue;
    const same = index[f].get(v) ?? [];
    const blank = index[f].get("") ?? [];
    if (!bestSame || same.length + blank.length < bestSame.length + bestBlank.length) {
      bestSame = same;
      bestBlank = blank;
    }
  }
  if (!bestSame) return all;
  return bestBlank.length ? mergeByOrder(bestSame, bestBlank) : bestSame;
}

// Two lists already in bucket order, merged into one — the walk keeps first-appearance order so a
// wildcard joins the earliest compatible bucket, as the cross product's pair order did.
function mergeByOrder(x: Bucket[], y: Bucket[]): Bucket[] {
  const out: Bucket[] = [];
  let i = 0,
    j = 0;
  while (i < x.length && j < y.length) out.push(x[i].order < y[j].order ? x[i++] : y[j++]);
  while (i < x.length) out.push(x[i++]);
  while (j < y.length) out.push(y[j++]);
  return out;
}

function factsAgree(a: Facts, b: Facts): boolean {
  for (let f = 0; f < FACT_COUNT; f++) if (a[f] && b[f] && a[f] !== b[f]) return false;
  return true;
}

// Every live root of `a` against every live root of `b`, then both compacted. Roots are re-read
// through find() as the walk goes, so a root already absorbed by an earlier union is skipped.
function pairBuckets(a: Bucket, b: Bucket, dsu: DSU): void {
  const seenA = new Set<number>();
  for (const ra0 of a.roots) {
    const ra = dsu.find(ra0);
    if (seenA.has(ra)) continue;
    seenA.add(ra);
    const seenB = new Set<number>();
    for (const rb0 of b.roots) {
      const rb = dsu.find(rb0);
      if (seenB.has(rb)) continue;
      seenB.add(rb);
      dsu.union(ra, rb);
    }
    b.roots = compact(b.roots, dsu);
  }
  a.roots = compact(a.roots, dsu);
}

function compact(roots: number[], dsu: DSU): number[] {
  const out: number[] = [];
  const seen = new Set<number>();
  for (const r0 of roots) {
    const r = dsu.find(r0);
    if (seen.has(r)) continue;
    seen.add(r);
    out.push(r);
  }
  return out;
}
