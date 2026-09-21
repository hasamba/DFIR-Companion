// The bucketed pair walk behind the hash and undated-path steps of correlation (#1483). The oracle
// is the cross product it replaced (#1476): every pair in index order through the same guarded
// union. Both must end maximal — no two components left compatible while an eligible pair of their
// members exists — and on the shapes without a wildcard tie they must end identical.
import { describe, it, expect } from "vitest";
import {
  DSU,
  unionEligible,
  type EligibleMember,
  type UnionFacts,
  type UnionStats,
} from "../../src/analysis/correlateUnion.js";

type Eligible = (a: string, b: string) => boolean;

// The hash step's replaced loop: every pair, earliest member outward.
function crossProduct(members: EligibleMember[], dsu: DSU, eligible: Eligible): void {
  for (let a = 0; a < members.length; a++)
    for (let b = a + 1; b < members.length; b++)
      if (eligible(members[a].sig, members[b].sig)) dsu.union(members[a].i, members[b].i);
}

// The path step's replaced loop: each member against the ones before it, latest first.
function nearestFirst(members: EligibleMember[], dsu: DSU, eligible: Eligible): void {
  for (let k = 1; k < members.length; k++)
    for (let j = k - 1; j >= 0; j--)
      if (eligible(members[j].sig, members[k].sig)) dsu.union(members[j].i, members[k].i);
}

function partition(dsu: DSU, n: number): string {
  const byRoot = new Map<number, number[]>();
  for (let i = 0; i < n; i++) {
    const r = dsu.find(i);
    (byRoot.get(r) ?? byRoot.set(r, []).get(r)!).push(i);
  }
  return [...byRoot.values()]
    .map((g) => g.join(","))
    .sort()
    .join(" | ");
}

// The invariant both walks must leave behind: any eligible pair still in two components is
// incompatible at the component level.
function assertMaximal(members: EligibleMember[], dsu: DSU, eligible: Eligible): void {
  for (let a = 0; a < members.length; a++)
    for (let b = a + 1; b < members.length; b++) {
      const x = members[a].i,
        y = members[b].i;
      if (dsu.find(x) === dsu.find(y)) continue;
      if (!eligible(members[a].sig, members[b].sig)) continue;
      expect(dsu.compatible(x, y), `pair ${x},${y} left compatible and apart`).toBe(false);
    }
}

// A tiny deterministic generator, so a failure names its seed.
function rng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return ((s >>> 0) % 10000) / 10000;
  };
}

const pick = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];

const sameClass: Eligible = (a, b) => a === b;

// The path step's predicate: same class, one side structured, corroborating sources.
const pathEligible: Eligible = (a, b) => {
  const [ka, sa, srcA] = a.split("/");
  const [kb, sb, srcB] = b.split("/");
  if (ka !== kb) return false;
  if (sa !== "s" && sb !== "s") return false;
  return !srcA || !srcB || srcA !== srcB;
};

interface Case {
  facts: UnionFacts[];
  members: EligibleMember[];
  prior: [number, number][]; // unions made before the walk (steps 0/0b)
}

function generate(seed: number, kind: "hash" | "path"): Case {
  const r = rng(seed);
  const n = 2 + Math.floor(r() * 9);
  const facts: UnionFacts[] = [];
  const members: EligibleMember[] = [];
  // Every third case records every fact on every member, so the no-tie comparison has a corpus.
  const full = seed % 3 === 0;
  for (let i = 0; i < n; i++) {
    facts.push({
      path: full ? "p" : pick(r, [undefined, "p"]),
      exec: full ? pick(r, ["x1", "x2"]) : pick(r, [undefined, undefined, "x1", "x2"]),
      record: full ? pick(r, ["r1", "r2"]) : pick(r, [undefined, undefined, "r1", "r2"]),
    });
    const klass = pick(r, ["host", "host", "host", "lab"]);
    const sig =
      kind === "hash"
        ? klass
        : `${klass}/${pick(r, ["s", "s", "t"])}/${pick(r, ["", "chainsaw", "hayabusa", "chainsaw+yara"])}`;
    members.push({ i, sig });
  }
  const prior: [number, number][] = [];
  if (r() < 0.4) prior.push([Math.floor(r() * n), Math.floor(r() * n)]);
  return { facts, members, prior };
}

function run(
  c: Case,
  kind: "hash" | "path",
  eligible: Eligible,
  walk: "new" | "old",
): { dsu: DSU; stats: UnionStats } {
  const dsu = new DSU(c.facts);
  for (const [a, b] of c.prior) dsu.union(a, b);
  const stats: UnionStats = { unions: 0, probes: 0 };
  if (walk === "new") unionEligible(c.members, dsu, eligible, kind === "hash" ? "forward" : "nearest", stats);
  else if (kind === "hash") crossProduct(c.members, dsu, eligible);
  else nearestFirst(c.members, dsu, eligible);
  return { dsu, stats };
}

function hasWildcard(c: Case): boolean {
  return c.facts.some((f) => !f.path || !f.exec || !f.record);
}

describe("unionEligible — the bucket walk reaches what the cross product reached (#1483)", () => {
  it("chains a bucket of identical fully-recorded members into one component in n−1 unions", () => {
    const facts = Array.from({ length: 50 }, () => ({ path: "p", exec: "x", record: "r" }));
    const dsu = new DSU(facts);
    const stats = { unions: 0, probes: 0 };
    unionEligible(
      facts.map((_, i) => ({ i, sig: "host" })),
      dsu,
      sameClass,
      "forward",
      stats,
    );
    expect(new Set(facts.map((_, i) => dsu.find(i))).size).toBe(1);
    expect(stats.unions).toBe(49);
  });

  it("never probes two fully-recorded buckets that already disagree", () => {
    const facts = Array.from({ length: 200 }, (_, i) => ({ path: "p", exec: `x${i}`, record: `r${i}` }));
    const dsu = new DSU(facts);
    const stats = { unions: 0, probes: 0 };
    unionEligible(
      facts.map((_, i) => ({ i, sig: "host" })),
      dsu,
      sameClass,
      "forward",
      stats,
    );
    expect(new Set(facts.map((_, i) => dsu.find(i))).size).toBe(200);
    expect(stats.unions).toBe(0);
    expect(stats.probes).toBe(0);
  });

  it("a wildcard joins the first compatible component in appearance order, then nothing that disagrees", () => {
    const facts: UnionFacts[] = [
      { path: "p" }, // 0: the wildcard
      { path: "p", exec: "x1", record: "r1" },
      { path: "p", exec: "x2", record: "r2" },
    ];
    const dsu = new DSU(facts);
    unionEligible(
      facts.map((_, i) => ({ i, sig: "host" })),
      dsu,
      sameClass,
    );
    expect(dsu.find(0)).toBe(dsu.find(1));
    expect(dsu.find(2)).not.toBe(dsu.find(0));
  });

  it("bridges a same-tool bucket through the other tool's member, as the pairwise walk did transitively", () => {
    // Three YARA hits on one path never corroborate each other; one Volatility row corroborates each,
    // and through it all four end in one component.
    const facts: UnionFacts[] = [{ path: "p" }, { path: "p" }, { path: "p" }, { path: "p" }];
    const members = [
      { i: 0, sig: "host/s/yara" },
      { i: 1, sig: "host/s/yara" },
      { i: 2, sig: "host/s/volatility" },
      { i: 3, sig: "host/s/yara" },
    ];
    const dsu = new DSU(facts);
    unionEligible(members, dsu, pathEligible);
    expect(new Set([0, 1, 2, 3].map((i) => dsu.find(i))).size).toBe(1);
    // Without the bridge the three stay three.
    const alone = new DSU(facts.slice(0, 2).concat(facts[3]));
    unionEligible([members[0], members[1], { i: 2, sig: "host/s/yara" }], alone, pathEligible);
    expect(new Set([0, 1, 2].map((i) => alone.find(i))).size).toBe(3);
  });

  it("a lab row and a host row with identical facts stay apart, and the host rows still chain past it", () => {
    const facts = [{ path: "p" }, { path: "p" }, { path: "p" }];
    const members = [
      { i: 0, sig: "host" },
      { i: 1, sig: "lab" },
      { i: 2, sig: "host" },
    ];
    const dsu = new DSU(facts);
    unionEligible(members, dsu, sameClass);
    expect(dsu.find(0)).toBe(dsu.find(2));
    expect(dsu.find(1)).not.toBe(dsu.find(0));
  });

  it("a root already holding two signatures (from a prior union) pairs through either of them", () => {
    // 0 (free-text, chainsaw) and 1 (structured, hayabusa) were unioned by an earlier step. 2 is a
    // free-text chainsaw row: it cannot pair with 0 but can with 1, and must land in their component.
    const facts: UnionFacts[] = [{}, { path: "p" }, {}];
    const dsu = new DSU(facts);
    dsu.union(0, 1);
    unionEligible(
      [
        { i: 0, sig: "host/t/chainsaw" },
        { i: 1, sig: "host/s/hayabusa" },
        { i: 2, sig: "host/t/chainsaw" },
      ],
      dsu,
      pathEligible,
    );
    expect(dsu.find(2)).toBe(dsu.find(0));
  });

  it.each([
    ["hash", sameClass],
    ["path", pathEligible],
  ] as const)(
    "%s walk: 400 generated cases end maximal and, without a wildcard tie, identical to the cross product",
    (kind, eligible) => {
      let compared = 0;
      for (let seed = 1; seed <= 400; seed++) {
        const c = generate(seed, kind);
        const fresh = run(c, kind, eligible, "new");
        const oracle = run(c, kind, eligible, "old");
        assertMaximal(c.members, fresh.dsu, eligible);
        assertMaximal(c.members, oracle.dsu, eligible);
        if (!hasWildcard(c)) {
          compared++;
          expect(partition(fresh.dsu, c.facts.length), `seed ${seed}`).toBe(
            partition(oracle.dsu, c.facts.length),
          );
        }
      }
      expect(compared).toBeGreaterThan(20);
    },
  );

  it.each([
    ["hash", sameClass],
    ["path", pathEligible],
  ] as const)(
    "%s walk: with wildcards the bucket walk lands on the replaced loop's partition on the bulk of generated cases",
    (kind, eligible) => {
      // A wildcard that could join several components is a tie the replaced loop broke by its pair
      // order and the bucket walk breaks by bucket order in the same direction; the two agree except
      // where members that share a bucket sat apart in the input.
      let same = 0,
        total = 0;
      for (let seed = 1; seed <= 400; seed++) {
        const c = generate(seed * 104729 + 1, kind);
        if (!hasWildcard(c)) continue;
        total++;
        const a = partition(run(c, kind, eligible, "new").dsu, c.facts.length);
        const b = partition(run(c, kind, eligible, "old").dsu, c.facts.length);
        if (a === b) same++;
      }
      expect(total).toBeGreaterThan(100);
      expect(same / total).toBeGreaterThan(0.9);
    },
  );

  it("path walk: a corroborating wildcard joins the LATEST earlier launch, as the time-sorted walk did", () => {
    // Two launches of one path from tool A, then a structured row from tool B with no command
    // line: it corroborates either launch and the replaced walk gave it to the nearer one.
    const facts: UnionFacts[] = [{ path: "p", exec: "x1" }, { path: "p", exec: "x2" }, { path: "p" }];
    const members = [
      { i: 0, sig: "host/s/a" },
      { i: 1, sig: "host/s/a" },
      { i: 2, sig: "host/s/b" },
    ];
    const dsu = new DSU(facts);
    unionEligible(members, dsu, pathEligible, "nearest");
    expect(dsu.find(2)).toBe(dsu.find(1));
    expect(dsu.find(0)).not.toBe(dsu.find(1));
  });
});
