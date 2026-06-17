import { describe, it, expect } from "vitest";
import {
  suggestNextTechniques,
  DEFAULT_MAX_NEXT_TECHNIQUES,
  DEFAULT_MAX_NEXT_PREVALENCE,
  type NextTechnique,
} from "../../src/analysis/adversaryEmulation.js";
import type { AdversaryGroup, AdversaryHint } from "../../src/analysis/adversaryHints.js";

const group = (id: string, name: string, techniques: string[]): AdversaryGroup => ({
  id,
  name,
  aliases: [],
  description: "",
  techniques,
});

// A minimal hint — suggestNextTechniques only reads `id` (to look the group up in the dataset).
const hint = (id: string): AdversaryHint => ({
  id,
  name: id,
  aliases: [],
  description: "",
  url: `https://attack.mitre.org/groups/${id}/`,
  overlapCount: 3,
  exactCount: 3,
  exactTechniques: [],
  overlapTechniques: [],
  groupTechniqueCount: 3,
  score: 3,
});

// Filler groups to give the dataset a realistic POPULATION, so prevalence (global rarity) is
// meaningful — distinctiveness ranking is computed over the whole `groups` array passed in.
const fillers = (n: number, techniques: string[], prefix = "F"): AdversaryGroup[] =>
  Array.from({ length: n }, (_, i) => group(`${prefix}${i}`, `Fill${i}`, techniques));

const ids = (next: NextTechnique[]): string[] => next.map((n) => n.id);

describe("suggestNextTechniques — distinctiveness ranking (#121)", () => {
  it("drops ubiquitous techniques and keeps the distinctive ones", () => {
    // 3 matched groups each use a rare technique (T1486) + a common one (T1059); 7 filler groups all
    // use T1059 too. N=10 → T1059 prevalence 1.0 (dropped), T1486 prevalence 0.3 (kept).
    const matched = [
      group("G1", "A", ["T1486", "T1059"]),
      group("G2", "B", ["T1486", "T1059"]),
      group("G3", "C", ["T1486", "T1059"]),
    ];
    const ds = [...matched, ...fillers(7, ["T1059"])];
    const next = suggestNextTechniques([], [hint("G1"), hint("G2"), hint("G3")], ds);
    expect(ids(next)).toEqual(["T1486"]); // the ubiquitous T1059 is gone
    expect(next[0].groupCount).toBe(3);
    expect(next[0].prevalence).toBeCloseTo(0.3, 5);
  });

  it("ranks a globally rarer technique above a more common one at equal support", () => {
    const matched = [
      group("G1", "A", ["T1486", "T1490"]),
      group("G2", "B", ["T1486", "T1490"]),
      group("G3", "C", ["T1486", "T1490"]),
    ];
    // T1486 used only by the 3 matched (3/20 = 0.15); T1490 by the 3 matched + 3 fillers (6/20 = 0.30).
    const ds = [...matched, ...fillers(3, ["T1490"], "M"), ...fillers(14, ["T9999"], "N")];
    const next = suggestNextTechniques([], [hint("G1"), hint("G2"), hint("G3")], ds);
    expect(ids(next).slice(0, 2)).toEqual(["T1486", "T1490"]); // rarer (more distinctive) first
    expect(next[0].score).toBeGreaterThan(next[1].score);
    expect(next[0].prevalence).toBeLessThan(next[1].prevalence);
  });

  it("computes score = support × ln(N / globalCount)", () => {
    // 2 matched groups use T1486; 8 fillers don't → N=10, globalCount=2, support=2.
    const ds = [group("G1", "A", ["T1486"]), group("G2", "B", ["T1486"]), ...fillers(8, ["T9999"])];
    const [n] = suggestNextTechniques([], [hint("G1"), hint("G2")], ds);
    expect(n.prevalence).toBeCloseTo(0.2, 5);
    expect(n.score).toBeCloseTo(2 * Math.log(10 / 2), 5);
  });

  it("honours an explicit maxPrevalence (and keeps generic techniques last, score 0, when disabled)", () => {
    const matched = [
      group("G1", "A", ["T1486", "T1059"]),
      group("G2", "B", ["T1486", "T1059"]),
      group("G3", "C", ["T1486", "T1059"]),
    ];
    const ds = [...matched, ...fillers(7, ["T1059"])]; // T1059 prevalence 1.0, T1486 0.3
    const hints = [hint("G1"), hint("G2"), hint("G3")];
    // cap disabled (1) → T1059 reappears but sinks to the bottom with score 0 (ln(N/N)=0)
    const all = suggestNextTechniques([], hints, ds, { maxPrevalence: 1 });
    expect(ids(all)).toEqual(["T1486", "T1059"]);
    expect(all.find((n) => n.id === "T1059")?.score).toBe(0);
    // strict cap (0.1) → even T1486 (0.3) is dropped
    expect(suggestNextTechniques([], hints, ds, { maxPrevalence: 0.1 })).toEqual([]);
  });
});

describe("suggestNextTechniques — observed-filter / shape / guards", () => {
  it("excludes a technique already observed at BASE level (different sub-technique)", () => {
    // case used T1059.001 (PowerShell); a group's T1059.003 (cmd) is the same family → not new ground
    const ds = [group("G1", "A", ["T1059.003", "T1486"]), ...fillers(9, ["T9999"])];
    const next = suggestNextTechniques(["T1059.001"], [hint("G1")], ds);
    expect(ids(next)).toEqual(["T1486"]);
  });

  it("dedups a technique within a single group (counts distinct groups, not occurrences)", () => {
    const ds = [group("G1", "A", ["T1486", "T1486", "t1486"]), ...fillers(9, ["T9999"])];
    const next = suggestNextTechniques([], [hint("G1")], ds);
    expect(next).toHaveLength(1);
    expect(next[0].groupCount).toBe(1);
  });

  it("labels each suggestion with its ATT&CK tactic, technique url, and prevalence", () => {
    const ds = [group("G1", "A", ["T1486"]), ...fillers(9, ["T9999"])];
    const [n] = suggestNextTechniques([], [hint("G1")], ds);
    expect(n).toMatchObject({
      id: "T1486",
      tactic: "Impact",
      url: "https://attack.mitre.org/techniques/T1486/",
    });
    expect(n.prevalence).toBeCloseTo(0.1, 5);
  });

  it("caps the result at maxTechniques", () => {
    const many = Array.from({ length: 20 }, (_, i) => `T${2000 + i}`);
    const ds = [group("G1", "A", many), ...fillers(19, ["T9999"])]; // each T20xx rare (1/20)
    const next = suggestNextTechniques([], [hint("G1")], ds, { maxTechniques: 5 });
    expect(next).toHaveLength(5);
  });

  it("defaults the cap to DEFAULT_MAX_NEXT_TECHNIQUES", () => {
    const many = Array.from({ length: DEFAULT_MAX_NEXT_TECHNIQUES + 8 }, (_, i) => `T${3000 + i}`);
    const ds = [group("G1", "A", many), ...fillers(29, ["T9999"])]; // each rare (1/30)
    const next = suggestNextTechniques([], [hint("G1")], ds);
    expect(next).toHaveLength(DEFAULT_MAX_NEXT_TECHNIQUES);
  });

  it("returns nothing when there are no matched groups", () => {
    expect(suggestNextTechniques(["T1059"], [], [group("G1", "A", ["T1486"])])).toEqual([]);
  });

  it("returns nothing when the dataset is empty", () => {
    expect(suggestNextTechniques([], [hint("G1")], [])).toEqual([]);
  });

  it("ignores a hint whose group is absent from the dataset (defensive)", () => {
    const ds = [group("G1", "A", ["T1486"]), ...fillers(9, ["T9999"])];
    expect(suggestNextTechniques([], [hint("G9")], ds)).toEqual([]);
  });

  it("skips unparseable technique ids in a group's list", () => {
    const ds = [group("G1", "A", ["nope", "TA0001", "T1486"]), ...fillers(9, ["T9999"])];
    expect(ids(suggestNextTechniques([], [hint("G1")], ds))).toEqual(["T1486"]);
  });

  it("exposes the default prevalence cap constant", () => {
    expect(DEFAULT_MAX_NEXT_PREVALENCE).toBeGreaterThan(0);
    expect(DEFAULT_MAX_NEXT_PREVALENCE).toBeLessThan(1);
  });
});
