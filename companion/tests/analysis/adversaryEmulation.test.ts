import { describe, it, expect } from "vitest";
import {
  suggestNextTechniques,
  DEFAULT_MAX_NEXT_TECHNIQUES,
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
const hint = (id: string, name = id): AdversaryHint => ({
  id,
  name,
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

const ids = (next: NextTechnique[]): string[] => next.map((n) => n.id);

describe("suggestNextTechniques", () => {
  it("suggests a matched group's techniques the case has NOT observed", () => {
    const observed = ["T1059", "T1566"];
    const groups = [group("G1", "Alpha", ["T1059", "T1566", "T1486", "T1021"])];
    const next = suggestNextTechniques(observed, [hint("G1")], groups);
    // T1059/T1566 already observed → only the two unseen techniques surface; equal support (1 group
    // each) → tie-break by worst tactic: T1486 (Impact) before T1021 (Lateral Movement)
    expect(ids(next)).toEqual(["T1486", "T1021"]);
    expect(next.every((n) => n.groupCount === 1)).toBe(true);
  });

  it("excludes a technique already observed at BASE level (different sub-technique)", () => {
    // case used T1059.001 (PowerShell); a group's T1059.003 (cmd) is the same family → not new ground
    const next = suggestNextTechniques(
      ["T1059.001"],
      [hint("G1")],
      [group("G1", "Alpha", ["T1059.003", "T1486"])],
    );
    expect(ids(next)).toEqual(["T1486"]);
  });

  it("ranks by support — a technique used by more matched groups comes first", () => {
    const groups = [
      group("G1", "Alpha", ["T1486", "T1490"]),
      group("G2", "Bravo", ["T1486"]),
      group("G3", "Charlie", ["T1486"]),
    ];
    const next = suggestNextTechniques([], [hint("G1"), hint("G2"), hint("G3")], groups);
    expect(next[0].id).toBe("T1486");
    expect(next[0].groupCount).toBe(3);
    expect(next[0].groups.map((g) => g.id)).toEqual(["G1", "G2", "G3"]);
    const t1490 = next.find((n) => n.id === "T1490");
    expect(t1490?.groupCount).toBe(1);
  });

  it("dedups a technique within a single group (counts distinct groups, not occurrences)", () => {
    const next = suggestNextTechniques(
      [],
      [hint("G1")],
      [group("G1", "Alpha", ["T1486", "T1486", "t1486"])],
    );
    expect(next).toHaveLength(1);
    expect(next[0].groupCount).toBe(1);
  });

  it("labels each suggestion with its ATT&CK tactic and a technique url", () => {
    const next = suggestNextTechniques([], [hint("G1")], [group("G1", "Alpha", ["T1486"])]);
    expect(next[0]).toMatchObject({
      id: "T1486",
      tactic: "Impact",
      url: "https://attack.mitre.org/techniques/T1486/",
    });
  });

  it("breaks support ties toward the worst plausible stage (impact before discovery)", () => {
    // both used by exactly one group → tie-break is tactic severity: Impact (T1486) before Discovery (T1087)
    const next = suggestNextTechniques([], [hint("G1")], [group("G1", "Alpha", ["T1087", "T1486"])]);
    expect(ids(next)).toEqual(["T1486", "T1087"]);
  });

  it("caps the result at maxTechniques", () => {
    const many = Array.from({ length: 20 }, (_, i) => `T${2000 + i}`);
    const next = suggestNextTechniques([], [hint("G1")], [group("G1", "Alpha", many)], { maxTechniques: 5 });
    expect(next).toHaveLength(5);
  });

  it("defaults the cap to DEFAULT_MAX_NEXT_TECHNIQUES", () => {
    const many = Array.from({ length: DEFAULT_MAX_NEXT_TECHNIQUES + 8 }, (_, i) => `T${3000 + i}`);
    const next = suggestNextTechniques([], [hint("G1")], [group("G1", "Alpha", many)]);
    expect(next).toHaveLength(DEFAULT_MAX_NEXT_TECHNIQUES);
  });

  it("returns nothing when there are no matched groups", () => {
    expect(suggestNextTechniques(["T1059"], [], [group("G1", "Alpha", ["T1486"])])).toEqual([]);
  });

  it("ignores a hint whose group is absent from the dataset (defensive)", () => {
    const next = suggestNextTechniques([], [hint("G9")], [group("G1", "Alpha", ["T1486"])]);
    expect(next).toEqual([]);
  });

  it("skips unparseable technique ids in a group's list", () => {
    const next = suggestNextTechniques([], [hint("G1")], [group("G1", "Alpha", ["nope", "TA0001", "T1486"])]);
    expect(ids(next)).toEqual(["T1486"]);
  });
});
