import { describe, it, expect } from "vitest";
import {
  applyRuleUpdates,
  diffRuleSets,
  ruleHash,
  ruleSetRevision,
  snapshotBase,
  type RuleMap,
} from "../../src/analysis/taggerRulesMerge.js";

// #2344: bringing a newer rule set (the bundled tags.yaml today, a released rule pack in #2349)
// into an analyst's edited copy without losing their edits or silently restoring their deletions.

const rule = (sev: string, text = "x", description = `${text} rule`) => ({
  description,
  any: [{ field: "message", contains: [text] }],
  tags: ["t"],
  severity: sev,
});

// The built-in set the analyst's copy was taken from…
const BASE_SET: RuleMap = {
  keep: rule("Low", "keep"),
  edited_by_me: rule("Low", "mine"),
  changed_upstream: rule("Low", "up"),
  both_changed: rule("Low", "both"),
  deleted_by_me: rule("Medium", "del"),
  retired: rule("Low", "old"),
};

// …the current built-in set…
const UPSTREAM: RuleMap = {
  keep: rule("Low", "keep"),
  edited_by_me: rule("Low", "mine"),
  changed_upstream: rule("High", "up"),
  both_changed: rule("High", "both"),
  deleted_by_me: rule("High", "del"),
  brand_new: rule("High", "new"),
};

// …and the analyst's copy.
const MINE: RuleMap = {
  keep: rule("Low", "keep"),
  edited_by_me: rule("Critical", "mine"),
  changed_upstream: rule("Low", "up"),
  both_changed: rule("Medium", "both"),
  retired: rule("Low", "old"),
  my_own: rule("High", "own"),
};

const BASE = snapshotBase(BASE_SET);

describe("ruleHash / ruleSetRevision", () => {
  it("ignores key order inside a rule", () => {
    expect(ruleHash({ a: 1, b: [1, { c: 2, d: 3 }] })).toBe(ruleHash({ b: [1, { d: 3, c: 2 }], a: 1 }));
  });

  it("changes when content changes, not when rule order changes", () => {
    expect(ruleSetRevision({ a: rule("Low"), b: rule("High") })).toBe(
      ruleSetRevision({ b: rule("High"), a: rule("Low") }),
    );
    expect(ruleSetRevision({ a: rule("Low") })).not.toBe(ruleSetRevision({ a: rule("High") }));
  });
});

describe("diffRuleSets with a base record", () => {
  const report = diffRuleSets({ upstream: UPSTREAM, mine: MINE, base: BASE });
  const keys = (items: Array<{ key: string }>) => items.map((i) => i.key).sort();

  it("classifies every rule", () => {
    expect(report.tracked).toBe(true);
    expect(keys(report.added)).toEqual(["brand_new"]);
    expect(keys(report.changed)).toEqual(["changed_upstream"]);
    expect(keys(report.conflicts)).toEqual(["both_changed"]);
    expect(keys(report.removedByYou)).toEqual(["deleted_by_me"]);
    expect(report.analystEdited).toEqual(["edited_by_me"]);
    expect(report.analystAdded).toEqual(["my_own"]);
    expect(report.retiredUpstream).toEqual(["retired"]);
    expect(report.inSync).toBe(1);
    expect(report.hasNews).toBe(true);
    expect(report.upstreamRevision).toBe(ruleSetRevision(UPSTREAM));
  });

  it("carries both versions on a changed rule and a conflict, and marks nothing uncertain", () => {
    const changed = report.changed[0];
    expect(changed.upstream).toEqual(rule("High", "up"));
    expect(changed.mine).toEqual(rule("Low", "up"));
    expect(report.conflicts[0].mine).toEqual(rule("Medium", "both"));
    expect([...report.added, ...report.changed, ...report.conflicts].every((i) => !i.uncertain)).toBe(true);
  });

  it("treats the same edit on both sides as in sync", () => {
    const r = diffRuleSets({
      upstream: { a: rule("High") },
      mine: { a: rule("High") },
      base: snapshotBase({ a: rule("Low") }),
    });
    expect(r.hasNews).toBe(false);
    expect(r.inSync).toBe(1);
  });

  it("calls a key both sides added with different content a conflict", () => {
    const r = diffRuleSets({
      upstream: { a: rule("High") },
      mine: { a: rule("Low") },
      base: snapshotBase({}),
    });
    expect(keys(r.conflicts)).toEqual(["a"]);
  });

  it("reports nothing new when the copy already holds every built-in rule", () => {
    const r = diffRuleSets({ upstream: UPSTREAM, mine: { ...UPSTREAM, extra: rule("Low") }, base: BASE });
    expect(r.hasNews).toBe(false);
    expect(r.added).toEqual([]);
  });

  it("does not count a rule the analyst deleted as news", () => {
    const r = diffRuleSets({
      upstream: { a: rule("Low"), b: rule("Low") },
      mine: { a: rule("Low") },
      base: snapshotBase({ a: rule("Low"), b: rule("Low") }),
    });
    expect(r.hasNews).toBe(false);
    expect(keys(r.removedByYou)).toEqual(["b"]);
  });
});

describe("diffRuleSets for a copy saved before revisions were recorded", () => {
  const report = diffRuleSets({ upstream: UPSTREAM, mine: MINE, base: null });

  it("compares by key and marks what it cannot attribute as uncertain", () => {
    expect(report.tracked).toBe(false);
    // No base: a missing key is new OR deleted by the analyst; a different one changed on an unknown side.
    expect(report.added.map((i) => i.key).sort()).toEqual(["brand_new", "deleted_by_me"]);
    expect(report.added.every((i) => i.uncertain)).toBe(true);
    expect(report.conflicts.map((i) => i.key).sort()).toEqual([
      "both_changed",
      "changed_upstream",
      "edited_by_me",
    ]);
    expect(report.conflicts.every((i) => i.uncertain)).toBe(true);
    expect(report.changed).toEqual([]);
    expect(report.removedByYou).toEqual([]);
    expect(report.analystAdded.sort()).toEqual(["my_own", "retired"]);
  });
});

describe("applyRuleUpdates", () => {
  it("adds and updates chosen rules and keeps every analyst edit and addition", () => {
    const out = applyRuleUpdates({
      upstream: UPSTREAM,
      mine: MINE,
      base: BASE,
      choices: { brand_new: "upstream", changed_upstream: "upstream", both_changed: "mine" },
    });
    expect(out.rules.brand_new).toEqual(rule("High", "new"));
    expect(out.rules.changed_upstream).toEqual(rule("High", "up"));
    expect(out.rules.both_changed).toEqual(rule("Medium", "both"));
    expect(out.rules.edited_by_me).toEqual(rule("Critical", "mine"));
    expect(out.rules.my_own).toEqual(rule("High", "own"));
    expect(out.rules.retired).toEqual(rule("Low", "old"));
    expect(out.rules).not.toHaveProperty("deleted_by_me");
    expect(out.applied.sort()).toEqual(["brand_new", "changed_upstream"]);
    expect(out.kept).toEqual(["both_changed"]);
  });

  it("takes the built-in version of a conflict when the analyst picks it", () => {
    const out = applyRuleUpdates({
      upstream: UPSTREAM,
      mine: MINE,
      base: BASE,
      choices: { both_changed: "upstream" },
    });
    expect(out.rules.both_changed).toEqual(rule("High", "both"));
  });

  it("restores a deleted rule only when asked, one rule at a time", () => {
    const untouched = applyRuleUpdates({
      upstream: UPSTREAM,
      mine: MINE,
      base: BASE,
      choices: { brand_new: "upstream" },
    });
    expect(untouched.rules).not.toHaveProperty("deleted_by_me");
    const restored = applyRuleUpdates({
      upstream: UPSTREAM,
      mine: MINE,
      base: BASE,
      choices: { deleted_by_me: "upstream" },
    });
    expect(restored.rules.deleted_by_me).toEqual(rule("High", "del"));
  });

  it("records a decision so the rule stops being offered, and leaves undecided rules offered", () => {
    const out = applyRuleUpdates({
      upstream: UPSTREAM,
      mine: MINE,
      base: BASE,
      choices: { brand_new: "upstream", both_changed: "mine" },
    });
    const next = diffRuleSets({ upstream: UPSTREAM, mine: out.rules, base: out.base });
    expect(next.added).toEqual([]);
    expect(next.conflicts).toEqual([]);
    expect(next.changed.map((i) => i.key)).toEqual(["changed_upstream"]);
    expect(next.analystEdited.sort()).toEqual(["both_changed", "edited_by_me"]);
    expect(next.removedByYou.map((i) => i.key)).toEqual(["deleted_by_me"]);
  });

  it("ignores a choice for a key that is not on offer", () => {
    const out = applyRuleUpdates({
      upstream: UPSTREAM,
      mine: MINE,
      base: BASE,
      choices: { keep: "upstream", my_own: "upstream", nope: "upstream", edited_by_me: "upstream" },
    });
    expect(out.applied).toEqual([]);
    expect(out.rules.edited_by_me).toEqual(rule("Critical", "mine"));
    expect(out.rules.my_own).toEqual(rule("High", "own"));
  });

  it("establishes a full base on a copy that had none", () => {
    const out = applyRuleUpdates({
      upstream: UPSTREAM,
      mine: MINE,
      base: null,
      choices: { brand_new: "upstream" },
    });
    expect(Object.keys(out.base.rules).sort()).toEqual(Object.keys(UPSTREAM).sort());
    const next = diffRuleSets({ upstream: UPSTREAM, mine: out.rules, base: out.base });
    expect(next.tracked).toBe(true);
    expect(next.hasNews).toBe(false);
    // The undecided "new or deleted" key is now honestly "removed by you", restorable.
    expect(next.removedByYou.map((i) => i.key)).toEqual(["deleted_by_me"]);
  });

  it("never mutates its inputs", () => {
    const mine = structuredClone(MINE);
    const base = structuredClone(BASE);
    applyRuleUpdates({
      upstream: UPSTREAM,
      mine,
      base,
      choices: { brand_new: "upstream", deleted_by_me: "upstream" },
    });
    expect(mine).toEqual(MINE);
    expect(base).toEqual(BASE);
  });
});
