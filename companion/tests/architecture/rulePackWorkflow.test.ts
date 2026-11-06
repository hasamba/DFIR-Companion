import { readdirSync, readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";

// RULE-PACK TAGS NEVER START AN APP RELEASE (#2349).
//
// Detection-rule packs are published from this repository as `rules-YYYY.MM.DD[.N]` releases. The
// app's release workflows (Docker image, Windows EXE, AppImage, extension zips) must react only to
// `v*` tags; a rules tag reaching them would build and publish an app release nobody asked for.
// Every workflow is read, so a new tag-driven workflow is covered the moment it is added.

const workflowsDir = new URL("../../../.github/workflows/", import.meta.url);
const files = readdirSync(workflowsDir).filter((n) => /\.ya?ml$/i.test(n));

type Triggers = Record<string, unknown>;
const load = (name: string): Record<string, unknown> =>
  (parseYaml(readFileSync(new URL(name, workflowsDir), "utf8")) ?? {}) as Record<string, unknown>;
const triggersOf = (wf: Record<string, unknown>): Triggers => {
  const on = wf.on;
  if (typeof on === "string") return { [on]: null };
  if (Array.isArray(on)) return Object.fromEntries(on.map((k) => [String(k), null]));
  return (on ?? {}) as Triggers;
};

/** Glob → RegExp for GitHub's tag filters (`*` within a segment, `**` across). */
const globToRegExp = (glob: string): RegExp =>
  new RegExp(
    "^" +
      glob
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*\*/g, "\u0000")
        .replace(/\*/g, "[^/]*")
        .replace(/\u0000/g, ".*")
        .replace(/\?/g, ".") +
      "$",
  );

describe("rule-pack tags and the app release workflows", () => {
  it("the publish workflow parses, runs on master for the rules file, and publishes not-latest", () => {
    const wf = load("rule-pack-publish.yml");
    const on = triggersOf(wf);
    const push = on.push as { branches?: string[]; paths?: string[] };
    expect(push.branches).toEqual(["master"]);
    expect(push.paths).toContain("companion/data/tags.yaml");
    expect(on).toHaveProperty("workflow_dispatch");
    expect(wf.permissions).toEqual({ contents: "write" });
    const text = readFileSync(new URL("rule-pack-publish.yml", workflowsDir), "utf8");
    expect(text).toMatch(/--latest=false/);
    expect(text).not.toMatch(/\$\{\{\s*secrets\./);
  });

  it("no workflow is triggered by a rules-* tag", () => {
    const sample = "rules-2026.11.06.2";
    const hits = files.filter((name) => {
      const push = triggersOf(load(name)).push as { tags?: string[]; "tags-ignore"?: string[] } | null;
      if (!push || typeof push !== "object") return false;
      if (push.tags) return push.tags.some((g) => globToRegExp(g).test(sample));
      if (push["tags-ignore"]) return !push["tags-ignore"].some((g) => globToRegExp(g).test(sample));
      return false; // a push trigger with only branches/paths never fires on a tag
    });
    expect(hits).toEqual([]);
  });

  it("no workflow runs on a release event (a pack release would start it)", () => {
    expect(files.filter((name) => "release" in triggersOf(load(name)))).toEqual([]);
  });

  it("the app release workflows still trigger on v* tags", () => {
    for (const name of ["docker-publish.yml", "release-artifacts.yml"]) {
      const push = triggersOf(load(name)).push as { tags?: string[] };
      expect(push.tags).toEqual(["v*"]);
    }
  });
});
