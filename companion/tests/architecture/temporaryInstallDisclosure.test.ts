import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// A TEMPORARY INSTALL NEVER ASKS, SO THE DOCS HAVE TO TELL.
//
// The Firefox manifest declares data collection (browsingActivity, websiteContent), and Firefox 140+
// turns that declaration into a consent screen — but only when installing a SIGNED add-on. An
// unsigned build loaded through about:debugging → "Load Temporary Add-on…" gets every permission
// granted silently and shows no notice at all: "if the extension makes installation time permission
// requests, these are not displayed as part of the temporary installation process".
//
// That route is not an edge case here. It is the ONLY route the project documents, because there is
// no AMO listing yet. So every analyst who follows our instructions installs a screenshot tool that
// Firefox never discloses. Raising the version floor did not fix that and could not: the floor
// decides whether Firefox CAN show the notice, not whether this install path does.
//
// The gate: any document that teaches the temporary-install route must state, in prose, every
// category the add-on declares. Derived from the manifest transform rather than hard-coded, so
// adding a category fails here until the prose catches up — the same shape as nodeEngineDocs.
const root = new URL("../../../", import.meta.url);
const read = (p: string): string => readFileSync(new URL(p, root), "utf8");

/** The literal `required: [...]` from the transform, which is the single source for what ships. */
function declaredCategories(): string[] {
  const src = read("extension/scripts/manifest-firefox.mjs");
  const block =
    /export const DATA_COLLECTION_PERMISSIONS[\s\S]*?required:\s*Object\.freeze\(\[([^\]]*)\]/.exec(src);
  expect(block, "DATA_COLLECTION_PERMISSIONS.required not found in manifest-firefox.mjs").not.toBeNull();
  return [...block![1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
}

/**
 * "browsingActivity" → /browsing\s+activity/i. The docs are written for analysts, so they say
 * "browsing activity", not the manifest's camelCase — match the words, not the key.
 */
function prosePattern(category: string): RegExp {
  const words = category
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(" ");
  return new RegExp(words.join("\\s+"), "i");
}

const DOC_DIRS = [".", "extension", "mkdocs-docs", "mkdocs-docs/reference"];

/**
 * USER_MANUAL.md is superseded by mkdocs-docs/ and is not maintained; CLAUDE.md says explicitly not
 * to update it. Gating on it would force an edit the project has decided against, so it is named
 * here rather than silently skipped by a pattern nobody can see.
 */
const NOT_MAINTAINED = ["USER_MANUAL.md"];

function docsTeachingTemporaryInstall(): string[] {
  const hits: string[] = [];
  for (const dir of DOC_DIRS) {
    const abs = fileURLToPath(new URL(dir, root));
    let entries: string[];
    try {
      entries = readdirSync(abs);
    } catch {
      continue; // a docs directory that does not exist yet is not a failure
    }
    for (const name of entries) {
      const rel = dir === "." ? name : `${dir}/${name}`;
      if (!name.endsWith(".md") || NOT_MAINTAINED.includes(name)) continue;
      if (!statSync(fileURLToPath(new URL(rel, root))).isFile()) continue;
      if (read(rel).includes("Load Temporary Add-on")) hits.push(rel);
    }
  }
  return hits;
}

describe("the temporary-install instructions disclose what Firefox will not", () => {
  const categories = declaredCategories();
  const docs = docsTeachingTemporaryInstall();

  it("finds the documents that teach the route at all", () => {
    // If this drops to zero the rest of the suite passes vacuously, which is exactly how a gate
    // stops guarding anything without ever going red.
    expect(docs.length).toBeGreaterThan(0);
    expect(docs).toContain("README.md");
    expect(docs).toContain("extension/README.md");
  });

  it("declares at least one category to disclose", () => {
    expect(categories.length).toBeGreaterThan(0);
    expect(categories).not.toContain("none");
  });

  it.each(docsTeachingTemporaryInstall())("%s names every declared category in prose", (doc) => {
    const text = read(doc);
    for (const category of categories) {
      expect(
        prosePattern(category).test(text),
        `${doc} teaches "Load Temporary Add-on…" but never says "${category}" in prose. Firefox ` +
          `shows no notice on that path, so this file is the only place the analyst can learn it.`,
      ).toBe(true);
    }
  });
});
