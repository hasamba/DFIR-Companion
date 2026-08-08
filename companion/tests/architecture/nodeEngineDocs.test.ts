import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

/**
 * npm's own semver, borrowed rather than added as a devDependency — it is already in the tree, and
 * a gate about dependency floors should not add one. Typed to the two calls used here because the
 * package ships no types and @types/semver is not installed.
 */
const semver = createRequire(import.meta.url)("semver") as {
  validRange(range: string): string | null;
  satisfies(version: string, range: string, opts?: { includePrerelease?: boolean }): boolean;
};
import { describe, expect, it } from "vitest";

// THE DOCUMENTED NODE FLOOR MUST BE THE REAL ONE (#474).
//
// USER_MANUAL.md told new users to install "Node 20 or later", framing 22.5 as an opt-in needed
// only for the NSRL SQLite backend. That stopped being true when the indexed case store became the
// primary backend: node:sqlite is now imported by case storage, auth and the job ledger, so the
// server does not start below 22.5 at all.
//
// The install therefore APPEARED to work — npm only warns on an engines mismatch — and the failure
// surfaced later, at first case open. This gate exists because that drift was silent: package.json
// moved and the prose did not, and nothing compared them.
//
// Derived from package.json rather than hard-coded, so raising the engine floor fails here until
// the prose is updated too, naming the file that still disagrees.
const root = new URL("../../../", import.meta.url);
const read = (p: string): string => readFileSync(new URL(p, root), "utf8");

const engines = JSON.parse(read("companion/package.json")).engines.node as string;
const FLOOR = engines.replace(/^[^\d]*/, ""); // ">=22.19" → "22.19"

/**
 * Compare Node versions COMPONENT-WISE, never as floats.
 *
 * parseFloat("22.5") > parseFloat("22.19") is true, so a float compare reads 22.5 as NEWER than
 * 22.19 and stops classifying a stale "install 22.5" instruction as stale. Codex review caught
 * exactly that in the first cut of this file — a gate that silently answers the wrong question is
 * worse than no gate.
 */
function cmp(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** Every doc that tells a reader which Node to install. */
const INSTALL_DOCS = ["USER_MANUAL.md", "README.md", "companion/README.md", "mkdocs-docs/getting-started.md"];

describe("the documented Node floor matches package.json engines", () => {
  it("declares a floor at all", () => {
    expect(FLOOR, "package.json engines.node is missing or unparseable").toMatch(/^\d+(\.\d+)*$/);
  });

  it.each(INSTALL_DOCS)("%s states the real floor", (doc) => {
    expect(read(doc), `${doc} never mentions Node ${FLOOR}`).toContain(FLOOR);
  });

  // The specific shape of the #474 bug: prose naming a LOWER version as the thing to install. A doc
  // may still mention an older release historically ("older Node releases cannot open…"), so this
  // looks for the install instruction, not any occurrence of a number.
  it.each(INSTALL_DOCS)("%s does not tell anyone to install an older Node", (doc) => {
    const stale = [...read(doc).matchAll(/Node\.?js?[^\n]{0,40}?\*\*(\d+(?:\.\d+)?)[^*]*\*\*/gi)]
      .map((m) => m[1])
      .filter((v) => cmp(v, FLOOR) < 0);
    expect(stale, `${doc} tells the reader to install Node ${stale.join(", ")}, below ${FLOOR}`).toEqual([]);
  });

  // THE FLOOR MUST NOT UNDERSTATE THE LOCKED TREE. This is the generalisation of what Codex review
  // found: undici@8.3.0 requires >=22.19.0 while package.json declared >=22.5, so turning on
  // engine-strict would have hard-failed `npm install` across 22.5–22.18 — the exact range the docs
  // called supported. A declared floor that is lower than some dependency's is the same class of
  // defect as #474 itself, just one layer down, and nothing was checking it.
  it("declares a floor no lower than any locked dependency demands", () => {
    const lock = JSON.parse(read("companion/package-lock.json")) as {
      packages: Record<
        string,
        { engines?: { node?: string }; optional?: boolean; os?: string[]; cpu?: string[] }
      >;
    };
    const unmet: string[] = [];
    for (const [name, meta] of Object.entries(lock.packages)) {
      // Platform-gated optional binaries are never installed here — @img/sharp-win32-ia32 caps at
      // Node 20 and npm skips it on every non-Windows-32 machine, so it cannot fail an install.
      if (meta.optional || meta.os || meta.cpu) continue;
      const want = meta.engines?.node;
      // A RANGE, NOT A FLOOR. `^20.19.0 || ^22.13.0 || >=24` is satisfiable at 22.19 even though it
      // contains ">=24"; reading the first `>=` out of it flagged eslint-visitor-keys falsely. The
      // only correct question is whether a machine on exactly our declared floor satisfies it.
      if (
        want &&
        semver.validRange(want) &&
        !semver.satisfies(`${FLOOR}.0`, want, { includePrerelease: false })
      ) {
        unmet.push(`${name || "(root)"} needs ${want}`);
      }
    }
    expect(
      unmet,
      `package.json declares >=${FLOOR}, but a machine on exactly that version does not satisfy:\n  ` +
        `${unmet.join("\n  ")}\nWith engine-strict on, those installs fail.`,
    ).toEqual([]);
  });

  it("keeps engine-strict on, so the mismatch fails at install time", () => {
    // Without this npm only warns, the install looks successful, and the real error arrives at
    // first case open — a much worse first experience than a clear refusal.
    expect(read("companion/.npmrc")).toMatch(/^engine-strict\s*=\s*true$/m);
  });
});
