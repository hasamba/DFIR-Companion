import { readFileSync } from "node:fs";
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
const FLOOR = engines.replace(/^[^\d]*/, ""); // ">=22.5" → "22.5"

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
      .filter((v) => Number.parseFloat(v) < Number.parseFloat(FLOOR));
    expect(stale, `${doc} tells the reader to install Node ${stale.join(", ")}, below ${FLOOR}`).toEqual([]);
  });

  it("keeps engine-strict on, so the mismatch fails at install time", () => {
    // Without this npm only warns, the install looks successful, and the real error arrives at
    // first case open — a much worse first experience than a clear refusal.
    expect(read("companion/.npmrc")).toMatch(/^engine-strict\s*=\s*true$/m);
  });
});
