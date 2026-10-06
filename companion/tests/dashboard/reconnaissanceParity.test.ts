// #1974 — the dashboard keeps its own copies of the tactic tables. Each copy must know the
// Reconnaissance tactic in the same place the server puts it, or recon rows vanish from that view.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { STORY_STAGE_ORDER } from "../../src/analysis/cockpitStory.js";

const JS_DIR = resolve(__dirname, "../../../public/js");
const src = (file: string): string => readFileSync(resolve(JS_DIR, file), "utf8");

// The string array literal assigned to `const NAME = [ … ];` in a dashboard module.
function arrayConst(source: string, name: string): string[] {
  const m = new RegExp(`const ${name} = \\[([\\s\\S]*?)\\];`).exec(source);
  if (!m) throw new Error(`${name} not found`);
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
}

describe("dashboard Reconnaissance parity (#1974)", () => {
  const kc = src("dashboard-kill-chain.js");
  const graph = src("dashboard-evidence-graph.js");
  const story = src("dashboard-cockpit-story.js");

  it("kill chain: T1595 maps to Reconnaissance, first in chain order, last in priority", () => {
    expect(kc).toMatch(/T1595: "Reconnaissance"/);
    expect(arrayConst(kc, "KC_CHAIN_ORDER")[0]).toBe("Reconnaissance");
    expect(arrayConst(kc, "KC_TACTIC_PRIORITY").at(-1)).toBe("Reconnaissance");
  });

  it("evidence graph: Reconnaissance is first in order and has its own colour", () => {
    expect(arrayConst(graph, "EV_KC_ORDER")[0]).toBe("Reconnaissance");
    expect(graph).toMatch(/Reconnaissance: "#[0-9a-f]{6}"/i);
  });

  it("cockpit story: the client stage order mirrors the server's", () => {
    expect(arrayConst(story, "STORY_STAGE_ORDER")).toEqual([...STORY_STAGE_ORDER]);
  });
});
