import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { LIVE_FROM_ENV_PREFIXES, RELOADABLE_ENV_PREFIXES } from "../../src/settings/envManager.js";

// U2 follow-up: Watson rebuilds its provider, and reads its limits, prompt file and graph cap, on every
// message. So a saved DFIR_AI_WATSON_* change is live once reloaded, and the save message must say so.
// Synthesis and the other AI roles keep their boot-time config: DFIR_AI_ itself stays NOT live.

async function browserPrefixes(): Promise<string[]> {
  const src = await readFile(
    new URL("../../../public/js/dashboard-env-settings.js", import.meta.url),
    "utf8",
  );
  const block = /const RELOADABLE_ENV_PREFIXES = \[([\s\S]*?)\];/.exec(src)![1];
  return block
    .split("\n")
    .map((line) => /^\s*"([^"]+)",?\s*$/.exec(line)?.[1])
    .filter((p): p is string => Boolean(p));
}

/** The browser's own rule: the longest reloadable prefix a key starts with. */
const groupOf = (prefixes: string[], key: string) =>
  prefixes.filter((p) => key.startsWith(p)).sort((a, b) => b.length - a.length)[0];

describe("Watson settings apply live", () => {
  it("reloads DFIR_AI_WATSON_ as its own live group on both halves", async () => {
    expect(RELOADABLE_ENV_PREFIXES.has("DFIR_AI_WATSON_")).toBe(true);
    expect(LIVE_FROM_ENV_PREFIXES.has("DFIR_AI_WATSON_")).toBe(true);
    expect(await browserPrefixes()).toContain("DFIR_AI_WATSON_");
  });

  it("routes every Watson key to the live group, and synthesis keys to the restart group", async () => {
    const prefixes = await browserPrefixes();
    for (const s of ["PROVIDER", "KEY", "BASE_URL", "MODEL", "COST_LIMIT_USD", "REACT_DELAY_SEC"]) {
      expect(groupOf(prefixes, `DFIR_AI_WATSON_${s}`)).toBe("DFIR_AI_WATSON_");
    }
    expect(groupOf(prefixes, "DFIR_AI_SYNTH_MODEL")).toBe("DFIR_AI_");
    expect(LIVE_FROM_ENV_PREFIXES.has("DFIR_AI_")).toBe(false);
    expect(LIVE_FROM_ENV_PREFIXES.has("DFIR_VISION_")).toBe(false);
  });
});
