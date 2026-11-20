// AI Agent Forensics (#2690): which AI-agent rule set is live — the installed AI-agent rule pack when
// one is installed (aiAgentPack.ts points this at its folder), else the bundled one. Loaded once and
// cached; a pack install or rollback calls setActiveAiAgentRulesDir and the next run picks it up.
// A broken installed set never breaks the run: it falls back to the bundled set and says why.

import { loadAiAgentRuleSet, bundledAiAgentRulesDir, type AiAgentRuleSet } from "./aiAgentRuleSet.js";

let activeDir: string | null = null;
let cached: { dir: string; set: AiAgentRuleSet } | null = null;
let lastProblem = "";

/** Point the live rule set at an installed pack folder, or back at the bundled set (null). */
export function setActiveAiAgentRulesDir(dir: string | null): void {
  activeDir = dir;
  cached = null;
}

/** The live rule set. Falls back to the bundled set when the installed one does not load. */
export function activeAiAgentRuleSet(): AiAgentRuleSet {
  const dir = activeDir ?? bundledAiAgentRulesDir();
  if (cached && cached.dir === dir) return cached.set;
  try {
    const set = loadAiAgentRuleSet(dir);
    cached = { dir, set };
    lastProblem = "";
    return set;
  } catch (e) {
    if (!activeDir) throw e; // the bundled set itself is broken: nothing to fall back to
    lastProblem = `installed AI-agent rule pack did not load (${(e as Error).message}); using the bundled rules`;
    const set = loadAiAgentRuleSet(bundledAiAgentRulesDir());
    cached = { dir, set };
    return set;
  }
}

/** Why the installed pack is not the one in use, or "" when it is. */
export function activeAiAgentRulesProblem(): string {
  return lastProblem;
}
