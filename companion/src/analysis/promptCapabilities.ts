// Prompt capability-drift detection (investigation-guidance #1). A DFIR_AI_*_PROMPT_FILE override
// REPLACES the built-in prompt wholesale (resolvePrompt in pipeline.ts), so a STALE ejected file
// silently disables capabilities the built-in has since gained. The live case: an old synthesis.txt
// ejected before issue #140 has no 'hypotheses' section, so hypothesis auto-generation never fires
// and 'confidenceReason' is never produced — yet tests (which use the built-in) all pass, and nothing
// warns the operator. This module NAMES the machine-checkable output markers each prompt must contain
// and reports which a given override text is missing, so preflight can warn instead of failing silent.
//
// The core here is PURE (markers + matching). The one impure helper (checkConfiguredPromptDrift) reads
// env + the override files and is called from startup preflight and once per synthesis run. Markers are
// LITERAL substrings (JSON field names / section keywords the prompt must mention); a case-sensitive
// `includes` is deliberately dumb so the check itself can't rot into false confidence.
import { readFileSync } from "node:fs";

export interface PromptCapability {
  /** resolvePrompt name, e.g. "SYNTH". */
  name: string;
  /** The filename `npm run prompts:eject` writes, e.g. "synthesis.txt" — shown in the warning. */
  file: string;
  /** The override env var that activates a file, e.g. "DFIR_AI_SYNTH_PROMPT_FILE". */
  envVar: string;
  /** Substrings that MUST appear in the prompt for its shipped capabilities to work. */
  markers: string[];
}

// Only prompts whose output has fields the pipeline DEPENDS ON deterministically are listed — a
// missing marker here means a real, silent capability loss, not a style drift. Keep markers to literal
// JSON field names / unmistakable section keywords so the check never false-positives on rewording.
export const PROMPT_CAPABILITIES: readonly PromptCapability[] = [
  {
    name: "SYNTH",
    file: "synthesis.txt",
    envVar: "DFIR_AI_SYNTH_PROMPT_FILE",
    // hypotheses      → issue #140 auto-generation (delta.hypotheses consumed in pipeline.ts)
    // confidenceReason→ issue #226 (confidence.ts / finding cards)
    // relatedFindingIds→ issue #222 FP→question re-answer wiring (else it degrades to prose matching)
    // logSource       → guidance #8 structured collection directives. NOTE: use "logSource" (a field
    //   name unique to the #8 `collect` instruction), NOT the bare word "collect" — that appears as
    //   prose in every older prompt ("collect email gateway logs"), so it silently PASSED a stale
    //   pre-#8 override that lacked the structured directive.
    // evidenceRequests→ guidance #11 second-look loop (delta.evidenceRequests drives the raw re-query).
    markers: ["hypotheses", "confidenceReason", "relatedFindingIds", "logSource", "evidenceRequests"],
  },
  {
    name: "TAGGERRULE",
    file: "tagger-rule.txt",
    envVar: "DFIR_AI_TAGGERRULE_PROMPT_FILE",
    // ruleId / decline / severity are the JSON keys the feature parses; an ejected file that drops
    // them is stale and would silently break NL rule suggestion.
    markers: ["ruleId", "decline", "severity"],
  },
  {
    name: "OBSERVE",
    file: "observe.txt",
    envVar: "DFIR_AI_OBSERVE_PROMPT_FILE",
    // observations / eventIds / whyItMatters are the JSON keys sanitizeObservations reads; an ejected
    // file that drops them yields zero usable observations and the deep pass silently degrades to a
    // plain re-synthesis that read nothing extra.
    markers: ["observations", "eventIds", "whyItMatters"],
  },
];

// The required markers absent from `text` (case-sensitive substring match). Empty = no drift.
export function missingMarkers(text: string, markers: readonly string[]): string[] {
  const hay = String(text ?? "");
  return markers.filter((m) => !hay.includes(m));
}

// One drifted prompt override: the capability plus the markers its override file is missing.
export interface PromptDrift {
  name: string;
  file: string;
  envVar: string;
  missing: string[];
}

// A human-readable one-line warning for a drift (used by preflight + the per-run log).
export function driftMessage(d: PromptDrift): string {
  return (
    `prompt override ${d.file} is missing capabilities: ${d.missing.join(", ")} — ` +
    `model output will silently lack them; re-run 'npm run prompts:eject' to refresh it`
  );
}

// Read the RAW override for each capability whose DFIR_AI_*_PROMPT (inline) or DFIR_AI_*_PROMPT_FILE is
// configured, and report which required markers it is missing. Deliberately checks the override CONTENT
// directly rather than the resolved prompt: resolvePrompt (pipeline.ts) silently falls back to the
// built-in on an unreadable/empty file, which would HIDE drift. Returns [] when no override is set (the
// built-in is used and has every marker) or all markers are present. Impure (env + fs) but cheap.
export function checkConfiguredPromptDrift(env: NodeJS.ProcessEnv = process.env): PromptDrift[] {
  const out: PromptDrift[] = [];
  for (const cap of PROMPT_CAPABILITIES) {
    const inline = env[`DFIR_AI_${cap.name}_PROMPT`];
    let text: string | undefined;
    if (inline && inline.trim().length > 0) {
      text = inline;
    } else {
      const file = env[`DFIR_AI_${cap.name}_PROMPT_FILE`];
      if (!file || file.trim().length === 0) continue;   // no override → built-in is used
      try {
        const raw = readFileSync(file, "utf8");
        if (raw.trim().length === 0) continue;            // empty file → resolvePrompt uses the built-in
        text = raw;
      } catch {
        continue;                                          // unreadable → resolvePrompt uses the built-in
      }
    }
    const missing = missingMarkers(text, cap.markers);
    if (missing.length) out.push({ name: cap.name, file: cap.file, envVar: cap.envVar, missing });
  }
  return out;
}

// Rot-guard: assert every capability's OWN built-in prompt contains all its markers. If a built-in
// prompt is reworded so a marker no longer literally appears, the marker list is stale and the whole
// drift check becomes meaningless — this makes that fail loudly (called from a unit test with the
// real built-ins). `builtinByName` maps a capability name to its built-in prompt text.
export function assertBuiltinsHaveMarkers(builtinByName: Record<string, string>): void {
  for (const cap of PROMPT_CAPABILITIES) {
    const text = builtinByName[cap.name];
    if (text === undefined) {
      throw new Error(`promptCapabilities: no built-in prompt supplied for "${cap.name}"`);
    }
    const missing = missingMarkers(text, cap.markers);
    if (missing.length) {
      throw new Error(
        `promptCapabilities: built-in ${cap.name} prompt is missing its own markers [${missing.join(", ")}] — ` +
        `the marker list is stale, update PROMPT_CAPABILITIES to match the current prompt`,
      );
    }
  }
}
