import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PROMPT_CAPABILITIES,
  missingMarkers,
  assertBuiltinsHaveMarkers,
  driftMessage,
  checkConfiguredPromptDrift,
} from "../../src/analysis/promptCapabilities.js";
import { BUILTIN_PROMPT_BY_NAME, getObservePrompt } from "../../src/analysis/pipeline.js";

describe("missingMarkers", () => {
  it("returns the markers absent from the text (case-sensitive)", () => {
    expect(missingMarkers("has hypotheses and confidenceReason", ["hypotheses", "relatedFindingIds"]))
      .toEqual(["relatedFindingIds"]);
  });

  it("returns [] when every marker is present", () => {
    expect(missingMarkers("a b c", ["a", "c"])).toEqual([]);
  });

  it("treats undefined/empty text as missing everything", () => {
    expect(missingMarkers("", ["x"])).toEqual(["x"]);
    expect(missingMarkers(undefined as unknown as string, ["x"])).toEqual(["x"]);
  });
});

describe("assertBuiltinsHaveMarkers (rot guard)", () => {
  it("passes for the real shipped built-in prompts", () => {
    // If a prompt rewrite drops a marker the pipeline still depends on, this fails loudly.
    expect(() => assertBuiltinsHaveMarkers(BUILTIN_PROMPT_BY_NAME)).not.toThrow();
  });

  it("throws when a built-in is missing one of its own markers", () => {
    expect(() => assertBuiltinsHaveMarkers({ SYNTH: "no markers here" })).toThrow(/missing its own markers/);
  });

  it("throws when a built-in is not supplied", () => {
    expect(() => assertBuiltinsHaveMarkers({})).toThrow(/no built-in prompt supplied/);
  });
});

describe("checkConfiguredPromptDrift", () => {
  const tmp = mkdtempSync(join(tmpdir(), "prompt-drift-"));
  afterEach(() => {
    // isolate env between cases
    for (const cap of PROMPT_CAPABILITIES) {
      delete process.env[`DFIR_AI_${cap.name}_PROMPT`];
      delete process.env[`DFIR_AI_${cap.name}_PROMPT_FILE`];
    }
  });

  it("reports nothing when no override is configured (built-in is used)", () => {
    expect(checkConfiguredPromptDrift({})).toEqual([]);
  });

  it("flags a stale synthesis override file missing capabilities", () => {
    const file = join(tmp, "stale-synthesis.txt");
    writeFileSync(file, "You are a DFIR analyst. Produce findings and keyQuestions.", "utf8");
    const drift = checkConfiguredPromptDrift({ DFIR_AI_SYNTH_PROMPT_FILE: file });
    expect(drift).toHaveLength(1);
    expect(drift[0].name).toBe("SYNTH");
    expect(drift[0].missing).toEqual(["hypotheses", "confidenceReason", "relatedFindingIds", "logSource", "evidenceRequests"]);
    expect(driftMessage(drift[0])).toContain("synthesis.txt");
  });

  it("flags a stale pre-#8 override whose only 'collect' is prose (the bare-word false-pass bug)", () => {
    const file = join(tmp, "pre8-synthesis.txt");
    // A pre-#8 re-eject: has hypotheses/confidenceReason/relatedFindingIds AND the prose "collect email
    // gateway logs" — but NOT the structured `collect { logSource }` directive. Must still be flagged.
    writeFileSync(file, "output: hypotheses, confidenceReason, relatedFindingIds, evidenceRequests. pointer: 'collect email gateway logs'", "utf8");
    const drift = checkConfiguredPromptDrift({ DFIR_AI_SYNTH_PROMPT_FILE: file });
    expect(drift).toHaveLength(1);
    expect(drift[0].missing).toEqual(["logSource"]);
  });

  it("passes a fresh override file that contains every marker", () => {
    const file = join(tmp, "fresh-synthesis.txt");
    writeFileSync(file, "output: hypotheses, confidenceReason, relatedFindingIds, collect { logSource }, evidenceRequests", "utf8");
    expect(checkConfiguredPromptDrift({ DFIR_AI_SYNTH_PROMPT_FILE: file })).toEqual([]);
  });

  it("does not flag an unreadable/empty override (resolvePrompt falls back to the built-in)", () => {
    const empty = join(tmp, "empty.txt");
    writeFileSync(empty, "   \n", "utf8");
    expect(checkConfiguredPromptDrift({ DFIR_AI_SYNTH_PROMPT_FILE: empty })).toEqual([]);
    expect(checkConfiguredPromptDrift({ DFIR_AI_SYNTH_PROMPT_FILE: join(tmp, "does-not-exist.txt") })).toEqual([]);
  });

  it("checks an inline *_PROMPT override too", () => {
    const drift = checkConfiguredPromptDrift({ DFIR_AI_SYNTH_PROMPT: "findings only, no other sections" });
    expect(drift).toHaveLength(1);
    expect(drift[0].missing).toContain("hypotheses");
  });
});

describe("OBSERVE prompt capability (deep pass)", () => {
  it("is registered with the fields sanitizeObservations parses", () => {
    const observe = PROMPT_CAPABILITIES.find((c) => c.name === "OBSERVE");
    expect(observe).toBeDefined();
    expect(observe!.envVar).toBe("DFIR_AI_OBSERVE_PROMPT_FILE");
    for (const marker of ["observations", "eventIds", "whyItMatters"]) {
      expect(observe!.markers).toContain(marker);
    }
  });

  it("the shipped prompt satisfies its own markers", () => {
    const observe = PROMPT_CAPABILITIES.find((c) => c.name === "OBSERVE")!;
    expect(missingMarkers(getObservePrompt(), observe.markers)).toEqual([]);
  });

  it("forbids the batch from emitting severities, findings or a narrative", () => {
    const text = getObservePrompt();
    expect(text).toMatch(/do NOT assign a severity/i);
    expect(text).toMatch(/do NOT create a finding/i);
  });
});

describe("synthesis prompt admits deep-pass observation ids", () => {
  // Regression guard for the halcyon benchmark result: findings derived from deep-pass observations
  // came back ungrounded because the relatedEventIds instruction named only the forensic timeline.
  it("does not scope relatedEventIds to the timeline alone", () => {
    expect(BUILTIN_PROMPT_BY_NAME.SYNTH).toMatch(/deep-pass observations|DEEP-PASS OBSERVATIONS/);
  });
});
