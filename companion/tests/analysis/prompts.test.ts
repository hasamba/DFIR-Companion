import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getSystemPrompt, getSynthesisPrompt, getNarrativePrompt, NARRATIVE_PROMPT, SYSTEM_PROMPT } from "../../src/analysis/pipeline.js";

const ENVS = ["DFIR_AI_SYSTEM_PROMPT", "DFIR_AI_SYSTEM_PROMPT_FILE", "DFIR_AI_SYNTH_PROMPT", "DFIR_AI_SYNTH_PROMPT_FILE"];
afterEach(() => { for (const e of ENVS) delete process.env[e]; });

describe("user-overridable prompts", () => {
  it("returns the built-in default when nothing is configured", () => {
    expect(getSystemPrompt()).toBe(SYSTEM_PROMPT);
  });

  it("uses an inline env override", () => {
    process.env.DFIR_AI_SYSTEM_PROMPT = "MY CUSTOM SYSTEM PROMPT";
    expect(getSystemPrompt()).toBe("MY CUSTOM SYSTEM PROMPT");
  });

  it("reads a prompt file, and inline text wins over the file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-prompts-"));
    const f = join(dir, "system.txt");
    await writeFile(f, "PROMPT FROM FILE", "utf8");

    process.env.DFIR_AI_SYSTEM_PROMPT_FILE = f;
    expect(getSystemPrompt()).toBe("PROMPT FROM FILE");

    process.env.DFIR_AI_SYSTEM_PROMPT = "INLINE WINS";
    expect(getSystemPrompt()).toBe("INLINE WINS");

    await rm(dir, { recursive: true, force: true });
  });

  it("falls back to the built-in prompt when the file is missing (never throws)", () => {
    process.env.DFIR_AI_SYNTH_PROMPT_FILE = join(tmpdir(), "definitely-not-a-real-prompt-file.txt");
    expect(getSynthesisPrompt()).toContain("SEPARATE finding for EACH distinct"); // a line from the default
  });

  it("falls back when the file is empty/whitespace", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-prompts-"));
    const f = join(dir, "empty.txt");
    await writeFile(f, "   \n\t ", "utf8");
    process.env.DFIR_AI_SYSTEM_PROMPT_FILE = f;
    expect(getSystemPrompt()).toBe(SYSTEM_PROMPT);
    await rm(dir, { recursive: true, force: true });
  });

  it("narrative prompt returns the built-in default and requires JSON shape with narrativeTimeline", () => {
    expect(getNarrativePrompt()).toBe(NARRATIVE_PROMPT);
    // The prompt must ask for a narrativeTimeline JSON field.
    expect(NARRATIVE_PROMPT).toContain("narrativeTimeline");
    // The prompt must instruct prose paragraphs, not bullet points.
    expect(NARRATIVE_PROMPT).toContain("prose");
    // The synthesis prompt must also include narrativeTimeline in its output spec.
    expect(getSynthesisPrompt()).toContain("narrativeTimeline");
  });
});
