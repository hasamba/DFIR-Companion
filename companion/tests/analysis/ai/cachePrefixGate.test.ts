import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import { CustomEntitiesStore } from "../../../src/analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../../../src/analysis/anonDiscovered.js";
import { AnonMapStore } from "../../../src/analysis/anonMap.js";
import { analyzeRestored, type ProviderCallContext } from "../../../src/analysis/ai/providerCall.js";
import { emptyState } from "../../../src/analysis/stateTypes.js";
import { aiSpan, withAiSpans } from "../../../src/analysis/ai/aiSpan.js";
import { createConsoleLogger } from "../../../src/logging/logger.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { ClaudeCodeProvider } from "../../../src/providers/claudeCode.js";
import type { ClaudeRunOptions } from "../../../src/providers/claudeRunner.js";

// #2658: with anonymization on, the cacheable prefix reaches a provider only MASKED, and only when the
// masked prompt starts with it — the clear prefix never leaves the gate. #2675: with anonymization off the
// prompt is clear anyway, so the clear prefix (AI-field markers removed) is sent when the prompt starts with it.

class Capture implements AIProvider {
  readonly name = "stub";
  readonly model = "stub-model";
  readonly sent: AnalyzeRequest[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    return { rawText: "{}" };
  }
}

const PREFIX = "<<<TIMELINE>>>\nJane Doe ran rclone\n<<<END TIMELINE>>>\n\n";
const PROMPT = `${PREFIX}CASE CONTEXT\nwhat did Jane Doe do?`;

async function setup(
  anonymize: boolean,
  prompt = PROMPT,
  prefix = PREFIX,
  p: AIProvider = new Capture(),
): Promise<AnalyzeRequest | undefined> {
  const root = await mkdtemp(join(tmpdir(), "dfir-cacheprefix-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const anonStore = new AnonControlStore(cases);
  await anonStore.save("c1", { ...(await anonStore.load("c1")), enabled: anonymize });
  const customEntitiesStore = new CustomEntitiesStore(cases);
  await customEntitiesStore.save("c1", [{ value: "Jane Doe", category: "PERSON" }]);
  const ctx: ProviderCallContext = {
    log: createConsoleLogger("error"),
    opts: {
      anonStore,
      customEntitiesStore,
      discoveredStore: new DiscoveredEntitiesStore(cases),
      anonMapStore: new AnonMapStore(cases),
    },
  };
  await analyzeRestored(ctx, "c1", emptyState("c1"), p, {
    systemPrompt: "s",
    userPrompt: prompt,
    cachePrefix: prefix,
    images: [],
  });
  return p instanceof Capture ? p.sent[0] : undefined;
}

describe("the cache prefix through the masking gate (#2658)", () => {
  it("anonymization on: a masked prefix the masked prompt starts with", async () => {
    const sent = (await setup(true))!;
    expect(sent.cachePrefix).toBeDefined();
    expect(sent.cachePrefix).not.toContain("Jane Doe");
    expect(sent.cachePrefix).toMatch(/ANON_PERSON_\d+ ran rclone/);
    expect(sent.userPrompt.startsWith(sent.cachePrefix!)).toBe(true);
    expect(sent.userPrompt).not.toContain("Jane Doe");
  });

  it("anonymization on: a prefix the prompt does not start with is dropped, never sent clear", async () => {
    const sent = (await setup(true, PROMPT, "Jane Doe was here\n"))!;
    expect(sent.cachePrefix).toBeUndefined();
    expect(sent.userPrompt).not.toContain("Jane Doe");
  });

  it("anonymization off: the clear prefix, and the prompt starts with it (#2675)", async () => {
    const sent = (await setup(false))!;
    expect(sent.cachePrefix).toBe(PREFIX);
    expect(sent.userPrompt).toBe(PROMPT);
  });

  it("anonymization off: AI-field markers are removed from the prefix like from the prompt", async () => {
    const prefix = withAiSpans(
      () => `<<<TIMELINE>>>\n${aiSpan("Watson: rclone ran")}\n<<<END TIMELINE>>>\n\n`,
    );
    const sent = (await setup(false, `${prefix}rest`, prefix))!;
    expect(sent.cachePrefix).toBe("<<<TIMELINE>>>\nWatson: rclone ran\n<<<END TIMELINE>>>\n\n");
    expect(sent.userPrompt).toBe(`${sent.cachePrefix}rest`);
  });

  it("anonymization off: a prefix that is empty once markers are removed is not sent", async () => {
    const sent = (await setup(false, "\uE000rest", "\uE000"))!;
    expect(sent.cachePrefix).toBeUndefined();
    expect(sent.userPrompt).toBe("rest");
  });

  it("anonymization off: a prefix the prompt does not start with is not sent", async () => {
    const sent = (await setup(false, PROMPT, "something else\n"))!;
    expect(sent.cachePrefix).toBeUndefined();
  });

  it("anonymization off: the Claude Code CLI receives a cached timeline block plus the rest", async () => {
    let stdin = "";
    const runner = async (o: ClaudeRunOptions) => {
      stdin = o.stdin ?? "";
      const result = JSON.stringify({ type: "result", subtype: "success", is_error: false, result: "{}" });
      return { code: 0, stdout: result, stderr: "" };
    };
    await setup(false, PROMPT, PREFIX, new ClaudeCodeProvider({ model: "sonnet", runner }));
    const content = (
      JSON.parse(stdin) as { message: { content: { text: string; cache_control?: unknown }[] } }
    ).message.content;
    expect(content).toHaveLength(2);
    expect(content[0].text).toBe(PREFIX);
    expect(content[0].cache_control).toEqual({ type: "ephemeral", ttl: "1h" });
    expect(content[0].text + content[1].text).toBe(PROMPT);
  });
});
