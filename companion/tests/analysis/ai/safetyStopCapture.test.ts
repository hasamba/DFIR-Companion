import { describe, it, expect } from "vitest";
import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, isAbsolute } from "node:path";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { analyzeRestored, type ProviderCallContext } from "../../../src/analysis/ai/providerCall.js";
import {
  SafetyStopCaptureStore,
  safetyStopCaptureFromEnv,
  type SafetyStopCapture,
} from "../../../src/analysis/ai/safetyStopCapture.js";
import { emptyState } from "../../../src/analysis/stateTypes.js";
import { createConsoleLogger } from "../../../src/logging/logger.js";
import {
  ProviderError,
  safetyStopError,
  type AIProvider,
  type AnalyzeRequest,
  type AnalyzeResult,
} from "../../../src/providers/provider.js";

// #2083 part B: an opt-in capture of the exact prompt a safety filter refused, saved into the case
// folder so it can be replayed later. Off by default; never writes outside the case folder.

const REQ: AnalyzeRequest = {
  systemPrompt: "SYSTEM PROMPT TEXT",
  userPrompt: "USER PROMPT with evidence rows",
  images: [],
  thinkingTokens: 4096,
  rejectTruncated: true,
};

class ThrowingProvider implements AIProvider {
  readonly name = "anthropic";
  readonly model = "claude-opus-5";
  calls = 0;
  constructor(private readonly err: Error) {}
  async analyze(): Promise<AnalyzeResult> {
    this.calls++;
    throw this.err;
  }
}

async function setup(caseId = "c1") {
  const root = await mkdtemp(join(tmpdir(), "dfir-safetycap-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  return { root, cases };
}

function ctxWith(opts: ProviderCallContext["opts"]): ProviderCallContext {
  return { log: createConsoleLogger("error"), opts };
}

async function captured(cases: CaseStore, caseId: string): Promise<Record<string, unknown>[]> {
  const dir = new SafetyStopCaptureStore(cases).dir(caseId);
  if (!existsSync(dir)) return [];
  const names = (await readdir(dir)).filter((n) => n.endsWith(".json"));
  return Promise.all(names.map(async (n) => JSON.parse(await readFile(join(dir, n), "utf8"))));
}

describe("SafetyStopCaptureStore (#2083)", () => {
  it("writes the refused prompt, step, provider, model and timestamp inside the case folder", async () => {
    const { cases } = await setup();
    const store = new SafetyStopCaptureStore(cases, () => new Date("2026-10-10T12:00:00.000Z"));
    const path = await store.capture("c1", {
      step: "synthesis",
      provider: "anthropic",
      model: "claude-opus-5",
      error: "stopped",
      anonymized: false,
      request: REQ,
    });
    const rel = relative(cases.caseDir("c1"), path);
    expect(rel.startsWith("..") || isAbsolute(rel)).toBe(false);
    const record = JSON.parse(await readFile(path, "utf8"));
    expect(record).toMatchObject({
      caseId: "c1",
      step: "synthesis",
      provider: "anthropic",
      model: "claude-opus-5",
      capturedAt: "2026-10-10T12:00:00.000Z",
      error: "stopped",
      anonymized: false,
      request: {
        systemPrompt: REQ.systemPrompt,
        userPrompt: REQ.userPrompt,
        thinkingTokens: 4096,
        rejectTruncated: true,
        imageCount: 0,
      },
    });
  });

  it("keeps two captures in the same millisecond apart", async () => {
    const { cases } = await setup();
    const store = new SafetyStopCaptureStore(cases, () => new Date("2026-10-10T12:00:00.000Z"));
    const input = {
      step: "deep-pass-observe",
      provider: "p",
      model: "m",
      error: "e",
      anonymized: false,
      request: REQ,
    };
    await store.capture("c1", input);
    await store.capture("c1", input);
    expect(await captured(cases, "c1")).toHaveLength(2);
  });

  it("names the file from a sanitised step so a label cannot steer the path", async () => {
    const { cases } = await setup();
    const store = new SafetyStopCaptureStore(cases);
    const path = await store.capture("c1", {
      step: "../../escape/../x",
      provider: "p",
      model: "m",
      error: "e",
      anonymized: false,
      request: REQ,
    });
    expect(relative(store.dir("c1"), path)).not.toContain("..");
    expect(relative(store.dir("c1"), path)).not.toMatch(/[\\/]/);
  });

  it("refuses an invalid case id and a case that does not exist, writing nothing", async () => {
    const { root, cases } = await setup();
    const store = new SafetyStopCaptureStore(cases);
    const input = { step: "s", provider: "p", model: "m", error: "e", anonymized: false, request: REQ };
    await expect(store.capture("../c1", input)).rejects.toThrow();
    await expect(store.capture("no-such-case", input)).rejects.toThrow();
    expect(existsSync(join(root, "no-such-case"))).toBe(false);
  });
});

describe("safetyStopCaptureFromEnv (#2083)", () => {
  it("is off unless the setting is a truthy flag", async () => {
    const { cases } = await setup();
    for (const raw of [undefined, "", "0", "false", "off", "no", "maybe"])
      expect(safetyStopCaptureFromEnv(cases, raw)).toBeUndefined();
    for (const raw of ["1", "true", "on", "YES"])
      expect(safetyStopCaptureFromEnv(cases, raw)).toBeInstanceOf(SafetyStopCaptureStore);
  });
});

describe("analyzeRestored captures a safety-stopped prompt when the setting is on (#2083)", () => {
  it("saves the exact request that was sent, then rethrows the safety stop unchanged", async () => {
    const { cases } = await setup();
    const stop = safetyStopError("Anthropic (claude-opus-5)");
    const provider = new ThrowingProvider(stop);
    const ctx = ctxWith({ safetyStopCapture: new SafetyStopCaptureStore(cases) });
    const err = await analyzeRestored(ctx, "c1", emptyState("c1"), provider, REQ, "synthesis").catch(
      (e) => e,
    );
    expect(err).toBe(stop);
    const records = await captured(cases, "c1");
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      step: "synthesis",
      provider: "anthropic",
      model: "claude-opus-5",
      error: stop.message,
      request: { systemPrompt: REQ.systemPrompt, userPrompt: REQ.userPrompt },
    });
  });

  it("captures nothing when the setting is off (no capture wired)", async () => {
    const { cases } = await setup();
    const provider = new ThrowingProvider(safetyStopError("x"));
    const err = await analyzeRestored(ctxWith({}), "c1", emptyState("c1"), provider, REQ, "synthesis").catch(
      (e) => e,
    );
    expect((err as ProviderError).kind).toBe("safety_stop");
    expect(await captured(cases, "c1")).toEqual([]);
  });

  it("captures nothing for an error that is not a safety stop", async () => {
    const { cases } = await setup();
    const calls: string[] = [];
    const capture: SafetyStopCapture = {
      capture: async (caseId) => {
        calls.push(caseId);
        return "";
      },
    };
    const provider = new ThrowingProvider(new ProviderError("boom", "other"));
    await analyzeRestored(
      ctxWith({ safetyStopCapture: capture }),
      "c1",
      emptyState("c1"),
      provider,
      REQ,
    ).catch(() => undefined);
    expect(calls).toEqual([]);
    expect(await captured(cases, "c1")).toEqual([]);
  });

  it("still throws the safety stop when the capture itself fails", async () => {
    await setup();
    const stop = safetyStopError("x");
    const capture: SafetyStopCapture = {
      capture: async () => {
        throw new Error("disk full");
      },
    };
    const provider = new ThrowingProvider(stop);
    const err = await analyzeRestored(
      ctxWith({ safetyStopCapture: capture }),
      "c1",
      emptyState("c1"),
      provider,
      REQ,
    ).catch((e) => e);
    expect(err).toBe(stop);
  });
});
