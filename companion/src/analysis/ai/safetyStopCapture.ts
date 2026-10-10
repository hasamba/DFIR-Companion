import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { isAbsolute, join, relative } from "node:path";

import { ProviderError, type AIProvider, type AnalyzeRequest } from "../../providers/provider.js";
import type { Logger } from "../../logging/logger.js";
import { isValidCaseId, type CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";

/**
 * Save the exact prompt a model's safety filter refused (#2083), so it can be replayed later to find
 * what trips the filter. Opt-in: DFIR_AI_CAPTURE_SAFETY_STOPS, read once at startup. Off → nothing is
 * wired and nothing is written.
 *
 * The file holds case evidence (the prompt IS the evidence the model was shown), so it stays inside
 * the case folder, under state/safety-stops/. It is the request as SENT: when the case's
 * anonymisation is on, the prompt is the masked text the provider saw, not the real values.
 * Screenshots are not copied — only how many there were and their types.
 */

/** The folder under the case's state directory that holds the captures. */
export const SAFETY_STOP_DIRNAME = "safety-stops";

// The step label becomes part of a file name: keep it short and inert.
const MAX_STEP_CHARS = 40;

export interface SafetyStopCaptureInput {
  /** The AI step that was refused (the call's label: "synthesis", "deep-pass-observe", …). */
  step: string;
  provider: string;
  model: string;
  /** The safety-stop message the provider raised. */
  error: string;
  /** True when the prompt was masked by the case's anonymisation before it was sent. */
  anonymized: boolean;
  request: AnalyzeRequest;
}

/** What the AI-call gate needs: one method, so a test can stand in for the store. */
export interface SafetyStopCapture {
  /** Writes one capture and returns its path. Throws when the case id or path is not safe. */
  capture(caseId: string, input: SafetyStopCaptureInput): Promise<string>;
}

export class SafetyStopCaptureStore implements SafetyStopCapture {
  constructor(
    private readonly cases: CaseStore,
    private readonly now: () => Date = () => new Date(),
  ) {}

  dir(caseId: string): string {
    return join(this.cases.stateDir(caseId), SAFETY_STOP_DIRNAME);
  }

  async capture(caseId: string, input: SafetyStopCaptureInput): Promise<string> {
    if (!isValidCaseId(caseId)) throw new Error(`refusing a safety-stop capture for case id "${caseId}"`);
    const caseDir = this.cases.caseDir(caseId);
    // Never create a case folder: a capture for a case that does not exist is dropped.
    if (!existsSync(caseDir)) throw new Error(`case ${caseId} has no folder; safety-stop capture skipped`);
    const capturedAt = this.now().toISOString();
    const dir = this.dir(caseId);
    const path = join(dir, captureFileName(capturedAt, input.step));
    assertInside(caseDir, path);
    await mkdir(dir, { recursive: true });
    await atomicWrite(path, JSON.stringify(captureRecord(caseId, capturedAt, input), null, 2));
    return path;
  }
}

function captureFileName(capturedAt: string, step: string): string {
  const stamp = capturedAt.replace(/[:.]/g, "-");
  const safeStep = step.replace(/[^a-z0-9-]/gi, "_").slice(0, MAX_STEP_CHARS) || "ai";
  return `${stamp}-${safeStep}-${randomUUID().slice(0, 8)}.json`;
}

function assertInside(caseDir: string, path: string): void {
  const rel = relative(caseDir, path);
  if (!rel || rel.startsWith("..") || isAbsolute(rel))
    throw new Error("safety-stop capture path escapes the case folder");
}

function captureRecord(caseId: string, capturedAt: string, input: SafetyStopCaptureInput) {
  const req = input.request;
  return {
    schema: 1,
    caseId,
    capturedAt,
    step: input.step,
    provider: input.provider,
    model: input.model,
    error: input.error,
    anonymized: input.anonymized,
    request: {
      systemPrompt: req.systemPrompt,
      userPrompt: req.userPrompt,
      ...(req.thinkingTokens !== undefined ? { thinkingTokens: req.thinkingTokens } : {}),
      ...(req.rejectTruncated !== undefined ? { rejectTruncated: req.rejectTruncated } : {}),
      imageCount: req.images.length,
      imageMimeTypes: req.images.map((i) => i.mimeType),
    },
  };
}

/**
 * The capture switch. Same truthy spellings as the composition root's isEnvFlag; anything else —
 * unset, blank, "0", a typo — is off, so the capture never runs unless the analyst opted in.
 */
export function safetyStopCaptureFromEnv(
  cases: CaseStore,
  raw: string | undefined,
): SafetyStopCaptureStore | undefined {
  return /^(1|true|yes|on)$/i.test(raw?.trim() ?? "") ? new SafetyStopCaptureStore(cases) : undefined;
}

/**
 * Called by the AI-call gate when a provider call failed. Saves the request when it was a safety
 * stop and a capture is wired. Best-effort: a capture failure is logged and never replaces the
 * safety stop the caller's retries and fallback act on.
 */
export async function captureIfSafetyStop(
  capture: SafetyStopCapture | undefined,
  log: Logger,
  caseId: string,
  provider: AIProvider,
  sent: { req: AnalyzeRequest; anonymized: boolean },
  label: string,
  err: unknown,
): Promise<void> {
  if (!capture || !(err instanceof ProviderError) || err.kind !== "safety_stop") return;
  try {
    const path = await capture.capture(caseId, {
      step: label,
      provider: provider.name,
      model: provider.model,
      error: err.message,
      anonymized: sent.anonymized,
      request: sent.req,
    });
    log.info(`[${label}] saved the safety-stopped prompt for replay: ${path}`, { caseId });
  } catch (captureErr) {
    log.warn(`[${label}] could not save the safety-stopped prompt: ${(captureErr as Error).message}`, {
      caseId,
    });
  }
}
