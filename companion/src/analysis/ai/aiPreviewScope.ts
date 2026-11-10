import { AsyncLocalStorage } from "node:async_hooks";
import { runReadOnly } from "../../storage/readOnlyScope.js";

/**
 * "Preview what the AI will see" (#2491): the scope a preview runs the REAL action in.
 *
 * The preview does not rebuild any prompt. It runs the action itself — synthesis, a report, a hunt
 * suggestion — so the prompt is built by the action's own code from the forensic timeline exactly as a
 * real press would build it. When the action reaches the AI-call gate (`analyzeRestored`), the gate sees
 * this scope, builds the as-sent request through the shared masking function (maskRequest.ts), stores
 * it here and throws AiPreviewCaptured. The provider is never called, so nothing is sent and nothing
 * is spent; the read-only storage scope (storage/readOnlyScope.ts) refuses every case write.
 *
 * ONLY THE FIRST REQUEST IS CAPTURED. An action that asks several times (deep pass batches, second
 * opinion's passes, a referee) builds its later prompts from the model's earlier answers, and
 * inventing those answers would let a made-up reply flow into the next prompt. The result says so.
 */
export interface AiPreviewImage {
  readonly index: number;
  readonly mimeType: string;
  /** "ocr-required": the real call OCR-redacts it first (not run in the preview); "sent-as-is" otherwise. */
  readonly handling: "ocr-required" | "sent-as-is";
}

export interface AiPreviewPresidio {
  /**
   * "off": not configured, off for the case, or anonymization is off; "not-gated": an import pre-scan
   * already covered this call; "clear": nothing would be held; "would-hold": the real call stops for
   * approval; "scan-failed": the real call stops because the scan cannot run.
   */
  readonly state: "off" | "not-gated" | "clear" | "would-hold" | "scan-failed";
  readonly held: ReadonlyArray<{ readonly category: string; readonly value: string }>;
  readonly message?: string;
}

/** The first request the action would send, exactly as the provider would receive it. */
export interface AiPreviewCapture {
  /** The call label the action uses ("synthesis", "narrative", …). */
  readonly kind: string;
  readonly provider: string;
  readonly model: string;
  /** Sent unmasked — the system prompt is the product's instructions, never masked. */
  readonly systemPrompt: string;
  /** The user prompt before masking (AI-field markers removed). */
  readonly clearPrompt: string;
  /** The user prompt the provider receives. */
  readonly maskedPrompt: string;
  readonly anonymized: boolean;
  readonly images: readonly AiPreviewImage[];
  readonly presidio: AiPreviewPresidio;
  /** Plain-English facts about how this preview differs from a real press (#2515), shown with it. */
  readonly notes?: readonly string[];
}

interface PreviewState {
  capture?: AiPreviewCapture;
  /** Building the capture failed (e.g. anonymization kept changing): the action's real outcome. */
  failure?: unknown;
  /** How many times the action reached the gate before it stopped. */
  calls: number;
  /**
   * An import's whole-payload Presidio pre-scan, answered without saving (#2515), and the
   * anonymization revision it masked with. It stands for a batch only while that revision is current.
   */
  preScan?: { readonly revision: number; readonly presidio: AiPreviewPresidio };
  /** Disclosures the action's preview adds before it runs (stored inputs used, …) — see noteAiPreview. */
  notes: string[];
}

const scope = new AsyncLocalStorage<PreviewState>();

/** Thrown at the gate inside a preview. Carries nothing from the case. */
export class AiPreviewCaptured extends Error {
  constructor() {
    super("AI preview: stopped before the provider call");
    this.name = "AiPreviewCaptured";
  }
}

export function isAiPreviewCapture(err: unknown): boolean {
  return err instanceof AiPreviewCaptured;
}

/** For a catch block on an AI path that would otherwise swallow the stop and carry on. */
export function rethrowIfAiPreview(err: unknown): void {
  if (err instanceof AiPreviewCaptured) throw err;
}

/** Add a plain-English disclosure to the active preview's result. No-op outside a preview. */
export function noteAiPreview(note: string): void {
  scope.getStore()?.notes.push(note);
}

/** Record an import pre-scan's preview answer (see PreviewState.preScan). No-op outside a preview. */
export function noteAiPreviewPreScan(revision: number, presidio: AiPreviewPresidio): void {
  const preview = scope.getStore();
  if (preview) preview.preScan = { revision, presidio };
}

/**
 * Record the first request of an action that does not go through the AI-call gate (the Jev review and
 * containment check, #2515) and stop it. The slot is claimed synchronously, so of several concurrent
 * requests the first one to reach here is the one shown; every call throws AiPreviewCaptured.
 * `build` runs only for the first request; a failure there is the preview's outcome.
 */
export async function recordAiPreviewCapture(build: () => Promise<AiPreviewCapture>): Promise<never> {
  const preview = scope.getStore();
  if (!preview) throw new Error("recordAiPreviewCapture outside an AI preview");
  if (preview.calls++ === 0) {
    try {
      preview.capture = await build();
    } catch (err) {
      preview.failure = err;
    }
  }
  throw new AiPreviewCaptured();
}

/** The active preview, or undefined for every real call. */
export function activeAiPreview(): PreviewState | undefined {
  return scope.getStore();
}

export type AiPreviewResult =
  | { readonly outcome: "captured"; readonly call: AiPreviewCapture }
  | { readonly outcome: "no-ai-call" }
  | { readonly outcome: "error"; readonly error: unknown };

/**
 * Run `action` as a preview. "captured" carries the first request; "no-ai-call" means the action
 * finished without asking the model (an empty timeline, nothing to promote); "error" carries what the
 * real action would have failed with before its first request (a merge decision, no provider, …).
 */
export async function runAiPreview(action: () => Promise<unknown>): Promise<AiPreviewResult> {
  const state: PreviewState = { calls: 0, notes: [] };
  return runReadOnly(() =>
    scope.run(state, async (): Promise<AiPreviewResult> => {
      let thrown: unknown;
      try {
        await action();
      } catch (err) {
        thrown = err;
      }
      if (state.failure !== undefined) return { outcome: "error", error: state.failure };
      if (state.capture) return { outcome: "captured", call: withNotes(state.capture, state.notes) };
      if (thrown !== undefined) return { outcome: "error", error: thrown };
      return { outcome: "no-ai-call" };
    }),
  );
}

function withNotes(call: AiPreviewCapture, notes: readonly string[]): AiPreviewCapture {
  return notes.length ? { ...call, notes: [...(call.notes ?? []), ...notes] } : call;
}
