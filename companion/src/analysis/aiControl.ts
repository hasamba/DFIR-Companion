import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { atomicWrite } from "../storage/atomicWrite.js";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import {
  StateFileCorruptError,
  parseStateObject,
  type StateFileCorruptNotice,
} from "../storage/stateFileCorrupt.js";

// Per-case AI analysis control. `enabled` gates every call to the model: the live screenshot
// pipeline, synthesis, and the CSV / log imports (the unified /import and /import-file and the
// dedicated /import-csv and /import-log, #1806) — with it off those are saved as evidence but not
// analyzed. Evidence is always captured, and deterministic imports (THOR, Hayabusa, …) always parse.
// It defaults to OFF so a fresh app start or a brand-new case captures evidence without
// spending any AI until the analyst deliberately turns it on (the same OPSEC/cost-first
// default-off stance as threat-intel enrichment). `lastAnalyzedSeq` is the highest
// capture sequence the live pipeline has analyzed, so turning AI on backfills everything
// captured while it was off.
export interface AiControl {
  enabled: boolean;
  lastAnalyzedSeq: number;
  // When true, the analyst notebook entries are appended to the synthesis prompt so the
  // AI can incorporate investigator hypotheses and open questions. Off by default (opt-in).
  includeNotebook?: boolean;
  // #2248: set while a failed screenshot window is still owed. lastAnalyzedSeq stays below the
  // lowest failed capture until recovery analyzes it. See composition/captureRecovery.ts.
  analysisHold?: AnalysisHold;
  // #2265: the live window whose model call is running right now, written before the call and
  // cleared when it ends. A restart that finds it set adopts those captures into the hold, so a
  // window cut off mid-call is still owed even when a later window moved the watermark past it.
  inFlightSeqs?: number[];
  // Watson (analysis/ai/watson/runMode.ts): whether it asks before acting. A missing field is "approve".
  // watsonAutoSince/By record who switched Auto on and when; both are cleared on a switch back.
  watsonRunMode?: "approve" | "auto";
  watsonAutoSince?: string;
  watsonAutoBy?: { id?: string; name: string };
  // #2760: set only on a fail-closed read of a damaged file (composition/aiControlCache.ts); never saved.
  corrupt?: StateFileCorruptNotice;
}

export interface AnalysisHold {
  /** Captures whose window failed and that have not been analyzed since. */
  failedSeqs: number[];
  /** The highest capture analyzed while the hold was open; newer ones are still owed. */
  analyzedThrough: number;
  /** Automatic recovery attempts used so far. */
  attempts: number;
  /** ISO time before which no automatic recovery runs (backoff). */
  nextAttemptAt?: string;
  /** Recovery hit its cap. The captures stay owed; only the AI off→on catch-up retries them. */
  gaveUp?: boolean;
  lastError?: string;
}

/**
 * #2265: the analyst-facing line for screenshots still owed by a failed window, or undefined when
 * nothing is held. Shared by the pushed idle status and the derived pill state (analysis/aiState.ts)
 * so the two never word it differently.
 */
export function describeAnalysisHold(hold: AnalysisHold | undefined): string | undefined {
  const count = hold?.failedSeqs.length ?? 0;
  if (!hold || count === 0) return undefined;
  return hold.gaveUp
    ? `${count} screenshot(s) could not be analyzed — turn AI off and on to retry, or press Skip screenshots`
    : `${count} screenshot(s) waiting for retry`;
}

/**
 * #2498: a short fingerprint of WHICH screenshots a hold owes. The dashboard sends it back with
 * "skip", so a hold that changed after the button was shown is refused instead of skipped blind.
 */
export function holdToken(hold: AnalysisHold | undefined): string | undefined {
  if (!hold || hold.failedSeqs.length === 0) return undefined;
  const seqs = [...hold.failedSeqs].sort((a, b) => a - b).join(",");
  return createHash("sha256").update(seqs).digest("hex").slice(0, 16);
}

/**
 * #2498: what an analyst's "skip" did. "stale" — the hold changed since the analyst saw it.
 * "frozen" — the case was closed or archived while the skip waited in the case's queue.
 */
export interface SkipHeldResult {
  outcome: "none" | "stale" | "frozen" | "skipped";
  skipped: number[];
  remaining: number[];
  lastError?: string;
}

export const DEFAULT_AI_CONTROL: AiControl = { enabled: false, lastAnalyzedSeq: 0 };
const DEFAULT = DEFAULT_AI_CONTROL;
const AI_CONTROL_FILE = "ai-control.json";
const AI_CONTROL_CORRUPT_CONSEQUENCE =
  "AI is held OFF for this case until the switch is set again — setting AI on or off rewrites the file.";

// No lower bound: capture recovery writes `lowest failed seq - 1`, which a real file can hold.
const isSeq = (v: unknown): boolean => typeof v === "number" && Number.isInteger(v);
const isSeqList = (v: unknown): boolean => Array.isArray(v) && v.every(isSeq);
const isHold = (v: unknown): boolean => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const h = v as Record<string, unknown>;
  return isSeqList(h.failedSeqs) && isSeq(h.analyzedThrough) && isSeq(h.attempts);
};

// The fields that gate behaviour, and the only values each may hold. A present field with any other
// value (the string "false", 1, null, …) is damage: read by truthiness it could switch AI or the
// notebook ON, so the file fails closed instead. A missing field takes its default. watsonRunMode
// is not checked: analysis/ai/watson/runMode.ts already reads any junk value as Approve.
const FIELD_CHECKS: ReadonlyArray<[keyof AiControl, (v: unknown) => boolean, string]> = [
  ["enabled", (v) => typeof v === "boolean", "true or false"],
  ["includeNotebook", (v) => typeof v === "boolean", "true or false"],
  ["lastAnalyzedSeq", isSeq, "a whole number"],
  ["inFlightSeqs", isSeqList, "a list of whole numbers"],
  ["analysisHold", isHold, "a hold record"],
];

function describeValue(v: unknown): string {
  if (v === null) return "null";
  return Array.isArray(v) ? "a list" : `a ${typeof v}`;
}

/** The reason a parsed record cannot be trusted, or undefined when every gating field is well-typed. */
function invalidAiControlField(raw: Record<string, unknown>): string | undefined {
  for (const [field, ok, expected] of FIELD_CHECKS) {
    if (field in raw && !ok(raw[field]))
      return `"${field}" must be ${expected}, found ${describeValue(raw[field])}`;
  }
  return undefined;
}

export class AiControlStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), AI_CONTROL_FILE);
  }

  /** Throws StateFileCorruptError (#2760) when the file exists but holds no readable record. */
  async load(caseId: string): Promise<AiControl> {
    let text: string;
    try {
      text = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...DEFAULT };
      throw err;
    }
    const raw = parseStateObject(text, caseId, AI_CONTROL_FILE, AI_CONTROL_CORRUPT_CONSEQUENCE);
    const bad = invalidAiControlField(raw);
    if (bad) throw new StateFileCorruptError(caseId, AI_CONTROL_FILE, AI_CONTROL_CORRUPT_CONSEQUENCE, bad);
    return { ...DEFAULT, ...(raw as Partial<AiControl>) };
  }

  async save(caseId: string, control: AiControl): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(control, null, 2));
  }
}
