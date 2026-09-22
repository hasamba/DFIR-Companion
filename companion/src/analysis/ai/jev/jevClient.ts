/**
 * Transport for Jev, TypeSafe's "System One" DECISION model (#1540).
 *
 * Jev writes no prose. You POST a `state` — the text to judge — plus a map of named, typed
 * questions, and get exactly one typed answer per question back. That is the whole contract, and
 * it is why this file knows nothing about cases, timelines or investigation state: it is a pure
 * transport, so the caller decides what is worth asking about and what to do with the verdicts.
 *
 * Two routes, one body shape:
 *   - OpenRouter — POST https://openrouter.ai/api/alpha/decisions, model `typesafe/jev-1.13`.
 *     Its response carries `usage.cost` in real dollars. `typesafe/jev-latest` does NOT exist
 *     there and returns 400; only the versioned id works.
 *   - TypeSafe direct — POST https://api.typesafe.ai/v1/systemone, model `jev-latest`. Same body,
 *     but the response prices nothing, so `costUSD` stays unset.
 *
 * Everything the service can refuse is checked here BEFORE the request goes out (a 2-level score,
 * a 300-option choice, blank instructions), because a 422 costs a round trip to learn what the
 * limits already said. The response is validated just as hard on the way back: a missing answer id
 * or a type that does not match the question is a thrown error, never a silently absent verdict.
 */

export type JevQuestion =
  | { type: "noul"; instructions: string; criteria?: { true?: string; false?: string } }
  | { type: "choice"; instructions: string; criteria: Record<string, string | null> }
  | { type: "score"; instructions: string; criteria: string[] };

export type JevAnswer =
  | { type: "noul"; noul: number }
  | { type: "choice"; choice: string; probabilities: Record<string, number>; confidence: number }
  | {
      type: "score";
      score: number;
      legend: Record<string, string>;
      probabilities: Record<string, number>;
      confidence: number;
    };

export interface JevUsage {
  inputTokens: number;
  outputTokens: number;
  costUSD?: number;
}

export interface JevRequestConfig {
  readonly baseUrl: string; // full endpoint URL
  readonly model: string;
  readonly apiKey: string;
  readonly timeoutMs: number;
  readonly maxRetries?: number; // retries AFTER the first attempt; default 4
}

export interface JevBatchResult {
  readonly model: string;
  readonly answers: Readonly<Record<string, JevAnswer>>;
  readonly usage: JevUsage;
}

// Service limits, as documented and as the 422s confirm.
const MAX_CHOICE_OPTIONS = 255;
const MIN_SCORE_LEVELS = 2;
const MAX_SCORE_LEVELS = 10;

const DEFAULT_MAX_RETRIES = 4;
const RETRY_BASE_DELAY_MS = 1_000;
// A blip, not a wall: worth one more go. 400/401/422 are deliberately absent — retrying a bad key
// or a malformed question re-runs into the same answer and only triples how long the caller waits.
const RETRYABLE_STATUSES: ReadonlySet<number> = new Set([429, 500, 502, 503, 524, 529]);
// Enough of an error body to name the offending field, not enough to flood a log line.
const MAX_ERROR_BODY_CHARS = 400;

/** A failure we may or may not try again. Internal — callers see a plain Error. */
class JevRequestFailure extends Error {
  constructor(
    message: string,
    readonly retryable: boolean,
  ) {
    super(message);
    this.name = "JevRequestFailure";
  }
}

/**
 * Strip the key out of anything that becomes an error message. The service echoes the offending
 * Authorization header back on some 401s, and a transport error can carry the whole request line —
 * either one would otherwise put a live credential in a log file or a dashboard toast.
 */
function redact(text: string, apiKey: string): string {
  if (apiKey.length < 8) return text; // too short to match safely; nothing real is this short
  return text.split(apiKey).join("[redacted]");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateQuestions(questions: Readonly<Record<string, JevQuestion>>): void {
  const ids = Object.keys(questions);
  if (ids.length === 0) throw new Error("Jev needs at least one question — there is nothing to decide.");
  for (const id of ids) {
    const q = questions[id] as JevQuestion | undefined;
    if (!q || !isRecord(q)) throw new Error(`Jev question "${id}" is not a question object.`);
    if (typeof q.instructions !== "string" || q.instructions.trim() === "")
      throw new Error(`Jev question "${id}": instructions must be a non-empty string.`);
    if (q.type === "choice") {
      const options = isRecord(q.criteria) ? Object.keys(q.criteria).length : 0;
      if (options < 1 || options > MAX_CHOICE_OPTIONS)
        throw new Error(
          `Jev question "${id}": a choice needs 1..${MAX_CHOICE_OPTIONS} options, got ${options}.`,
        );
    } else if (q.type === "score") {
      const levels = Array.isArray(q.criteria) ? q.criteria.length : 0;
      if (levels < MIN_SCORE_LEVELS || levels > MAX_SCORE_LEVELS)
        throw new Error(
          `Jev question "${id}": a score needs ${MIN_SCORE_LEVELS}..${MAX_SCORE_LEVELS} ordered level ` +
            `descriptions, got ${levels}.`,
        );
    } else if (q.type !== "noul") {
      throw new Error(
        `Jev question "${id}": unknown question type "${String((q as { type?: unknown }).type)}".`,
      );
    }
  }
}

function numberField(raw: Record<string, unknown>, field: string, id: string): number {
  const value = raw[field];
  if (typeof value !== "number" || !Number.isFinite(value))
    throw new Error(`Jev answer "${id}": ${field} must be a finite number, got ${JSON.stringify(value)}.`);
  return value;
}

function numberMap(raw: Record<string, unknown>, field: string, id: string): Record<string, number> {
  const value = raw[field];
  if (!isRecord(value)) throw new Error(`Jev answer "${id}": ${field} must be a map of numbers.`);
  const out: Record<string, number> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry !== "number" || !Number.isFinite(entry))
      throw new Error(`Jev answer "${id}": ${field}["${key}"] is not a finite number.`);
    out[key] = entry;
  }
  return out;
}

function stringMap(raw: Record<string, unknown>, field: string, id: string): Record<string, string> {
  const value = raw[field];
  if (!isRecord(value)) throw new Error(`Jev answer "${id}": ${field} must be a map of strings.`);
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry !== "string") throw new Error(`Jev answer "${id}": ${field}["${key}"] is not a string.`);
    out[key] = entry;
  }
  return out;
}

function parseAnswer(id: string, question: JevQuestion, raw: unknown): JevAnswer {
  if (!isRecord(raw)) throw new Error(`Jev answer "${id}" is missing or is not an object.`);
  if (raw.type !== question.type)
    throw new Error(
      `Jev answer "${id}": expected a "${question.type}" answer, got "${String(raw.type)}". ` +
        `The question and its answer must agree.`,
    );
  if (question.type === "noul") {
    const noul = numberField(raw, "noul", id);
    if (noul < 0 || noul > 1)
      throw new Error(`Jev answer "${id}": noul is a probability and must be 0..1, got ${noul}.`);
    return { type: "noul", noul };
  }
  if (question.type === "choice") {
    const choice = raw.choice;
    if (typeof choice !== "string" || !(choice in question.criteria))
      throw new Error(`Jev answer "${id}": choice "${String(choice)}" is not one of the offered options.`);
    return {
      type: "choice",
      choice,
      probabilities: numberMap(raw, "probabilities", id),
      confidence: numberField(raw, "confidence", id),
    };
  }
  // A score is probability-weighted, so it can land BETWEEN two levels (2.45 of 0..4). Never round
  // it here — the fraction is the caller's signal that the model sat on the fence.
  return {
    type: "score",
    score: numberField(raw, "score", id),
    legend: stringMap(raw, "legend", id),
    probabilities: numberMap(raw, "probabilities", id),
    confidence: numberField(raw, "confidence", id),
  };
}

function parseUsage(raw: unknown): JevUsage {
  const usage = isRecord(raw) ? raw : {};
  const num = (value: unknown): number => (typeof value === "number" && Number.isFinite(value) ? value : 0);
  const cost = usage.cost;
  return {
    inputTokens: num(usage.input_tokens),
    outputTokens: num(usage.output_tokens),
    // Only the OpenRouter route prices the call. The TypeSafe direct route sends no cost field,
    // and an absent costUSD is what lets the caller say "unpriced" instead of "$0.00".
    ...(typeof cost === "number" && Number.isFinite(cost) ? { costUSD: cost } : {}),
  };
}

function parseBatch(
  fallbackModel: string,
  json: unknown,
  questions: Readonly<Record<string, JevQuestion>>,
): JevBatchResult {
  if (!isRecord(json)) throw new Error("Jev returned a body that is not a JSON object.");
  const rawAnswers = json.answers;
  if (!isRecord(rawAnswers)) throw new Error("Jev returned no answers map.");
  const answers: Record<string, JevAnswer> = {};
  for (const [id, question] of Object.entries(questions)) {
    answers[id] = parseAnswer(id, question, rawAnswers[id]);
  }
  return {
    model: typeof json.model === "string" ? json.model : fallbackModel,
    answers,
    usage: parseUsage(json.usage),
  };
}

async function requestOnce(cfg: JevRequestConfig, body: string, fetchImpl: typeof fetch): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
  try {
    let res: Response;
    try {
      res = await fetchImpl(cfg.baseUrl, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${cfg.apiKey}` },
        body,
        signal: controller.signal,
      });
    } catch (err) {
      // A timeout is a wall, not a blip (the repo's AI retry policy says the same): retrying only
      // makes the caller wait another full timeout for the same silence.
      if (controller.signal.aborted)
        throw new JevRequestFailure(`Jev request timed out after ${cfg.timeoutMs}ms`, false);
      const detail = redact(err instanceof Error ? err.message : String(err), cfg.apiKey);
      throw new JevRequestFailure(`Jev transport error: ${detail}`, true);
    }
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      const detail = redact(text.slice(0, MAX_ERROR_BODY_CHARS), cfg.apiKey) || "(empty body)";
      throw new JevRequestFailure(
        `Jev HTTP ${res.status} from ${cfg.baseUrl}: ${detail}`,
        RETRYABLE_STATUSES.has(res.status),
      );
    }
    try {
      return await res.json();
    } catch {
      throw new JevRequestFailure(`Jev returned a body that is not JSON (HTTP ${res.status}).`, false);
    }
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Ask Jev every question in one call. One request with thirteen questions is far cheaper and
 * faster than thirteen requests, which is why `questions` is a map rather than a single question.
 *
 * `fetchImpl` is injected so tests never touch the network.
 */
export async function askJev(
  cfg: JevRequestConfig,
  state: unknown,
  questions: Readonly<Record<string, JevQuestion>>,
  fetchImpl: typeof fetch = fetch,
): Promise<JevBatchResult> {
  validateQuestions(questions);
  let body: string;
  try {
    body = JSON.stringify({ model: cfg.model, state, questions });
  } catch (err) {
    throw new Error(`Jev state could not be serialized to JSON: ${(err as Error).message}`);
  }
  const maxRetries = cfg.maxRetries ?? DEFAULT_MAX_RETRIES;
  for (let attempt = 0; ; attempt++) {
    try {
      return parseBatch(cfg.model, await requestOnce(cfg, body, fetchImpl), questions);
    } catch (err) {
      const retryable = err instanceof JevRequestFailure && err.retryable;
      if (!retryable || attempt >= maxRetries) throw err;
      await new Promise((resolve) => setTimeout(resolve, RETRY_BASE_DELAY_MS * 2 ** attempt));
    }
  }
}
