import { ProviderError, type AIProvider } from "../../providers/provider.js";

/**
 * The fallback synthesis model (#1734): used when the synthesis model's safety filter stops an
 * answer partway (Claude Code's "…safeguards stopped the response"). Built from
 * DFIR_AI_SYNTH_FALLBACK_* at startup; absent → a stop fails once the safety retries run out.
 */
export interface SynthesisFallback {
  provider: AIProvider;
  label: string;
}

/** The DFIR_AI_SYNTH_SAFETY_RETRIES tuning range (#1740): a whole number, capped for cost. */
const MAX_SAFETY_RETRIES = 3;
const DEFAULT_SAFETY_RETRIES = 1;

/**
 * How many times a safety-stopped synthesis model is asked again before the fallback (#1740). A
 * stop is random at normal evidence sizes — three scored runs were stopped once and passed on the
 * retry — so the default is one. Read strictly: a whole number 0–3 (larger is capped at 3);
 * blank or anything else is the default.
 */
export function safetyRetriesFromEnv(raw: string | undefined): number {
  const value = raw?.trim() ?? "";
  if (!/^\d+$/.test(value)) return DEFAULT_SAFETY_RETRIES;
  return Math.min(Number(value), MAX_SAFETY_RETRIES);
}

/**
 * The error a synthesis call throws when the primary's safety filter used up the retry budget and
 * no fallback is set (#1740). Only synthesis and the deep pass (#2076) say this: the provider's own safety_stop reaches every
 * AI path and must not claim retries that other paths never run.
 */
export function synthesisSafetyExhaustedError(
  label: string,
  stops: number,
  retries: number,
  task = "synthesis",
): ProviderError {
  const times = stops === 1 ? "once" : `${stops} times`;
  return new ProviderError(
    `${label}'s safety filter stopped the ${task} answer ${times} ` +
      `(DFIR_AI_SYNTH_SAFETY_RETRIES allows ${retries} ${retries === 1 ? "retry" : "retries"}). ` +
      "Set a fallback synthesis model (DFIR_AI_SYNTH_FALLBACK_MODEL) in Settings, or choose another " +
      "synthesis model.",
    "safety_stop",
  );
}

/**
 * Which model answers ONE synthesis call. It starts on the primary. A safety_stop from the primary
 * is retried on the primary while the call's budget lasts (#1740); after that, the call switches to
 * the fallback for good, so a later parse retry stays on the fallback and the primary is not
 * re-asked. The budget covers the whole call, across parse retries — a cost ceiling. No fallback →
 * the stop that exhausts the budget is rethrown. One instance per call; nothing leaks between runs.
 * `task` names the work in that error: "synthesis" by default, "deep-pass" for the deep pass's
 * batch reads (#2076).
 */
export class SynthesisModelChoice {
  private active: AIProvider;
  private stopped: string | undefined;
  private stops = 0;

  constructor(
    private readonly primary: AIProvider,
    private readonly primaryLabel: string,
    private readonly fallback: SynthesisFallback | undefined,
    private readonly safetyRetries: number = DEFAULT_SAFETY_RETRIES,
    private readonly task: string = "synthesis",
  ) {
    this.active = primary;
  }

  /** The provider whose answer is used — the fallback once the primary was stopped for good. */
  get answeredBy(): AIProvider {
    return this.active;
  }

  /** The label the answering model is recorded under. */
  get answeredByLabel(): string {
    return this.active === this.primary ? this.primaryLabel : (this.fallback?.label ?? this.primaryLabel);
  }

  /** The primary's label when the call switched to the fallback; undefined when it never did. */
  get fallbackFrom(): string | undefined {
    return this.stopped;
  }

  /** How many times the primary's safety filter stopped an answer in this call. */
  get safetyStops(): number {
    return this.stops;
  }

  /** The primary's label, for the log line. */
  get primaryName(): string {
    return this.primaryLabel;
  }

  /**
   * Run `call` on the active model. On the primary's safety_stop: count it, run `beforeNext` (the
   * caller's cancellation check, so a cancelled run starts no further call), then ask the primary
   * again while the budget lasts (`onRetry`), else switch to the fallback (`onSwitch`), else throw
   * synthesisSafetyExhaustedError. A stop from the fallback, and every other error, is rethrown
   * unchanged.
   */
  async ask<T>(
    call: (provider: AIProvider) => Promise<T>,
    beforeNext: () => void,
    onSwitch: (from: string, to: string) => void,
    onRetry: (err: ProviderError, stops: number) => void = () => undefined,
  ): Promise<T> {
    for (;;) {
      try {
        return await call(this.active);
      } catch (err) {
        const safetyStop = err instanceof ProviderError && err.kind === "safety_stop";
        if (!safetyStop || this.active !== this.primary) throw err;
        this.stops++;
        if (this.stops <= this.safetyRetries) {
          beforeNext();
          onRetry(err, this.stops);
          continue;
        }
        if (!this.fallback)
          throw synthesisSafetyExhaustedError(this.primaryLabel, this.stops, this.safetyRetries, this.task);
        beforeNext();
        this.stopped = this.primaryLabel;
        this.active = this.fallback.provider;
        onSwitch(this.primaryLabel, this.fallback.label);
      }
    }
  }
}
