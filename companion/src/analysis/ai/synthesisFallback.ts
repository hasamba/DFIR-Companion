import { ProviderError, type AIProvider } from "../../providers/provider.js";

/**
 * The fallback synthesis model (#1734): used when the synthesis model's safety filter stops an
 * answer partway (Claude Code's "…safeguards stopped the response"). Built from
 * DFIR_AI_SYNTH_FALLBACK_* at startup; absent → a stop fails the synthesis once.
 */
export interface SynthesisFallback {
  provider: AIProvider;
  label: string;
}

/**
 * Which model answers ONE synthesis call. It starts on the primary; a safety_stop from the primary
 * switches it to the fallback for the rest of that call, so a later parse retry stays on the
 * fallback and the primary is never re-asked with evidence that already stopped it. One instance
 * per call — the switch never leaks into another synthesis.
 */
export class SynthesisModelChoice {
  private active: AIProvider;
  private stopped: string | undefined;

  constructor(
    private readonly primary: AIProvider,
    private readonly primaryLabel: string,
    private readonly fallback: SynthesisFallback | undefined,
  ) {
    this.active = primary;
  }

  /** The provider whose answer is used — the fallback once the primary was stopped. */
  get answeredBy(): AIProvider {
    return this.active;
  }

  /** The label the answering model is recorded under. */
  get answeredByLabel(): string {
    return this.active === this.primary ? this.primaryLabel : (this.fallback?.label ?? this.primaryLabel);
  }

  /** The primary's label when its safety filter stopped it; undefined when it never did. */
  get fallbackFrom(): string | undefined {
    return this.stopped;
  }

  /**
   * Run `call` on the active model. On the primary's safety_stop with a fallback set: run
   * `beforeSwitch` (the caller's cancellation check, so a cancelled run starts no second call),
   * report the switch, and answer from the fallback. Every other error is rethrown unchanged.
   */
  async ask<T>(
    call: (provider: AIProvider) => Promise<T>,
    beforeSwitch: () => void,
    onSwitch: (from: string, to: string) => void,
  ): Promise<T> {
    try {
      return await call(this.active);
    } catch (err) {
      const safetyStop = err instanceof ProviderError && err.kind === "safety_stop";
      if (!safetyStop || !this.fallback || this.active !== this.primary) throw err;
      beforeSwitch();
      this.stopped = this.primaryLabel;
      this.active = this.fallback.provider;
      onSwitch(this.primaryLabel, this.fallback.label);
      return await call(this.active);
    }
  }
}
