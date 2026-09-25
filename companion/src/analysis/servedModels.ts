// Which concrete model served each AI call (#1601).
//
// A provider may answer an alias ("sonnet") with a concrete model ("claude-sonnet-5") and report it
// back as `usage.resolvedModel`. Only the claude-code provider does today. This module is where
// that answer goes after every completed call, so three readers can use it:
//
//   - the job that made the call — matched by its AbortSignal, see JobManager.useServedModels;
//   - a queued or running job that has not had an answer yet — "last run: Sonnet 5", from the
//     per-provider map below;
//   - the synthesis run manifest — collectServedModel() scopes one call chain, so a concurrent call
//     for another case can never leak its answer into this run's record.
//
// Filled only from real answers. There is no probe call at startup, and a provider that reports no
// resolvedModel leaves every reader with the alias alone.
import { AsyncLocalStorage } from "node:async_hooks";

export interface ServedModelEvent {
  /** Provider name, e.g. "claude-code". */
  provider: string;
  /** The configured model — the alias the job was pinned to. */
  alias: string;
  /** The concrete model the provider reported, already validated. */
  resolvedModel: string;
  /** The caller's cancel signal, when the call carried one — identifies the job. */
  signal?: AbortSignal;
}

export interface ServedModelInput {
  provider: string;
  alias: string;
  resolvedModel: unknown;
  signal?: AbortSignal;
}

export type ServedModelListener = (event: ServedModelEvent) => void;

const MAX_MODEL_ID_CHARS = 200;

const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

/**
 * A model id from a provider's output, or undefined. The value comes from a subprocess's JSON, so
 * it is checked like any other untrusted input before it reaches a job row or a manifest.
 */
export function validResolvedModel(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_MODEL_ID_CHARS) return undefined;
  if (CONTROL_CHARS.test(trimmed)) return undefined;
  return trimmed;
}

interface Collector {
  resolvedModel?: string;
}

const scope = new AsyncLocalStorage<Collector>();

function key(provider: string, alias: string): string {
  return `${provider}\u0000${alias}`;
}

export class ServedModelRegistry {
  private readonly last = new Map<string, string>();
  private readonly listeners = new Set<ServedModelListener>();

  /** Note one completed call. A call with no valid resolvedModel changes nothing. */
  record(input: ServedModelInput): void {
    const resolvedModel = validResolvedModel(input.resolvedModel);
    if (!resolvedModel) return;
    this.last.set(key(input.provider, input.alias), resolvedModel);
    const collector = scope.getStore();
    if (collector) collector.resolvedModel = resolvedModel;
    const event: ServedModelEvent = {
      provider: input.provider,
      alias: input.alias,
      resolvedModel,
      ...(input.signal ? { signal: input.signal } : {}),
    };
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // A listener failure must never fail the AI call that reported the model.
      }
    }
  }

  /** The concrete model the last completed call for this provider and alias ran on. */
  lastFor(provider: string, alias: string): string | undefined {
    return this.last.get(key(provider, alias));
  }

  subscribe(listener: ServedModelListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** Tests only: forget every answer and every listener. */
  reset(): void {
    this.last.clear();
    this.listeners.clear();
  }
}

/** The process-wide registry: the CLI's alias mapping is process-wide knowledge. */
export const servedModels = new ServedModelRegistry();

/**
 * Run `fn` and report the concrete model the last call inside it ran on. Scoped to this call chain
 * (AsyncLocalStorage), so a call for another case at the same moment cannot change the answer.
 */
export async function collectServedModel<T>(
  fn: () => Promise<T>,
): Promise<{ value: T; resolvedModel?: string }> {
  const collector: Collector = {};
  const value = await scope.run(collector, fn);
  return collector.resolvedModel ? { value, resolvedModel: collector.resolvedModel } : { value };
}
