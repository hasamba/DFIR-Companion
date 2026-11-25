// Types for dev-launch.mjs. It is .mjs so `npm run dev` runs it under plain `node` before tsx is
// loaded, and tsconfig has no allowJs, so the test that imports it needs this bridge (the same
// arrangement as upstreamRulesDiff.d.mts). Nothing generates this file.

export declare const HEAP_FLOOR_MB: number;
export declare const HEAP_CEILING_MB: number;

export interface HeapSizing {
  readonly heapMb: number;
  readonly memMb: number;
  readonly source: "machine" | "container";
}

export interface ExistingHeapFlag {
  readonly where: "NODE_OPTIONS" | "launcher arguments";
  /** Flags the child must be given explicitly (NODE_OPTIONS is inherited, so empty there). */
  readonly flags: readonly string[];
}

export declare function computeHeapMb(input: {
  readonly totalMemBytes: number;
  readonly constrainedMemBytes?: number;
}): HeapSizing;

export declare function existingHeapFlag(input: {
  readonly nodeOptions?: string;
  readonly execArgv?: readonly string[];
  readonly args?: readonly string[];
}): ExistingHeapFlag | null;

export declare const FORWARDED_SIGNALS: readonly ("SIGINT" | "SIGTERM")[];
export declare const FORWARD_GRACE_MS: number;

export interface ForwardTarget {
  readonly exitCode: number | null;
  readonly signalCode: string | null;
  kill(signal: string): unknown;
}

export interface SignalForwarder {
  onSignal(signal: string): void;
  cancel(): void;
}

export declare function createSignalForwarder(
  child: ForwardTarget,
  opts?: {
    readonly graceMs?: number;
    readonly setTimer?: (fn: () => void, ms: number) => unknown;
    readonly clearTimer?: (timer: unknown) => void;
  },
): SignalForwarder;

export declare function heapLogLine(sizing: HeapSizing | null, existing?: ExistingHeapFlag | null): string;
