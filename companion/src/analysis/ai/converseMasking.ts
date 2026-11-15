import type { ConverseRequest, ToolTurn } from "../../providers/toolCalling.js";
import {
  createAnonymizer,
  type AnonPair,
  type AnonPolicy,
  type Anonymizer,
  type KnownEntities,
} from "../anonymize.js";
import { ANON_LITERAL_PREFIX } from "../anonTokenLiterals.js";
import { AnonymizationChangedError } from "../anonRevision.js";
import { isGuardedUsername } from "../anonUsernames.js";

// The masking half of converseRestored (Watson phase 5, D6): how one send's transcript is masked,
// which readable fields it carries, and the checks that keep an earlier send's values masked.

export const MASKING_CHANGED =
  "The masking changed between Watson's lookups, so nothing was sent. Send your message again.";

/**
 * Apply `mask` to every string leaf AND every object key of `value` (controller ruling, review I2: a
 * model-written key can hold a case value). Numbers and other leaves stay as they are.
 */
export function maskDeep<T>(mask: (s: string) => string, value: T): T {
  if (typeof value === "string") return mask(value) as T;
  if (Array.isArray(value)) return value.map((v: unknown) => maskDeep(mask, v)) as T;
  if (value && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [mask(k), maskDeep(mask, v)])) as T;
  return value;
}

/** Every string leaf and object key of `value`. */
export function stringLeaves(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringLeaves);
  if (value && typeof value === "object")
    return Object.entries(value).flatMap(([k, v]) => [k, ...stringLeaves(v)]);
  return [];
}

/**
 * Every readable field a send carries, prompt first (so the gate's authored spans stay valid):
 * assistant text, every string leaf of the tool-call arguments, every tool result and the readable
 * opaque text. Encrypted payloads (`opaque`) are never listed. `echoed`, when the adapter reported
 * it, replaces the readable opaque text: a block the adapter drops is never sent, so never gated.
 */
export function outboundTexts(
  send: Pick<ConverseRequest, "userPrompt" | "transcript">,
  echoed?: readonly string[],
): string[] {
  const out = [send.userPrompt];
  for (const turn of send.transcript) {
    if (turn.role === "tool") out.push(...turn.results.map((r) => r.content));
    else
      out.push(
        turn.text,
        ...turn.calls.flatMap((c) => stringLeaves(c.input)),
        ...(echoed ? [] : (turn.opaqueText ?? [])),
      );
  }
  return [...out, ...(echoed ?? [])];
}

export function maskTurn(mask: (s: string) => string, turn: ToolTurn): ToolTurn {
  if (turn.role === "tool")
    return { ...turn, results: turn.results.map((r) => ({ ...r, content: mask(r.content) })) };
  return {
    ...turn,
    text: mask(turn.text),
    calls: turn.calls.map((c) => ({ ...c, input: maskDeep(mask, c.input) })),
  };
}

/** Drift guard (an assertion): every seeded token still means what an earlier send said it meant. */
export function assertSeedKept(anon: Anonymizer, seed: readonly AnonPair[]): void {
  const now = new Map(anon.pairs().map((p) => [p.token, p.value]));
  if (seed.every((p) => now.get(p.token) === p.value)) return;
  throw new AnonymizationChangedError(MASKING_CHANGED);
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * The final outbound check (review I1): no value an earlier send masked may leave in clear, in any
 * readable field this send carries. Masking keeps every seed value known, so this should never fire;
 * when it does (for example a username marked "Leave visible" mid-round), nothing is sent.
 */
export function assertNoSeedInClear(seed: readonly AnonPair[], outbound: readonly string[]): void {
  if (seed.length === 0) return;
  // A guarded username (admin, Administrator, guest, …) is never masked as a bare word, only inside
  // an account, so only its account forms (`QUAL\\name`, `name@domain`) count (review R1-I1).
  const guarded = (p: AnonPair) => p.category === "USER" && isGuardedUsername(p.value.toLowerCase());
  const alt = (ps: AnonPair[]) => ps.map((p) => escapeRe(p.value)).join("|");
  const plain = alt(seed.filter((p) => !guarded(p)));
  const qualified = alt(seed.filter(guarded));
  const parts = [
    ...(plain ? [`(?<![\\p{L}\\p{N}_])(?:${plain})(?![\\p{L}\\p{N}_])`] : []),
    ...(qualified
      ? [`\\\\(?:${qualified})(?![\\p{L}\\p{N}_])`, `(?<![\\p{L}\\p{N}_])(?:${qualified})@`]
      : []),
  ];
  const clear = new RegExp(parts.join("|"), "iu");
  if (outbound.some((text) => clear.test(text))) throw new AnonymizationChangedError(MASKING_CHANGED);
}

/**
 * Readable signed reasoning holding a value this masking would now hide. A seeded copy probes it,
 * so the send's own anonymizer never mints. An already-minted token is escaped by apply(): no change.
 */
export function staleReadable(policy: AnonPolicy, known: KnownEntities, anon: Anonymizer) {
  const probe = createAnonymizer(policy, known, anon.pairs());
  return (text: string): boolean => probe.apply(text).replaceAll(ANON_LITERAL_PREFIX, "ANON_") !== text;
}

/** A provider that cannot report or drop its echoed reasoning: stale readable text holds the send. */
export function assertNothingStale(transcript: readonly ToolTurn[], stale: (text: string) => boolean): void {
  for (const turn of transcript)
    if (turn.role === "assistant" && (turn.opaqueText ?? []).some(stale))
      throw new AnonymizationChangedError(MASKING_CHANGED);
}
