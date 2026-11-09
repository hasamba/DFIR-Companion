import type { AnonControl } from "../anonControl.js";
import type { CustomEntity, KnownEntities } from "../anonymize.js";
import { mapFindings, PresidioScanError, PresidioTimeoutError, type PresidioFinding } from "../presidio.js";
import { splitAuthored, type AuthoredText } from "./presidioAuthoredText.js";
import type { ProviderCallContext } from "./providerCallContext.js";

/**
 * The Presidio scan the AI-call gate runs over already-masked text (#418), split out of
 * providerCall.ts for #2491 so the "Preview what the AI will see" path can ask the SAME question —
 * which values would this call hold? — without the gate's two side effects (saving the pending
 * approvals and throwing). `presidioHeldValues` is that question; `presidioGate` (providerCall.ts)
 * is it plus the save and the throw. One function, two callers, no copy.
 */

// Presidio's /analyze cannot take an arbitrarily large body, and a big CSV would be many
// requests. These bound it. They are module constants rather than env vars to keep the
// settings surface small — the truncation is logged, so hitting the cap is visible.
//
// NAMED "_CHARS", NOT "_BYTES": both are compared against JS string .length, which counts
// UTF-16 code units, not UTF-8 bytes. For non-ASCII PII (Hebrew, Cyrillic, accented names —
// all plausible in a DFIR case) that undercounts real UTF-8 size by up to ~3-4x, so the
// effective request-size cap is larger than a "_BYTES" name would imply. Left as a rough
// request-size bound rather than switched to a real byte measure (e.g. Buffer.byteLength)
// because the cap only needs to keep /analyze requests reasonably sized, not hit an exact
// number — and the split/truncate arithmetic below is unit-tested against character counts.
export const PRESIDIO_SCAN_CHUNK_CHARS = 50_000;
export const PRESIDIO_SCAN_MAX_CHARS = 5_000_000;
// How far the next chunk rewinds when a chunk had to be cut mid-line (see splitOnLineBoundaries).
// It only has to exceed the longest value Presidio's ENTITY_MAP can produce — names, IBANs, card
// and phone numbers, national IDs are all far under 256 characters — so this buys the guarantee
// cheaply: at the 50,000-char chunk size it re-scans at most 0.5% of the text.
export const PRESIDIO_SCAN_OVERLAP_CHARS = 256;

/** Values the analyst has already vetted or vetoed, case-folded on both sides. */
export function alreadyApproved(known: KnownEntities): Set<string> {
  // known.suppressed is DOCUMENTED as pre-lowercased (anonDiscovered.ts) and both writers
  // enforce it today, but that invariant is easy to violate at a distance and this is the
  // load-bearing case: a suppressed value is deliberately left UNMASKED, so Presidio sees it
  // raw on every single call. A case-fold mismatch here would re-trigger the approval gate
  // forever on a value the analyst already vetoed. Lower-case defensively rather than trust it.
  return new Set<string>([
    ...(known.custom ?? []).map((e) => e.value.toLowerCase()),
    ...(known.suppressed ?? []).map((s) => s.toLowerCase()),
  ]);
}

/**
 * Whether the per-case Presidio switch is on. A null control means the store is not wired, which
 * everywhere else in this module means "no per-case opinion" — so it leaves the configured layer
 * running rather than silently standing the gate down.
 */
export function presidioEnabledFor(control: AnonControl | null): boolean {
  return control?.presidio !== false;
}

/** The one message shape for a Presidio scan that could not run — the analyst's next action. */
export function presidioScanFailed(url: string, err: unknown): PresidioScanError {
  // A silent request and a refused connection need opposite advice, and getting that wrong is
  // expensive: telling someone to start a container that is already running sends them to look in
  // the one place the problem is not. Branch on the typed error, never on message wording.
  if (err instanceof PresidioTimeoutError)
    return new PresidioScanError(
      `Presidio is enabled but the scan at ${url} did not finish: ${err.message} ` +
        `(budget ${err.timeoutMs}ms). The analyzer may be busy — it serializes requests when run ` +
        `with a single worker — or the connection may be hanging without being refused. Raise ` +
        `DFIR_PRESIDIO_TIMEOUT_MS, give the analyzer more workers, check the URL and network path, ` +
        `or untick Presidio in the case's Anonymization panel to proceed without name detection.`,
      true,
    );
  // Every AI path goes through this gate, so the message says "the AI call", never "synthesis".
  // The per-case untick comes before DFIR_PRESIDIO_URL because it works at once (#1945).
  return new PresidioScanError(
    `Presidio is not reachable at ${url}. The AI call did not run. ` +
      `(${(err as Error).message}; not reachable, or returned an unusable response.) ` +
      `Start the analyzer and try again, or untick Presidio for this case in the Anonymization ` +
      `panel to continue with the built-in masking only (no restart). Clearing DFIR_PRESIDIO_URL ` +
      `also disables the layer, but needs a restart.`,
    false,
  );
}

/**
 * Cap what gets scanned, and SAY SO when the cap bites.
 *
 * A silent partial scan is worse than no scan: an analyst who sees "import scanned, no PII found"
 * must be able to trust that claim. Naming the unscanned character count is what stops a truncated
 * scan being mistaken for a complete one.
 */
export function capScanLength(
  ctx: ProviderCallContext,
  caseId: string,
  masked: string,
  maxChars: number,
): string {
  if (masked.length <= maxChars) return masked;
  ctx.log.warn(
    `[presidio] import pre-scan truncated — ${masked.length - maxChars} character(s) of this ` +
      `import were NOT scanned for PII (cap is ${maxChars} characters)`,
    { caseId },
  );
  return masked.slice(0, maxChars);
}

/**
 * Split on line boundaries so an entity is never cut in half across two /analyze requests — a
 * half an email address on each side of a chunk edge is two values Presidio recognises as neither.
 *
 * A line boundary is not always available. A prompt can carry a single line longer than the chunk
 * size — one enormous JSON object, a base64 blob, a log line with no newline for 60k characters —
 * and there the split falls back to a hard cut at the limit, which is exactly the mid-entity slice
 * the line search exists to avoid. That is a fail-OPEN in a fail-closed gate: the halves match
 * nothing, the scan reports clean, and the intact value goes to the model anyway.
 *
 * So a hard cut REWINDS the next chunk by `overlapChars`, making the two chunks share a window
 * wide enough to contain any entity Presidio maps. A value straddling the cut is therefore whole in
 * the second chunk even though it was severed in the first. Duplicates that overlap creates cost
 * nothing: mapFindings already dedupes on category + case-folded value.
 */
export function splitOnLineBoundaries(text: string, chunkChars: number, overlapChars = 0): string[] {
  // Never let the rewind consume more than a quarter of a chunk: `start` must advance, and a
  // pathological overlap >= chunkChars would rewind as far as it stepped and loop forever.
  const overlap = Math.max(0, Math.min(overlapChars, Math.floor(chunkChars / 4)));
  const chunks: string[] = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(start + chunkChars, text.length);
    let cutMidLine = false;
    if (end < text.length) {
      const nl = text.lastIndexOf("\n", end);
      if (nl > start) end = nl + 1;
      else cutMidLine = true;
    }
    chunks.push(text.slice(start, end));
    start = cutMidLine ? end - overlap : end;
  }
  return chunks;
}

/**
 * The values the gate WOULD hold for this already-masked prompt: scanned in chunks, found by
 * Presidio, not already vetted or vetoed by the analyst, and not only inside text the synthesis
 * model wrote. Empty when Presidio is not configured or is off for the case. Throws only
 * PresidioScanError (the scan could not run) — never saves and never raises the approval hold.
 */
export async function presidioHeldValues(
  ctx: ProviderCallContext,
  caseId: string,
  maskedText: string,
  known: KnownEntities,
  control: AnonControl | null,
  authored?: AuthoredText,
): Promise<CustomEntity[]> {
  const presidio = ctx.opts.presidio;
  if (!presidio || !presidioEnabledFor(control)) return [];

  // CHUNKED, on the same line-boundary split and the same chunk size as presidioPreScan. This used
  // to hand Presidio the whole prompt in one request, which made the unit of work as large as the
  // case: a 104k-char synthesis prompt was one indivisible request, so any timeout had to be sized
  // against however large this case happened to have grown. Chunking is what lets ONE fixed budget
  // be correct for every case, and it also bounds the damage of a timeout — an abandoned request
  // keeps running server-side (see DEFAULT_PRESIDIO_TIMEOUT_MS), so a smaller unit of work means
  // less of the single worker is left occupied by a scan nobody is waiting for any more.
  //
  // No maxChars cap here, unlike the pre-scan: capping would silently leave the tail of a prompt
  // unscanned on the way to the model, and this gate's whole contract is to fail closed.
  const chunkChars = ctx.opts.presidioScanCapsOverride?.chunkChars ?? PRESIDIO_SCAN_CHUNK_CHARS;
  const raw: PresidioFinding[] = [];
  for (const chunk of splitOnLineBoundaries(maskedText, chunkChars, PRESIDIO_SCAN_OVERLAP_CHARS)) {
    try {
      raw.push(...(await presidio.client.analyze(chunk)));
    } catch (err) {
      throw presidioScanFailed(presidio.url, err);
    }
  }

  const found = mapFindings(raw, presidio.minScore);
  if (found.length === 0) return [];

  const alreadyKnown = alreadyApproved(known);
  const unknown = found.filter((e) => !alreadyKnown.has(e.value.toLowerCase()));
  // Values that occur only in text the synthesis model wrote are not held (see presidioAuthoredText.ts).
  const { held, skipped } = splitAuthored(unknown, maskedText, authored);
  if (skipped.length > 0)
    ctx.log.info(
      `[presidio] ${skipped.length} value(s) found only in AI-written text — not held ` +
        `(${[...new Set(skipped.map((e) => e.category))].join(", ")})`,
      { caseId },
    );
  return held;
}
