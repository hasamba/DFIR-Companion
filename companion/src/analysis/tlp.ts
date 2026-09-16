import { TLP_LABELS, type TlpLabel, type TlpMarking } from "./stateTypes.js";

// FIRST TLP 2.0 semantics (#933 item 21). Pure, no I/O. TLP_LABELS/TlpLabel/TlpMarking live in
// stateTypes.ts (Shared layer, since ForensicEvent needs to reference them); this file holds the
// logic that reads and ranks them.

// TheHive's own real legacy numeric scheme (0=WHITE, 1=GREEN, 2=AMBER, 3=RED) — the pre-2.0 TLP
// version, where WHITE is the label TLP 2.0 renamed to CLEAR.
const LEGACY_NUMERIC: Record<number, TlpLabel> = { 0: "CLEAR", 1: "GREEN", 2: "AMBER", 3: "RED" };

// Legacy and current string forms, normalized (uppercased, trimmed) before lookup.
const STRING_FORMS: Record<string, TlpLabel> = {
  "TLP:WHITE": "CLEAR",
  "TLP:CLEAR": "CLEAR",
  "TLP:GREEN": "GREEN",
  "TLP:AMBER": "AMBER",
  "TLP:AMBER+STRICT": "AMBER_STRICT",
  "TLP:RED": "RED",
};

// Maps a raw marking value — read from imported, untrusted data, hence `unknown` rather than a
// narrower type — to a TlpMarking. undefined = no value given at all, nothing was ever lost.
// {label:"unrecognized", raw} = a value WAS given but doesn't match any known legacy or current
// form (including a value of the wrong JS type entirely) — preserved verbatim, never silently
// dropped or defaulted to a guess.
export function normalizeLegacyTlp(raw: unknown): TlpMarking | undefined {
  if (raw === null || raw === undefined) return undefined;
  if (typeof raw === "number") {
    const label = LEGACY_NUMERIC[raw];
    return label ? { label } : { label: "unrecognized", raw };
  }
  // JSON.stringify, not String(): String(["TLP:RED"]) is the misleading "TLP:RED" (arrays
  // stringify as their joined elements) — an Ollama code review caught this as a real
  // "verbatim" claim violated for a value that would visually look like a valid marking.
  // JSON.stringify itself can throw (a BigInt) or return undefined (a function/symbol) for a
  // handful of exotic, non-JSON-serializable types — String() is a safe universal fallback there.
  if (typeof raw !== "string") {
    let rawStr: string;
    try {
      rawStr = JSON.stringify(raw) ?? String(raw);
    } catch {
      rawStr = String(raw);
    }
    return { label: "unrecognized", raw: rawStr };
  }
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  const label = STRING_FORMS[trimmed.toUpperCase()];
  return label ? { label } : { label: "unrecognized", raw };
}

const RANK: Record<TlpLabel, number> = Object.fromEntries(TLP_LABELS.map((label, i) => [label, i])) as Record<
  TlpLabel,
  number
>;

// The single most restrictive REAL label among those given. Unmarked (undefined) and
// unrecognized entries do not participate in the ranking — see hasUnmarkedOrUnrecognized(),
// which callers MUST also check before trusting this result as "the" marking (an Ollama design
// review found that skipping unmarked entries here can look like "no restriction found" when
// some inputs simply had no marking at all — that is a different fact from "found CLEAR").
export function mostRestrictive(markings: readonly (TlpMarking | undefined)[]): TlpLabel | undefined {
  let best: TlpLabel | undefined;
  for (const m of markings) {
    // A label surviving from persisted state can predate this schema (or be hand-edited) and
    // carry a value RANK has no entry for — `RANK[bogus]` is `undefined`, and `best === undefined`
    // would otherwise let it win purely by being first regardless of its real rank. Treat exactly
    // like "unrecognized": it does not participate in the ranking.
    if (!m || m.label === "unrecognized" || !(m.label in RANK)) continue;
    if (best === undefined || RANK[m.label] < RANK[best]) best = m.label;
  }
  return best;
}

// True whenever any given marking is absent or unrecognized. A caller falling back to a default
// (e.g. irisMap.ts's own fix) must floor at AMBER whenever this is true, never trust
// mostRestrictive() alone — that function ignores exactly the entries this one reports on.
export function hasUnmarkedOrUnrecognized(markings: readonly (TlpMarking | undefined)[]): boolean {
  return markings.some((m) => !m || m.label === "unrecognized");
}

// Whichever of `label` and `floor` is MORE restrictive — never looser than `floor`, but keeps
// `label` unchanged when it is already at least as restrictive. An Ollama code review found an
// earlier version of irisMap.ts's own "floor at amber" fix implemented as an unconditional
// override instead of a floor — it replaced a real RED marking with amber (a LOOSENING) whenever
// any OTHER linked event was simply unmarked. A floor is a minimum, not a replacement.
export function atLeastAsRestrictive(label: TlpLabel, floor: TlpLabel): TlpLabel {
  return RANK[label] <= RANK[floor] ? label : floor;
}

// "Missing labels do not mean permission to publish": true for RED, AMBER_STRICT, AMBER, an
// unrecognized marking, and undefined — unconditionally true for undefined, since this function
// is only ever called on data already known to carry intelligence semantics (see tlp.ts's own
// design note in RECOMMENDATION-933.21.md for why there is no "case-native" exception here).
export function requiresAnalystConfirmation(marking: TlpMarking | undefined): boolean {
  return !marking || (marking.label !== "GREEN" && marking.label !== "CLEAR");
}

// True ONLY for a real RED label. An unrecognized marking requires confirmation instead of
// blocking — treating it as a block would make it indistinguishable from a real RED, hiding the
// distinction an analyst needs to see.
export function blocksSharing(marking: TlpMarking | undefined): boolean {
  return marking?.label === "RED";
}

// The rule for when two events carrying a marking are merged/aggregated into one (e.g.
// eventAggregate.ts's own within-import row collapsing): a real marking always survives a merge
// with an unmarked or unrecognized one, and the tighter of two real markings wins. Never
// last-write-wins — an Ollama design review found that risk directly.
//
// An unrecognized marking is treated with AMBER-level caution everywhere else in this module
// (requiresAnalystConfirmation, irisMap.ts's own amber floor), so a real winner LOOSER than amber
// (GREEN/CLEAR) must still defer to a present unrecognized marking — an Ollama code review found
// an earlier version of this function let GREEN/CLEAR silently discard an unrecognized marking's
// own caution AND its preserved raw value. A real winner already at least as restrictive as amber
// (RED/AMBER_STRICT/AMBER) needs no such deference — it is already the more cautious answer.
export function combineMarkings(
  a: TlpMarking | undefined,
  b: TlpMarking | undefined,
): TlpMarking | undefined {
  const winner = mostRestrictive([a, b]);
  const unrecognized = a?.label === "unrecognized" ? a : b?.label === "unrecognized" ? b : undefined;
  if (winner && RANK[winner] <= RANK.AMBER) return { label: winner };
  if (unrecognized) return unrecognized;
  return winner ? { label: winner } : undefined;
}
