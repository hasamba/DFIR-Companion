import { buildDetectContext, detectImportKindEx } from "./importDetect.js";
import type { ExternalImporter } from "./declarativeImporter.js";

// Choosing between the built-in importers and the analyst's own (custom declarative) importers.
// Moved out of importDetect.ts (#1736) when the choice started returning HOW it was made, because
// importDetect.ts sits at the 800-line limit. The decision is recorded where it is made and never
// re-inferred downstream — the support bundle reports it as the import's `detection`.

/** How detectImportWithCustomEx chose (#1736) — what the support bundle reports as `detection`. */
export type ImportDecision =
  "builtin_confident" | "builtin_unconfident" | "custom_first" | "custom_gap_filled" | "no_match";

// Resolve a file to a built-in ImportKind OR a custom importer id, honoring the user's precedence.
export function detectImportWithCustom(
  filename: string,
  text: string,
  importers: Map<string, ExternalImporter>,
  precedence: "builtin-first" | "external-first",
): string {
  return detectImportWithCustomEx(filename, text, importers, precedence).kind;
}

/** The same decision, with the confidence and the rule that made it — never re-inferred later. */
export function detectImportWithCustomEx(
  filename: string,
  text: string,
  importers: Map<string, ExternalImporter>,
  precedence: "builtin-first" | "external-first",
): { kind: string; confident: boolean; decision: ImportDecision } {
  const tryCustom = (): string | null => {
    if (importers.size === 0) return null;
    const ctx = buildDetectContext(filename, text);
    const ordered = [...importers.values()].sort((a, b) => a.priority - b.priority);
    for (const imp of ordered) {
      try {
        if (imp.detect(ctx)) return imp.id;
      } catch {
        /* skip a throwing importer */
      }
    }
    return null;
  };

  const builtin = (kind: string, confident: boolean) => ({
    kind,
    confident,
    decision: (kind === "unknown"
      ? "no_match"
      : confident
        ? "builtin_confident"
        : "builtin_unconfident") as ImportDecision,
  });
  if (precedence === "external-first") {
    const custom = tryCustom();
    if (custom) return { kind: custom, confident: true, decision: "custom_first" };
    const ex = detectImportKindEx(filename, text);
    return builtin(ex.kind, ex.confident);
  }
  const { kind, confident } = detectImportKindEx(filename, text);
  if (confident) return builtin(kind, true); // a specific built-in wins
  const custom = tryCustom(); // else custom fills the gap, else the generic fallback
  return custom ? { kind: custom, confident: true, decision: "custom_gap_filled" } : builtin(kind, false);
}
