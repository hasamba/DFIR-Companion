// Confidence scoring (#226). Findings carry a numeric 0-100 `confidence` (AI certainty this finding
// is real, weighing evidence strength + source corroboration + model certainty — see SYNTHESIS_PROMPT)
// plus a `confidenceReason` one-liner. `confidenceLabel` derives the low/medium/high bucket from the
// same thresholds the dashboard already uses for its badge colors (conf-high/conf-mid/conf-low), so a
// single source of truth backs both the numeric filter and any low/medium/high display.
export type ConfidenceLabel = "low" | "medium" | "high";

export const CONFIDENCE_HIGH_THRESHOLD = 80;
export const CONFIDENCE_MEDIUM_THRESHOLD = 50;

export function confidenceLabel(confidence: number | undefined): ConfidenceLabel | undefined {
  if (confidence === undefined) return undefined;
  if (confidence >= CONFIDENCE_HIGH_THRESHOLD) return "high";
  if (confidence >= CONFIDENCE_MEDIUM_THRESHOLD) return "medium";
  return "low";
}
