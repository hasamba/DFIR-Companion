import { adapterById } from "./registry.js";

// Sentinel override value meaning "force no adapter — plain screenshot only", distinct from ""
// (no override / auto-detect). Shared between the content script (artifactCapture.ts) and the
// popup's <select> option value.
export const OVERRIDE_NONE = "__none__";

/**
 * Resolve which adapter id is actually in effect for a tab, given what matchUrl auto-detected and
 * what the analyst forced via the popup's manual override. Pure — the content script
 * (artifactCapture.ts) is the only caller.
 *   - overrideId === ""            → no override, use the auto-detected adapter (may be null)
 *   - overrideId === OVERRIDE_NONE → forced off — plain screenshot only, regardless of detection
 *   - overrideId === <adapter id>  → forced to that adapter, IF it's a real registry id, else
 *                                     fall back to auto-detect (a stale/bad override must not stick)
 */
export function resolveActiveAdapter(detectedId: string | null, overrideId: string): string | null {
  if (overrideId === "") return detectedId;
  if (overrideId === OVERRIDE_NONE) return null;
  return adapterById(overrideId) ? overrideId : detectedId;
}
