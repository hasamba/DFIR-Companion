// Rule identity of a detection-style event description. Shared by detection grouping (synthGroup.ts)
// and the mark-false-positive "find similar" scorer (falsePositiveSimilarity.ts).

// Minimum length for an extracted rule header to be trusted (guards against a stray "[x] y: z").
const DETECTION_MIN_HEAD = 10;

/**
 * Extract the RULE IDENTITY from a detection-style description, or null when the description is not in
 * that format. Detection importers render:
 *
 *     "<Tool> [<Artifact>] <Detector>: <RuleName> - <per-event detail>"
 *
 * e.g. "Velociraptor [Windows.Detection.Sigma] Sigma: Encoded PowerShell - Computer: ws-01 User: alice".
 * The head identifies WHICH rule fired; the tail is per-event detail (host, user, path) that differs on
 * every hit. Fingerprinting the whole description therefore shatters one rule into one pattern per host —
 * measured on a real Velociraptor+Sigma case, 1,089 events produced 367 patterns instead of ~116.
 *
 * This is deliberately a HEURISTIC with a strict fallback: a description that does not carry both an
 * "[Artifact]" bracket and a "<Detector>: " separator returns null and keeps the existing fingerprint.
 * The failure mode is therefore "grouped less", never "grouped wrongly" — important because this couples
 * to an importer's rendering format, the same fragility that makes the login graph break silently when
 * mapWindows changes its description layout.
 */
export function detectionRuleHead(description: string | undefined): string | null {
  const desc = String(description ?? "");
  if (!/\[[^\]]+\]/.test(desc)) return null; // needs the "[Artifact]" bracket
  if (!desc.includes(": ")) return null; // needs the "<Detector>: <RuleName>" separator
  const cut = desc.indexOf(" - ");
  const head = (cut > 0 ? desc.slice(0, cut) : desc).trim();
  return head.length >= DETECTION_MIN_HEAD ? head : null;
}
