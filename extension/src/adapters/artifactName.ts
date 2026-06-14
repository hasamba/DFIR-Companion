// Build the synthetic evidence filename for a pushed artifact. The companion's importDetect routes
// on CONTENT, but a Velociraptor-looking name nudges ambiguous rows to the Velociraptor importer, so
// embedding the adapter id is a useful hint as well as a human-readable audit label. Pure (date is
// injected) → unit-tested.

export function buildArtifactFilename(adapterId: string, date: Date): string {
  // Cap generously so a full artifact name (e.g. DetectRaptor.Windows.Detection.Applications) isn't
  // truncated; the row-level `_Source` carries the untruncated name regardless.
  const safeId = (adapterId || "artifact").replace(/[^\w.\-]+/g, "_").slice(0, 90) || "artifact";
  // 2026-06-14T10-30-00 — colons aren't filename-safe on Windows.
  const stamp = date.toISOString().replace(/\.\d+Z$/, "").replace(/:/g, "-");
  return `${safeId}-${stamp}.json`;
}
