/**
 * What an uploads-only Velociraptor import (/import-external on an "Uploaded Files" URL) reports
 * back: the per-file outcome lists, plus a warning for each file whose JSON kind was only guessed
 * (#1824) — the same sentence /import answers with (routes/importNotes.ts).
 */
export interface VeloUploadsOutcome {
  addedEvents: number;
  addedIocs: number;
  imported: string[];
  skipped: string[];
  warnings?: Array<{ file: string; warning: string }>;
}

/** The per-file fields of the route's answer. `warnings` is present only when a file was a guess. */
export function uploadOutcomeFields(
  out: VeloUploadsOutcome,
): Pick<VeloUploadsOutcome, "imported" | "skipped" | "warnings"> {
  return {
    imported: out.imported,
    skipped: out.skipped,
    ...(out.warnings?.length ? { warnings: out.warnings } : {}),
  };
}
