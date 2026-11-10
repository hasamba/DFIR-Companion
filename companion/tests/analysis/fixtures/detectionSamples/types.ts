// One synthetic raw record for the detection-overlap check (#2348). Every sample is a record the
// REAL importer accepts, so the importer, the bundled Sigma rules and the shipped tagger rules all
// read the same evidence. Records are synthetic: documentation IPs, example.* domains, fake ids.

/** Which importer reads the record. "m365" covers UAL, Entra sign-in and Entra directory audit;
 * "gcp" and "azure" (Azure Activity Log, #2500) are both read by the cloud-activity importer;
 * "gws" is a Google Workspace Reports API activity (#2522). */
export type DetectionSampleKind = "cloudtrail" | "m365" | "gcp" | "azure" | "gws";

export interface DetectionSample {
  /** Stable, unique name — printed in every report line. */
  id: string;
  kind: DetectionSampleKind;
  record: Record<string, unknown>;
  /** Where the record came from (the test it was copied from, or the Sigma rule it was built for). */
  from: string;
}

export const sample = (
  kind: DetectionSampleKind,
  id: string,
  from: string,
  record: Record<string, unknown>,
): DetectionSample => ({ id, kind, from, record });
