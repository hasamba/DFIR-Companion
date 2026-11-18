// Where a ForensicEvent's record and its time came from. Types only, so stateTypes.ts (the shared
// layer) can carry the fields without growing past its size limit.

// Where an aggregated cloud event came from (#2301). `group` keys its member records in the case's
// provenance relation (analysis/cloudRecordStore.ts; GET /cases/:id/source-records/:group pages them);
// `refs` is a bounded sample of record identities and `count` all of them. `conflict`: a member
// shared its record id with a DIFFERENT payload already imported. `hashIdentified`: a member had no
// provider id and is identified by its content hash.
export interface SourceRecords {
  group: string;
  count: number;
  refs: string[];
  conflict?: boolean;
  hashIdentified?: boolean;
}

/** The optional time-basis field a ForensicEvent carries (#2684). */
export interface EventTimeBasisFields {
  // "scan": `timestamp` is when the scanner looked, not when the artifact's event happened — a THOR
  // row that fell back to the scan time. A coverage gap that closes on such a row is the wait before
  // collection (gapEdgeClass.ts). Importer-only: stripAiExtractedFrom drops it from every model delta.
  timeBasis?: "scan";
}
