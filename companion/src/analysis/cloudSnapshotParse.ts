// Read a Microsoft-Extractor-Suite configuration snapshot CSV (#2305) into observations, and word
// each observation as a forensic event. Pure: the per-case comparison with earlier snapshots is
// ingest/cloudSnapshotImports.ts's job, over cloudStateStore.ts.
//
// The wording is the contract: a snapshot row is "state observed at collection; history unknown".
// It never names an action ("New-InboxRule") and never claims when the state began or who set it, and
// its description prefix ("M365 snapshot:", "Entra snapshot:") is one the action rules in tags.yaml
// do not match, so the inbox-rule ACTION rules never fire on observed state.

import { parseCsv } from "./csvImport.js";
import { stripBom } from "./tolerantJson.js";
import { snapshotCsvShape, type SnapshotShape } from "./cloudExportDetect.js";
import { mapInboxRule, mapTransportRule, mailboxDomains, creatorDomains } from "./cloudSnapshotRules.js";
import { mapOauthGrant, mapMfaState } from "./cloudSnapshotGrants.js";
import {
  collectionTime,
  type CollectionTime,
  type MappedSnapshot,
  type SnapRow,
  type SnapshotDecision,
} from "./cloudSnapshotModel.js";

export const OBSERVED_WORDING = "state observed at collection; history unknown";

export const SHAPE_LABEL: Record<SnapshotShape, string> = {
  inboxRules: "MES inbox rules snapshot",
  transportRules: "MES transport rules snapshot",
  oauthGrants: "MES OAuth permissions snapshot",
  mfaState: "MES MFA methods snapshot",
};

const PREFIX: Record<SnapshotShape, string> = {
  inboxRules: "M365 snapshot",
  transportRules: "M365 snapshot",
  oauthGrants: "Entra snapshot",
  mfaState: "Entra snapshot",
};

const SOURCE: Record<SnapshotShape, string> = {
  inboxRules: "Microsoft 365",
  transportRules: "Microsoft 365",
  oauthGrants: "Entra ID",
  mfaState: "Entra ID",
};

export interface SnapshotEvent {
  timestamp: string;
  description: string;
  severity: MappedSnapshot["severity"];
  mitreTechniques: string[];
  sources: string[];
  artifactName: string;
  message: string;
}

export interface ParsedSnapshot {
  shape: SnapshotShape | null;
  /** Data rows read. */
  total: number;
  /** One per distinct identity, first row wins. */
  rows: MappedSnapshot[];
  /** Rows repeating an identity already read from the same file. */
  duplicates: number;
  /** Rows without the columns that name the object. */
  skipped: number;
  time: CollectionTime;
  /** The events a first import of this file creates (every row new) — what the matrix proves. */
  events: SnapshotEvent[];
}

function rowsOf(text: string): { headers: Set<string>; rows: SnapRow[] } {
  const { headers, rows } = parseCsv(stripBom(text).body);
  const keys = headers.map((h) => h.trim().toLowerCase());
  return {
    headers: new Set(keys),
    rows: rows.map((cols) => Object.fromEntries(keys.map((k, i) => [k, cols[i] ?? ""]))),
  };
}

function mapperFor(shape: SnapshotShape, rows: readonly SnapRow[]): (r: SnapRow) => MappedSnapshot | null {
  switch (shape) {
    case "inboxRules": {
      const domains = mailboxDomains(rows);
      return (r) => mapInboxRule(r, domains);
    }
    case "transportRules": {
      const domains = creatorDomains(rows);
      return (r) => mapTransportRule(r, domains);
    }
    case "oauthGrants":
      return mapOauthGrant;
    case "mfaState":
      return mapMfaState;
  }
}

const SEVERITY_RANK = { Info: 0, Low: 1, Medium: 2, High: 3 } as const;

/** The event one observation adds; `decision` is "new" or "changed" (the others add none). */
export function snapshotEvent(
  m: MappedSnapshot,
  shape: SnapshotShape,
  time: CollectionTime,
  decision: Extract<SnapshotDecision, { kind: "new" | "changed" }>,
): SnapshotEvent {
  const changed = decision.kind === "changed";
  const body = changed
    ? `state differs from the snapshot collected ${decision.previous.observedAt}: ${decision.diff.join(", ")}; now: ${m.summary}`
    : m.summary;
  // A change between two collections is worth a look even when the new state is benign.
  const severity = changed && SEVERITY_RANK[m.severity] < SEVERITY_RANK.Low ? "Low" : m.severity;
  return {
    timestamp: time.observedAt,
    description: `${PREFIX[shape]}: ${m.subject} — ${body}; ${OBSERVED_WORDING}`,
    severity,
    mitreTechniques: m.mitre,
    sources: [SOURCE[shape]],
    artifactName: SHAPE_LABEL[shape],
    message: [
      `Observed at ${time.observedAt} — ${time.basis}`,
      ...m.details,
      `${SHAPE_LABEL[shape]}: what the object held when collected, not when it was set or by whom`,
    ].join(". "),
  };
}

/** Parse a snapshot CSV. `label` is the upload's (stored) file name, read for the MES collection time. */
export function parseCloudSnapshot(
  text: string,
  opts: { label: string; importedAt: string },
): ParsedSnapshot {
  const time = collectionTime(opts.label, opts.importedAt);
  const { headers, rows } = rowsOf(text);
  const shape = snapshotCsvShape(headers);
  if (!shape) return { shape, total: rows.length, rows: [], duplicates: 0, skipped: 0, time, events: [] };
  const map = mapperFor(shape, rows);
  const seen = new Set<string>();
  const out: MappedSnapshot[] = [];
  let duplicates = 0;
  let skipped = 0;
  for (const r of rows) {
    const m = map(r);
    if (!m) skipped++;
    else if (seen.has(m.identityKey)) duplicates++;
    else {
      seen.add(m.identityKey);
      out.push(m);
    }
  }
  const events = out.map((m) => snapshotEvent(m, shape, time, { kind: "new" }));
  return { shape, total: rows.length, rows: out, duplicates, skipped, time, events };
}
