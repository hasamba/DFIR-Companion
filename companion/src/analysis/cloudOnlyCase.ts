// Cloud-only case predicate (#2555). A tenant-log case (UAL, Entra sign-ins, Workspace, Okta …) has
// no Windows host to collect from, so host-centric remedies — "collect Windows.EventLogs.Evtx
// (Sysmon EID 3)", "Windows.Sysinternals.Autoruns", "Security.evtx 4688" — point the analyst at a
// collection that cannot exist. The coverage backstop (negativeAnswerCoverage.ts), the Evidence-gaps
// labels (knownUnknowns.ts) and the cloud key-question seeds (cloudKeyQuestions.ts) all ask this
// one question, so they cannot disagree about what kind of case it is.
//
// Conservative by design: true only when the case has NO host at all, at least one cloud-provenance
// row, and no host process telemetry. A mixed host + cloud case keeps every host remedy; a host-less
// case with no cloud evidence (screenshots, a manual row) keeps the #1588 "any host" fallback.
//
// Shaped to be widened by #2559 (the case's main evidence source): the per-event helpers and the
// label set are exported, so a source classifier can call or replace them without re-deriving them.
// Pure, no I/O.

import { CLOUD_AUDIT_RE, isGeneratedCoverageRow } from "./cloudMetadataAccess.js";
import type { ForensicEvent } from "./stateTypes.js";

/** Importer source labels (`ForensicEvent.sources`) that are tenant / cloud-control-plane logs. */
export const CLOUD_SOURCE_LABELS: ReadonlySet<string> = new Set(
  [
    "Microsoft 365",
    "Entra ID",
    "Google Workspace",
    "Okta",
    "Azure Activity",
    "Azure Storage Logs",
    "GCP Audit",
    "GCP Cloud Audit Log",
    "AWS CloudTrail",
    "cloudtrail",
  ].map((s) => s.toLowerCase()),
);

// CLOUD_AUDIT_RE does not match the Entra sign-in importer's description prefix, so it is added here.
const ENTRA_SIGNIN_RE = /^Entra sign-in:/;

/** True when the row came from a tenant / cloud audit log. */
export function hasCloudProvenance(e: ForensicEvent): boolean {
  if (e.canonical?.event.category === "cloud") return true;
  if ((e.sources ?? []).some((s) => CLOUD_SOURCE_LABELS.has(s.trim().toLowerCase()))) return true;
  const d = e.description ?? "";
  return ENTRA_SIGNIN_RE.test(d) || CLOUD_AUDIT_RE.test(d);
}

/** True when the row is host telemetry: it names a host, or a process ran on one. */
export function hasHostTelemetry(e: ForensicEvent): boolean {
  return !!(e.asset ?? "").trim() || !!(e.processName ?? "").trim();
}

export interface CloudOnlyInput {
  /** The events the caller reasons over (in scope, not dismissed). */
  events: readonly ForensicEvent[];
  /** Canonical hosts the caller already resolved (e.g. the collection inventory's). */
  hosts?: readonly string[];
}

/** No host, at least one cloud row, no host telemetry. The generated coverage row is ignored. */
export function isCloudOnlyCase({ events, hosts = [] }: CloudOnlyInput): boolean {
  if (hosts.length) return false;
  let cloud = false;
  for (const e of events) {
    if (isGeneratedCoverageRow(e)) continue;
    if (hasHostTelemetry(e)) return false;
    if (!cloud && hasCloudProvenance(e)) cloud = true;
  }
  return cloud;
}
