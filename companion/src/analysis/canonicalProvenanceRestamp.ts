import type { ForensicEvent } from "./stateTypes.js";

// #1352: read-time re-stamp of the `network.source.provenance` stamp for an already-canonical
// envelope that an AUDITED edge-observed writer persisted before it stamped (siemImport.ts began
// at d0b613fa, #1310; the other writers landed theirs in the same change). #1342 made
// hostBinding.ts's IP index fail-closed on the stamp, so without this every IP -> host binding on
// such a case vanished at once — identical 4624 evidence bound if imported today and not if
// imported yesterday, with nothing but the #1345 counter to say so.
//
// WHY THIS IS SOUND WHERE THE LEGACY PATH IS NOT. canonicalEvent.ts's legacy upgrade copies a
// pre-canonical `srcIp` whose original importer is unknowable, so it stays unstamped (EXEMPT in
// the sweep). An already-canonical envelope is different: `producer.importer` names the writer,
// and for the writers below the audit (ARCHITECTURE.md § "The `network.source.provenance` trust
// flag") already found that every address they write is one their own recorder edge observed. The
// provenance was always knowable from the envelope; only the stamp was missing.
//
// The contract lives in ARCHITECTURE.md; the writer registry in
// tests/architecture/networkSourceProvenanceSweep.test.ts (`SITES`) is the list of record, and
// that test pins this allowlist to the `producer.importer` ids those files declare — an id here
// that no audited writer declares, or an audited writer whose id is missing here, fails it. The
// legacy-upgrade importer and `email` (the one header-sourced writer, whose address write #1184
// removed) are never in it. Pure — no I/O, returns the same object when there is nothing to do.
// No schemaVersion bump: nothing is removed or re-read, an optional field is filled in on the
// same terms its writer would have (policy: mkdocs-docs/reference/canonical-events.md).

/** `producer.importer` ids written by the audited edge-observed writers (sweep `SITES`). */
export const EDGE_OBSERVED_IMPORTERS: ReadonlySet<string> = new Set([
  "aws-cloudtrail", // awsImport.ts, awsComputeRow.ts, awsLineage.ts
  "azure-storage-log", // azureStorageLogImport.ts
  "azure-activity", // cloudActivityImport.ts
  "gcp-audit", // gcpRow.ts
  "google-workspace", // googleWorkspaceImport.ts
  "m365", // m365Import.ts (and passwordSprayFanout.ts rows built from it)
  "m365-audit", // entraAuditImport.ts, exchangeAuditImport.ts, mailboxChain.ts
  "network", // webChainRows.ts, dnsWireRows.ts, networkImport.ts, smbChainRows.ts, tlsSession.ts
  "combined-log", // combinedLogImport.ts
  "windows-event", // siemImport.ts — EVTX IpAddress/SourceIp/SourceAddress
  "aws-vpc-flow-log", // awsFlowLogImport.ts
  "azure-vnet-flow-log", // azureFlowLogImport.ts
  "gcp-vpc-flow-log", // gcpFlowLogImport.ts
  "exporter-flow", // exporterFlowImport.ts
  "auditd", // auditdImport.ts
  "ecar", // ecarImport.ts (and passwordSprayFanout.ts rows built from it)
]);

/**
 * Re-stamp `network.source.provenance: "edge-observed"` on an envelope whose importer is audited
 * edge-observed and whose address is present but unstamped. Any other event — no envelope, no
 * address, already stamped, importer outside the allowlist — is returned as the same object.
 */
export function restampEdgeObserved(event: ForensicEvent): ForensicEvent {
  const canonical = event.canonical;
  const source = canonical?.network?.source;
  if (!canonical || !source?.address || source.provenance) return event;
  if (!EDGE_OBSERVED_IMPORTERS.has(canonical.producer?.importer ?? "")) return event;
  return {
    ...event,
    canonical: {
      ...canonical,
      // The `address:` key is spelled out so the sweep sees this as a registered write site.
      network: {
        ...canonical.network,
        source: { ...source, address: source.address, provenance: "edge-observed" },
      },
    },
  };
}
