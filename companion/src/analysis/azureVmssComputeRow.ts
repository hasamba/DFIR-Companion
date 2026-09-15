// The words and the envelope block of one Azure VMSS-member compute-lifecycle row (#931 item 8,
// #1078): every part is the record's own — a recorded operation, a launch fact, a remote-access
// request — and a secret (admin password, SSH key material) never reaches the row. Each row is
// one OBSERVED lifecycle epoch for a member, never a claim of a proven distinct physical machine.
// The pass that fills the state lives in azureVmssCompute.ts.

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type {
  AzureComputeLaunch,
  AzureVmssComputeBlock,
  AzureVmssComputeFact,
} from "./canonicalAzureCompute.js";
import { normalizeTime, type MappedEvent } from "./siemImport.js";
import { show, type Timed } from "./azureComputeState.js";
import {
  BASIS,
  COVERAGE_NOTE,
  DESCRIPTION_MAX,
  FACT_MITRE,
  FACT_WORDS,
  LIMIT_NOTE,
  OPERATIONS_NAMED_MAX,
  RAW_RECORDS_MAX,
  VMSS_COMPUTE_MAX,
  VMSS_EPOCHS_PER_MEMBER_MAX,
  byTime,
  firstTime,
  plural,
  type Operation,
  type Remote,
  type VmssEpoch,
  type VmssMember,
} from "./azureVmssComputeState.js";

const whoAt = (time: number, by: string, locator: string): string =>
  `at ${new Date(time).toISOString()} by ${show(by, 60)} (${locator})`;

function operationWords(e: Operation): string {
  const call = show(e.call, 60);
  const label =
    e.kind === "start"
      ? "recorded: started"
      : e.kind === "deallocate"
        ? "recorded: deallocated"
        : "recorded: deleted";
  return `${call}: ${label} ${whoAt(e.time, e.by, e.locator)}`;
}

function launchWords(l: Omit<AzureComputeLaunch, "time"> & Timed): string {
  const facts = [
    l.vmSize ? `size ${show(l.vmSize, 30)}` : "",
    l.image ? `image ${show(l.image, 120)}` : "",
    l.adminUsername ? `admin username ${show(l.adminUsername, 40)} (no credential material shown)` : "",
    l.networkInterfaces.length
      ? `network interfaces ${l.networkInterfaces.map((n) => show(n, 80)).join(", ")}`
      : "",
    l.identityAssigned ? "managed identity recorded (content not read)" : "no managed identity recorded",
  ].filter(Boolean);
  return `recorded write ${new Date(l.time).toISOString()} by ${show(l.by)} (${l.locators.join(", ")}) — ${facts.join(", ")}`;
}

export function summaryRow(
  member: VmssMember,
  epoch: VmssEpoch,
  facts: readonly AzureVmssComputeFact[],
  grade: Severity,
  coverage: { records: number; first: string; last: string },
  uploadId: string,
): MappedEvent {
  const operations = epoch.operations.all().sort(byTime);
  const operationsBeyond = Math.max(0, operations.length - OPERATIONS_NAMED_MAX) + epoch.operations.beyond;
  const parts = [
    epoch.launch ? launchWords(epoch.launch) : "write/launch not in this upload",
    ...(operations.length
      ? [
          `recorded operations${operationsBeyond ? ` (${Math.min(operations.length, OPERATIONS_NAMED_MAX)} named, ${operationsBeyond} further not individually named)` : ""}: ${operations
            .slice(0, OPERATIONS_NAMED_MAX)
            .map(operationWords)
            .join("; ")}`,
        ]
      : []),
    ...(epoch.remote.length
      ? [
          `remote-access requests (requested; whether anything ran is not in the Activity Log): ${epoch.remote
            .slice()
            .sort(byTime)
            .map((r: Remote) => `${show(r.call, 60)} ${whoAt(r.time, r.by, r.locator)}`)
            .join("; ")}${epoch.remoteBeyond ? `; +${plural(epoch.remoteBeyond, "more request")}` : ""}`,
        ]
      : []),
    ...(epoch.notSucceeded
      ? [`${plural(epoch.notSucceeded, "record")} without a recorded success — not joined`]
      : []),
  ];
  const factWords = facts.length
    ? `recorded facts: ${facts
        .map((f) => {
          const c = epoch.facts.get(f);
          return `${FACT_WORDS[f]}${c ? ` (${c.locator})` : ""}`;
        })
        .join(", ")} (${plural(facts.length, "kind")})`
    : "recorded facts: none";
  const reserved = [...(epoch.launch?.locators ?? []), ...[...epoch.facts.values()].map((c) => c.locator)];
  const cited = [...new Set([...reserved, ...epoch.locators])].slice(0, RAW_RECORDS_MAX);
  const notCited = Math.max(0, epoch.contributing - cited.length);
  const tail = [
    factWords,
    ...(notCited ? [`${plural(notCited, "further record")} not individually cited`] : []),
    LIMIT_NOTE,
    COVERAGE_NOTE,
  ].join("; ");
  const head = `Azure VMSS compute lifecycle: ${show(member.instanceId, 60)} (scale set ${show(member.setName, 60)}, subscription ${show(member.subscriptionId, 40)}, resource group ${show(member.resourceGroup, 40)}) [epoch ${epoch.index}]`;
  const room = DESCRIPTION_MAX - head.length - tail.length - 6;
  const lead = parts.join("; ");
  const description = `${head} [${lead.length > room ? `${lead.slice(0, Math.max(0, room - 1))}…` : lead}; ${tail}]`;
  const identity = createHash("sha256")
    .update(
      `${member.subscriptionId.length}:${member.subscriptionId}|${member.resourceGroup.length}:${member.resourceGroup}|${member.setName.length}:${member.setName}|${member.instanceId.length}:${member.instanceId}|${epoch.index}|${uploadId.length}:${uploadId}`,
    )
    .digest("hex")
    .slice(0, 32);
  const block: AzureVmssComputeBlock = {
    instanceId: member.instanceId,
    subscriptionId: member.subscriptionId,
    resourceGroup: member.resourceGroup,
    setName: member.setName,
    epoch: epoch.index,
    ...(epoch.launch
      ? { launch: (({ time, ...rest }) => ({ ...rest, time: new Date(time).toISOString() }))(epoch.launch) }
      : {}),
    operations: operations.map(({ time, ...e }) => ({ ...e, time: new Date(time).toISOString() })),
    operationsBeyond,
    remote: epoch.remote.map(({ time, ...r }) => ({ ...r, time: new Date(time).toISOString() })),
    remoteBeyond: epoch.remoteBeyond,
    attempts: { notSucceeded: epoch.notSucceeded },
    facts: [...facts],
    notCited,
    coverage,
    basis: BASIS,
  };
  const observed = new Date(firstTime(epoch)).toISOString();
  const mitre = grade === "Low" ? [] : [...new Set(facts.map((f) => FACT_MITRE[f]))];
  return {
    timestamp: normalizeTime(observed),
    description,
    severity: grade,
    mitre,
    aggKey: boundedAggKey(`azure-vmss-compute-lifecycle|${identity}`),
    sources: ["Azure Activity"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "compute-lifecycle", action: "lifecycle", outcome: "success" },
      actor: { kind: "account", name: epoch.launch?.by ?? member.instanceId },
      // No `region` set here, matching azureComputeRow.ts's own precedent — Azure's resource group
      // is not the same concept as an AWS/GCP region; the full identity lives in the block below.
      cloud: {
        provider: "azure",
        accountId: member.subscriptionId,
        resource: `${member.setName}/${member.instanceId}`,
      },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: { rawRecords: cited.map((l) => ({ source: "azure-activity", locator: l })) },
      producer: {
        importer: "azure-activity",
        parserVersion: "1",
        mappingVersion: "azure-vmss-compute-lifecycle-v1",
        ruleVersions: ["azure-vmss-compute-v1"],
      },
      azureVmssCompute: block,
    }),
  };
}

/** The members beyond the reported bound, the records past a tracked-entity bound, and the
 * epochs past their own examined bound (#1078) — counts, never claims. */
export function omittedRow(
  count: number,
  severity: Severity,
  untrackedRecords: number,
  uploadId: string,
  epochsBeyond = 0,
): MappedEvent {
  const description = `Azure VMSS compute lifecycle — ${count ? `${count} further epoch${count === 1 ? "" : "s"} with a lifecycle in this upload beyond the ${VMSS_COMPUTE_MAX} reported — not shown` : "no further epoch beyond the reported"}${untrackedRecords ? `; ${plural(untrackedRecords, "record")} naming members past the tracked bound — not read` : ""}${epochsBeyond ? `; ${plural(epochsBeyond, "epoch")} past its own examined bound (up to ${VMSS_EPOCHS_PER_MEMBER_MAX} per member, or the global cap) — not read` : ""}`;
  return {
    timestamp: "",
    description,
    severity,
    mitre: [],
    aggKey: boundedAggKey(
      `azure-vmss-compute-lifecycle|omitted|${createHash("sha256").update(uploadId).digest("hex").slice(0, 16)}|${count}|${untrackedRecords}`,
    ),
    sources: ["Azure Activity"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "compute-lifecycle", action: "omitted" },
      cloud: { provider: "azure" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "azure-activity", locator: "omitted" }] },
      producer: {
        importer: "azure-activity",
        parserVersion: "1",
        mappingVersion: "azure-vmss-compute-lifecycle-v1",
      },
    }),
  };
}
