// The words and the envelope block of one Azure VM compute-lifecycle row (#931 item 8 second
// half, #1066): every part is the record's own — a recorded operation, a launch fact, a
// remote-access request — the facts the grade rests on are packed with the tail and never
// clipped, and a secret (admin password, SSH key material) never reaches the row. The pass that
// fills the state lives in azureCompute.ts.

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { AzureComputeBlock, AzureComputeFact, AzureComputeLaunch } from "./canonicalAzureCompute.js";
import { normalizeTime, type MappedEvent } from "./siemImport.js";
import {
  AZURE_COMPUTE_MAX,
  BASIS,
  COVERAGE_NOTE,
  DESCRIPTION_MAX,
  FACT_MITRE,
  FACT_WORDS,
  LIMIT_NOTE,
  OPERATIONS_NAMED_MAX,
  RAW_RECORDS_MAX,
  VMS_TRACKED_MAX,
  byTime,
  firstTime,
  plural,
  show,
  type Operation,
  type Remote,
  type Timed,
  type Vm,
} from "./azureComputeState.js";

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
  vm: Vm,
  facts: readonly AzureComputeFact[],
  grade: Severity,
  coverage: { records: number; first: string; last: string },
  uploadId: string,
): MappedEvent {
  const operations = vm.operations.all().sort(byTime);
  const operationsBeyond = Math.max(0, operations.length - OPERATIONS_NAMED_MAX) + vm.operations.beyond;
  const parts = [
    vm.launch ? launchWords(vm.launch) : "write/launch not in this upload",
    ...(operations.length
      ? [
          `recorded operations${operationsBeyond ? ` (${Math.min(operations.length, OPERATIONS_NAMED_MAX)} named, ${operationsBeyond} further not individually named)` : ""}: ${operations
            .slice(0, OPERATIONS_NAMED_MAX)
            .map(operationWords)
            .join("; ")}`,
        ]
      : []),
    ...(vm.remote.length
      ? [
          `remote-access requests (requested; whether anything ran is not in the Activity Log): ${vm.remote
            .slice()
            .sort(byTime)
            .map((r: Remote) => `${show(r.call, 60)} ${whoAt(r.time, r.by, r.locator)}`)
            .join("; ")}${vm.remoteBeyond ? `; +${plural(vm.remoteBeyond, "more request")}` : ""}`,
        ]
      : []),
    ...(vm.notSucceeded
      ? [`${plural(vm.notSucceeded, "record")} without a recorded success — not joined`]
      : []),
  ];
  const factWords = facts.length
    ? `recorded facts: ${facts
        .map((f) => {
          const c = vm.facts.get(f);
          return `${FACT_WORDS[f]}${c ? ` (${c.locator})` : ""}`;
        })
        .join(", ")} (${plural(facts.length, "kind")})`
    : "recorded facts: none";
  const reserved = [...(vm.launch?.locators ?? []), ...[...vm.facts.values()].map((c) => c.locator)];
  const cited = [...new Set([...reserved, ...vm.locators])].slice(0, RAW_RECORDS_MAX);
  const notCited = Math.max(0, vm.contributing - cited.length);
  const tail = [
    factWords,
    ...(notCited ? [`${plural(notCited, "further record")} not individually cited`] : []),
    LIMIT_NOTE,
    COVERAGE_NOTE,
  ].join("; ");
  const head = `Azure compute lifecycle: ${show(vm.vmName, 60)} (subscription ${show(vm.subscriptionId, 40)}, resource group ${show(vm.resourceGroup, 40)})`;
  const room = DESCRIPTION_MAX - head.length - tail.length - 6;
  const lead = parts.join("; ");
  const description = `${head} [${lead.length > room ? `${lead.slice(0, Math.max(0, room - 1))}…` : lead}; ${tail}]`;
  const identity = createHash("sha256")
    .update(
      `${vm.subscriptionId.length}:${vm.subscriptionId}|${vm.resourceGroup.length}:${vm.resourceGroup}|${vm.vmName.length}:${vm.vmName}|${uploadId.length}:${uploadId}`,
    )
    .digest("hex")
    .slice(0, 32);
  const block: AzureComputeBlock = {
    vmName: vm.vmName,
    subscriptionId: vm.subscriptionId,
    resourceGroup: vm.resourceGroup,
    ...(vm.launch
      ? { launch: (({ time, ...rest }) => ({ ...rest, time: new Date(time).toISOString() }))(vm.launch) }
      : {}),
    operations: operations.map(({ time, ...e }) => ({ ...e, time: new Date(time).toISOString() })),
    operationsBeyond,
    remote: vm.remote.map(({ time, ...r }) => ({ ...r, time: new Date(time).toISOString() })),
    remoteBeyond: vm.remoteBeyond,
    attempts: { notSucceeded: vm.notSucceeded },
    facts: [...facts],
    notCited,
    coverage,
    basis: BASIS,
  };
  const observed = new Date(firstTime(vm)).toISOString();
  const mitre = grade === "Low" ? [] : [...new Set(facts.map((f) => FACT_MITRE[f]))];
  return {
    timestamp: normalizeTime(observed),
    description,
    severity: grade,
    mitre,
    aggKey: boundedAggKey(`azure-compute-lifecycle|${identity}`),
    sources: ["Azure Activity"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "compute-lifecycle", action: "lifecycle", outcome: "success" },
      actor: { kind: "account", name: vm.launch?.by ?? vm.vmName },
      // No `region` set here: Azure's resource group is not the same concept as an AWS/GCP
      // region, and the schema has no dedicated resource-group field — the full identity lives in
      // the azureCompute block below.
      cloud: {
        provider: "azure",
        accountId: vm.subscriptionId,
        resource: vm.vmName,
      },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: { rawRecords: cited.map((l) => ({ source: "azure-activity", locator: l })) },
      producer: {
        importer: "azure-activity",
        parserVersion: "1",
        mappingVersion: "azure-compute-lifecycle-v1",
        ruleVersions: ["azure-compute-v1"],
      },
      azureCompute: block,
    }),
  };
}

/** The VMs beyond the reported bound, and the records past the tracked bound — counts, never claims. */
export function omittedRow(
  count: number,
  severity: Severity,
  untrackedRecords: number,
  uploadId: string,
): MappedEvent {
  const description = `Azure compute lifecycle — ${count ? `${count} further VM${count === 1 ? "" : "s"} with a lifecycle in this upload beyond the ${AZURE_COMPUTE_MAX} reported — not shown` : "no further VM beyond the reported"}${untrackedRecords ? `; ${plural(untrackedRecords, "record")} naming VMs past the ${VMS_TRACKED_MAX} tracked — not read` : ""}`;
  return {
    timestamp: "",
    description,
    severity,
    mitre: [],
    aggKey: boundedAggKey(
      `azure-compute-lifecycle|omitted|${createHash("sha256").update(uploadId).digest("hex").slice(0, 16)}|${count}|${untrackedRecords}`,
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
        mappingVersion: "azure-compute-lifecycle-v1",
      },
    }),
  };
}
