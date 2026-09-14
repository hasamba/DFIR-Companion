// The words and the envelope block of one GCP instance compute-lifecycle row (#931 item 8 second
// half, #1066): every part is the record's own — a recorded operation, a launch fact, an
// attachment interval, a tallied session — the facts the grade rests on are packed with the tail
// and never clipped, and metadata content never reaches the row. The pass that fills the state
// lives in gcpCompute.ts.

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { GcpComputeBlock, GcpComputeFact, GcpComputeLaunch } from "./canonicalGcpCompute.js";
import { normalizeTime, type MappedEvent } from "./siemImport.js";
import {
  BASIS,
  COVERAGE_NOTE,
  DESCRIPTION_MAX,
  FACT_MITRE,
  FACT_WORDS,
  GCP_COMPUTE_MAX,
  INSTANCES_TRACKED_MAX,
  LIMIT_NOTE,
  OPERATIONS_NAMED_MAX,
  RAW_RECORDS_MAX,
  byTime,
  firstTime,
  plural,
  show,
  type Instance,
  type Operation,
  type Timed,
} from "./gcpComputeState.js";

const whoAt = (time: number, by: string, locator: string): string =>
  `at ${new Date(time).toISOString()} by ${show(by, 60)} (${locator})`;

const OPERATION_LABEL: Record<Operation["kind"], string> = {
  start: "recorded: started",
  stop: "recorded: stopped",
  delete: "recorded: deleted",
  "metadata-replaced": "recorded: metadata replaced (content not shown)",
};

function operationWords(e: Operation): string {
  return `${show(e.call, 60)}: ${OPERATION_LABEL[e.kind]} ${whoAt(e.time, e.by, e.locator)}`;
}

function launchWords(l: Omit<GcpComputeLaunch, "time"> & Timed): string {
  const facts = [
    l.machineType ? `machine type ${show(l.machineType, 60)}` : "",
    l.sourceImage ? `source image ${show(l.sourceImage, 120)}` : "",
    l.network ? `network ${show(l.network, 80)}` : "",
    l.subnetwork ? `subnetwork ${show(l.subnetwork, 80)}` : "",
    l.metadataKeys.length
      ? `metadata keys ${l.metadataKeys.map((k) => show(k, 40)).join(", ")} (values not shown)`
      : "no metadata recorded",
  ].filter(Boolean);
  return `recorded insert ${new Date(l.time).toISOString()} by ${show(l.by)} (${l.locators.join(", ")}) — ${facts.join(", ")}`;
}

function sessionWords(inst: Instance): string[] {
  if (inst.sessions.size === 0) return [];
  return [...inst.sessions.values()]
    .sort((a, b) => (a.first?.time ?? 0) - (b.first?.time ?? 0))
    .map((s) => {
      const cited = s.cited
        .slice()
        .sort((a, b) => a.time - b.time)
        .map((c) => `${show(c.call, 80)} at ${new Date(c.time).toISOString()} (${c.locator})`)
        .join("; ");
      return `calls recorded from ${show(s.email, 80)} while it was the instance's recorded service account (this account may be shared with other resources this upload does not distinguish): ${plural(s.records, "record")}${s.first ? ` ${new Date(s.first.time).toISOString()} (${s.first.locator})` : ""}${s.last ? ` → ${new Date(s.last.time).toISOString()} (${s.last.locator})` : ""}${cited ? `; ${cited}` : ""}`;
    });
}

export function summaryRow(
  inst: Instance,
  facts: readonly GcpComputeFact[],
  grade: Severity,
  coverage: { records: number; first: string; last: string },
  uploadId: string,
): MappedEvent {
  const operations = inst.operations.all().sort(byTime);
  const operationsBeyond = Math.max(0, operations.length - OPERATIONS_NAMED_MAX) + inst.operations.beyond;
  const parts = [
    inst.launch ? launchWords(inst.launch) : "insert not in this upload",
    ...(operations.length
      ? [
          `recorded operations${operationsBeyond ? ` (${Math.min(operations.length, OPERATIONS_NAMED_MAX)} named, ${operationsBeyond} further not individually named)` : ""}: ${operations
            .slice(0, OPERATIONS_NAMED_MAX)
            .map(operationWords)
            .join("; ")}`,
        ]
      : []),
    ...sessionWords(inst),
    ...(inst.notSucceeded
      ? [`${plural(inst.notSucceeded, "record")} without a recorded success — not joined`]
      : []),
  ];
  const factWords = facts.length
    ? `recorded facts: ${facts
        .map((f) => {
          const c = inst.facts.get(f);
          return `${FACT_WORDS[f]}${c ? ` (${c.locator})` : ""}`;
        })
        .join(", ")} (${plural(facts.length, "kind")})`
    : "recorded facts: none";
  const reserved = [...(inst.launch?.locators ?? []), ...[...inst.facts.values()].map((c) => c.locator)];
  const cited = [...new Set([...reserved, ...inst.locators])].slice(0, RAW_RECORDS_MAX);
  const notCited = Math.max(0, inst.contributing - cited.length);
  const tail = [
    factWords,
    ...(notCited ? [`${plural(notCited, "further record")} not individually cited`] : []),
    LIMIT_NOTE,
    COVERAGE_NOTE,
  ].join("; ");
  const head = `GCP compute lifecycle: ${show(inst.instanceName, 60)} (project ${show(inst.project, 40)}, zone ${show(inst.zone, 30)})`;
  const room = DESCRIPTION_MAX - head.length - tail.length - 6;
  const lead = parts.join("; ");
  const description = `${head} [${lead.length > room ? `${lead.slice(0, Math.max(0, room - 1))}…` : lead}; ${tail}]`;
  const identity = createHash("sha256")
    .update(
      `${inst.project.length}:${inst.project}|${inst.zone.length}:${inst.zone}|${inst.instanceName.length}:${inst.instanceName}|${uploadId.length}:${uploadId}`,
    )
    .digest("hex")
    .slice(0, 32);
  const block: GcpComputeBlock = {
    instanceName: inst.instanceName,
    project: inst.project,
    zone: inst.zone,
    ...(inst.launch
      ? { launch: (({ time, ...rest }) => ({ ...rest, time: new Date(time).toISOString() }))(inst.launch) }
      : {}),
    operations: operations.map(({ time, ...e }) => ({ ...e, time: new Date(time).toISOString() })),
    operationsBeyond,
    attachments: inst.attachments.map((a) => ({
      email: a.email,
      from: new Date(a.time).toISOString(),
      ...(a.to !== null ? { to: new Date(a.to).toISOString() } : {}),
      locator: a.locator,
    })),
    attachmentsBeyond: inst.attachmentsBeyond,
    sessions: [...inst.sessions.values()]
      .filter((s) => s.first && s.last)
      .map((s) => ({
        email: s.email,
        records: s.records,
        first: { time: new Date(s.first!.time).toISOString(), locator: s.first!.locator },
        last: { time: new Date(s.last!.time).toISOString(), locator: s.last!.locator },
        cited: s.cited.map((c) => ({
          call: c.call,
          time: new Date(c.time).toISOString(),
          locator: c.locator,
        })),
      })),
    attempts: { notSucceeded: inst.notSucceeded },
    facts: [...facts],
    notCited,
    coverage,
    basis: BASIS,
  };
  const observed = new Date(firstTime(inst)).toISOString();
  const mitre = grade === "Low" ? [] : [...new Set(facts.map((f) => FACT_MITRE[f]))];
  return {
    timestamp: normalizeTime(observed),
    description,
    severity: grade,
    mitre,
    aggKey: boundedAggKey(`gcp-compute-lifecycle|${identity}`),
    sources: ["GCP Cloud Audit Log"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "compute-lifecycle", action: "lifecycle", outcome: "success" },
      actor: { kind: "account", name: inst.launch?.by ?? inst.instanceName },
      cloud: { provider: "gcp", accountId: inst.project, region: inst.zone, resource: inst.instanceName },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: { rawRecords: cited.map((l) => ({ source: "gcp-cloud-audit-log", locator: l })) },
      producer: {
        importer: "gcp-cloud-audit-log",
        parserVersion: "1",
        mappingVersion: "gcp-compute-lifecycle-v1",
        ruleVersions: ["gcp-compute-v1"],
      },
      gcpCompute: block,
    }),
  };
}

/** The instances beyond the reported bound, and the records past the tracked bound — counts, never claims. */
export function omittedRow(
  count: number,
  severity: Severity,
  untrackedRecords: number,
  uploadId: string,
): MappedEvent {
  const description = `GCP compute lifecycle — ${count ? `${count} further instance${count === 1 ? "" : "s"} with a lifecycle in this upload beyond the ${GCP_COMPUTE_MAX} reported — not shown` : "no further instance beyond the reported"}${untrackedRecords ? `; ${plural(untrackedRecords, "record")} naming instances past the ${INSTANCES_TRACKED_MAX} tracked — not read` : ""}`;
  return {
    timestamp: "",
    description,
    severity,
    mitre: [],
    aggKey: boundedAggKey(
      `gcp-compute-lifecycle|omitted|${createHash("sha256").update(uploadId).digest("hex").slice(0, 16)}|${count}|${untrackedRecords}`,
    ),
    sources: ["GCP Cloud Audit Log"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "compute-lifecycle", action: "omitted" },
      cloud: { provider: "gcp" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "gcp-cloud-audit-log", locator: "omitted" }] },
      producer: {
        importer: "gcp-cloud-audit-log",
        parserVersion: "1",
        mappingVersion: "gcp-compute-lifecycle-v1",
      },
    }),
  };
}
