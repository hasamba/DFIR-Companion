import type { ForensicEvent } from "./stateTypes.js";

// Guided evidence collection per incident type (#347). Steps name EVIDENCE, not tools: an analyst
// knows they need Windows event logs before they know which importer produces them, and a
// tool-named step would sit unticked because they used the other tool that yields the same evidence.
//
// `satisfiedBy` lists the event source labels that count. Labels come from two places and BOTH must
// be covered or a step under-ticks:
//   1. importer literals  — a fixed label the importer stamps ("MemProcFS", "Entra ID", ...)
//   2. detectTool()       — CSV/log/SIEM imports derive the label from the filename, yielding
//                           vendor names ("SentinelOne", "Splunk", ...)
// Missing (2) would leave the EDR step blind to Defender, SentinelOne, Carbon Black and Cortex XDR
// — the ones an analyst is most likely to actually have. collectionPlanVocabulary.test.ts pins
// every label against the real importers so an invented one fails the build.
//
// Pure and deterministic — no I/O, no AI.

export interface CollectionStepDef {
  id: string;
  label: string;
  // Empty = this evidence cannot be imported by this tool; the step is still worth doing, and
  // renders as "collect outside DFIR Companion" rather than nagging forever.
  satisfiedBy: readonly string[];
}

export const COLLECTION_STEPS: readonly CollectionStepDef[] = [
  {
    id: "edr",
    label: "EDR telemetry",
    satisfiedBy: [
      "EDR (ECAR)",
      "CrowdStrike Falcon",
      "SentinelOne",
      "Carbon Black",
      "Cortex XDR",
      "Microsoft Defender",
      "Wazuh",
      "Falco",
    ],
  },
  {
    id: "windows-event-logs",
    label: "Windows event logs",
    satisfiedBy: ["Chainsaw", "Hayabusa", "EVTX", "Sysmon", "Windows Event Log"],
  },
  {
    id: "endpoint-triage",
    label: "Endpoint triage artifacts",
    satisfiedBy: [
      "Velociraptor",
      "KAPE",
      "Autopsy",
      "Cyber Triage",
      "MFT",
      "UsnJrnl",
      "Prefetch",
      "Amcache",
      "ShimCache",
      "LNK",
      "JumpLists",
      "Shellbags",
      "RecycleBin",
      "SRUM",
      "Hindsight",
    ],
  },
  { id: "memory", label: "Memory image", satisfiedBy: ["MemProcFS", "Volatility", "Rekall", "VolWeb"] },
  {
    id: "network",
    label: "Network traffic / IDS",
    satisfiedBy: ["Zeek", "Suricata", "Snort", "Security Onion", "Cisco ASA", "Arkime", "Wireshark"],
  },
  { id: "web-logs", label: "Web server access logs", satisfiedBy: ["Web Access Log"] },
  {
    id: "m365",
    label: "Microsoft 365 / mailbox audit",
    satisfiedBy: ["Microsoft 365", "Email", "Google Workspace"],
  },
  { id: "identity", label: "Identity sign-in logs", satisfiedBy: ["Entra ID", "Okta", "Google Workspace"] },
  {
    id: "cloud-audit",
    label: "Cloud control-plane audit",
    satisfiedBy: ["AWS CloudTrail", "Azure Activity", "GCP Audit", "Kubernetes Audit"],
  },
  {
    id: "siem",
    label: "SIEM / aggregated logs",
    satisfiedBy: [
      "SIEM",
      "SIEM import",
      "Splunk",
      "Elastic",
      "Microsoft Sentinel",
      "QRadar",
      "Graylog",
      "Syslog",
      "journald",
      "auditd",
      "osquery",
      "sysdig",
    ],
  },
  { id: "sandbox", label: "Malware sandbox report", satisfiedBy: ["CAPEv2", "Falcon Sandbox"] },
  { id: "super-timeline", label: "Super-timeline", satisfiedBy: ["Plaso", "Timesketch"] },
  { id: "threat-scan", label: "Threat / YARA scan", satisfiedBy: ["THOR", "YARA", "VirusTotal", "Nessus"] },
  { id: "physical-access", label: "Physical access records", satisfiedBy: [] },
];

const BY_ID = new Map<string, CollectionStepDef>(COLLECTION_STEPS.map((s) => [s.id, s]));

export function getCollectionStep(id: string): CollectionStepDef | undefined {
  return BY_ID.get(id);
}

export interface CollectionOverride {
  state: "collected" | "na";
  reason: string;
}

export type CollectionStepState =
  | "collected" // derived: matching evidence is in the case
  | "outstanding" // derived: not yet collected
  | "external" // nothing can import this; collect it outside the tool
  | "override-collected" // analyst asserted they have it
  | "override-na"; // analyst asserted it does not apply here

export interface CollectionStep {
  id: string;
  label: string;
  satisfiedBy: readonly string[];
  state: CollectionStepState;
  reason: string; // the analyst's override reason ("" when derived)
}

export interface CollectionPlan {
  steps: CollectionStep[];
  nextStepId: string; // the first step still worth collecting ("" when none)
  collected: number;
  total: number; // excludes external and n/a steps — they are not collectable here
}

// Build the plan for one case. `stepIds` is the incident type's declared order; unknown ids are
// dropped rather than rendered as blank rows (a typo in a custom type's JSON must not reach the UI).
export function buildCollectionPlan(
  stepIds: readonly string[],
  events: readonly ForensicEvent[],
  overrides: Readonly<Record<string, CollectionOverride>>,
): CollectionPlan {
  // One pass over the timeline; every other panel already holds it in memory.
  const present = new Set<string>();
  for (const e of events) for (const s of e.sources ?? []) present.add(s);

  const steps: CollectionStep[] = [];
  for (const id of stepIds) {
    const def = BY_ID.get(id);
    if (!def) continue;
    const override = overrides[id];
    const state: CollectionStepState = override
      ? override.state === "collected"
        ? "override-collected"
        : "override-na"
      : def.satisfiedBy.length === 0
        ? "external"
        : def.satisfiedBy.some((s) => present.has(s))
          ? "collected"
          : "outstanding";
    steps.push({
      id: def.id,
      label: def.label,
      satisfiedBy: def.satisfiedBy,
      state,
      reason: override?.reason ?? "",
    });
  }

  const countable = steps.filter((s) => s.state !== "external" && s.state !== "override-na");
  return {
    steps,
    nextStepId: steps.find((s) => s.state === "outstanding")?.id ?? "",
    collected: countable.filter((s) => s.state === "collected" || s.state === "override-collected").length,
    total: countable.length,
  };
}
