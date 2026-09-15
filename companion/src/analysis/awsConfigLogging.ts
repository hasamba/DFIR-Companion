// AWS Config recorder calls, read for the STATE their request establishes (#1071, surfaced by
// #931 item 14 / #1063): PutConfigurationRecorder / StopConfigurationRecorder /
// DeleteDeliveryChannel / StartConfigurationRecorder / DeleteConfigurationRecorder (#1075). Split
// from loggingChange.ts (which already holds the CloudTrail/ec2/guardduty/s3 branches of this same
// family) purely to stay under that file's 800-line size ledger cap — the shared `reading()`
// helper, `Fact`/`LoggingReading` types and small readers all live there and are imported here,
// the same way loggingChangeCloud.ts (GCP/Azure) already does.
//
// No captured export exists in this repo (the #1065 design doc states the same basis for its own
// GCP assumptions) — request shapes follow AWS's own documented API reference.
// `PutConfigurationRecorder`'s response is empty (no created/updated discriminator), so its state
// is ALWAYS "prior-state-not-in-record" — never "created" or "reconfigured", either of which would
// claim something this record does not establish. `Start`/`Stop`/`DeleteConfigurationRecorder`
// operate on the customer-managed recorder only — a distinct service-linked recorder, which these
// APIs cannot touch, may coexist under a different name (#1075, Codex design round 1); deleting
// the recorder does not delete configuration history already recorded before the delete.

import type { Severity } from "./stateTypes.js";
import {
  bool,
  classifyAwsFailure,
  field,
  LIST_MAX,
  list,
  lower,
  objects,
  reading,
  show,
  type Fact,
  type LoggingReading,
} from "./loggingChange.js";
import { getCI, isObject } from "./siemImport.js";

type Row = Record<string, unknown>;

type ConfigStrategy = "all" | "inclusion" | "exclusion" | "legacy-list" | "unknown";

/** `recordingGroup.recordingStrategy.useOnly` wins when present, even over a stray `allSupported`. */
function configStrategyOf(group: Row): { strategy: ConfigStrategy; rawUseOnly: string } {
  const rawUseOnly = field(group, "recordingStrategy", "useOnly");
  const useOnly = lower(rawUseOnly);
  if (useOnly === "all_supported_resource_types") return { strategy: "all", rawUseOnly };
  if (useOnly === "inclusion_by_resource_types") return { strategy: "inclusion", rawUseOnly };
  if (useOnly === "exclusion_by_resource_types") return { strategy: "exclusion", rawUseOnly };
  if (rawUseOnly) return { strategy: "unknown", rawUseOnly }; // an explicit but unrecognized value
  // No recordingStrategy at all: the historical pre-strategy shape, driven by allSupported alone.
  const allSupported = bool(getCI(group, "allSupported"));
  if (allSupported === true) return { strategy: "all", rawUseOnly: "" };
  if (allSupported === false) return { strategy: "legacy-list", rawUseOnly: "" };
  return { strategy: "unknown", rawUseOnly: "" }; // recordingGroup present but neither field recorded
}

interface ConfigRecordingGroup {
  strategy: ConfigStrategy;
  present: boolean;
  /** Set only when `strategy` is "unknown" because of an explicit, unrecognized `useOnly` value —
   * distinct from "unknown" because neither `recordingStrategy` nor `allSupported` was present at
   * all (Codex code review, finding #3). Empty string for every other case. */
  rawUseOnly: string;
  /** The FULL list (never LIST_MAX-capped) — used for the aggregation key so two configurations
   * differing only past the display cap are never collapsed into one row. */
  fullResourceTypes: string[];
  /** Bounded for display and canonical facts. */
  resourceTypes: string[];
  resourceTypesTruncated: boolean;
  includeGlobalResourceTypes: boolean | undefined;
}
function configRecordingGroup(recorder: Row): ConfigRecordingGroup {
  const group = isObject(getCI(recorder, "recordingGroup"))
    ? (getCI(recorder, "recordingGroup") as Row)
    : null;
  if (!group)
    return {
      strategy: "unknown",
      present: false,
      rawUseOnly: "",
      fullResourceTypes: [],
      resourceTypes: [],
      resourceTypesTruncated: false,
      includeGlobalResourceTypes: undefined,
    };
  const { strategy, rawUseOnly } = configStrategyOf(group);
  let full: string[] = [];
  if (strategy === "exclusion") {
    const excl = isObject(getCI(group, "exclusionByResourceTypes"))
      ? (getCI(group, "exclusionByResourceTypes") as Row)
      : null;
    if (excl) full = list(getCI(excl, "resourceTypes"), Number.MAX_SAFE_INTEGER);
  } else if (strategy === "inclusion" || strategy === "legacy-list") {
    full = list(getCI(group, "resourceTypes"), Number.MAX_SAFE_INTEGER);
  }
  const bounded = full.slice(0, LIST_MAX);
  return {
    strategy,
    present: true,
    rawUseOnly,
    fullResourceTypes: full,
    resourceTypes: bounded,
    resourceTypesTruncated: full.length > bounded.length,
    includeGlobalResourceTypes: bool(getCI(group, "includeGlobalResourceTypes")),
  };
}

interface ConfigModeOverride {
  /** The FULL list (never LIST_MAX-capped) — feeds the aggregation key. */
  fullResourceTypes: string[];
  /** Bounded for display and canonical facts. */
  resourceTypes: string[];
  resourceTypesTruncated: boolean;
  frequency: string;
}
interface ConfigRecordingMode {
  present: boolean;
  frequency: string;
  overrides: ConfigModeOverride[];
  /** The default frequency is DAILY, or any override sets DAILY for some resource types. */
  anyDaily: boolean;
}
function configRecordingMode(recorder: Row): ConfigRecordingMode {
  const mode = isObject(getCI(recorder, "recordingMode")) ? (getCI(recorder, "recordingMode") as Row) : null;
  if (!mode) return { present: false, frequency: "", overrides: [], anyDaily: false };
  const frequency = field(mode, "recordingFrequency");
  const overrides = objects(getCI(mode, "recordingModeOverrides"), LIST_MAX).map((o) => {
    // The full list feeds the key (Codex code review, finding #1) — an override's resource-type
    // list can itself run past LIST_MAX even though at most LIST_MAX override OBJECTS are read.
    const full = list(getCI(o, "resourceTypes"), Number.MAX_SAFE_INTEGER);
    const bounded = full.slice(0, LIST_MAX);
    return {
      fullResourceTypes: full,
      resourceTypes: bounded,
      resourceTypesTruncated: full.length > bounded.length,
      frequency: field(o, "recordingFrequency"),
    };
  });
  const anyDaily = lower(frequency) === "daily" || overrides.some((o) => lower(o.frequency) === "daily");
  return { present: true, frequency, overrides, anyDaily };
}

/** The severity and, when narrowing, the one-sentence reason — strategy-aware, never a flat Boolean checklist. */
function configGrade(
  group: ConfigRecordingGroup,
  mode: ConfigRecordingMode,
): { severity: Severity; narrowingNote: string | null } {
  if (group.strategy === "unknown")
    return {
      severity: "Medium",
      narrowingNote: !group.present
        ? "recordingGroup absent; AWS's documented default records all supported resource types except the global IAM types"
        : group.rawUseOnly
          ? `recording strategy not recognized in this record: ${group.rawUseOnly}`
          : "recordingGroup present but neither recordingStrategy nor allSupported recorded; AWS's documented default records all supported resource types except the global IAM types",
    };
  if (group.strategy === "inclusion" || group.strategy === "legacy-list")
    return {
      severity: "High",
      narrowingNote: `inclusion list narrows coverage to ${group.fullResourceTypes.length || "0"} named resource type(s)`,
    };
  if (group.strategy === "exclusion") {
    if (group.fullResourceTypes.length === 0) return { severity: "Low", narrowingNote: null };
    return {
      severity: "High",
      narrowingNote: `exclusion list narrows coverage by excluding ${group.fullResourceTypes.length} resource type(s)`,
    };
  }
  // strategy === "all"
  const globalExcluded = group.includeGlobalResourceTypes === false;
  if (globalExcluded || mode.anyDaily) {
    return {
      severity: "High",
      narrowingNote: [
        ...(globalExcluded ? ["global resource types excluded"] : []),
        ...(mode.anyDaily ? ["daily (not continuous) recording for some or all resource types"] : []),
      ].join("; "),
    };
  }
  return { severity: "Low", narrowingNote: null };
}

function configRecorderScopeWords(group: ConfigRecordingGroup): string {
  if (group.strategy === "all")
    return `all supported resource types${group.includeGlobalResourceTypes === false ? " (global resource types excluded)" : ""}`;
  if (group.strategy === "inclusion" || group.strategy === "legacy-list")
    return `inclusion list (${group.resourceTypes.map((r) => show(r, 40)).join(", ") || "none named"})`;
  if (group.strategy === "exclusion")
    return group.fullResourceTypes.length
      ? `exclusion list (${group.resourceTypes.map((r) => show(r, 40)).join(", ") || "none named"})`
      : "exclusion strategy, no resource types excluded";
  return "recording scope not established by this record";
}

/** `source`/`name`/`errorCode` match `decodeCloudTrailLogging`'s own signature exactly, so
 * `awsImport.ts` calls the two as a simple `??` fallback chain. */
export function decodeAwsConfigLogging(
  source: string,
  eventName: string,
  request: unknown,
  errorCode: string,
): LoggingReading | null {
  if (lower(source).replace(/\.amazonaws\.com$/, "") !== "config") return null;
  const n = lower(eventName);
  const req: Row = isObject(request) ? request : {};
  const failure = errorCode.trim() ? classifyAwsFailure(errorCode) : null;

  if (n === "putconfigurationrecorder") {
    const recorder = isObject(getCI(req, "configurationRecorder"))
      ? (getCI(req, "configurationRecorder") as Row)
      : {};
    const name = field(recorder, "name") || "(name not recorded)";
    // roleARN is a normal AWS resource identifier (never a secret) but was missing entirely from
    // the first draft — a role change on an otherwise-identical recorder must not look identical
    // to the prior call (Codex code review, finding #2).
    const roleArn = field(recorder, "roleARN");
    const group = configRecordingGroup(recorder);
    const mode = configRecordingMode(recorder);
    const grade = configGrade(group, mode);

    const facts: Fact[] = [];
    if (roleArn) facts.push({ name: "roleARN", value: roleArn });
    if (!group.present) facts.push({ name: "recordingGroup", value: "not in the request" });
    else {
      facts.push({
        name: "recordingStrategy",
        value: group.strategy === "unknown" ? group.rawUseOnly || "not recorded" : group.strategy,
      });
      if (group.strategy === "all")
        facts.push({
          name: "includeGlobalResourceTypes",
          value:
            group.includeGlobalResourceTypes === undefined
              ? "not in the request"
              : String(group.includeGlobalResourceTypes),
        });
      else if (group.strategy === "inclusion" || group.strategy === "legacy-list")
        facts.push({ name: "resourceTypes", value: group.resourceTypes.join(", ") || "(none named)" });
      else if (group.strategy === "exclusion")
        facts.push({
          name: "exclusionByResourceTypes",
          value: group.resourceTypes.join(", ") || "(none named)",
        });
    }
    if (!mode.present) facts.push({ name: "recordingMode", value: "not in the request" });
    else {
      facts.push({ name: "recordingFrequency", value: mode.frequency || "(not recorded)" });
      for (const o of mode.overrides)
        facts.push({
          name: "recordingModeOverride",
          value: `${o.resourceTypes.join(",") || "(types not recorded)"}${o.resourceTypesTruncated ? ` (+${o.fullResourceTypes.length - o.resourceTypes.length} more)` : ""} → ${o.frequency || "(frequency not recorded)"}`,
        });
    }

    // A single qualifier source for the recordingGroup omission/unknown-strategy sentence — never
    // both `!group.present` AND `grade.narrowingNote` at once, which duplicated the same text and
    // wasted the rendered qualifiers' bounded space (Codex code review, finding #6).
    const qualifiers = [
      ...(!mode.present ? ["recordingMode absent; AWS's documented default is CONTINUOUS"] : []),
      ...(grade.narrowingNote ? [grade.narrowingNote] : []),
      ...(group.resourceTypesTruncated
        ? [`${group.resourceTypes.length} of ${group.fullResourceTypes.length} resource types shown`]
        : []),
      ...mode.overrides
        .filter((o) => o.resourceTypesTruncated)
        .map(
          (o) =>
            `recordingModeOverride: ${o.resourceTypes.length} of ${o.fullResourceTypes.length} resource types shown`,
        ),
    ];

    const posture = `Config recorder ${show(name, 40)}: ${configRecorderScopeWords(group)}${mode.present ? `, ${show(mode.frequency, 20) || "(frequency not recorded)"} recording` : ""}`;

    // The FULL resource-type lists (recorder-level AND every override's own) feed the key — never
    // the display-bounded ones — so two configurations differing only past the display cap, in
    // either place, are never collapsed into one row. The raw (unrecognized) strategy value and
    // the role ARN are included too, for the same reason.
    const key = [
      group.strategy,
      group.rawUseOnly,
      ...group.fullResourceTypes,
      String(group.includeGlobalResourceTypes),
      roleArn,
      mode.frequency,
      ...mode.overrides.map((o) => `${o.fullResourceTypes.join(",")}:${o.frequency}`),
    ].join("|");

    return reading(
      "aws",
      "config-recorder",
      name,
      "prior-state-not-in-record",
      grade.severity,
      posture,
      facts,
      qualifiers,
      failure,
      { key },
    );
  }
  if (n === "stopconfigurationrecorder") {
    const name = field(req, "configurationRecorderName") || "(name not recorded)";
    return reading(
      "aws",
      "config-recorder",
      name,
      "disabled",
      "High",
      `Config recorder stopped: ${show(name, 40)}`,
      [],
      [],
      failure,
    );
  }
  if (n === "startconfigurationrecorder") {
    const name = field(req, "configurationRecorderName") || "(name not recorded)";
    return reading(
      "aws",
      "config-recorder",
      name,
      "enabled",
      "Low",
      `Config recorder started: ${show(name, 40)}`,
      [],
      [],
      failure,
    );
  }
  if (n === "deleteconfigurationrecorder") {
    const name = field(req, "configurationRecorderName") || "(name not recorded)";
    return reading(
      "aws",
      "config-recorder",
      name,
      "deleted",
      "High",
      `Config recorder deleted: ${show(name, 40)} — previously recorded configuration history is not deleted by this operation`,
      [],
      [],
      failure,
    );
  }
  if (n === "deletedeliverychannel") {
    const name = field(req, "deliveryChannelName") || "(name not recorded)";
    return reading(
      "aws",
      "config-delivery-channel",
      name,
      "deleted",
      "High",
      `Config delivery channel deleted: ${show(name, 40)} — the customer-managed recorder had to be stopped first and cannot restart until a delivery channel exists again`,
      [],
      [],
      failure,
    );
  }
  return null;
}
