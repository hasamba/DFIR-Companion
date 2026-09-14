// AWS Config recorder calls, read for the STATE their request establishes (#1071, surfaced by
// #931 item 14 / #1063): PutConfigurationRecorder / StopConfigurationRecorder /
// DeleteDeliveryChannel. Split from loggingChange.ts (which already holds the CloudTrail/ec2/
// guardduty/s3 branches of this same family) purely to stay under that file's 800-line size
// ledger cap — the shared `reading()` helper, `Fact`/`LoggingReading` types and small readers all
// live there and are imported here, the same way loggingChangeCloud.ts (GCP/Azure) already does.
//
// No captured export exists in this repo (the #1065 design doc states the same basis for its own
// GCP assumptions) — request shapes follow AWS's own documented API reference.
// `PutConfigurationRecorder`'s response is empty (no created/updated discriminator), so its state
// is ALWAYS "prior-state-not-in-record" — never "created" or "reconfigured", either of which would
// claim something this record does not establish. Start/DeleteConfigurationRecorder are out of
// scope — see #1075.

import type { Severity } from "./stateTypes.js";
import {
  bool,
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
function configStrategyOf(group: Row): ConfigStrategy {
  const useOnly = lower(field(group, "recordingStrategy", "useOnly"));
  if (useOnly === "all_supported_resource_types") return "all";
  if (useOnly === "inclusion_by_resource_types") return "inclusion";
  if (useOnly === "exclusion_by_resource_types") return "exclusion";
  if (useOnly) return "unknown"; // an explicit but unrecognized strategy value
  // No recordingStrategy at all: the historical pre-strategy shape, driven by allSupported alone.
  const allSupported = bool(getCI(group, "allSupported"));
  if (allSupported === true) return "all";
  if (allSupported === false) return "legacy-list";
  return "unknown";
}

interface ConfigRecordingGroup {
  strategy: ConfigStrategy;
  present: boolean;
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
      fullResourceTypes: [],
      resourceTypes: [],
      resourceTypesTruncated: false,
      includeGlobalResourceTypes: undefined,
    };
  const strategy = configStrategyOf(group);
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
    fullResourceTypes: full,
    resourceTypes: bounded,
    resourceTypesTruncated: full.length > bounded.length,
    includeGlobalResourceTypes: bool(getCI(group, "includeGlobalResourceTypes")),
  };
}

interface ConfigRecordingMode {
  present: boolean;
  frequency: string;
  overrides: { resourceTypes: string[]; frequency: string }[];
  /** The default frequency is DAILY, or any override sets DAILY for some resource types. */
  anyDaily: boolean;
}
function configRecordingMode(recorder: Row): ConfigRecordingMode {
  const mode = isObject(getCI(recorder, "recordingMode")) ? (getCI(recorder, "recordingMode") as Row) : null;
  if (!mode) return { present: false, frequency: "", overrides: [], anyDaily: false };
  const frequency = field(mode, "recordingFrequency");
  const overrides = objects(getCI(mode, "recordingModeOverrides"), LIST_MAX).map((o) => ({
    resourceTypes: list(getCI(o, "resourceTypes")),
    frequency: field(o, "recordingFrequency"),
  }));
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
      narrowingNote: group.present
        ? "recording strategy not recognized in this record"
        : "recordingGroup absent; AWS's documented default records all supported resource types except the global IAM types",
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
  const denied = !!errorCode.trim();

  if (n === "putconfigurationrecorder") {
    const recorder = isObject(getCI(req, "configurationRecorder"))
      ? (getCI(req, "configurationRecorder") as Row)
      : {};
    const name = field(recorder, "name") || "(name not recorded)";
    const group = configRecordingGroup(recorder);
    const mode = configRecordingMode(recorder);
    const grade = configGrade(group, mode);

    const facts: Fact[] = [];
    if (!group.present) facts.push({ name: "recordingGroup", value: "not in the request" });
    else {
      facts.push({
        name: "recordingStrategy",
        value: group.strategy === "unknown" ? "not recognized" : group.strategy,
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
          value: `${o.resourceTypes.join(",") || "(types not recorded)"} → ${o.frequency || "(frequency not recorded)"}`,
        });
    }

    const qualifiers = [
      ...(!group.present
        ? [
            "recordingGroup absent; AWS's documented default records all supported resource types except the global IAM types",
          ]
        : []),
      ...(!mode.present ? ["recordingMode absent; AWS's documented default is CONTINUOUS"] : []),
      ...(grade.narrowingNote ? [grade.narrowingNote] : []),
      ...(group.resourceTypesTruncated
        ? [`${group.resourceTypes.length} of ${group.fullResourceTypes.length} resource types shown`]
        : []),
    ];

    const posture = `Config recorder ${show(name, 40)}: ${configRecorderScopeWords(group)}${mode.present ? `, ${show(mode.frequency, 20) || "(frequency not recorded)"} recording` : ""}`;

    // The FULL resource-type list feeds the key (never the display-bounded one) so two
    // configurations differing only past the display cap are never collapsed into one row.
    const key = [
      group.strategy,
      ...group.fullResourceTypes,
      String(group.includeGlobalResourceTypes),
      mode.frequency,
      ...mode.overrides.map((o) => `${o.resourceTypes.join(",")}:${o.frequency}`),
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
      denied,
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
      denied,
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
      denied,
    );
  }
  return null;
}
