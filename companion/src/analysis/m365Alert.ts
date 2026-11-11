// Decoder for Microsoft 365 Security & Compliance alert records in the Unified Audit Log (#2551).
//
// RecordType 40 (`SecurityComplianceAlerts`): Operation `AlertTriggered` / `AlertEntityGenerated`,
// Workload `SecurityComplianceCenter`. The UAL row's own `UserId` is the literal service account
// `SecurityComplianceAlerts`, and its `ObjectId` is the alert id — neither says what fired or for
// whom. The detail sits in the top-level `Name` / `Severity` and in `Data`, a SECOND JSON string
// nested inside AuditData (`an` alert name, `sev` severity, `f3u` user, `op` triggering operation,
// `reid` triggering record id). Without this decoder the row read "AlertTriggered by
// SecurityComplianceAlerts", graded Info, and every alert in a case folded into one counted row.
//
// It is the tenant's OWN detection, so it is graded above Info: vendor Informational/Low → Medium,
// vendor Medium/High → High. AlertEntityGenerated is the per-entity companion of the same alert and
// sits one level lower, so the AlertTriggered row carries the finding.
//
// Every value is adversary-influenced (an alert name can echo a rule or mailbox name the attacker
// chose), so each is put on one line and capped with a digest tail, like the importer's other notes.

import type { Severity } from "./stateTypes.js";
import { boundedTextTo } from "./aggKey.js";
import { getCI, isObject, str } from "./siemFieldPick.js";
import { oneLine } from "./siemImport.js";

type Row = Record<string, unknown>;

export interface M365Alert {
  readonly name: string;
  readonly vendorSeverity: string;
  readonly user: string;
  readonly op: string;
  readonly alertId: string;
  readonly reid: string;
  readonly entity: boolean;
}

/** A nested `Data` string larger than this is not parsed — the top-level fields still decode. */
const DATA_MAX_CHARS = 64 * 1024;
const NAME_MAX = 200;
const FIELD_MAX = 120;
const SEVERITY_MAX = 40;

const ALERT_OPS: Readonly<Record<string, boolean>> = { alerttriggered: false, alertentitygenerated: true };

/** The first candidate that is a non-blank value, on one line, control characters removed and capped. */
function clean(max: number, ...candidates: unknown[]): string {
  for (const v of candidates) {
    const s = oneLine(str(v).replace(/[\u0000-\u001f\u007f]+/g, " "));
    if (s) return boundedTextTo(s, max);
  }
  return "";
}

/** The nested `Data` object, or `{}` when it is missing, malformed, oversized or not an object. */
function nestedData(rec: Row): Row {
  const raw = getCI(rec, "Data");
  if (isObject(raw)) return raw;
  if (typeof raw !== "string" || raw.length > DATA_MAX_CHARS || !raw.trim().startsWith("{")) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    return isObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

/** Decode an alert record; `null` for any UAL operation that is not a Security & Compliance alert. */
export function decodeM365Alert(rec: Row, op: string): M365Alert | null {
  const entity = ALERT_OPS[op.toLowerCase().trim()];
  if (entity === undefined) return null;
  const data = nestedData(rec);
  return {
    name: clean(NAME_MAX, getCI(data, "an"), getCI(rec, "Name")),
    vendorSeverity: clean(SEVERITY_MAX, getCI(data, "sev"), getCI(rec, "Severity")),
    user: clean(FIELD_MAX, getCI(data, "f3u")),
    op: clean(FIELD_MAX, getCI(data, "op")),
    alertId: clean(FIELD_MAX, getCI(rec, "AlertId"), getCI(rec, "ObjectId")),
    reid: clean(FIELD_MAX, getCI(data, "reid")),
    entity,
  };
}

const LOWER: Readonly<Record<string, Severity>> = { High: "Medium", Medium: "Low" };

/** Vendor Informational/Low (or unknown) → Medium, Medium/High → High; an entity row one lower. */
export function alertSeverity(alert: M365Alert): Severity {
  const base: Severity = /^(?:medium|high)$/i.test(alert.vendorSeverity) ? "High" : "Medium";
  return alert.entity ? (LOWER[base] ?? base) : base;
}

/** T1114.003 only when the alert names a mail-forwarding / redirect operation. */
export function alertMitre(alert: M365Alert): string[] {
  return /redirect|forward/i.test(alert.op) ? ["T1114.003"] : [];
}

/** The row description: the `M365 <workload>: <op>` prefix the tagger keys on, then the alert. */
export function alertDescription(workload: string, op: string, alert: M365Alert): string {
  let d = `M365 ${workload || "SecurityComplianceCenter"}: ${op}`;
  if (alert.name) d += ` — "${alert.name}"`;
  if (alert.vendorSeverity) d += ` (${alert.vendorSeverity})`;
  if (alert.user) d += ` for ${alert.user}`;
  if (alert.op) d += ` — op ${alert.op}`;
  if (alert.reid) d += ` (record ${alert.reid})`;
  return d;
}
