// Falcon API alert / detect JSON (#2592 Part 2): the console or API export of Falcon's own
// detections — alerts v2 (one flat object per alert, `composite_id`) and legacy detects (one object
// per detection with a `behaviors[]` list, `detection_id`), alone, as an array, or inside the API's
// `{ resources: [...] }` envelope.
//
// A detection is Falcon's verdict, so it keeps Falcon's severity (falconSeverity, shared with the
// sensor DetectionSummaryEvent rows) and is never demoted to Info. An Informational detection stays
// Info and does not reach the forensic timeline, by design.

import { createCanonicalEvent } from "./canonicalEvent.js";
import { addIoc, type SiemIoc } from "./iocSink.js";
import { oneLine, str, type MappedEvent } from "./siemImport.js";
import { boundedAggKey } from "./aggKey.js";
import type { Severity } from "./stateTypes.js";
import { CROWDSTRIKE_SOURCE, field, falconSeverity } from "./crowdstrikeFields.js";
import { crowdstrikeTimeOf } from "./crowdstrikeTime.js";

type Row = Record<string, unknown>;

const obj = (v: unknown): Row | undefined =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Row) : undefined;

/** A Falcon API alert or legacy detect: an alert id AND a tactic/technique or a behaviors list. */
export function isCrowdstrikeAlert(rec: unknown): boolean {
  const r = obj(rec);
  if (!r) return false;
  const id = field(r, "composite_id") || field(r, "detection_id");
  return (
    id !== "" && (field(r, "tactic") !== "" || field(r, "technique") !== "" || Array.isArray(r["behaviors"]))
  );
}

/** The alert records of a parsed file: the API `resources` envelope, an array, or one object. */
export function alertRecords(root: unknown): Row[] | null {
  const r = obj(root);
  const list: unknown[] =
    r && Array.isArray(r["resources"]) ? r["resources"] : Array.isArray(root) ? root : r ? [r] : [];
  const rows = list.map(obj).filter((x): x is Row => x !== undefined);
  return rows.some(isCrowdstrikeAlert) ? rows : null;
}

/** File-level check for importDetect: jsonSample does not unwrap `resources`, so look at the root too. */
export function isCrowdstrikeAlertFile(root: unknown, sample: unknown): boolean {
  return isCrowdstrikeAlert(sample) || alertRecords(root) !== null;
}

function addHash(sink: Map<string, SiemIoc>, raw: string): void {
  const h = raw.toLowerCase();
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/.test(h)) addIoc(sink, "hash", h);
}

// The behavior's own severity when it has one, else the detect-level maximum.
function severityOf(b: Row, parent: Row): Severity {
  if (field(b, "severity_name") || field(b, "severity"))
    return falconSeverity(field(b, "severity_name"), field(b, "severity"));
  return falconSeverity(field(parent, "max_severity_displayname"), field(parent, "max_severity"));
}

// One alert (v2) or one behavior of a legacy detect, with the detect-level fallbacks in `parent`.
function mapOne(
  b: Row,
  parent: Row,
  key: string,
  recordIndex: number,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  const device = obj(parent["device"]) ?? obj(b["device"]) ?? {};
  const host = field(device, "hostname") || field(b, "hostname") || field(device, "device_id");
  const name = field(b, "display_name") || field(b, "name") || field(b, "scenario") || "detection";
  const tactic = field(b, "tactic");
  const technique = field(b, "technique");
  const techniqueId = field(b, "technique_id");
  const file = field(b, "filename");
  const cmd = field(b, "cmdline");
  const action = field(b, "pattern_disposition_description");
  const user = field(b, "user_name");
  addHash(sink, field(b, "sha256"));
  addHash(sink, field(b, "md5"));
  const timestamp =
    crowdstrikeTimeOf(b, ["context_timestamp", "timestamp", "created_timestamp"])?.iso ??
    crowdstrikeTimeOf(parent, ["first_behavior", "created_timestamp"])?.iso ??
    "";
  const description =
    `${CROWDSTRIKE_SOURCE} detection: ${name}` +
    (tactic || technique ? ` — ${tactic}/${technique}` : "") +
    (file || cmd ? ` — ${[file, cmd].filter(Boolean).join(" ")}` : "") +
    (action ? ` — ${action}` : "") +
    (host ? ` @ ${host}` : "");
  const mapped: MappedEvent = {
    timestamp,
    severity: severityOf(b, parent),
    mitre: /^T\d{4}(?:\.\d{3})?$/.test(techniqueId) ? [techniqueId] : [],
    description,
    aggKey: boundedAggKey(`cs|alert|${key}`),
    sources: [CROWDSTRIKE_SOURCE],
    ...(host ? { asset: host } : {}),
    ...(cmd ? { commandLine: cmd } : {}),
  };
  const canonical = createCanonicalEvent({
    event: { category: "other", type: "alert", action: name },
    ...(user ? { actor: { kind: "account", name: user }, account: { name: user } } : {}),
    ...(host ? { target: { kind: "host", name: host } } : {}),
    time: { observed: timestamp, normalized: timestamp, timezone: "UTC", precision: "millisecond" },
    evidence: { rawRecords: [{ source: "crowdstrike", locator: `record:${recordIndex}` }] },
    producer: { importer: "crowdstrike", parserVersion: "1", mappingVersion: "crowdstrike-alert-v1" },
    rawFieldMap: { "event.action": ["display_name", "name", "scenario"] },
  });
  return { ...mapped, canonical };
}

/** One forensic event per alert, or per behavior of a legacy detect. */
export function mapCrowdstrikeAlert(
  rec: Row,
  recordIndex: number,
  sink: Map<string, SiemIoc>,
): MappedEvent[] {
  const id = field(rec, "composite_id") || field(rec, "detection_id");
  const behaviors = Array.isArray(rec["behaviors"])
    ? rec["behaviors"].map(obj).filter((x): x is Row => x !== undefined)
    : [];
  if (behaviors.length === 0) return [mapOne(rec, rec, id, recordIndex, sink)];
  return behaviors.map((b, i) =>
    mapOne(b, rec, `${id}|${oneLine(str(b["behavior_id"])) || i}`, recordIndex, sink),
  );
}
