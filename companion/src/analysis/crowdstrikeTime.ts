// Event time for CrowdStrike Falcon rows (#2592), shared by the sensor mapper and the API alert mapper.
// A field is used only when it is valid: blank, zero, malformed or out-of-range values fall through to
// the next field. Epoch numbers below 1e11 are seconds (fractional allowed), larger ones milliseconds;
// anything else must be a date string Date.parse reads.

import { field } from "./crowdstrikeFields.js";

type Row = Record<string, unknown>;

const MIN_MS = Date.UTC(1990, 0, 1);
const MAX_MS = Date.UTC(2100, 0, 1);

function toMs(raw: string): number | undefined {
  if (!raw) return undefined;
  const n = Number(raw);
  let ms: number;
  if (Number.isFinite(n)) {
    if (n <= 0) return undefined;
    ms = n < 1e11 ? Math.round(n * 1000) : Math.round(n);
  } else {
    ms = Date.parse(raw);
    if (Number.isNaN(ms)) return undefined;
  }
  return ms >= MIN_MS && ms < MAX_MS ? ms : undefined;
}

/** The first valid time among `keys`, as ISO 8601 UTC, with the key it came from. */
export function crowdstrikeTimeOf(rec: Row, keys: readonly string[]): { iso: string; from: string } | null {
  for (const key of keys) {
    const ms = toMs(field(rec, key));
    if (ms !== undefined) return { iso: new Date(ms).toISOString(), from: key };
  }
  return null;
}

// Sensor rows: ContextTimeStamp (the event itself) → ProcessStartTime → timestamp (the sensor's send
// time) → @timestamp (LogScale ingest).
const SENSOR_TIME_FIELDS = ["ContextTimeStamp", "ProcessStartTime", "timestamp", "@timestamp"] as const;
export function crowdstrikeTime(rec: Row): { iso: string; from: string } | null {
  return crowdstrikeTimeOf(rec, SENSOR_TIME_FIELDS);
}
