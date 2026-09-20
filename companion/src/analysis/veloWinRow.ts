import { getCI, getPath, isObject, str } from "./siemImport.js";
import { resolveRowHost } from "./hostIdentity.js";
import { pickTime, vrTime } from "./veloRowTime.js";

type Row = Record<string, unknown>;

// ───────────────────────────── EVTX-row normalization ─────────────────────────────

// A Velociraptor parsed-evtx row carries `System` + `EventData` (sometimes under `Event`), or —
// for artifacts that flatten the event (e.g. DetectRaptor's Windows.Detection.Evtx) — top-level
// `Channel`/`EventID`/`EventData`. Reshape either to the flat record `mapWindows` consumes,
// normalizing the EventID (number or `{ Value }`/`{ #text }`) to a bare value, plus the host.
// The parsed Windows event a Velociraptor row carries, in any of the three places the artifacts put
// it: `System`/`EventData` at the top level (Windows.EventLogs.Evtx), under `Event` (Sigma), or under
// `_Event` (Windows.Hayabusa.Rules / Windows.Sigma.Base hunt output, #1476). A Hayabusa row whose
// event was not read here came through text-only — no pid, command line, path or record identity —
// and correlation, left with only the file path, folded distinct executions of one binary into one row.
function nestedWinEvent(row: Row): { sys: Row | null; ed: unknown; message: string } {
  for (const wrap of [null, "Event", "_Event"]) {
    const base = wrap === null ? row : getCI(row, wrap);
    if (!isObject(base)) continue;
    const sys = getCI(base, "System");
    if (isObject(sys)) {
      return {
        sys,
        ed: getCI(base, "EventData"),
        message: str(getCI(base, "Message")) || str(getCI(row, "Message")),
      };
    }
  }
  return { sys: null, ed: getCI(row, "EventData"), message: str(getCI(row, "Message")) };
}

export function winRowToFlat(row: Row): { rec: Row; host: string } | null {
  const { sys, ed: edRaw, message } = nestedWinEvent(row);

  if (sys) {
    let eid: unknown = getCI(sys, "EventID");
    if (isObject(eid)) eid = getCI(eid, "Value") ?? getCI(eid, "#text");
    const channel =
      str(getCI(sys, "Channel")) ||
      str(getPath(sys, "Provider.Name")) ||
      str(getPath(sys, "Provider.#attributes.Name"));
    // The record number rides along so mapWindows can mint the record identity two parsers of one
    // log share (correlate.ts step 0b). Without it a Hayabusa and a Chainsaw reading of one record
    // never met, and the path step was left to guess.
    const recordId = getCI(sys, "EventRecordID");
    return {
      host: resolveRowHost(row).asset, // collector identity first; System.Computer only when no Fqdn (#1417)
      rec: {
        event_id: eid,
        channel,
        event_data: isObject(edRaw) ? edRaw : {},
        "@timestamp": vrTime(getCI(sys, "TimeCreated")),
        message,
        ...(recordId != null && str(recordId).trim() ? { EventRecordID: recordId } : {}),
      },
    };
  }

  // Flat shape: top-level Channel/EventID/EventData with no System wrapper.
  let eidFlat: unknown = getCI(row, "EventID") ?? getCI(row, "EventId");
  if (eidFlat == null && !isObject(edRaw)) return null;
  if (isObject(eidFlat)) eidFlat = getCI(eidFlat, "Value") ?? getCI(eidFlat, "#text");
  return {
    host: resolveRowHost(row).asset,
    rec: {
      event_id: eidFlat,
      channel: str(getCI(row, "Channel")),
      event_data: isObject(edRaw) ? edRaw : {},
      "@timestamp": pickTime(row),
      message: str(getCI(row, "Message")),
    },
  };
}
