// DetectRaptor.Windows.Detection.HijackLibsMFT — a DLL on disk whose name matches a known
// hijackable / side-loadable library (hijacklibs.net). The signal is LOCATION: the same DLL sitting
// in the vendor's own install tree is the legitimate file; the same name somewhere else is a
// side-load candidate. So compare the DLL's path to the entry's ExpectedLocation regex — a match is
// the real library (Low), a miss is the technique (Medium + T1574.00x).
//
// In its own module (not velociraptorImport) because that file is frozen at the size ledger. Before
// this pack was rescued (importDetect no longer rejects its unsampled row shape), its T1574 evidence
// in scenarios 004/005 was dropped at import.

import {
  firstStr,
  oneLine,
  getCI,
  isObject,
  str,
  addIoc,
  type MappedEvent,
  type SiemIoc,
} from "./siemImport.js";
import { withHostSuffix } from "./velociraptorTitle.js";
import { pickTime } from "./veloRowTime.js";
import { isDetectionContentPath } from "./veloDetectionNoise.js";
import { boundedAggKey } from "./aggKey.js";
import type { Severity } from "./stateTypes.js";

type Row = Record<string, unknown>;

export function mapHijackLib(
  row: Row,
  artifact: string,
  host: string,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  const info = getCI(row, "HijackLibInfo");
  const infoObj: Row = isObject(info) ? info : {};
  const dll = str(getCI(infoObj, "DllName")) || str(getCI(row, "FileName")) || "a DLL";
  const vendor = str(getCI(infoObj, "Vendor"));
  const type = str(getCI(infoObj, "Type"));
  const expected = str(getCI(infoObj, "ExpectedLocation"));
  const path = firstStr(row, ["OSPath", "FullPath", "_FullPath", "FileName"]);
  const url = str(getCI(infoObj, "Url"));

  // Does the DLL sit where the vendor puts it? ExpectedLocation is a path regex from the entry.
  let inExpectedPlace = false;
  if (expected && path) {
    try {
      inExpectedPlace = new RegExp(expected, "i").test(path);
    } catch {
      inExpectedPlace = false; // a malformed pattern is treated as "cannot confirm legitimate"
    }
  }

  // Type → the specific ATT&CK sub-technique; default to the parent when unknown.
  const mitre = /search[\s_-]*order/i.test(type)
    ? ["T1574.001"]
    : /side[\s_-]*load|sideload/i.test(type)
      ? ["T1574.002"]
      : ["T1574"];
  const severity: Severity = inExpectedPlace ? "Low" : "Medium";
  const verdict = inExpectedPlace
    ? "in its vendor location (likely legitimate)"
    : "OUTSIDE its expected vendor location — DLL side-load candidate";
  const sha = str(getCI(infoObj, "ExecutableSHA256")).toLowerCase();
  if (path && !isDetectionContentPath(path)) addIoc(sink, "file", path);

  let description = `Velociraptor${artifact ? ` [${artifact}]` : ""}: hijackable DLL ${dll}${
    vendor ? ` (${vendor})` : ""
  } at ${oneLine(path)} ${verdict}${type ? ` [${type}]` : ""}${url ? ` — ${url}` : ""}`;
  description = withHostSuffix(description.slice(0, 600), host).slice(0, 600);

  return {
    timestamp: pickTime(row),
    description,
    severity,
    mitre,
    // Host and DLL lead, the unbounded path trails, and boundedAggKey closes the key. A plain
    // .slice(0, 400) collapsed two DLLs under one deep directory into a single row — and the
    // aggregator does not merely miscount a collision, it overwrites the survivor's path and hash.
    // A hijackable-DLL scan walks the whole disk, so a deep path is its normal input (#722).
    aggKey: boundedAggKey(`vr|hijacklib|${host.toLowerCase()}|${dll.toLowerCase()}|${path.toLowerCase()}`),
    sources: ["Velociraptor"],
    ...(sha && /^[a-f0-9]{64}$/.test(sha) ? { sha256: sha } : {}),
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
  };
}
