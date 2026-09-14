import type { ForensicEvent } from "./stateTypes.js";
import type { TelemetryFamily } from "./remediationBoundary.js";

// What a row that names the remediated artifact IS — read from the UPGRADED canonical envelope's
// (category, type, action) and, where the envelope collapses two different things into one
// triple, from the row's source (#969). The class is a reading aid for the analyst, never a
// filter and never a verdict:
//
//   activity   — the row records something happening: a start, a logon, a flow, a service or task
//                or registry event (the Windows importer emits one triple for create and remove,
//                so those say "the record does not distinguish create from remove").
//   detection  — a scanner's or sensor's claim about the object (Defender, Suricata, a Zeek
//                notice): it says the object was SEEN, nothing about when it arrived.
//   presence   — a presence record (Amcache, ShimCache, Prefetch): its timestamp is not an
//                execution time (ShimCache) or is a last-run summary (Prefetch); it cannot place
//                an action after the boundary on its own.
//   listing-of-older-object — a file listing (MFT, a directory listing) whose object's own
//                modification time is BEFORE the boundary: the object was there already.
//   unclassified — a shape the table does not know; shown with its triple.
//
// tests/analysis/remediationShapes.test.ts asserts the class of REAL importer fixtures (not table
// membership): a Prefetch row is `presence`, an MFT row with an older fileModified is
// `listing-of-older-object`, a Defender 1116 is `detection`, a Sysmon 1 is `activity`.

export type HitClass = "activity" | "detection" | "presence" | "listing-of-older-object" | "unclassified";

const PRESENCE_SOURCES = /amcache|shimcache|appcompat|prefetch|bam\b|userassist/i;
const LISTING_SOURCES =
  /\bmft\b|mftecmd|\$mft|usnjrnl|usn journal|directory listing|file listing|filesystem/i;
const DETECTION_SOURCES = /defender|suricata|zeek|snort|sigma|hayabusa|chainsaw|thor|yara|clamav|edr/i;

const ACTIVITY: ReadonlySet<string> = new Set([
  "process/start",
  "authentication/logon",
  "authentication/sign-in",
  "network/connection",
  "network/flow",
  "network/dns",
  "network/query",
  "network/transfer",
  "service/service",
  "service/install",
  "service/start",
  "task/event",
  "task/create",
  "registry/event",
  "registry/set",
  "process/observation",
  "file/write",
  "file/create",
  "file/modify",
  "file/delete",
  "cloud/event",
]);
const DETECTION: ReadonlySet<string> = new Set([
  "file/detection",
  "file/action",
  "network/alert",
  "network/notice",
  "other/detection",
]);
const LISTING: ReadonlySet<string> = new Set(["file/listing", "file/observation"]);

/** Notes said beside a class where the envelope cannot say more. */
export const CLASS_NOTES: Readonly<Record<string, string>> = {
  "service/service": "the record does not distinguish create from remove",
  "task/event": "the record does not distinguish create from delete",
  "registry/event": "the record does not distinguish set from delete",
  "process/observation": "an observation of a process, not a recorded start",
};

const sourcesOf = (e: ForensicEvent): string => (e.sources ?? []).join(" ");

export function tripleOf(e: ForensicEvent): string {
  const ev = e.canonical?.event;
  return ev ? `${ev.category}/${ev.type}${ev.action ? `/${ev.action}` : ""}` : "(no envelope)";
}

const pairOf = (e: ForensicEvent): string => {
  const ev = e.canonical?.event;
  return ev ? `${ev.category}/${ev.type}` : "";
};

/**
 * The class of a row that names the artifact, given the boundary time. Source first where the
 * envelope collapses presence and listing into `process/observation` / `file/observation`.
 */
export function classifyHit(e: ForensicEvent, boundaryMs: number): { cls: HitClass; note?: string } {
  const src = sourcesOf(e);
  const pair = pairOf(e);
  if (PRESENCE_SOURCES.test(src)) return { cls: "presence", note: presenceNote(src) };
  if (LISTING_SOURCES.test(src) || LISTING.has(pair)) {
    const modified = Date.parse(e.fileModified ?? "");
    if (Number.isFinite(modified) && modified < boundaryMs)
      return {
        cls: "listing-of-older-object",
        note: "the object's own modification time is before the boundary",
      };
    if (LISTING_SOURCES.test(src))
      return {
        cls: "unclassified",
        note: "a listing whose object time is not recorded or is after the boundary",
      };
  }
  if (DETECTION.has(pair) || (DETECTION_SOURCES.test(src) && !ACTIVITY.has(pair)))
    return {
      cls: "detection",
      note: "a scanner's or sensor's claim; says nothing about when the object arrived",
    };
  if (ACTIVITY.has(pair))
    return { cls: "activity", ...(CLASS_NOTES[pair] ? { note: CLASS_NOTES[pair] } : {}) };
  return { cls: "unclassified", note: `shape ${tripleOf(e)} is not in the table` };
}

function presenceNote(src: string): string {
  if (/shimcache|appcompat/i.test(src))
    return "ShimCache: the timestamp is the file's, not an execution time";
  if (/prefetch/i.test(src)) return "Prefetch: a last-run summary, not a dated start";
  return "a presence record; its time is not a recorded action";
}

/** The telemetry family a row belongs to, for coverage facts. */
export function familyOf(e: ForensicEvent): TelemetryFamily | null {
  const src = sourcesOf(e);
  if (/defender/i.test(src) || pairOf(e) === "file/detection" || pairOf(e) === "file/action")
    return "defender";
  const cat = e.canonical?.event?.category;
  if (cat === "process") return "process";
  if (cat === "authentication") return "authentication";
  if (cat === "network") return "network";
  if (PRESENCE_SOURCES.test(src) || LISTING_SOURCES.test(src) || cat === "file") return "file-listing";
  return null;
}

/** The families that matter for an artifact kind — what an analyst would expect to see it in. */
export function relevantFamilies(kind: string): TelemetryFamily[] {
  switch (kind) {
    case "path":
    case "hash":
      return ["process", "file-listing", "defender"];
    case "account":
      return ["authentication", "process"];
    case "domain":
    case "ip":
      return ["network"];
    case "service":
    case "task":
    case "regkey":
      return ["process"];
    default:
      return ["process"];
  }
}
