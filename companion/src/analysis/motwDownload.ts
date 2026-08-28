// Reading a Mark-of-the-Web (Zone.Identifier ADS) download record.
//
// Windows writes an alternate data stream next to every file a browser saves, recording which
// security zone it came from. Velociraptor's Windows.Analysis.EvidenceOfDownload surfaces it, and
// that record is often the ONLY surviving evidence of how an intrusion started — the dropper is
// long deleted, but the stream on a sibling file still names the zone and the URL.
//
// velociraptorImport graded every one of those rows Info, which never reaches the forensic
// timeline. On one benchmark collection that buried fifteen ZoneId=3 rows — the whole attack
// toolkit, eleven staged PowerShell phase scripts among them — under "download evidence".
//
// Two jobs live here because both answer "what does this ADS actually say":
//   • zoneText()          — the stream is NUL-terminated, so its values arrive with a trailing NUL.
//   • gradeMotwDownload() — zone + file type ⇒ severity + technique.
//
// Kept out of velociraptorImport.ts, which is frozen at its current size by the file-size ledger
// (#384) — see check-file-size.mjs.
import type { Severity } from "./stateTypes.js";
import { STAGING_EXT } from "./stagingPaths.js";

// Internet Explorer's URLSecurityZones, unchanged since IE4 and still what Windows writes today.
const ZONE_NAMES: Record<string, string> = {
  "0": "Local machine",
  "1": "Local intranet",
  "2": "Trusted site",
  "3": "Internet",
  "4": "Restricted site",
};

// The zones that mean "this file came from outside the org". 3 is the ordinary internet download;
// 4 is a site the user's own policy distrusts, which is strictly worse.
const UNTRUSTED_ZONES = new Set(["3", "4"]);

// Executable and script types — the same list stagingPaths.ts uses to decide that a file in Temp is
// a binary rather than a document, kept shared so the two can never disagree about what "runnable"
// means.
const RUNNABLE_EXT = new RegExp(`^(?:${STAGING_EXT})$`, "i");

// Disk-image containers. Called out separately from RUNNABLE_EXT because they are not runnable at
// all — they matter for the opposite reason: mounting one does NOT propagate the mark to the files
// inside, so delivering a payload in an .iso is how an attacker strips MOTW from it. A .zip is left
// out on purpose; archive downloads are ordinary, and Windows does propagate the mark through them.
const CONTAINER_EXT = /^(?:iso|img|vhd|vhdx)$/i;

// Every C0 and C1 control character. The ADS is NUL-terminated, but a hand-edited stream can carry
// stray CR/LF too, so strip the whole range rather than the one byte that prompted this.
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/g;

/**
 * A value read out of the Zone.Identifier stream, cleaned for display and for IOC matching.
 *
 * The stream is NUL-terminated, so `HostUrl=https://…/main` arrives with a trailing NUL attached.
 * Left in, that NUL rides into the event description and into the URL indicator, where it silently
 * defeats every later comparison — the same URL seen in proxy logs or a browser-history artifact no
 * longer matches, so correlation misses the link — and makes the case text unsearchable by ordinary
 * tools, which stop at the first NUL and call the rest binary.
 */
export function zoneText(v: string): string {
  return v.replace(CONTROL_CHARS, "").trim();
}

export interface MotwGrade {
  severity: Severity;
  mitre: string[];
  /** Human-readable zone for the description ("Internet zone"), or "" when the zone is unknown. */
  zoneLabel: string;
}

/**
 * Grade a download record from its zone and the file it marked.
 *
 * An untrusted-zone EXECUTABLE or SCRIPT is the finding: the user pulled runnable code off the
 * internet, which is the precondition ATT&CK calls T1204.002, and it is worth an analyst's eye even
 * before anything proves it ran. A document, an image or an archive from the same zone is ordinary
 * browsing and stays at Info — the record is still on the timeline, it just is not a lead.
 */
export function gradeMotwDownload(zoneId: string, fileName: string): MotwGrade {
  const zone = zoneText(zoneId);
  const zoneLabel = ZONE_NAMES[zone] ? `${ZONE_NAMES[zone]} zone` : "";
  if (!UNTRUSTED_ZONES.has(zone)) return { severity: "Info", mitre: [], zoneLabel };
  const name = zoneText(fileName);
  const dot = name.lastIndexOf(".");
  const ext = dot >= 0 ? name.slice(dot + 1) : "";
  if (!RUNNABLE_EXT.test(ext) && !CONTAINER_EXT.test(ext)) return { severity: "Info", mitre: [], zoneLabel };
  return { severity: "Medium", mitre: ["T1204.002"], zoneLabel };
}
