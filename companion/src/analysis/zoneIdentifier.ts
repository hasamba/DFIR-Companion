// A file downloaded through a browser or a script carries a Zone.Identifier alternate data stream
// naming where it came from. Windows.Analysis.EvidenceOfDownload surfaces that as a parsed `ZoneId`
// column alongside the raw stream text, and mapDownload graded every such row Info — which never
// reaches the forensic timeline, so a PowerShell script pulled from the Internet and left in the
// Recycle Bin was invisible to synthesis.
//
// Kept as its own module rather than inlined into velociraptorImport.ts, which is frozen at its
// current size by the file-size ledger (#384) — see check-file-size.mjs.
import { str, getCI } from "./siemImport.js";

type Row = Record<string, unknown>;

// Zones: 3 = Internet, 4 = Restricted sites. Both mean the file crossed a network boundary onto this
// host. 0-2 (local machine / intranet / trusted) did not, and say nothing about how it arrived.
const REMOTE_ZONES = new Set(["3", "4"]);

// Extensions that RUN, or that mount something that runs. A document arriving from the Internet is
// ordinary; an executable, a script, or a mountable container is how a payload lands — so the zone
// becomes a finding only for these, never for the zone on its own.
const PAYLOAD_EXT =
  /\.(exe|dll|sys|scr|com|cpl|ocx|msi|msp|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|jar|py|pyw|lnk|reg|inf|chm|iso|img|vhd|vhdx)$/i;

// The parsed ZoneId column, else the raw stream text the artifact also carries
// ("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=…").
function downloadZone(row: Row): string {
  const direct = str(getCI(row, "ZoneId")).trim();
  if (direct) return direct;
  return /zoneid\s*=\s*(\d+)/i.exec(str(getCI(row, "_ZoneIdentifierContent")))?.[1] ?? "";
}

/** Executable content that came from outside this host — the shape a delivered payload has. */
export function isRemotePayloadDownload(row: Row, path: string): boolean {
  return REMOTE_ZONES.has(downloadZone(row)) && PAYLOAD_EXT.test(path);
}
