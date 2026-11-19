// The aggregation fingerprint the Velociraptor importer folds into a detection's agg key. Lifted out
// of velociraptorImport.ts (at its size-ledger cap) so the AI Agent Forensics dispatch hook fits (#2690).

import { oneLine } from "./siemImport.js";
import { networkTokens } from "./networkTokens.js";

// A stable djb2 hash → base36, for folding message content into an aggregation key compactly.
function hashStr(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}

// Fingerprint a message for aggregation: strip VOLATILE bits (GUIDs, digits — PIDs, record ids,
// counters), keep the words AND every network address, then hash the WHOLE thing: two detections
// differing only by PID collapse; two naming different tools (HackTool:Passview vs Mimikatz) or
// peers stay apart. Hashing (not a prefix) lets a token anywhere in a long boilerplate message
// separate events and keeps the key a fixed length however many addresses one message names.
export function msgFingerprint(msg: string): string {
  const line = oneLine(msg)
    .toLowerCase()
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "");
  const addrs = networkTokens(line);
  const norm = line
    .replace(/\d+/g, "")
    .replace(/[^a-z]+/g, " ")
    .trim();
  const joined = addrs.length ? `${norm} ${addrs.join(" ")}`.trim() : norm;
  return joined ? hashStr(joined) : "";
}
