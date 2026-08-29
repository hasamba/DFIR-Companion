// Aggregation keys for the Velociraptor mappers, in one place so the rule they all follow is
// visible at once: the HOST LEADS, the unbounded field TRAILS, and boundedAggKey closes the key.
//
// Every key here used to put an unbounded field (a Sigma rule title, a scanned path, a download
// URL, a scheduled-task name, a persistence command line) BEFORE the host and then truncate the
// whole key at 400 characters. The host was therefore the first field truncation threw away, and
// the same detection on two machines came back as one finding on one machine — the cross-host
// merge #659 fixed for Windows events, arriving again through five more mappers.
//
// That is not a miscount. applyEventIdentity overwrites the survivor's path, hash and description
// with whichever row landed last, so a collision DELETES one host's evidence.
//
// Kept out of velociraptorImport.ts, which is frozen at its current size by the file-size ledger
// (#384) — see check-file-size.mjs.
import { boundedAggKey } from "./aggKey.js";

// Volatile identifiers (pids, record ids, GUIDs) fold so one detection repeated with a fresh id
// stays one row. That normalisation must never reach the HOST: WS01 and WS02 are two machines, and
// digit-stripping them recreates the exact merge the host-first ordering exists to prevent. Every
// key below therefore normalises its DISCRIMINATOR fields only, with the host held literal.
const GUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g;

function foldVolatileIds(s: string): string {
  return s.replace(GUID_RE, "<guid>").replace(/\d+/g, "#");
}

// Sigma with no parsed event underneath. The rule title is the only discriminator besides the host,
// and a verbose Sigma title reaches the bound on its own.
export function sigmaAggKey(host: string, title: string): string {
  return boundedAggKey(`vr-sigma|${host.toLowerCase()}|${title.toLowerCase()}`);
}

// A DetectRaptor verdict on a file / registry key / named pipe. `subject` is the matched path,
// process, pipe or evidence line — the field that can exhaust the bound by itself.
export function detectionAggKey(host: string, title: string, subject: string): string {
  return boundedAggKey(
    `vr-det|${host.toLowerCase()}|${foldVolatileIds(`${title}|${subject}`.toLowerCase())}`,
  );
}

// A DetectRaptor verdict overlaid on a parsed Windows event. The Windows key already leads with its
// own host, so it goes first and the verdict title — the unbounded half — trails it.
export function detectionOverlayAggKey(windowsAggKey: string, title: string): string {
  return boundedAggKey(`vr-det|${windowsAggKey}|${title.toLowerCase()}`);
}

// A Zone.Identifier download. The source URL trails: a real download URL carries query strings and
// tracking parameters that pass 400 characters routinely.
export function downloadAggKey(host: string, name: string, urlDisplay: string): string {
  return boundedAggKey(
    `vr-download|${host.toLowerCase()}|${foldVolatileIds(`${name}|${urlDisplay}`.toLowerCase())}`,
  );
}

// A scheduled task. The task name is a nested path and is the unbounded field.
export function taskAggKey(host: string, taskName: string): string {
  return boundedAggKey(`vr-task|${host.toLowerCase()}|${foldVolatileIds(taskName.toLowerCase())}`);
}

// A PersistenceSniper autostart. `subject` is the entry's Value (a command line) or its Path — what
// actually distinguishes one autostart from another, and the field with no length ceiling.
export function persistenceAggKey(host: string, technique: string, subject: string): string {
  return boundedAggKey(
    `vr-persist|${host.toLowerCase()}|${foldVolatileIds(`${technique}|${subject}`.toLowerCase())}`,
  );
}
