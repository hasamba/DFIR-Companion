// Process access, remote threads and image tampering, read one record at a time (#932 item 9).
//
// Sysmon 10 (ProcessAccess) used to be graded by its event id — Medium + T1003 on EVERY handle,
// so explorer.exe opening chrome.exe read as credential dumping — with one special case for
// lsass.exe. Sysmon 8 (CreateRemoteThread) was High + T1055 on every row unless the source was a
// benign thread source. The fields that say what the record ESTABLISHES were never read: the
// rights the handle was opened with (`GrantedAccess`), the modules on the caller's stack
// (`CallTrace` — `UNKNOWN(…)` for a frame no module backs), and where the new thread starts
// (`StartModule`/`StartFunction`/`StartAddress` — outside any module is the shellcode shape,
// `KERNEL32.DLL!LoadLibraryW` is the DLL-injection shape).
//
// One record establishes: that a handle with these rights was opened, or a thread was created, by
// this process into that process. It does not establish that memory was read or written, that the
// thread's code was hostile, or that a sequence happened. So the words say the rights and the
// start, the grade follows the record's OWN evidence first — an unbacked frame or start, a write-,
// duplication- or thread-capable handle, lsass as the target — and source trust lowers only the
// one documented routine shape (a benign accessor's plain read of lsass with a backed trace).
// Trust is path-anchored (winProcessBaseline), never a name allowlist. The identities the later
// join needs — process GUIDs, pids — are kept in the key and the envelope now; a GUID-less row
// keys on its own record so PID reuse never folds two rows into one.

import type { Severity } from "./stateTypes.js";
import type { CanonicalEntity } from "./canonicalEvent.js";
import {
  BENIGN_LSASS_ACCESSORS,
  BENIGN_THREAD_SOURCES,
  EDR_AGENTS,
  isBenignLsassAccessor,
  isBenignThreadSource,
  isTrustedSystemImage,
  SUSP_PATH,
} from "./winProcessBaseline.js";

export type ProcessKind = "procaccess" | "thread" | "tamper";

export interface ProcessOverlay {
  description: string;
  severity: Severity;
  mitre: string[];
  /** `event.type` — access, remote_thread, tamper. */
  type: string;
  /** Appended to the aggregation key: rights/start, both process identities, the record fallback. */
  identity: string;
  entities: { subject?: CanonicalEntity; object?: CanonicalEntity };
  /** The singular canonical process — the TARGET of a two-process relation, the tampered process on 25. */
  process: { pid?: number; name?: string; executable?: string };
  rawFields: Record<string, string[]>;
}

// Windows process access rights — a literal table (winnt.h). ALL_ACCESS is a display alias only;
// every predicate runs on the expanded bits.
const RIGHTS: ReadonlyArray<[number, string]> = [
  [0x1, "TERMINATE"],
  [0x2, "CREATE_THREAD"],
  [0x8, "VM_OPERATION"],
  [0x10, "VM_READ"],
  [0x20, "VM_WRITE"],
  [0x40, "DUP_HANDLE"],
  [0x80, "CREATE_PROCESS"],
  [0x100, "SET_QUOTA"],
  [0x200, "SET_INFORMATION"],
  [0x400, "QUERY_INFORMATION"],
  [0x800, "SUSPEND_RESUME"],
  [0x1000, "QUERY_LIMITED_INFORMATION"],
  [0x2000, "SET_LIMITED_INFORMATION"],
  [0x10000, "DELETE"],
  [0x20000, "READ_CONTROL"],
  [0x40000, "WRITE_DAC"],
  [0x80000, "WRITE_OWNER"],
  [0x100000, "SYNCHRONIZE"],
];
const KNOWN_BITS = RIGHTS.reduce((m, [bit]) => m | bit, 0);
const B = Object.fromEntries(RIGHTS.map(([bit, name]) => [name, bit])) as Record<string, number>;
const ALL_ACCESS = new Set([0x1fffff, 0x1f0fff]);
// The routine read shape a trusted accessor of lsass may hold: VM_READ plus query/synchronize only.
const ROUTINE_READ_BITS = B.VM_READ | B.QUERY_INFORMATION | B.QUERY_LIMITED_INFORMATION | B.SYNCHRONIZE;
const QUERY_ONLY_BITS = B.QUERY_INFORMATION | B.QUERY_LIMITED_INFORMATION | B.SYNCHRONIZE;
const FRAMES_MAX = 32;
const TRACE_CHARS_MAX = 8192;
// A usable process GUID: well-formed and not the all-zero placeholder some feeds write.
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ZERO_GUID = /^0{8}-0{4}-0{4}-0{4}-0{12}$/;
const WORD_MAX = 80;
const LSASS = /(?:^|[\\/])lsass\.exe$/i;
const SYSTEM_MODULE = /^(?:[a-z]:)?\\?windows\\(?:system32|syswow64|winsxs)\\/i;
const LOADLIBRARY = /^LoadLibrary/i;

export const HANDLE_READ_NOTE = "handle rights, not a read observed";
export const HANDLE_WRITE_NOTE = "handle rights, not a write observed";
export const GUIDS_NOTE = "process GUIDs not in this record";

export interface AccessMask {
  rights: string[];
  bits: number;
  readable: boolean;
  /** absent — the feed did not carry the field; unreadable — it did, and the value is not a mask. */
  state: "absent" | "unreadable" | "value";
  /** Bits outside the table, as hex — "" when none. */
  unknown: string;
}

/** The rights in a `GrantedAccess` value (hex or decimal); tri-state on absence and garbage. */
export function decodeAccessMask(text: string | undefined): AccessMask {
  if (text === undefined) return { rights: [], bits: 0, readable: false, state: "absent", unknown: "" };
  const raw = text.trim();
  const n = /^0x[0-9a-f]{1,8}$/i.test(raw) ? parseInt(raw, 16) : /^\d{1,10}$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isFinite(n) || n < 0)
    return { rights: [], bits: 0, readable: false, state: "unreadable", unknown: "" };
  const rights = RIGHTS.filter(([bit]) => (n & bit) !== 0).map(([, name]) => name);
  const unknownBits = n & ~KNOWN_BITS;
  return {
    rights,
    bits: n,
    readable: true,
    state: "value",
    unknown: unknownBits ? `0x${unknownBits.toString(16)}` : "",
  };
}

const rightsWords = (m: AccessMask): string =>
  ALL_ACCESS.has(m.bits)
    ? `ALL_ACCESS (0x${m.bits.toString(16)})`
    : `${[...m.rights, ...(m.unknown ? [`unknown ${m.unknown}`] : [])].join("|") || "no rights"} (0x${m.bits.toString(16)})`;

export interface CallTrace {
  state: "absent" | "value";
  frames: string[];
  unbacked: number;
  /** The first module outside System32/SysWOW64/WinSxS — "" when every frame is a system module. */
  firstForeign: string;
}

/**
 * Sysmon's `module+offset|module+offset|…`; an `UNKNOWN(…)` frame is one no module backs. The
 * EVIDENCE (unbacked frames, the first foreign module) is counted over the whole bounded text;
 * only the retained frames are capped, so a frame past the cap still grades.
 */
export function readCallTrace(text: string | undefined): CallTrace {
  if (text === undefined) return { state: "absent", frames: [], unbacked: 0, firstForeign: "" };
  const all = text
    .slice(0, TRACE_CHARS_MAX)
    .split("|")
    .map((f) => f.trim())
    .filter(Boolean);
  const unbacked = all.filter((f) => /^UNKNOWN\b/i.test(f)).length;
  const modules = all.map((f) => f.replace(/\+(?:0x)?[0-9a-f]+(?:\(.*)?$/i, "").trim());
  const firstForeign = modules.find((m) => m && !/^UNKNOWN\b/i.test(m) && !SYSTEM_MODULE.test(m)) ?? "";
  return { state: "value", frames: all.slice(0, FRAMES_MAX), unbacked, firstForeign };
}

export interface ThreadStart {
  state: "absent" | "unbacked" | "module";
  module: string;
  function: string;
  address: string;
}

/** Where a remote thread starts: absent from the record, outside any module, or inside one. */
export function readStart(fields: { module?: string; function?: string; address?: string }): ThreadStart {
  const address = (fields.address ?? "").trim();
  const fn = (fields.function ?? "").trim();
  if (fields.module === undefined) return { state: "absent", module: "", function: fn, address };
  const module = fields.module.trim();
  if (!module || module === "-" || /^UNKNOWN\b/i.test(module))
    return { state: "unbacked", module: "", function: fn, address };
  return { state: "module", module, function: fn === "-" ? "" : fn, address };
}

const baseName = (p: string): string => p.slice(Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/")) + 1);
// A system process NAME from a path that is not a system path — the masquerade is the record's own
// signal, and it raises rather than lowers.
const MASQ_NOTE = "a system process name from a non-system path";
const isMasquerade = (image: string): boolean => {
  const name = baseName(image).toLowerCase();
  if (!/[\\/]/.test(image.trim())) return false;
  if ((BENIGN_THREAD_SOURCES.has(name) || BENIGN_LSASS_ACCESSORS.has(name)) && !isTrustedSystemImage(image))
    return true;
  // An EDR agent's name outside the vendor's own install root is the same signal.
  return (
    EDR_AGENTS.some((a) => a.name === name) && !isBenignThreadSource(image) && !isBenignLsassAccessor(image)
  );
};
const rightsCapability = (has: (bit: number) => boolean): string =>
  has(B.VM_WRITE) && (has(B.VM_OPERATION) || has(B.CREATE_THREAD))
    ? "write-capable handle"
    : has(B.DUP_HANDLE)
      ? "handle-duplication right (can yield full access)"
      : has(B.CREATE_THREAD)
        ? "thread-creation right"
        : has(B.VM_WRITE)
          ? "write right"
          : "read-capable handle";
const clip = (s: string, max: number): string => {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 1)}…`;
};
const pidOf = (v: string): number | undefined =>
  /^\d{1,10}$/.test(v.trim()) && Number(v.trim()) > 0 ? Number(v.trim()) : undefined;
const guidOf = (v: string): string => {
  const g = v.trim().replace(/^\{|\}$/g, "");
  return GUID.test(g) && !ZERO_GUID.test(g) ? g : "";
};

interface ProcessIdentity {
  guid: string;
  pid?: number;
  image: string;
  /** `<guid>` or `pid:<n>` or "" — the key's discriminator. */
  id: string;
}

function identityOf(field: (key: string) => string, prefix: string): ProcessIdentity {
  const guid = guidOf(field(`${prefix}ProcessGuid`) || field(`${prefix}ProcessGUID`));
  const pid = pidOf(field(`${prefix}ProcessId`));
  const image = field(`${prefix}Image`).trim();
  return { guid, pid, image, id: guid || (pid !== undefined ? `pid:${pid}` : "") };
}

function entityOf(p: ProcessIdentity): CanonicalEntity | undefined {
  if (!p.id && !p.image) return undefined;
  return {
    kind: "process",
    ...(p.id ? { id: p.id } : {}),
    ...(p.image ? { name: baseName(p.image) } : {}),
    ...(p.pid !== undefined ? { pid: p.pid } : {}),
  };
}

const rawFieldsFor = (
  role: "subject" | "object",
  prefix: string,
  p: ProcessIdentity,
): Record<string, string[]> => ({
  ...(p.id ? { [`${role}.id`]: [p.guid ? `${prefix}ProcessGuid` : `${prefix}ProcessId`] } : {}),
  ...(p.image ? { [`${role}.name`]: [`${prefix}Image`] } : {}),
  ...(p.pid !== undefined ? { [`${role}.pid`]: [`${prefix}ProcessId`] } : {}),
});
// The singular canonical process is the TARGET (the tampered process on 25): its provenance names
// the Target fields, never the source's.
const processFieldsFor = (prefix: string, p: ProcessIdentity): Record<string, string[]> => ({
  ...(p.pid !== undefined ? { "process.pid": [`${prefix}ProcessId`] } : {}),
  ...(p.image ? { "process.name": [`${prefix}Image`], "process.executable": [`${prefix}Image`] } : {}),
});

/** The GUID-less fallback: the record's own id, else its import-local row — a row never folds. */
function recordFallback(guids: boolean, recordId: string, row: number): string {
  if (guids) return "";
  return `|rec:${/^[1-9]\d{0,18}$/.test(recordId.trim()) ? recordId.trim() : `row:${row}`}`;
}

export interface OverlayInput {
  kind: ProcessKind;
  /** One event-data field by name, "" when absent. */
  field: (key: string) => string;
  /** True when the record carries the field at all (present-but-empty is a value). */
  has: (key: string) => boolean;
  description: string;
  severity: Severity;
  mitre: string[];
  /** The record's EventRecordID as written, and its import-local index. */
  recordId: string;
  row: number;
}

function accessGrade(
  target: string,
  source: string,
  mask: AccessMask,
  trace: CallTrace,
): { severity: Severity; mitre: string[]; note: string; qualifier: string } {
  const lsass = LSASS.test(target);
  const has = (bit: number): boolean => (mask.bits & bit) !== 0;
  // a. Code outside any module opened the handle — the record's own fact, whatever the rights.
  if (trace.unbacked > 0)
    return {
      severity: "High",
      mitre: [],
      note: `call trace has ${trace.unbacked} unbacked frame${trace.unbacked === 1 ? "" : "s"}`,
      qualifier: "",
    };
  if (lsass) {
    // b. A write-, duplication- or thread-capable handle on lsass: no trust exception.
    if (
      mask.readable &&
      (has(B.VM_WRITE) || has(B.DUP_HANDLE) || has(B.CREATE_THREAD) || has(B.VM_OPERATION))
    )
      return { severity: "High", mitre: ["T1003.001"], note: "", qualifier: HANDLE_READ_NOTE };
    // c. A read: High, unless the ONE routine shape — a benign accessor holding VM_READ plus
    //    query/synchronize bits only, no unknown bit, with a backed (or absent) trace.
    if (mask.readable && has(B.VM_READ)) {
      const routine = (mask.bits & ~ROUTINE_READ_BITS) === 0 && !mask.unknown;
      if (routine && isBenignLsassAccessor(source))
        return { severity: "Low", mitre: [], note: "routine read by a system-path accessor", qualifier: "" };
      return { severity: "High", mitre: ["T1003.001"], note: "", qualifier: HANDLE_READ_NOTE };
    }
    // d. Rights ABSENT from the record (a feed that drops GrantedAccess): the source context is all
    //    there is — the trade isTrustedSystemImage makes for an absent path. Rights present but
    //    UNREADABLE: the target is the lead, no technique.
    if (mask.state === "absent")
      return isBenignLsassAccessor(source)
        ? {
            severity: "Low",
            mitre: [],
            note: "rights not in this record; a system-path accessor",
            qualifier: "",
          }
        : {
            severity: "High",
            mitre: ["T1003.001"],
            note: "rights not in this record",
            qualifier: HANDLE_READ_NOTE,
          };
    if (!mask.readable) return { severity: "Medium", mitre: [], note: "rights not readable", qualifier: "" };
    // e. Query only.
    if ((mask.bits & ~QUERY_ONLY_BITS) === 0 && !mask.unknown)
      return { severity: "Low", mitre: [], note: "query-only handle", qualifier: "" };
    return { severity: "Medium", mitre: [], note: "other rights on lsass", qualifier: "" };
  }
  // f. Any target: a capability that enables injection — no trust exception; the path is said, and
  //    a masqueraded system name raises it.
  if (mask.readable) {
    const masq = isMasquerade(source);
    const trusted = source.trim() && isTrustedSystemImage(source) ? " from a system-path source" : "";
    if (masq && (has(B.VM_WRITE) || has(B.DUP_HANDLE) || has(B.CREATE_THREAD) || has(B.VM_READ)))
      return {
        severity: "High",
        mitre: [],
        note: `${rightsCapability(has)} — ${MASQ_NOTE}`,
        qualifier: HANDLE_WRITE_NOTE,
      };
    if (has(B.VM_WRITE) && (has(B.VM_OPERATION) || has(B.CREATE_THREAD)))
      return {
        severity: "Medium",
        mitre: [],
        note: `write-capable handle${trusted}`,
        qualifier: HANDLE_WRITE_NOTE,
      };
    if (has(B.DUP_HANDLE))
      return {
        severity: "Medium",
        mitre: [],
        note: `handle-duplication right (can yield full access)${trusted}`,
        qualifier: HANDLE_WRITE_NOTE,
      };
    if (has(B.CREATE_THREAD))
      return {
        severity: "Medium",
        mitre: [],
        note: `thread-creation right${trusted}`,
        qualifier: HANDLE_WRITE_NOTE,
      };
    if (has(B.VM_WRITE))
      return { severity: "Medium", mitre: [], note: `write right${trusted}`, qualifier: HANDLE_WRITE_NOTE };
    // g. A read of another process: a lead from a non-system path, telemetry from a system one.
    if (has(B.VM_READ))
      return source.trim() && isTrustedSystemImage(source)
        ? {
            severity: "Info",
            mitre: [],
            note: "read-capable handle from a system-path source",
            qualifier: "",
          }
        : { severity: "Low", mitre: [], note: "read-capable handle", qualifier: HANDLE_READ_NOTE };
  }
  // h. Everything else is telemetry.
  return {
    severity: "Info",
    mitre: [],
    note: mask.state === "absent" ? "rights not in this record" : mask.readable ? "" : "rights not readable",
    qualifier: "",
  };
}

function threadGrade(
  start: ThreadStart,
  source: string,
): { severity: Severity; mitre: string[]; note: string } {
  const benign = isBenignThreadSource(source);
  if (start.state === "unbacked")
    return { severity: "High", mitre: ["T1055"], note: "thread start outside any module" };
  if (start.state === "module" && LOADLIBRARY.test(start.function))
    return { severity: "High", mitre: ["T1055.001"], note: "the DLL-injection shape" };
  // A system or EDR name at a non-system path, or any source at a suspicious path (Temp, AppData,
  // Public), creating a remote thread: the record's own signal raises, whatever the start omits.
  if (isMasquerade(source)) return { severity: "High", mitre: ["T1055"], note: MASQ_NOTE };
  if (SUSP_PATH.test(source.replace(/\//g, "\\")))
    return { severity: "High", mitre: ["T1055"], note: "source at a suspicious path" };
  if (start.state === "absent")
    return benign
      ? { severity: "Low", mitre: [], note: "start module not in this record; a system-path source" }
      : { severity: "Medium", mitre: ["T1055"], note: "start module not in this record" };
  return benign
    ? { severity: "Low", mitre: [], note: "routine remote thread from a system-path source" }
    : {
        severity: "Medium",
        mitre: ["T1055"],
        note: `remote thread; start in ${clip(start.module, WORD_MAX)}`,
      };
}

/**
 * The overlay for a Sysmon 10 / 8 / 25 record over the Windows mapper's own description and table
 * grade. The mapper's mitre is REPLACED (the table's default technique was the overclaim).
 */
export function processOverlay(input: OverlayInput): ProcessOverlay {
  const { field, has, kind } = input;
  const source = identityOf(field, "Source");
  const target = identityOf(field, kind === "tamper" ? "" : "Target");
  const guids = kind === "tamper" ? target.guid !== "" : source.guid !== "" && target.guid !== "";
  const guidsNote = guids ? "" : GUIDS_NOTE;
  const fallback = recordFallback(guids, input.recordId, input.row);
  const srcName = clip(baseName(source.image) || "(unknown process)", WORD_MAX);
  const dstName = clip(baseName(target.image) || "(unknown process)", WORD_MAX);
  const ids = `|src:${source.id}|dst:${target.id}${fallback}`;
  const process = {
    ...(target.pid !== undefined ? { pid: target.pid } : {}),
    ...(target.image ? { name: baseName(target.image), executable: target.image } : {}),
  };
  const common = (
    words: string[],
    g: { severity: Severity; mitre: string[] },
    type: string,
    identity: string,
    entities: ProcessOverlay["entities"],
    rawFields: Record<string, string[]>,
  ): ProcessOverlay => ({
    description: `${input.description} — ${[...words, guidsNote].filter(Boolean).join(" — ")}`.slice(0, 600),
    severity: g.severity,
    mitre: [...g.mitre],
    type,
    identity,
    entities,
    process,
    rawFields,
  });
  if (kind === "tamper") {
    const type = clip(field("Type"), WORD_MAX);
    return common(
      [`${dstName}${type ? `: ${type}` : ""}`],
      { severity: input.severity, mitre: input.mitre },
      "tamper",
      `|tamper:${type.toLowerCase()}|proc:${target.id}${fallback}`,
      { ...(entityOf(target) ? { object: entityOf(target) } : {}) },
      { ...rawFieldsFor("object", "", target), ...processFieldsFor("", target) },
    );
  }
  const entities = {
    ...(entityOf(source) ? { subject: entityOf(source) } : {}),
    ...(entityOf(target) ? { object: entityOf(target) } : {}),
  };
  const rawFields = {
    ...rawFieldsFor("subject", "Source", source),
    ...rawFieldsFor("object", "Target", target),
    ...processFieldsFor("Target", target),
  };
  if (kind === "thread") {
    const start = readStart({
      ...(has("StartModule") ? { module: field("StartModule") } : {}),
      function: field("StartFunction"),
      address: field("StartAddress"),
    });
    const g = threadGrade(start, source.image);
    const where =
      start.state === "module"
        ? `starting at ${clip(`${start.module}${start.function ? `!${start.function}` : ""}`, WORD_MAX)}`
        : start.state === "unbacked"
          ? `starting at ${clip(start.address || "an address", 24)} — outside any module`
          : "start module not in this record";
    const startKey =
      start.state === "module"
        ? `${start.module}!${start.function}`
        : start.state === "unbacked"
          ? start.address || "unbacked"
          : "absent";
    return common(
      [`creates a thread in ${dstName} from ${srcName} ${where}`, g.note],
      g,
      "remote_thread",
      `|thread:${startKey.toLowerCase()}${ids}`,
      entities,
      rawFields,
    );
  }
  const mask = decodeAccessMask(has("GrantedAccess") ? field("GrantedAccess") : undefined);
  const trace = readCallTrace(has("CallTrace") ? field("CallTrace") : undefined);
  const g = accessGrade(target.image, source.image, mask, trace);
  const traceWords =
    trace.unbacked > 0 ? "" : trace.firstForeign ? `via ${clip(baseName(trace.firstForeign), WORD_MAX)}` : "";
  const rightsKey = mask.readable
    ? [...mask.rights, ...(mask.unknown ? [mask.unknown] : [])].join(",").toLowerCase()
    : "unreadable";
  return common(
    [
      `opens ${dstName} with ${mask.readable ? rightsWords(mask) : "rights not readable"} from ${srcName}`,
      g.note,
      traceWords,
      g.qualifier,
    ],
    g,
    "access",
    `|access:${rightsKey}${ids}|${trace.unbacked}`,
    entities,
    rawFields,
  );
}
