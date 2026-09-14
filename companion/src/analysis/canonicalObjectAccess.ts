// Windows object-access vocabulary (#930 item 7), shared by the importer and the readings: a
// file's access rights by bit (`0x1` is ReadData OR ListDirectory — the record cannot tell a file
// from a directory, so the class is "read-or-listing" until a file row evidences the object), and
// the pid / id / path normalisation every join compares through.

export type AccessClass =
  | "read-or-listing"
  | "data-write"
  | "delete"
  | "metadata"
  | "attribute-write"
  | "execute-or-traverse"
  | "unknown";

/** File-object access rights (Security 4663 / 4656 AccessMask), by bit. */
const FILE_RIGHTS: readonly [number, string, AccessClass][] = [
  [0x1, "ReadData/ListDirectory", "read-or-listing"],
  [0x2, "WriteData/AddFile", "data-write"],
  [0x4, "AppendData/AddSubdirectory", "data-write"],
  [0x8, "ReadEA", "metadata"],
  [0x10, "WriteEA", "attribute-write"],
  [0x20, "Execute/Traverse", "execute-or-traverse"],
  [0x40, "DeleteChild", "delete"],
  [0x80, "ReadAttributes", "metadata"],
  [0x100, "WriteAttributes", "attribute-write"],
  [0x10000, "DELETE", "delete"],
  [0x20000, "READ_CONTROL", "metadata"],
  [0x40000, "WRITE_DAC", "attribute-write"],
  [0x80000, "WRITE_OWNER", "attribute-write"],
  [0x100000, "SYNCHRONIZE", "metadata"],
];
const KNOWN = FILE_RIGHTS.reduce((m, [bit]) => m | bit, 0) >>> 0;
const MAX_U32 = 0xffffffff;

export interface FileAccessMask {
  /** absent — no field; unreadable — not an unsigned 32-bit mask; value — decoded. */
  state: "absent" | "unreadable" | "value";
  bits: number;
  rights: string[];
  classes: AccessClass[];
  /** Bits outside the table, as hex — "" when none. */
  unknown: string;
}

/** Decode an AccessMask (hex or decimal) as an UNSIGNED 32-bit value; anything else is unreadable. */
export function decodeFileAccessMask(text: string | undefined): FileAccessMask {
  if (text === undefined) return { state: "absent", bits: 0, rights: [], classes: [], unknown: "" };
  const raw = text.trim();
  let n: number = NaN;
  if (/^0x[0-9a-f]{1,8}$/i.test(raw)) n = parseInt(raw, 16);
  else if (/^\d{1,10}$/.test(raw)) n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > MAX_U32)
    return { state: "unreadable", bits: 0, rights: [], classes: [], unknown: "" };
  const bits = n >>> 0;
  const hit = FILE_RIGHTS.filter(([bit]) => (bits & bit) !== 0);
  const unknownBits = (bits & ~KNOWN) >>> 0;
  const classes = [...new Set(hit.map(([, , c]) => c))];
  if (unknownBits) classes.push("unknown");
  return {
    state: "value",
    bits,
    rights: hit.map(([, name]) => name),
    classes,
    unknown: unknownBits ? `0x${unknownBits.toString(16)}` : "",
  };
}

/** A Windows pid as logged (hex `0x1a4` on Security, decimal on Sysmon) → a number, or null. */
export function normalisePid(raw: string | undefined): number | null {
  const s = (raw ?? "").trim();
  if (!s || s === "-") return null;
  const n = /^0x[0-9a-f]{1,8}$/i.test(s) ? parseInt(s, 16) : /^\d{1,10}$/.test(s) ? Number(s) : NaN;
  return Number.isInteger(n) && n >= 0 && n <= MAX_U32 ? n : null;
}

/** A logon id / handle id as logged (hex or decimal) → a canonical lowercase hex string, or null. */
export function normaliseId(raw: string | undefined): string | null {
  const s = (raw ?? "").trim();
  if (!s || s === "-") return null;
  if (/^0x[0-9a-f]{1,16}$/i.test(s))
    return `0x${s
      .slice(2)
      .toLowerCase()
      .replace(/^0+(?=.)/, "")}`;
  if (/^\d{1,20}$/.test(s)) return `0x${BigInt(s).toString(16)}`;
  return null;
}

/** A Windows path for comparison: separators unified, `\\?\` stripped, case-folded. Null when it
 * names a device object or a short (8.3) segment — those are said, never normalised. */
export function normaliseWinPath(raw: string | undefined): { key: string } | { unmappable: string } | null {
  const s = (raw ?? "").trim();
  if (!s) return null;
  const stripped = s.replace(/^\\\\\?\\/, "").replace(/\//g, "\\");
  if (/^\\device\\/i.test(stripped)) return { unmappable: "device path" };
  if (/~\d+(\\|$)/.test(stripped)) return { unmappable: "short (8.3) name" };
  return { key: stripped.toLowerCase().replace(/\\+/g, "\\").replace(/\\$/, "") };
}
