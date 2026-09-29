// Windows folder permissions for the team-mode MCP delivery check (#1863).
//
// On POSIX, mcpDelivery.ts reads mode bits to prove that no other user can write the cases root or the
// `.mcp-delivery` folder. Mode bits say nothing on Windows, so this module reads the folders' ACLs.
// Everything is by SID, never by account name, so a localized Windows ("Jeder", "Tout le monde") gives
// the same answer.
//
// SCOPE, stated rather than discovered: only the five broad principals below are judged. A named user
// or a custom group with write access is not refused — on a domain file server an analyst group with
// write access is normal. Deny entries are ignored, so an Allow that a Deny cancels still refuses:
// that errs toward refusing a delivery, never toward handing over a copy another user could swap.

/**
 * Spawns a binary with discrete argv, no shell, and a timeout — the shape of mcpDelivery's
 * TransferRunner, restated here so this module imports nothing from its caller.
 */
export type AclRunner = (
  binary: string,
  args: string[],
  opts: { timeoutMs: number },
) => Promise<{ stdout: string; stderr: string; code: number }>;

/** One access-control entry, read by SID. `rights` is the FileSystemRights mask, unsigned. */
export interface AclEntry {
  sid: string;
  rights: number;
  allow: boolean;
}

/** The permissions of one folder. `nullDacl`: no access list at all, which grants everyone everything. */
export interface AclRecord {
  path: string;
  owner: string;
  nullDacl: boolean;
  entries: AclEntry[];
}

/** Principals that mean "other users". Well-known SIDs, the same on every Windows in every language. */
export const BROAD_SIDS: Readonly<Record<string, string>> = {
  "S-1-1-0": "Everyone",
  "S-1-5-11": "Authenticated Users",
  "S-1-5-32-545": "Users",
  "S-1-5-7": "Anonymous",
  "S-1-5-32-546": "Guests",
};

/**
 * Every right that lets a holder change the folder or what is in it: WriteData/CreateFiles 0x2,
 * AppendData/CreateDirectories 0x4, WriteExtendedAttributes 0x10, DeleteSubdirectoriesAndFiles 0x40,
 * WriteAttributes 0x100, Delete 0x10000, ChangePermissions 0x40000, TakeOwnership 0x80000,
 * GENERIC_ALL 0x10000000, GENERIC_WRITE 0x40000000. The FullControl, Modify and Write composites all
 * contain some of these; ReadAndExecute (0x200A9) and GENERIC_READ contain none.
 */
export const WRITE_RIGHTS_MASK = 0x500d0156;

/** The time PowerShell gets to start and read two ACLs. A cold start on a busy host takes seconds. */
export const ACL_READ_TIMEOUT_MS = 30_000;

const SID_RE = /^S-1-\d+(-\d+)*$/;

/** Why other users can write this folder, or undefined when none of the broad principals can. */
export function aclProblem(record: AclRecord): string | undefined {
  if (record.nullDacl) return "it has no access list, so everyone has full access";
  const ownerName = BROAD_SIDS[record.owner];
  if (ownerName) return `${ownerName} owns it`;
  const writers = record.entries
    .filter((e) => e.allow && BROAD_SIDS[e.sid] && (e.rights & WRITE_RIGHTS_MASK) !== 0)
    .map((e) => BROAD_SIDS[e.sid]);
  if (writers.length === 0) return undefined;
  return `${[...new Set(writers)].join(", ")} can write it`;
}

/** A PowerShell single-quoted literal. PowerShell treats the three typographic single quotes as quotes too. */
export function psLiteral(value: string): string {
  return `'${value.replace(/['‘’‚‛]/g, (q) => q + q)}'`;
}

/**
 * The script. Errors are terminating, so a failed read stops it with a non-zero exit instead of
 * printing a partial answer. Rules come back as SecurityIdentifier, so no name is ever translated.
 *
 * PURE .NET, NO CMDLETS BEYOND THE ENGINE. Get-Acl, New-Object and ConvertTo-Json live in modules
 * PowerShell autoloads, and autoload fails when the Companion inherits a PowerShell 7 PSModulePath:
 * Windows PowerShell then reports "Get-Acl was found in the module Microsoft.PowerShell.Security, but
 * the module could not be loaded" — first seen on the Windows CI runner, and exactly what an analyst
 * who starts the Companion from pwsh would hit. DirectorySecurity reads the same descriptor, and the
 * JSON is built by hand: every value is a SID, an integer, a boolean, or the index of a requested
 * path, so nothing needs escaping.
 */
function aclScript(paths: string[]): string {
  return [
    "$ErrorActionPreference = 'Stop'",
    "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)",
    "$sidType = [System.Security.Principal.SecurityIdentifier]",
    "$ac = [System.Security.AccessControl.AccessControlSections]",
    "$sections = $ac::Access -bor $ac::Owner",
    `$paths = @(${paths.map(psLiteral).join(",")})`,
    "$recs = [System.Collections.Generic.List[string]]::new()",
    "for ($i = 0; $i -lt $paths.Count; $i++) {",
    "  $acl = [System.Security.AccessControl.DirectorySecurity]::new($paths[$i], $sections)",
    "  $rules = [System.Collections.Generic.List[string]]::new()",
    "  foreach ($x in $acl.GetAccessRules($true, $true, $sidType)) {",
    "    $rules.Add('{\"s\":\"' + $x.IdentityReference.Value + '\",\"r\":' + [int]$x.FileSystemRights + ',\"t\":' + [int]$x.AccessControlType + '}')",
    "  }",
    "  $n = [bool]($acl.GetSecurityDescriptorSddlForm($ac::Access) -match 'D:NO_ACCESS_CONTROL')",
    "  $recs.Add('{\"p\":' + $i + ',\"o\":\"' + $acl.GetOwner($sidType).Value + '\",\"n\":' + $n.ToString().ToLowerInvariant() + ',\"a\":[' + ($rules -join ',') + ']}')",
    "}",
    "[Console]::Out.Write('[' + ($recs -join ',') + ']')",
  ].join("\n");
}

function fail(why: string): never {
  throw new Error(`unexpected ACL output: ${why}`);
}

function parseEntry(raw: unknown): AclEntry {
  const e = raw as { s?: unknown; r?: unknown; t?: unknown };
  if (typeof e?.s !== "string" || !SID_RE.test(e.s)) fail("an entry without a SID");
  const r = e.r;
  if (typeof r !== "number" || !Number.isInteger(r) || r < -(2 ** 31) || r >= 2 ** 32) fail("bad rights");
  if (e.t !== 0 && e.t !== 1) fail("an entry that is neither allow nor deny");
  return { sid: e.s, rights: r >>> 0, allow: e.t === 0 };
}

// `p` is the index of the requested path; the script never echoes the path text itself.
function parseRecord(raw: unknown, paths: string[]): AclRecord {
  const r = raw as { p?: unknown; o?: unknown; n?: unknown; a?: unknown };
  if (typeof r?.p !== "number" || !Number.isInteger(r.p)) fail("a record without a path index");
  const path = paths[r.p];
  if (path === undefined) fail(`a path that was not asked for: index ${r.p}`);
  if (typeof r.o !== "string" || !SID_RE.test(r.o)) fail(`no owner for ${path}`);
  if (typeof r.n !== "boolean") fail(`no access-list flag for ${path}`);
  if (!Array.isArray(r.a)) fail(`no entries for ${path}`);
  return { path, owner: r.o, nullDacl: r.n, entries: r.a.map(parseEntry) };
}

/** Strict: exactly one record for every requested path, no duplicates, no extras. Throws otherwise. */
export function parseAclOutput(stdout: string, paths: string[]): Map<string, AclRecord> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    fail("not JSON");
  }
  if (!Array.isArray(parsed)) fail("not a list");
  const records = new Map<string, AclRecord>();
  for (const record of parsed.map((raw) => parseRecord(raw, paths))) {
    if (records.has(record.path)) fail(`${record.path} twice`);
    records.set(record.path, record);
  }
  for (const p of paths) if (!records.has(p)) fail(`nothing for ${p}`);
  return records;
}

/**
 * Reads the ACLs of `paths` with ONE powershell.exe run: no shell, no profile, non-interactive, the
 * script base64-encoded as UTF-16LE so no argv quoting is involved, and the runner's timeout. Throws
 * on anything but a complete answer; the caller fails closed.
 */
export async function readWindowsAcls(
  paths: string[],
  runner: AclRunner,
  timeoutMs: number = ACL_READ_TIMEOUT_MS,
): Promise<Map<string, AclRecord>> {
  const encoded = Buffer.from(aclScript(paths), "utf16le").toString("base64");
  const args = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded];
  const result = await runner("powershell.exe", args, { timeoutMs });
  if (result.code !== 0) {
    throw new Error(`powershell.exe exited ${result.code}: ${result.stderr.trim().slice(0, 500)}`);
  }
  return parseAclOutput(result.stdout, paths);
}
