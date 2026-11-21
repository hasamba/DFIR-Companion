/**
 * Windows known-folder GUID prefixes (#2750). UserAssist records a program under a known folder as
 * `{KNOWNFOLDERID}\rest`, e.g. `{6D809377-6AF0-444B-8957-A3773F02200E}\Foo\foo.exe` for
 * `C:\Program Files\Foo\foo.exe`, where Prefetch and Amcache name the folder itself. To make the same
 * program one hunt item, a LEADING known-folder GUID segment is replaced by its folder in the form the
 * other artifacts reduce to (volume dropped, lower-case, per-user folders under `\users\*`). PURE.
 *
 * GUIDs and default paths: Microsoft's KNOWNFOLDERID reference (Knownfolders.h). Left out on purpose:
 * FOLDERID_ProgramFiles / FOLDERID_ProgramFilesCommon, whose path depends on the bitness of the process
 * that resolved them. The x86 folders are mapped as they resolve on 64-bit Windows, the case for any
 * current endpoint. An unknown GUID is left exactly as it is, so it never merges into a wrong item.
 */
const KNOWN_FOLDERS: Readonly<Record<string, string>> = {
  "6d809377-6af0-444b-8957-a3773f02200e": "\\program files", // ProgramFilesX64
  "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e": "\\program files (x86)", // ProgramFilesX86
  "6365d5a7-0f0d-45e5-87f6-0da56b6a4f7d": "\\program files\\common files", // ProgramFilesCommonX64
  "de974d24-d9c6-4d3e-bf91-f4455120b917": "\\program files (x86)\\common files", // ProgramFilesCommonX86
  "f38bf404-1d43-42f2-9305-67de0b28fc23": "\\windows", // Windows
  "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7": "\\windows\\system32", // System
  "d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27": "\\windows\\syswow64", // SystemX86
  "62ab5d82-fdc1-4dc3-a9dd-070d1d495d97": "\\programdata", // ProgramData
  "5e6c858f-0e22-4760-9afe-ea3317b67173": "\\users\\*", // Profile
  "f1b32785-6fba-4fcf-9d55-7b8e7f157091": "\\users\\*\\appdata\\local", // LocalAppData
  "a520a1a4-1780-4ff6-bd18-167343c5af16": "\\users\\*\\appdata\\locallow", // LocalAppDataLow
  "3eb685db-65f9-4cf6-a03a-e3ef65729f3d": "\\users\\*\\appdata\\roaming", // RoamingAppData
  "5cd7aee2-2219-4a67-b85d-6c9ce15660cb": "\\users\\*\\appdata\\local\\programs", // UserProgramFiles
  "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "\\users\\*\\desktop", // Desktop
  "374de290-123f-4565-9164-39c4925e467b": "\\users\\*\\downloads", // Downloads
  "fdd39ad0-238f-46af-adb4-6c85480369c7": "\\users\\*\\documents", // Documents
};

/** `{guid}` as the whole first segment (an optional leading `\` allowed). */
const LEADING_GUID = /^\\?\{([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}(?=\\|$)/i;

/** The path with a leading known-folder GUID replaced by its folder; any other path unchanged. */
export function expandKnownFolder(path: string): string {
  const m = LEADING_GUID.exec(path);
  if (!m) return path;
  const folder = KNOWN_FOLDERS[m[1].toLowerCase()];
  return folder ? folder + path.slice(m[0].length) : path;
}
