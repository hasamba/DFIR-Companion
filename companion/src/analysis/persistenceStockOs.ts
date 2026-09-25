// Two stock Windows 11 autostarts that PersistenceSniper's own verdict columns misreport (#1665).
// Kept out of persistenceSniperImport.ts so the two bounds read as one unit and stay testable alone.
//
// 1. Store (MSIX) apps. Files under C:\Program Files\WindowsApps\<package>\ are catalog-signed, so a
//    per-file Authenticode check returns NotSigned for Paint, Notepad and Snipping Tool. That is
//    expected for a Store file, not an anomaly. The bound is lexical, and deliberately strict: the
//    WHOLE value must be one path, on C:, directly under the literal Program Files\WindowsApps
//    folder, in a package folder of the documented <Name>_<Version>_<Arch>_<ResourceId>_<PublisherId>
//    shape with Microsoft's publisher ID. Every tail segment is plain filename characters, so there
//    is no room for arguments, a second path, an alternate data stream, a device or UNC prefix,
//    forward slashes, "." / ".." segments or a trailing dot that Windows would strip. WindowsApps is
//    owned by TrustedInstaller; a user-level intruder cannot plant a file there.
//
// 2. OneDrive's per-user tasks. OneDriveStandaloneUpdater.exe is on the LOLBAS list and lives in the
//    user profile, so the module reports IsBuiltinBinary=False and the LOLBin rule fired on the two
//    tasks every Windows 11 profile has. Only the exact stock shape counts: root-folder task name
//    with a domain/local account SID, the updater at its stock path, the argument paired to the task
//    name, and a user-level principal. The caller still escalates on a bad signature or a staged
//    path. Residual risk, accepted in #1665: the artifact carries no resolved signature for the
//    %localappdata% form and no task principal, so a binary swapped in place under the stock task is
//    not caught here.

const MS_PUBLISHER_ID = "8wekyb3d8bbwe";

// <Name>_<Version>_<Arch>_<ResourceId>_<PublisherId>, Microsoft publisher only.
const PACKAGE_FOLDER = `[A-Za-z0-9][A-Za-z0-9.-]{0,49}_\\d{1,5}\\.\\d{1,5}\\.\\d{1,5}\\.\\d{1,5}_(?:x64|x86|arm64|arm|neutral)_[A-Za-z0-9.-]{0,30}_${MS_PUBLISHER_ID}`;
// Plain filename characters only: no whitespace, colon, slash, quote or wildcard.
const SEGMENT = "[A-Za-z0-9_.-]+";

const STORE_APP_RE = new RegExp(
  `^C:\\\\Program Files\\\\WindowsApps\\\\${PACKAGE_FOLDER}(?:\\\\${SEGMENT})*\\\\${SEGMENT}\\.(?:exe|dll)$`,
  "i",
);

/** Drop ONE matching pair of surrounding double quotes; anything else is returned unchanged. */
function unquote(text: string): string {
  return text.length >= 2 && text.startsWith('"') && text.endsWith('"') ? text.slice(1, -1) : text;
}

/** A segment Windows would normalise away or walk out of: ".", "..", or a trailing dot/space. */
function hasUnsafeSegment(path: string): boolean {
  return path.split("\\").some((seg) => seg === "." || seg === ".." || /[. ]$/.test(seg));
}

/** True only for a value that is exactly one executable inside a Microsoft Store package folder. */
export function isMicrosoftStoreAppPath(value: string): boolean {
  const path = unquote(value.trim());
  return STORE_APP_RE.test(path) && !hasUnsafeSegment(path);
}

const ONEDRIVE_TASK_RE =
  /^\\OneDrive (Reporting Task|Standalone Update Task)-S-1-5-21-\d{1,10}-\d{1,10}-\d{1,10}-\d{1,10}$/i;

// The updater at its stock per-user location: the unresolved %localappdata% form, or the resolved
// profile path. The profile name allows spaces (real account names do); hasUnsafeSegment rejects
// "..", "." and a trailing dot or space.
const UPDATER_PATH = `(?:%localappdata%|C:\\\\Users\\\\[A-Za-z0-9._ -]{1,64}\\\\AppData\\\\Local)\\\\Microsoft\\\\OneDrive\\\\OneDriveStandaloneUpdater\\.exe`;
const UPDATER_RE = new RegExp(`^(?:"(${UPDATER_PATH})"|(${UPDATER_PATH}))(?: (/reporting))?$`, "i");

/** The only argument each stock task passes. */
const STOCK_ARG: Record<string, string> = {
  "reporting task": "/reporting",
  "standalone update task": "",
};

export interface PersistenceFields {
  technique: string;
  path: string;
  value: string;
  accessGained: string;
}

/** True only for one of the two stock per-user OneDrive scheduled tasks, exactly as Windows creates it. */
export function isStockOneDriveTask(f: PersistenceFields): boolean {
  if (f.technique.trim().toLowerCase() !== "scheduled task") return false;
  if (f.accessGained.trim().toLowerCase() !== "user") return false;
  const task = ONEDRIVE_TASK_RE.exec(f.path.trim());
  if (!task) return false;
  const action = UPDATER_RE.exec(f.value.trim());
  if (!action) return false;
  if (hasUnsafeSegment(action[1] ?? action[2])) return false;
  return (action[3] ?? "").toLowerCase() === STOCK_ARG[task[1].toLowerCase()];
}
