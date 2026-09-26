import { isTrustedSystemImage, LOLBINS, SUSP_PATH } from "../winProcessBaseline.js";

/**
 * Ordinary system activity the session-command notes skip, and the relevance order they cap by (#1683).
 *
 * A full-level Hayabusa import grades many ordinary Sysmon process rows Low or Medium, so every Edge,
 * update and task-host process inside an attack session became a "quiet command". The baseline here
 * drops them without dropping the quiet attack commands #1594 exists for:
 *   - A process whose image is a trusted system image (a system path, not a suspicious one) is
 *     ordinary, UNLESS the image is a LOLBin, a discovery/staging binary or a script interpreter.
 *     `net.exe view` in System32 stays: the stock path is not the verdict, the binary is.
 *   - A small exact allowlist of benign (binary, argument) shapes that are LOLBins by name.
 *   - A file write into a stock install location, a PowerShell policy-test script, or a WindowsApps
 *     alias stub written by a system process.
 * A row with no image path is never skipped: there is nothing to judge it on.
 */

/** Notes kept per finding; the rest are counted as "N more". */
export const MAX_SESSION_COMMANDS = 12;

/** Discovery and staging binaries that live in System32 but are tradecraft inside a session. */
export const SESSION_RECON_BINARIES = new Set([
  "whoami.exe",
  "tasklist.exe",
  "taskkill.exe",
  "systeminfo.exe",
  "ipconfig.exe",
  "nltest.exe",
  "netsh.exe",
  "netstat.exe",
  "arp.exe",
  "route.exe",
  "nslookup.exe",
  "ping.exe",
  "hostname.exe",
  "quser.exe",
  "qwinsta.exe",
  "query.exe",
  "subst.exe",
  "dsquery.exe",
  "klist.exe",
  "cmdkey.exe",
  "attrib.exe",
  "icacls.exe",
  "takeown.exe",
  "cipher.exe",
  "fsutil.exe",
  "wbadmin.exe",
  "mountvol.exe",
  "diskshadow.exe",
  "esentutl.exe",
  "ntdsutil.exe",
  "expand.exe",
  "makecab.exe",
  "forfiles.exe",
  "xcopy.exe",
  "robocopy.exe",
  "tar.exe",
  "certreq.exe",
]);

/** Interpreters an attacker brings or renames; never baseline, always ranked first. */
export const SCRIPT_INTERPRETERS = new Set(["python.exe", "pythonw.exe", "py.exe", "wsl.exe", "bash.exe"]);

/** Benign LOLBin invocations, matched on the binary name AND the arguments after the image. */
export const BENIGN_SYSTEM_COMMANDS: readonly { program: string; args: RegExp }[] = [
  { program: "msiexec.exe", args: /^-embedding\b/i }, // the Windows Installer COM server
  { program: "rundll32.exe", args: /\bacproxy\.dll\b/i }, // the autochk proxy task
  { program: "wevtutil.exe", args: /^(?:un)?install-manifest\b/i }, // an update registering its event manifest
];

const DRIVE = String.raw`(?:[a-z]:|\\\\\?\\[a-z]:|\\device\\harddiskvolume\d+)?`;
/** The Windows update agent's own directory (MoUsoCoreWorker, wuaucltcore). */
export const WINDOWS_UPDATE_IMAGE = new RegExp(String.raw`^${DRIVE}\\windows\\uus\\`, "i");
/** A file written here is an install or an update, not a drop an analyst needs listed. */
export const STOCK_WRITE_TARGET = new RegExp(
  String.raw`^${DRIVE}\\(?:program files(?: \(x86\))?|windows\\(?:system32|syswow64)|programdata\\microsoft)\\`,
  "i",
);
/** The per-user app-execution-alias stubs (winget.exe, python3.exe) the Store service writes. */
export const WINDOWSAPPS_STUB_DIR = /\\appdata\\local\\microsoft\\windowsapps\\/i;
/** PowerShell writes and deletes one of these on every start to probe the execution policy. */
export const PS_POLICY_TEST_SCRIPT = /^__PSScriptPolicyTest_[\w.]+\.ps1$/i;
/** Where the OS and installed products live: a row from here ranks after one from a user path. */
const SYSTEM_LOCATION = new RegExp(
  String.raw`^${DRIVE}\\(?:windows|program files(?: \(x86\))?|programdata\\microsoft)\\`,
  "i",
);

function winPath(path: string | undefined): string {
  return (path ?? "").trim().replace(/\//g, "\\");
}

function hasPath(path: string): boolean {
  return path.includes("\\");
}

function nameOf(path: string): string {
  return (path.split("\\").pop() ?? "").toLowerCase();
}

function withExe(name: string): string {
  const n = name.toLowerCase();
  return n.endsWith(".exe") ? n : `${n}.exe`;
}

/** A LOLBin, a discovery/staging binary or a script interpreter: tradecraft wherever it lives. */
export function isToolOfInterest(name: string): boolean {
  const n = withExe(name);
  return LOLBINS.has(n) || SESSION_RECON_BINARIES.has(n) || SCRIPT_INTERPRETERS.has(n);
}

/** The arguments after the image token of a command line. */
function argsOf(commandLine: string): string {
  return commandLine.replace(/^\s*(?:"[^"]*"|\S+)\s*/, "");
}

/** The image path of a process row: its recorded image, else a command line that starts with a path. */
export function processImage(image: string | undefined, commandLine: string): string {
  const recorded = winPath(image);
  if (hasPath(recorded)) return recorded;
  const first = winPath(
    commandLine
      .match(/^\s*(?:"([^"]*)"|(\S+))/)
      ?.slice(1)
      .find(Boolean),
  );
  return hasPath(first) ? first : recorded;
}

/** True when a process row is ordinary system activity. `image` comes from processImage. */
export function isBaselineProcess(image: string, commandLine: string): boolean {
  if (!hasPath(image) || SUSP_PATH.test(image)) return false;
  const name = nameOf(image);
  const trusted = isTrustedSystemImage(image);
  const args = argsOf(commandLine);
  if (trusted && BENIGN_SYSTEM_COMMANDS.some((s) => s.program === name && s.args.test(args))) return true;
  if (isToolOfInterest(name)) return false;
  return trusted || WINDOWS_UPDATE_IMAGE.test(image);
}

/** True when a script/binary file write is ordinary: a stock install target, or a known OS side effect. */
export function isBaselineWrite(target: string, writerImage: string | undefined): boolean {
  const path = winPath(target);
  if (PS_POLICY_TEST_SCRIPT.test(nameOf(path))) return true;
  if (STOCK_WRITE_TARGET.test(path)) return true;
  const writer = winPath(writerImage);
  return (
    WINDOWSAPPS_STUB_DIR.test(path) &&
    hasPath(writer) &&
    isTrustedSystemImage(writer) &&
    !isToolOfInterest(nameOf(writer))
  );
}

/**
 * Cap order, lowest first:
 *   0 — a row from a user or other non-system location (the kit, a renamed interpreter), a script
 *       interpreter anywhere, or a row with no path to judge;
 *   1 — a LOLBin or discovery binary from a system location, or a write into a system temp folder;
 *   2 — everything else (update payloads and the like under C:\Windows).
 */
export function relevanceRank(
  kind: "process" | "file-write",
  path: string | undefined,
  program: string,
): 0 | 1 | 2 {
  const p = winPath(path);
  const names = kind === "process" ? [program, ...(hasPath(p) ? [nameOf(p)] : [])] : [];
  if (names.some((n) => SCRIPT_INTERPRETERS.has(withExe(n)))) return 0;
  if (!hasPath(p) || !SYSTEM_LOCATION.test(p)) return 0;
  return SUSP_PATH.test(p) || names.some(isToolOfInterest) ? 1 : 2;
}
