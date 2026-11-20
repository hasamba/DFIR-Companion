/**
 * The threat-hunt target of an autorun command (#2748, the user's decision "Program; script for
 * LOLBins"). PURE. A startup item or scheduled task is counted by the program it runs, so two hosts
 * running the same binary from differently named tasks are one item — except when the program is a
 * script host or a built-in Windows tool. Every such task on a fleet runs the same powershell.exe or
 * regsvr32.exe, so keying on it would fold a rare malicious task into one common item. Those are keyed
 * on the script or DLL they run instead. When that cannot be told reliably (an encoded command, a URL,
 * a nested tool, nothing at all), there is NO target and the caller keys the item on the entry name.
 * Over-merging hides a rare entry; under-merging only adds noise — so every doubt gives no target.
 */

/** Script hosts and built-in tools: an autorun running one is keyed on what it runs, never on the tool. */
export const SCRIPT_HOST_TOOLS: ReadonlySet<string> = new Set([
  "powershell.exe",
  "powershell_ise.exe",
  "pwsh.exe",
  "cmd.exe",
  "wscript.exe",
  "cscript.exe",
  "mshta.exe",
  "regsvr32.exe",
  "rundll32.exe",
  "msiexec.exe",
  "hh.exe",
  "installutil.exe",
  "regasm.exe",
  "regsvcs.exe",
  "msbuild.exe",
  "odbcconf.exe",
  "forfiles.exe",
  "conhost.exe",
  "explorer.exe",
  "wsl.exe",
  "bash.exe",
]);

const RUNNABLE_EXT = "exe|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|msi|dll|ocx|cpl|scr|sct|lnk|bin";
const UNQUOTED_PROGRAM = new RegExp(`^(.+?\\.(?:${RUNNABLE_EXT}))(?=[\\s,]|$)`, "i");
const BARE_FILE = new RegExp(`^[^\\\\/:*?"<>|\\s]+\\.(?:${RUNNABLE_EXT})$`, "i");
const PATH_START = /^(?:[A-Za-z]:\\|\\\\[^\\]|%[A-Za-z0-9_()]+%\\)/;
const URL_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
const SWITCH_VALUE = /^[-/][A-Za-z]+[:=]/;

// Folders the environment variables in a Run value or task command name. The user folder is a
// placeholder: normalisePathPattern generalises every \users\<name> to \users\* anyway.
const ENV: Record<string, string> = {
  systemroot: "C:\\Windows",
  windir: "C:\\Windows",
  systemdrive: "C:",
  programfiles: "C:\\Program Files",
  "programfiles(x86)": "C:\\Program Files (x86)",
  programw6432: "C:\\Program Files",
  commonprogramfiles: "C:\\Program Files\\Common Files",
  programdata: "C:\\ProgramData",
  allusersprofile: "C:\\ProgramData",
  public: "C:\\Users\\Public",
  userprofile: "C:\\Users\\user",
  appdata: "C:\\Users\\user\\AppData\\Roaming",
  localappdata: "C:\\Users\\user\\AppData\\Local",
  temp: "C:\\Users\\user\\AppData\\Local\\Temp",
  tmp: "C:\\Users\\user\\AppData\\Local\\Temp",
};

/** `%SystemRoot%\x.exe` → `C:\Windows\x.exe`; an unknown variable is left as written. */
export function expandEnv(path: string): string {
  return path.replace(/%([A-Za-z0-9_()]+)%/g, (all, name: string) =>
    Object.hasOwn(ENV, name.toLowerCase()) ? ENV[name.toLowerCase()] : all,
  );
}

const unquote = (v: string): string => v.replace(/^(["'])(.*)\1$/, "$2").trim();

/** Split a Windows command line into the program and the rest, quoted paths with spaces included. */
export function splitCommandLine(commandLine: string): { program: string; rest: string } {
  const s = commandLine.trim();
  const q = s[0];
  if (q === '"' || q === "'") {
    const end = s.indexOf(q, 1);
    if (end > 0) return { program: s.slice(1, end).trim(), rest: s.slice(end + 1).trim() };
    return { program: s.slice(1).trim(), rest: "" };
  }
  const m = PATH_START.test(s) ? UNQUOTED_PROGRAM.exec(s) : null; // only a path holds unquoted spaces
  const program = m ? m[1] : (s.split(/\s+/)[0] ?? "");
  return { program, rest: s.slice(program.length).trim() };
}

/** Whitespace-separated arguments; a quoted argument keeps its spaces. */
function tokens(args: string): string[] {
  return (args.match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map(unquote).filter(Boolean);
}

const fileName = (p: string): string => (p.replace(/\//g, "\\").split("\\").pop() ?? "").toLowerCase();

/** `regsvr32` → `regsvr32.exe`: a tool is often named without its extension. */
const toolName = (p: string): string => {
  const n = fileName(p);
  return n.includes(".") ? n : `${n}.exe`;
};

/** The script, DLL or file a script host / built-in tool runs, or undefined when it is not clear. */
function scriptTarget(args: string): string | undefined {
  const list = tokens(args).map((t) => t.replace(SWITCH_VALUE, "").trim());
  if (list.some((t) => URL_RE.test(t))) return undefined;
  // A path may hold unquoted spaces: read it from its first token on, up to its extension.
  const at = list.findIndex((t) => PATH_START.test(t));
  const pick = at >= 0 ? list.slice(at).join(" ") : list.find((t) => BARE_FILE.test(t.replace(/,.*$/, "")));
  if (!pick) return undefined;
  const target = expandEnv(splitCommandLine(pick).program.replace(/,.*$/, "")).trim();
  return target && !SCRIPT_HOST_TOOLS.has(toolName(target)) ? target : undefined;
}

/**
 * The hunt target of an autorun: the program's full path (as written, environment expanded), or the
 * script / DLL a script host or built-in tool runs. `args` are extra arguments from a separate column
 * (a scheduled task's Arguments). Undefined when there is no reliable target.
 */
export function huntCommandTarget(command: string, args = ""): string | undefined {
  const { program, rest } = splitCommandLine(command);
  if (!program) return undefined;
  if (SCRIPT_HOST_TOOLS.has(toolName(program))) return scriptTarget([rest, args].filter(Boolean).join(" "));
  if (!PATH_START.test(program) && !BARE_FILE.test(program)) return undefined;
  return expandEnv(program);
}
