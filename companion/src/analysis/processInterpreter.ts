// ATT&CK T1059 is "Command and Scripting Interpreter": a shell or script host running commands. A
// process-create event earns it only when the process IS one. The Windows event table used to put it
// on every Sysmon 1 and Security 4688 row, so a case of 5,727 events carried it on 5,467 of them,
// every phase read "Execution", and the MITRE matrix counted taskhostw.exe as scripting.

const INTERPRETERS = new Set([
  "cmd.exe",
  "powershell.exe",
  "powershell_ise.exe",
  "pwsh.exe",
  "wscript.exe",
  "cscript.exe",
  "python.exe",
  "pythonw.exe",
  "py.exe",
  "perl.exe",
  "ruby.exe",
  "php.exe",
  "node.exe",
  "bash.exe",
  "sh.exe",
  "wsl.exe",
]);

/** The last path segment of a Windows or POSIX image path, lowercased. */
function baseName(image: string): string {
  return (image.trim().split(/[\\/]/).pop() ?? "").toLowerCase();
}

/** `["T1059"]` when `image` is a command or scripting interpreter, else no technique. */
export function interpreterTechniques(image: string): string[] {
  return INTERPRETERS.has(baseName(image)) ? ["T1059"] : [];
}
