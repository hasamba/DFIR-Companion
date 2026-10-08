// ATT&CK T1059 is "Command and Scripting Interpreter": a shell or script host running commands. A
// process-create event earns it only when the process IS one. The Windows event table used to put it
// on every Sysmon 1 and Security 4688 row, so a case of 5,727 events carried it on 5,467 of them,
// every phase read "Execution", and the MITRE matrix counted taskhostw.exe as scripting.

// Compared without a trailing ".exe", so one list serves Windows and Linux images.
const INTERPRETERS = new Set([
  "cmd",
  "powershell",
  "powershell_ise",
  "pwsh",
  "wscript",
  "cscript",
  "py",
  "perl",
  "ruby",
  "php",
  "node",
  "nodejs",
  "bash",
  "sh",
  "dash",
  "zsh",
  "ksh",
  "csh",
  "tcsh",
  "fish",
  "wsl",
]);

// python, pythonw, python3, python3.11 — any version suffix.
const PYTHON = /^python[0-9.]*w?$/;

/** The last path segment of a Windows or POSIX image path, lowercased, without ".exe". */
function baseName(image: string): string {
  return (image.trim().split(/[\\/]/).pop() ?? "").toLowerCase().replace(/\.exe$/, "");
}

/** `["T1059"]` when `image` is a command or scripting interpreter, else no technique. */
export function interpreterTechniques(image: string): string[] {
  const name = baseName(image);
  return INTERPRETERS.has(name) || PYTHON.test(name) ? ["T1059"] : [];
}
