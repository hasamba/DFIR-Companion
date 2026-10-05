// Echo-only commands (#1948). A lab run of scenario 021 had process rows where a renamed copy of
// cmd.exe ran only `cmd /c echo <marker>`. The command prints text and does nothing else, yet Sigma
// graded the rows High ("Impacket tools execution", "binary rename") and High findings cited them.
// This module says when a row is such a command, and when a finding rests on nothing else; the cap
// itself is applied in findingGrounding.ts. Row severity is never changed.
//
// The rule keys on the command SHAPE only, never on marker text, and it is narrow on purpose
// (triage of #1948):
//   - cmd expands `%VAR%` (and `!VAR!`) BEFORE it parses operators, so `cmd /c echo %X%` runs
//     whatever X holds. `%` and `!` disqualify, as do every operator and escape: `& | < > ^ ( )`
//     and a newline. Only `/c`: `/k` leaves a shell open.
//   - The first word of a command line is adversary-chosen text. `cmd` / `cmd.exe` is accepted as
//     it stands; any other first word only when the row itself says the file is cmd.exe — its image
//     field, or a TRUSTED rename note (renamedBinaryNote.ts).

import { isFileTraceOf, isTrustedRenameRow, parseRenamedBinaryNote } from "./renamedBinaryNote.js";
import type { ForensicEvent } from "./stateTypes.js";

const CMD = "cmd.exe";
// Every character that lets text after `echo` do more than print.
const UNSAFE = /[%!&|<>^()\u0000-\u001f]/u;
// argv0 (quoted or bare), optional harmless switches, `/c`, then `echo` and its text.
const SHAPE = /^\s*("[^"]+"|\S+)\s+(?:\/[qdau]\s+)*\/c\s+echo(?:\s+(.*))?$/isu;

const leaf = (p: string): string =>
  (
    p
      .replace(/^"|"$/gu, "")
      .replace(/[/\\]+$/u, "")
      .split(/[/\\]/u)
      .pop() ?? p
  ).toLowerCase();
const asExe = (name: string): string => (name.endsWith(".exe") ? name : `${name}.exe`);

/** The on-disk name of a trusted renamed copy of cmd.exe, or null. */
function renamedCmdOf(e: ForensicEvent): string | null {
  const note = parseRenamedBinaryNote(e.description);
  if (!note || !isTrustedRenameRow(e)) return null;
  return leaf(note.original) === CMD ? leaf(note.onDisk) : null;
}

/** Whether the row says the file that ran is cmd.exe, apart from its command line. */
function rowIdentifiesCmd(e: ForensicEvent): boolean {
  return (!!e.processName && leaf(e.processName) === CMD) || !!renamedCmdOf(e);
}

/** A process row whose whole command is `cmd /c echo …`: it prints text and does nothing else. */
export function isEchoOnlyCommand(e: ForensicEvent): boolean {
  const cl = e.commandLine;
  if (!cl || UNSAFE.test(cl)) return false;
  const m = SHAPE.exec(cl);
  if (!m) return false;
  const argv0 = leaf(m[1]);
  return argv0 === "cmd" || argv0 === CMD || rowIdentifiesCmd(e);
}

/** The file names an echo row may have on disk: what a presence trace of the same file is named. */
function fileLeaves(e: ForensicEvent): string[] {
  const out = [CMD];
  if (e.processName) out.push(leaf(e.processName));
  const argv0 = SHAPE.exec(e.commandLine ?? "")?.[1];
  if (argv0) out.push(asExe(leaf(argv0)));
  const renamed = renamedCmdOf(e);
  if (renamed) out.push(renamed);
  return out;
}

export interface EchoOnlyEvidence {
  rows: number; // the echo-only process rows cited
  renamed: string[]; // on-disk names of trusted renamed copies of cmd.exe — the rename is real
}

/**
 * Non-null when EVERY cited row is an echo-only process row or a file-presence trace (MFT, Amcache,
 * Prefetch, …) of the same file. Any other row — network, a file write, another command — returns
 * null and the finding keeps its grade. Same precedent as decoyOnlyEvidence (#1502).
 */
export function echoOnlyEvidence(supporting: readonly ForensicEvent[]): EchoOnlyEvidence | null {
  const echoes = supporting.filter(isEchoOnlyCommand);
  if (echoes.length === 0) return null;
  const leaves = new Set(echoes.flatMap(fileLeaves));
  const echoIds = new Set(echoes.map((e) => e.id));
  for (const e of supporting) {
    if (echoIds.has(e.id)) continue;
    if (!isFileTraceOf(e, leaves)) return null;
  }
  const renamed = [...new Set(echoes.map(renamedCmdOf).filter((n): n is string => !!n))];
  return { rows: echoes.length, renamed };
}

/** The reason text a capped finding carries. */
export function echoOnlyReason(evidence: EchoOnlyEvidence): string {
  const rename = evidence.renamed.length
    ? `; ${evidence.renamed.join(", ")} is a renamed cmd.exe — the rename is real, but the command did nothing`
    : "";
  return `capped: echo only, no effect — every cited process row runs only \`cmd /c echo …\`, which prints text and does nothing else${rename}`;
}
