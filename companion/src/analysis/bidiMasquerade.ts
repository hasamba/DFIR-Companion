// Right-to-left override masquerading (MITRE T1036.002, #2027).
//
// APT29's Day 1 payload is `C:\ProgramData\victim\<U+202E>cod.3aka3.scr`: the RLO makes Explorer
// draw the name backwards from that point, so the victim sees `rcs.3aka3.doc` — a Word document —
// and double-clicks a screensaver executable. No legitimate program names itself or a file it
// writes with a bidi control, so a process image, parent image, command line or created/target file
// name that carries one is graded High and tagged T1036.002, with a note naming the trick and
// showing what the analyst's victim saw.
//
// Applied per row at the shared aggregation seam (eventAggregate.ts), so every importer that maps
// into a MappedEvent — the SIEM/NXLog/EVTX-JSON path, Chainsaw, Hayabusa, Velociraptor, KAPE — is
// covered by the one rule. The same pass escapes the character in the row's description and raw
// message, whether or not the row is graded: a raw U+202E reverses the text around it in the
// dashboard and in every export.

import type { MappedEvent } from "./siemImport.js";
import { SEVERITY_RANK } from "./stateTypes.js";
import { appendDerivedNote } from "./derivedNote.js";
import {
  bidiControlsIn,
  bidiVisual,
  escapeBidiControls,
  hasBidiControl,
  normalizeBidiMojibake,
} from "./bidiControl.js";

export const BIDI_MASQUERADE_MARKER = "[bidi masquerade:";
export const BIDI_MASQUERADE_TECHNIQUE = "T1036.002";

const TOKEN_EDGE = /["'\s\\/]/;

/** The file-name token around the first bidi control in `value` (decoded), or "" when there is none. */
export function bidiNameToken(value: string): string {
  const s = normalizeBidiMojibake(value);
  const at = s.search(/[\u202a-\u202e\u2066-\u2069]/);
  if (at < 0) return "";
  let start = at;
  while (start > 0 && !TOKEN_EDGE.test(s[start - 1])) start--;
  let end = at + 1;
  while (end < s.length && !TOKEN_EDGE.test(s[end])) end++;
  return s.slice(start, end);
}

// The disguise matters where it is created and where it is run: the file write, the launch (image
// and command line), and the launch's children (parent image). A row that only records what the
// disguised process DID afterwards — its DLL loads, connections, registry writes, a handle opened
// on it — names it as its image too; graded High, the payload's 60-odd image loads in the APT29
// set would bury the launch. Those rows are still escaped, never graded. A row whose importer
// carries no envelope cannot say which it is, so its own name counts.
function launchOrWrite(m: MappedEvent): boolean {
  const ev = m.canonical?.event;
  if (!ev) return true;
  return ev.category === "file" || (ev.category === "process" && ev.type === "start");
}

// The name-bearing fields, most specific first: the row's own file/image, then the process, its
// parent, then its command line. A command line or parent image is carried by launches only.
function maskedName(m: MappedEvent): string {
  const own = launchOrWrite(m) ? [m.path, m.processName] : [];
  for (const v of [...own, m.parentName, m.commandLine]) {
    if (v && hasBidiControl(v)) return bidiNameToken(v);
  }
  return "";
}

/** The note for a disguised name: which trick, and how the name is drawn on screen. */
export function bidiMasqueradeNote(name: string): string {
  const controls = bidiControlsIn(name);
  const trick = controls.includes("RLO")
    ? "right-to-left override"
    : `bidi control ${controls.map((c) => `<${c}>`).join(" ")}`;
  const shown = bidiVisual(name);
  const renders = shown !== name.replace(/[\u202a-\u202e\u2066-\u2069]/g, "") ? ` displays as ${shown}` : "";
  return `${trick} in a file name — ${escapeBidiControls(name)}${renders} (T1036.002)`;
}

/** Escape bidi controls in the row's text and grade a disguised name. Mutates `m`; idempotent. */
export function annotateBidiMasquerade(m: MappedEvent): void {
  if (hasBidiControl(m.description)) m.description = escapeBidiControls(m.description);
  if (m.message && hasBidiControl(m.message)) m.message = escapeBidiControls(m.message);
  const name = maskedName(m);
  if (!name) return;
  if (SEVERITY_RANK.High < SEVERITY_RANK[m.severity]) m.severity = "High";
  if (!m.mitre.includes(BIDI_MASQUERADE_TECHNIQUE)) m.mitre = [...m.mitre, BIDI_MASQUERADE_TECHNIQUE];
  if (!m.description.includes(BIDI_MASQUERADE_MARKER))
    m.description = appendDerivedNote(m.description, BIDI_MASQUERADE_MARKER, bidiMasqueradeNote(name));
}
