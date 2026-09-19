// How a Windows event's subject fields are rendered into the 600-char description (#1416).
//
// `renderFields` in siemImport.ts capped EVERY field at 140 chars. A real Sysmon EID 1 command line
// runs 150–250 chars, and the evidence sits in its TAIL: the C2 socket, the `-hashes …@target`, the
// `whoami` after the redirect. The 140-cap kept `"C:\…\AnyDesk.exe" /d /v:off /c echo … --start-ser`
// and dropped `--connect 45.227.254.124:443`, so the AI never saw the indicator the row existed for.
// Two moves fix it without pushing the tail off the 600-char cliff downstream:
//   1. A command line that BEGINS with its Image repeats the field rendered just before it. Drop the
//      path, keep the arguments behind a short marker: `CommandLine=… /d /v:off /c echo …`. The key
//      stays `CommandLine=` so an analyst's search still lands.
//   2. The four command-shaped fields get a wider cap; every other field keeps 140. When the whole
//      subject would still overrun its share of the description, ParentCommandLine gives way first
//      and CommandLine last — the child's arguments are the evidence, the parent's are context.

export const DESCRIPTION_CAP = 600;
export const SUBJECT_FIELD_CAP = 140;
export const COMMAND_FIELD_CAP = 400;
export const SUBJECT_SEP = " - ";
// The marker that stands in for a dropped Image prefix. One glyph, so it costs nothing of the cap.
export const ARGS_MARKER = "…";
// The fewest chars a trimmed command field keeps past its `Key=` — enough to still name the command.
const TRIM_FLOOR = 40;

// Field keys whose value is a command or script, lowercased for the case-insensitive key lookup.
const COMMAND_FIELDS: ReadonlySet<string> = new Set([
  "commandline",
  "parentcommandline",
  "scriptblocktext",
  "payload",
]);
// The field carrying the executable a command line begins with: Sysmon spells it Image, Security
// 4688 spells it NewProcessName; the parent side likewise.
const IMAGE_FIELDS: Readonly<Record<string, readonly string[]>> = {
  commandline: ["Image", "NewProcessName"],
  parentcommandline: ["ParentImage", "ParentProcessName"],
};
// The order fields give way in when the subject overruns its budget. CommandLine is last on purpose.
const TRIM_ORDER = ["parentcommandline", "payload", "scriptblocktext", "commandline"];

export interface SubjectPart {
  key: string;
  text: string; // `Key=value`, already capped
}

export function subjectFieldCap(key: string): number {
  return COMMAND_FIELDS.has(key.toLowerCase()) ? COMMAND_FIELD_CAP : SUBJECT_FIELD_CAP;
}

// Drop the image the command line begins with — quoted or bare, case-insensitive (Windows paths) —
// and keep the arguments behind the marker. A command line that IS the image, or that spells the
// binary differently (`cmd.exe /c …` under Image=C:\Windows\System32\cmd.exe), is returned verbatim:
// nothing repeats, so nothing is dropped.
export function stripImagePrefix(cmd: string, image: string): string {
  const img = image.trim();
  if (!img) return cmd;
  const lower = cmd.toLowerCase();
  const target = img.toLowerCase();
  let end = -1;
  if (lower.startsWith(`"${target}"`)) end = target.length + 2;
  else if (lower.startsWith(target)) end = target.length;
  if (end === -1) return cmd;
  const rest = cmd.slice(end);
  // A bare prefix must end at a token boundary — `…\cmd.exe.bak /x` does not repeat `…\cmd.exe`.
  if (rest && !/^\s/.test(rest)) return cmd;
  const args = rest.trim();
  return args ? `${ARGS_MARKER} ${args}` : cmd;
}

// One rendered subject field. `value` is already one-lined; `lookup` reads a sibling field by name.
export function renderSubjectField(
  key: string,
  value: string,
  lookup: (field: string) => string,
): SubjectPart {
  let v = value;
  for (const f of IMAGE_FIELDS[key.toLowerCase()] ?? []) {
    const image = lookup(f).trim();
    if (image) {
      v = stripImagePrefix(v, image);
      break;
    }
  }
  return { key, text: `${key}=${v.slice(0, subjectFieldCap(key))}` };
}

// The subject's share of the description: whatever the head and the host tail leave of the cap.
export function subjectBudget(head: string, tail: string): number {
  return DESCRIPTION_CAP - head.length - tail.length - SUBJECT_SEP.length;
}

// Join the parts; when the line would exceed `budget`, shorten the fields in TRIM_ORDER, each no
// further than its floor, until it fits. Anything still over is left to the caller's final cap.
export function joinSubjectParts(parts: readonly SubjectPart[], budget?: number): string {
  const texts = parts.map((p) => p.text);
  const length = () =>
    texts.reduce((n, t) => n + t.length, 0) + SUBJECT_SEP.length * Math.max(0, texts.length - 1);
  if (budget !== undefined) {
    for (const key of TRIM_ORDER) {
      const over = length() - budget;
      if (over <= 0) break;
      const i = parts.findIndex((p) => p.key.toLowerCase() === key);
      if (i === -1) continue;
      const floor = `${parts[i].key}=`.length + TRIM_FLOOR;
      const cut = Math.min(over, texts[i].length - floor);
      if (cut <= 0) continue;
      texts[i] = `${texts[i].slice(0, texts[i].length - cut - ARGS_MARKER.length)}${ARGS_MARKER}`;
    }
  }
  return texts.join(SUBJECT_SEP);
}
