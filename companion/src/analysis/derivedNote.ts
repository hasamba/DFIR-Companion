// One way to append a derived note to an event's description.
//
// A correlation pass that raises an event says why in a trailing "[<name>: <reason>]" note. The base
// text is clipped BEFORE the note goes on, never after: clipping the joined string let a long
// description push the note off the end while the severity bump still applied — a raised event
// with no stated reason (#939). Every pass used to clip on its own, with a bare slice, and that
// clip removed the notes EARLIER passes had appended to the same long event — the exfil marker went
// on after character 700, and the next pass's slice(0, 700) took it off again (#939 review).
//
// So: split the description at the first registered note, clip only the base, keep every existing
// note intact, append the new one. The registry below is the list of names; a note whose name is
// not here is base text to the clip, and a later pass removes it. tests/analysis/derivedNote.test.ts
// reads every *_MARKER constant under src/analysis and fails when one is missing from this list.

export const DESCRIPTION_BASE_MAX = 700;

export const DERIVED_NOTE_NAMES: readonly string[] = [
  "confirmed exfiltration",
  "initial access",
  "unexpected parent",
  "sacrificial process",
  "timestomp corroboration",
  "ransomware precursors",
  "certutil transfer",
  "metadata credential access",
  "cloud bulk read",
  "noninteractive account browsing",
  "container escape",
];

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// The first registered note, and everything after it. Anchored to a registered NAME so an
// importer's own bracket — "[risk: high]", "[DENIED: …]" — stays base text and is clipped with it.
const FIRST_NOTE = new RegExp(`\\s*\\[(?:${DERIVED_NOTE_NAMES.map(escapeRe).join("|")}):`, "u");

/**
 * The base text and the registered notes, apart. `notes` is "" when no pass has raised the event.
 * Every reader that shortens a description goes through this split, so a note a pass appended is
 * never cut through its middle: the AI prompt renderer (promptDescription.ts, #959) shows the model
 * the reason an event was raised, however long the base text ran.
 */
export function splitDerivedNotes(description: string | undefined): { base: string; notes: string } {
  const text = description ?? "";
  const at = FIRST_NOTE.exec(text)?.index ?? -1;
  if (at < 0) return { base: text, notes: "" };
  return { base: text.slice(0, at), notes: text.slice(at).trim() };
}

/** The description with `<marker> <note>]` appended after a clipped base and every existing note. */
export function appendDerivedNote(
  description: string | undefined,
  marker: string,
  note: string,
  baseMax: number = DESCRIPTION_BASE_MAX,
): string {
  const { base: rawBase, notes: existing } = splitDerivedNotes(description);
  const base = rawBase.slice(0, baseMax).trimEnd();
  return [base, existing, `${marker} ${note.trim()}]`].filter(Boolean).join(" ").trim();
}
