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
// The wider base cap for passes that run on every merged event and read the description as a command
// line (jndiInjection, containerEscape): it must cover the widest description an importer emits.
export const WIDE_DESCRIPTION_BASE_MAX = 1600;
// Every base cap a timeline pass passes to appendDerivedNote MUST be one of these. eventRevision clips
// a re-imported raw text at each of them to recognise a restatement of a clipped base; a pass clipping
// at any other cap makes a plain re-import write a false revision entry (#2186). derivedNote.test.ts
// fails when a pass under src/analysis passes a cap that is not one of these shared constants.
export const DERIVED_NOTE_BASE_CLIPS: readonly number[] = [DESCRIPTION_BASE_MAX, WIDE_DESCRIPTION_BASE_MAX];

export const DERIVED_NOTE_NAMES: readonly string[] = [
  "confirmed exfiltration",
  "initial access",
  "unexpected parent",
  "sacrificial process",
  "timestomp corroboration",
  "ransomware precursors",
  "ransomware precursor",
  "BEC pairing",
  "certutil transfer",
  "metadata credential access",
  "cloud bulk read",
  "noninteractive account browsing",
  "container escape",
  "jndi injection",
  "download-marked file executed",
  "ran a download-marked file",
  "stream referenced by a command line",
  "command line references a stream",
  "injection sequence",
  "hollowing sequence",
  "after Defender",
  "persistence executed",
  "infection window",
  "app corroboration",
  "smb-staged file executed",
  "ran a share-staged file",
  "service/task creation after a pipe call",
  "preceded by a service-control pipe call",
  "flow resource attribution",
  "flow identity/execution",
  "flow sensitive-data",
  "downloaded from a visited page",
  "referrer page visited",
  "preceded a download mark",
  "matches a download mark",
  "sandbox verdict",
  "download record",
  "persisted as",
  "origin page visited",
  "download URL visited",
  "preceded a quarantine record",
  "ran a quarantine-marked file",
  "quarantine-marked file used",
  "a quarantine-marked file",
  "renamed binary",
  "build-time",
  "shared source mtime",
  "inherited modified time",
  "CLR usage log",
  "own-child handle",
  "normal OS behaviour",
  "transfer tool staged",
  "attack tool store",
  "lab-setup",
  "look-alike account",
  "bidi masquerade",
];

/**
 * The subset of the names above whose pass LOWERS a grade rather than raising one (#1535).
 *
 * The super-timeline's cap evicts a row that a named rule deliberately graded Info AFTER ordinary
 * bulk Info telemetry (analysis/setAsideRows.ts), and this is how a pass that states its reason
 * through the shared helper qualifies without the store learning its name. If you are adding a
 * `*_MARKER` above and your pass lowers a severity, add the name here too.
 */
export const DERIVED_NOTE_DOWNGRADES: readonly string[] = [
  "build-time",
  "own-child handle",
  "normal OS behaviour",
  "lab-setup",
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

/**
 * The description with `<marker> <note>]` appended after a clipped base and every existing note.
 * The note body is neutralised (#2574): a body quotes attacker-chosen names (a renamed file, a
 * look-alike account, a bulk-read object), and one holding note syntax must not open a second note.
 */
export function appendDerivedNote(
  description: string | undefined,
  marker: string,
  note: string,
  baseMax: number = DESCRIPTION_BASE_MAX,
): string {
  const { base: rawBase, notes: existing } = splitDerivedNotes(description);
  const base = rawBase.slice(0, baseMax).trimEnd();
  const body = neutraliseForgedNotes(note.trim());
  return [base, existing, `${marker} ${body}]`].filter(Boolean).join(" ").trim();
}

// ── Forged notes (#2574) ──────────────────────────────────────────────────────────────────────────
// Importers write attacker-chosen names into descriptions. A name holding "[look-alike account: …]"
// read exactly like a product note, split the description there (splitDerivedNotes), and — worse —
// tripped the passes that skip a row already carrying their marker, so the REAL note and its raise
// never landed. Every importer row is neutralised once, at the aggregator seam (eventAggregate.ts),
// before any pass can note it; a writer that notes a row before aggregation neutralises it first
// (appendRowNote). Only note-shaped brackets are touched, so "[FAILED]", "[risk: high]",
// "[System.Convert]" and "file[1].exe" stay byte-identical — no eventRevision noise on re-import.

/** The pair a forged note's brackets become: visibly not a note, one BMP unit each, NFKC-stable. */
export const FORGED_NOTE_OPEN = "\u27E6";
export const FORGED_NOTE_CLOSE = "\u27E7";

// The two BEC-pairing tails m365BecPairing.ts appends without a registered name.
const UNREGISTERED_NOTE_OPENERS = [
  "hides mail\\s*;",
  "[^\\[\\]]{0,200}?granted to a user created within 24 hours",
];
const FORGED_OPENER = new RegExp(
  `\\[(?=\\s*(?:(?:${DERIVED_NOTE_NAMES.map(escapeRe).join("|")})\\s*:|${UNREGISTERED_NOTE_OPENERS.join("|")}))`,
  "giu",
);

/**
 * `text` with every note-shaped bracket pair rewritten to ⟦ ⟧ — nested ones too, so
 * "[renamed binary: [look-alike account: x]]" leaves no opener behind. Idempotent; unchanged when
 * there is none. Each rewritten opener takes the first `]` after it that no earlier opener took.
 */
export function neutraliseForgedNotes(text: string): string {
  FORGED_OPENER.lastIndex = 0;
  if (!FORGED_OPENER.test(text)) return text;
  const chars = text.split(""); // UTF-16 units, the same indices indexOf and exec report
  const taken = new Set<number>();
  FORGED_OPENER.lastIndex = 0;
  for (let m = FORGED_OPENER.exec(text); m; m = FORGED_OPENER.exec(text)) {
    chars[m.index] = FORGED_NOTE_OPEN;
    let close = text.indexOf("]", m.index + 1);
    while (close >= 0 && taken.has(close)) close = text.indexOf("]", close + 1);
    if (close >= 0) {
      taken.add(close);
      chars[close] = FORGED_NOTE_CLOSE;
    }
  }
  return chars.join("");
}

// Set ONLY by neutraliseRowNotes, so no writer can claim a row is clean without cleaning it. Object
// spread copies symbol keys, so a `{ ...row }` keeps it; JSON drops it, so it never persists.
const NEUTRALISED = Symbol("derivedNote.neutralised");
type NoteRow = { description: string; [NEUTRALISED]?: true };

/** Neutralise a row's description once, in place (rows are mutated at the import seam), and mark it. */
export function neutraliseRowNotes<T extends { description: string }>(row: T): T {
  const r = row as T & NoteRow;
  if (r[NEUTRALISED]) return row;
  r.description = neutraliseForgedNotes(r.description);
  r[NEUTRALISED] = true;
  return row;
}

/** Carry the mark to a row built from a marked one (the aggregator's output event). */
export function carryNoteMark(from: object, to: object): void {
  if ((from as NoteRow)[NEUTRALISED]) (to as NoteRow)[NEUTRALISED] = true;
}

/** For a writer that notes an importer row BEFORE aggregation: neutralise the row, then append. */
export function appendRowNote(
  row: { description: string },
  marker: string,
  note: string,
  baseMax: number = DESCRIPTION_BASE_MAX,
): string {
  return appendDerivedNote(neutraliseRowNotes(row).description, marker, note, baseMax);
}
