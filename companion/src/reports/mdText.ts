import type { Finding } from "../analysis/stateTypes.js";

// One home for "untrusted text → safe Markdown fragment".
//
// Report text — finding titles and descriptions, hypothesis titles and reasons, analyst free-text,
// operator-supplied compliance control titles — is written from evidence the ATTACKER chose:
// filenames, command lines, registry values, service names. reports/html.ts already stops that text
// becoming live markup in the HTML export. These helpers stop it becoming report STRUCTURE: a title
// carrying a newline and "## 5 Conclusion" would otherwise forge a section inside a forensic
// deliverable, and reports/docx.ts classifies headings by their TEXT, so the forged section reaches
// the DOCX outline too. Report integrity is the product here, so structure is never borrowed from
// the data the report is about.

/**
 * Table-cell text. Escapes the pipe (the GFM cell separator) AND neutralizes newlines. A \n or \r
 * inside a GFM table cell ends the row; the text after the newline becomes spurious rows with empty
 * trailing cells, corrupting the table structure. The corrupted Markdown flows to the HTML export
 * (marked parses the broken table) and the DOCX export, producing broken tables in all three
 * deliverables. Newlines reach here from report-meta free-text fields (revisions[].comments,
 * distribution[].name, glossary entries) and from AI-generated descriptions that contain a literal
 * newline (#12).
 */
export function cellMd(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");
}

/**
 * Text interpolated INTO a line that already has a meaning — a heading, a list item, a bold label.
 * A newline would end that line and let the rest of the value start a construct of its own, so the
 * value is flattened onto the one line it was placed on. Nothing is dropped: the reader still sees
 * the whole string, attributed to the finding or hypothesis that carries it.
 */
export function oneLineMd(value: string): string {
  return value.replace(/[\r\n]+/g, " ").trim();
}

/**
 * A block of prose emitted on its own lines. Paragraphs, lists, emphasis and code spans survive —
 * this is the report's body text and it should read as written. What does not survive is anything
 * that opens a SECTION: an ATX heading (`## …`), a setext underline (`===`), or a thematic break
 * (`---`, which is also a setext H2 underline). Those are escaped with a backslash, so the marker
 * renders as the literal characters the author typed instead of restructuring the document.
 */
export function blockMd(value: string): string {
  return value
    .split(/\r?\n/)
    .map((line) =>
      /^ {0,3}(#{1,6}(\s|$)|=+[ \t]*$|-{2,}[ \t]*$)/.test(line) ? line.replace(/^([ \t]*)/, "$1\\") : line,
    )
    .join("\n");
}

/**
 * A finding's "other commands in this session" note (#1594) as Markdown list lines.
 *
 * The command text is attacker-chosen, so each one goes in a code span whose backtick fence is longer
 * than any backtick run inside it (CommonMark), on one line — it can neither open a section nor
 * borrow emphasis or link syntax. Only entries whose row is in the report's projected timeline are
 * shown (scope and false positives already applied). The notes the synthesis capped (#1683) are
 * counted on a last line; the count is a number, never attacker text.
 */
export function sessionCommandsMd(f: Finding, visible: ReadonlyMap<string, unknown>): string[] {
  const shown = (f.sessionCommands ?? []).filter((c) => visible.has(c.eventId));
  if (!shown.length) return [];
  const more = Math.max(0, Math.floor(Number(f.sessionCommandsMore) || 0));
  return [
    "- Other commands in this session (not named above):",
    ...shown.map((c) => {
      const who = c.accounts?.length ? ` (${oneLineMd(c.accounts.join(", "))})` : "";
      return `  - ${oneLineMd(c.timestamp || "(undated)")} on ${codeSpan(c.host)}${who}: ${codeSpan(c.text)}`;
    }),
    ...(more ? [`  - … and ${more} more in the case timeline`] : []),
  ];
}

function codeSpan(value: string): string {
  const text = oneLineMd(value);
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = "`".repeat(longest + 1);
  return `${fence} ${text} ${fence}`;
}
