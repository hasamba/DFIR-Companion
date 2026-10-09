import type { Finding } from "../analysis/stateTypes.js";
import { mdControlPictures } from "./controlChars.js";

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
 * deliverables. Other C0 controls and DEL become visible Control Pictures (#9). Newlines reach here from report-meta free-text fields (revisions[].comments,
 * distribution[].name, glossary entries) and from AI-generated descriptions that contain a literal
 * newline (#12).
 */
export function cellMd(value: string): string {
  return mdControlPictures(value.replace(/\|/g, "\\|").replace(/[\r\n]+/g, " "));
}

/**
 * Text interpolated INTO a line that already has a meaning — a heading, a list item, a bold label.
 * A newline would end that line and let the rest of the value start a construct of its own, so the
 * value is flattened onto the one line it was placed on. Nothing is dropped: the reader still sees
 * the whole string, attributed to the finding or hypothesis that carries it.
 */
export function oneLineMd(value: string): string {
  return mdControlPictures(value.replace(/[\r\n]+/g, " ").trim());
}

// Indent, then any blockquote and list-item markers: the part of a line before its content. A
// heading may open inside a list item (`- # Forged`), so the check looks past those markers too.
const CONTAINER_PREFIX = "[ \\t]*(?:(?:>|[-*+][ \\t]|\\d{1,9}[.)][ \\t])[ \\t]*)*";
// Group 1 is the prefix the marker actually follows, so the backslash lands right before the marker.
const SECTION_MARKER_RE = new RegExp(`^(${CONTAINER_PREFIX})(?:#{1,6}(?:\\s|$)|=+[ \\t]*$|-+[ \\t]*$)`);

// A code fence, or a raw-HTML block of the kinds that only end at a closing marker (`</pre>`, `-->`,
// `?>`, `>`, `]]>`) or at the end of the document. Left open, either one turns every later report
// section into code or hidden markup (#1918). Group 2 is the opener, which is escaped in full: a
// fence with only its first character escaped would still leave a `` `` `` code-span opener.
const RUNAWAY_BLOCK_RE = new RegExp(
  `^(${CONTAINER_PREFIX})(\`{3,}|~{3,}|<(?=(?:script|pre|style|textarea)(?:[\\s>]|$)|!--|\\?|![A-Za-z]|!\\[CDATA\\[))`,
  "i",
);

function escapeSectionMarker(line: string): string {
  const block = RUNAWAY_BLOCK_RE.exec(line);
  if (block) {
    const [, prefix, opener] = block;
    return `${prefix}${opener.replace(/./g, "\\$&")}${line.slice(prefix.length + opener.length)}`;
  }
  const m = SECTION_MARKER_RE.exec(line);
  return m ? `${m[1]}\\${line.slice(m[1].length)}` : line;
}

/**
 * A block of prose emitted on its own lines. Paragraphs, lists, emphasis and code spans survive —
 * this is the report's body text and it should read as written. What does not survive is anything
 * that opens a SECTION: an ATX heading (`## …`) or a setext underline of ANY length (`===`, `---`,
 * and a single `-`, which CommonMark also accepts — #1898). Those are escaped with a backslash, so
 * the marker renders as the literal characters the author typed instead of restructuring the
 * document. The check looks past any indent (a list item's continuation can sit at four or more
 * spaces) and past blockquote and list-item markers, and the backslash goes after them, so a quote
 * stays a quote and a list stays a list.
 * The same holds for a block that never ends on its own: a code fence (```` ``` ````, `~~~`) or a raw
 * HTML block such as `<pre>` or `<!--` is escaped, so finding text cannot turn the rest of the report
 * into code (#1918). Inline code spans are untouched.
 * A line that only holds `-` is never a list item with text, so real bullets are untouched.
 * Thematic breaks of `*` or `_` are left alone: they render a rule, never a heading.
 */
export function blockMd(value: string): string {
  // A lone CR is a line break to marked, so it is split on here too — otherwise "benign\r## X"
  // would slip past the per-line check and forge a heading.
  return mdControlPictures(value)
    .split(/\r\n|\r|\n/)
    .map(escapeSectionMarker)
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
      return `  - ${oneLineMd(c.timestamp || "(undated)")} on ${codeSpanMd(c.host)}${who}: ${codeSpanMd(c.text)}`;
    }),
    ...(more ? [`  - … and ${more} more in the case timeline`] : []),
  ];
}

/**
 * Inline code for untrusted text: flattened onto one line (oneLineMd), in a backtick fence longer
 * than any backtick run inside it (CommonMark), so the text can neither open a section nor close the
 * span early and borrow emphasis or link syntax (#1594, #2052).
 */
export function codeSpanMd(value: string): string {
  const text = oneLineMd(value);
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = "`".repeat(longest + 1);
  return `${fence} ${text} ${fence}`;
}
