// One home for "control characters in untrusted text → something a report can carry".
//
// Imported event descriptions are adversary-chosen and may hold NUL bytes and other C0 controls.
// Stored state keeps those exact bytes (evidence integrity), so the mapping happens only at the
// report seam. Each control becomes its visible Unicode Control Picture (U+2400 + code, so NUL is
// "␀"): the reader still sees that a control was there and which one, and nothing is dropped.
// Bidi controls (RLO, …) become `<RLO>`-style markers the same way: raw, they reverse the text after
// them in every viewer, so an RLO-masqueraded file name would read backwards in the report (#2027).

import { escapeBidiControls, escapeBidiControlsAs } from "../analysis/bidiControl.js";

const CONTROL_PICTURE_BASE = 0x2400;
const DEL_PICTURE = "␡";
const REPLACEMENT_CHAR = "�";

function controlPicture(ch: string): string {
  return String.fromCharCode(CONTROL_PICTURE_BASE + ch.charCodeAt(0));
}

// C0 controls XML 1.0 forbids: everything below U+0020 except TAB, LF and CR.
const XML_FORBIDDEN_C0 = /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g;
// Non-characters XML 1.0 forbids, and UTF-16 surrogates that are not part of a valid pair.
const XML_FORBIDDEN_OTHER = /[￾￿]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/**
 * Text safe to place in an XML 1.0 document (the .docx). One forbidden character makes
 * word/document.xml unparseable and the whole deliverable unopenable. C0 controls become Control
 * Pictures; U+FFFE, U+FFFF and lone surrogates have no picture and become U+FFFD.
 */
export function xmlSafeText(value: string): string {
  return escapeBidiControls(value)
    .replace(XML_FORBIDDEN_C0, controlPicture)
    .replace(XML_FORBIDDEN_OTHER, REPLACEMENT_CHAR);
}

// Markdown reads `<RLO>` as an HTML tag (GitHub hides it), and a path's own backslash before it
// ("victim\<RLO>") escapes the bracket. Single angle quotes mean nothing to Markdown, in a code span
// or after a backslash, so the marker survives every renderer and the DOCX lexer.
// Display-only and one-way: a literal "‹RLO›" in evidence renders the same — see bidiControl.ts.
const MD_MARKER_OPEN = "\u2039";
const MD_MARKER_CLOSE = "\u203a";

// C0 controls a Markdown fragment must not carry raw: everything below U+0020 except TAB, LF, CR
// (the mdText callers fold or split on line breaks themselves), plus DEL.
const MD_CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

/** Markdown text with every C0 control (except TAB, LF, CR) and DEL shown as its Control Picture, and every bidi control as a marker. */
export function mdControlPictures(value: string): string {
  return escapeBidiControlsAs(value, MD_MARKER_OPEN, MD_MARKER_CLOSE).replace(MD_CONTROL, (ch) =>
    ch === "\u007F" ? DEL_PICTURE : controlPicture(ch),
  );
}

/** A CSV cell value with NUL shown as "␀" and every bidi control as a marker. A quoted CR is legal CSV and stays exact. */
export function csvNulPicture(value: string): string {
  return escapeBidiControls(value).replace(/\u0000/g, controlPicture);
}
