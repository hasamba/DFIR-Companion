// One home for "control characters in untrusted text → something a report can carry".
//
// Imported event descriptions are adversary-chosen and may hold NUL bytes and other C0 controls.
// Stored state keeps those exact bytes (evidence integrity), so the mapping happens only at the
// report seam. Each control becomes its visible Unicode Control Picture (U+2400 + code, so NUL is
// "␀"): the reader still sees that a control was there and which one, and nothing is dropped.

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
  return value.replace(XML_FORBIDDEN_C0, controlPicture).replace(XML_FORBIDDEN_OTHER, REPLACEMENT_CHAR);
}

// C0 controls a Markdown fragment must not carry raw: everything below U+0020 except TAB, LF, CR
// (the mdText callers fold or split on line breaks themselves), plus DEL.
const MD_CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

/** Markdown text with every C0 control (except TAB, LF, CR) and DEL shown as its Control Picture. */
export function mdControlPictures(value: string): string {
  return value.replace(MD_CONTROL, (ch) => (ch === "\u007F" ? DEL_PICTURE : controlPicture(ch)));
}

/** A CSV cell value with NUL shown as "␀". A quoted CR is legal CSV and stays exact. */
export function csvNulPicture(value: string): string {
  return value.replace(/\u0000/g, controlPicture);
}
