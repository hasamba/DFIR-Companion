// Per-language string literals for the 🔍 hunt-modal query builders (#2572).
//
// Every value these builders template comes from evidence: file paths, URLs, domains, process
// names, host names. They are adversary-controlled, so quoting them is a correctness requirement.
// The builders used to share one helper that escaped `"` and nothing else. In KQL, SPL, ES|QL and
// VQL the backslash is also an escape character, so that helper got three things wrong:
//   - a plain path like C:\Windows\Temp\x.ps1 was mis-read (`\W`, `\T`, `\x` are escapes);
//   - a trailing backslash (C:\Temp\) escaped the closing quote and left the string open;
//   - a crafted value (C:\a\evil\" or true //x) closed the string early, so `or true` ran as query
//     text and `//` commented out the rest of the KQL query.
// Each language now has its own function. Each escapes the backslash FIRST and then the quote, so
// any value round-trips as exactly one literal and can never close the string or add operators.
//
// Language rules, from the vendors' own definitions:
//   KQL   — https://learn.microsoft.com/en-us/kusto/query/scalar-data-types/string
//           "\" escapes the enclosing quote, \t, \n and the backslash itself (\\); \uXXXX is
//           accepted; a raw newline / return must not appear in a quoted literal.
//   SPL   — https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutsearchlanguagesyntax
//           "The backslash character ( \ ) is used to escape quotes, pipes, and itself. Backslash
//           escape sequences are still expanded inside quotes." SPL has no newline escape, so a
//           newline stays raw inside the quotes. An asterisk CANNOT be escaped in SPL: a `*` in a
//           value stays a wildcard (a broader match, never a change to the query structure).
//   ES|QL — Elasticsearch's ES|QL lexer (x-pack/plugin/esql/src/main/antlr/lexer/Expression.g4):
//           QUOTED_STRING : '"' (ESCAPE_SEQUENCE | UNESCAPED_CHARS)* '"'
//           ESCAPE_SEQUENCE : '\\' [tnr"\\] ;  UNESCAPED_CHARS : ~[\r\n"\\]
//           Docs: https://www.elastic.co/docs/reference/query-languages/esql/esql-syntax
//   VQL   — Velociraptor's vfilter lexer and utils.Unquote: `"…"` strings with \\ \" \n \r \xHH.
//   YAML  — the Sigma skeleton uses YAML double-quoted scalars, whose escapes are a superset of
//           JSON's, so JSON.stringify is a valid YAML scalar. U+0085/U+2028/U+2029 are escaped
//           too: YAML 1.1 parsers treat them as line breaks and would fold them.
//   YARA  — text strings and meta values: \" \\ \t \n \r and \xHH.
//
// The CrowdStrike CQL card has its own quoting in js/dashboard-hunt-cql.js (#2558), because a `*`
// in a CQL quoted value is a wildcard it routes to a regex instead.
(function () {
  "use strict";

  const hex2 = (ch) => ch.charCodeAt(0).toString(16).padStart(2, "0");
  const hex4 = (ch) => ch.charCodeAt(0).toString(16).padStart(4, "0");
  // C0 controls, DEL, and the three characters some parsers treat as line breaks.
  const CONTROL = /[\u0000-\u001f\u007f\u0085\u2028\u2029]/g;

  // Microsoft Defender / Sentinel KQL: "…" literal.
  const kqlString = (v) =>
    `"${String(v)
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/\n/g, "\\n")
      .replace(/\t/g, "\\t")
      .replace(CONTROL, (ch) => `\\u${hex4(ch)}`)}"`;

  // Splunk SPL: "…" search term. Backslash, then quote; nothing else is an escape.
  const splEscape = (v) => String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const splString = (v) => `"${splEscape(v)}"`;
  // A contains-match ("*value*"). The surrounding wildcards are the builder's; the value's own `*`
  // cannot be escaped in SPL and stays a wildcard.
  const splContains = (v) => `"*${splEscape(v)}*"`;

  // Elastic ES|QL: "…" literal. A raw CR or LF is not allowed inside it.
  const esqlString = (v) =>
    `"${String(v)
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/\n/g, "\\n")
      .replace(/\r/g, "\\r")
      .replace(/\t/g, "\\t")}"`;

  // Velociraptor VQL: "…" literal.
  const vqlString = (v) =>
    `"${String(v)
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/\n/g, "\\n")
      .replace(/\r/g, "\\r")}"`;

  // YAML double-quoted scalar (Sigma skeleton).
  const yamlString = (v) =>
    JSON.stringify(String(v)).replace(/[\u0085\u2028\u2029]/g, (ch) => `\\u${hex4(ch)}`);

  // YARA text string / meta value.
  const yaraString = (v) =>
    `"${String(v)
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/\n/g, "\\n")
      .replace(/\r/g, "\\r")
      .replace(/\t/g, "\\t")
      .replace(/[\u0000-\u001f\u007f]/g, (ch) => `\\x${hex2(ch)}`)}"`;

  // Free text placed after a line comment (`//`, `--`): a line break would end the comment and
  // turn the rest of the value into live query text, so every break becomes a space.
  const commentText = (v) => String(v).replace(CONTROL, " ");

  window.kqlString = kqlString;
  window.splString = splString;
  window.splContains = splContains;
  window.esqlString = esqlString;
  window.vqlString = vqlString;
  window.yamlString = yamlString;
  window.yaraString = yaraString;
  window.commentText = commentText;
})();
