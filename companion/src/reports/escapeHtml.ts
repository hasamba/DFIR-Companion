/**
 * HTML-escaping for generated report documents.
 *
 * One definition, because there were two: `html.ts` and `interactiveHtml.ts` each carried a
 * byte-identical copy, both escaping only `& < > "`. Both exporters embed untrusted evidence —
 * hostnames, command lines, quoted log text — into markup, so an escaping fix applied to one and
 * not the other is a fix that only half-lands, with nothing to flag the divergence (#521).
 *
 * The single quote is included deliberately. A value interpolated into a single-quoted attribute
 * escapes it otherwise, and the browser-side helper was already hardened this way in #217 — these
 * server-side exporters had not followed.
 */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
