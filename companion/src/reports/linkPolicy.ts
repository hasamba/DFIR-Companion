// Shared link policy for exported reports (Word #2053, HTML #2072).
//
// Evidence text is adversary-controlled, and a saved report is usually opened from disk.
// There, a relative, protocol-relative (`//host/share`) or UNC (`\\host\share`) target
// resolves to `file://host/share`, and on Windows following it can leak NTLM credentials.
// So a target stays live only when the RAW string is already an absolute http(s)/mailto
// URL. It is never resolved against a base URL, because a base would turn `//host` into
// `https://host` and let it through.

const ABSOLUTE_WEB_LINK_SCHEME = /^(?:https?|mailto):/i;

/**
 * True only for an absolute http:, https: or mailto: href, judged on the raw string and
 * then re-checked after parsing with no base. Rejects relative, protocol-relative, UNC,
 * javascript:/file:/data: and defanged hxxp(s) targets.
 */
export function isAbsoluteWebLink(href: string): boolean {
  if (!ABSOLUTE_WEB_LINK_SCHEME.test(href)) return false;
  try {
    return ABSOLUTE_WEB_LINK_SCHEME.test(new URL(href).protocol);
  } catch {
    return false;
  }
}
