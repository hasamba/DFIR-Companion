// Host-name primitives shared by the masking roster (superRoster.ts), the prompt entities
// (pasteEntities.ts) and the free-text host detector (rowTextHosts.ts). A leaf module: it imports no
// other Watson module, so those three can use it without an import cycle.

/** An IPv4 literal, or any name with a colon (IPv6): it never gives a short label. */
export const IP_LIKE = /^\d{1,3}(?:\.\d{1,3}){3}$|:/;

/** Words a multi-word profile name is not split into, and that are never a short host label. */
export const COMMON_WORDS: ReadonlySet<string> = new Set([
  "the",
  "and",
  "for",
  "admin",
  "user",
  "users",
  "local",
  "default",
  "public",
  "test",
  "temp",
  "new",
  "old",
  "backup",
  "service",
  "system",
  "owner",
  "guest",
  "home",
]);

/** A host field's FQDN gives its short label too (FILESRV.acme.com → FILESRV), as forensic assets do. */
export function withShortLabel(host: string | undefined): string[] {
  const h = host?.trim();
  if (!h) return [];
  const label = h.split(".")[0];
  const named =
    h.includes(".") && !IP_LIKE.test(h) && label.length >= 3 && !COMMON_WORDS.has(label.toLowerCase());
  return named ? [h, label] : [h];
}
