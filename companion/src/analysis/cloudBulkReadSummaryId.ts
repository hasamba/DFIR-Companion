/**
 * The identity of a cloud bulk-read summary: its words outside the marker and its stable id.
 *
 * Split out of cloudBulkRead.ts (at the size cap) by #1356. Both functions must separate exactly
 * what groupKey separates — a principal, its credential, the account, the provider, the address,
 * the client and the window's start — because two summaries that agree on either axis lose one of
 * themselves: replacement filters by id, and correlate.ts unions rows whose timestamp, cleaned
 * description and host agree.
 */
import type { BulkGroup } from "./cloudBulkRead.js";

const lower = (s: string): string => (s ?? "").trim().toLowerCase();

/**
 * The identity words of a summary — everything OUTSIDE the marker. correlate.ts keys exact-duplicate
 * detection on timestamp + cleanDescription + host, and cleanDescription strips the whole marker,
 * so every component groupKey separates on must be spoken here (#1356): the credential fingerprint
 * beside a principal, the account and the provider. Without them two credentials under one role,
 * starting in the same second, cleaned to identical words and correlate.ts unioned them into one.
 */
export function summaryHead(group: BulkGroup): string {
  const fingerprint = group.credentialId ? `credential ${group.credentialId.slice(0, 12)}…` : "";
  // A credential-only group (#931 item 4 — Account Key/SAS auth) has no principal; name the
  // credential fingerprint instead of rendering a blank.
  const who = group.principal
    ? `${group.principal}${fingerprint ? ` (${fingerprint})` : ""}`
    : fingerprint || "an unidentified caller";
  const account = group.account ? ` account ${group.account.slice(0, 32)}` : "";
  const where = group.provider ? ` in ${group.provider}${account}` : account ? ` in${account}` : "";
  return `Cloud bulk read by ${who}${where}${group.sourceIp ? ` from ${group.sourceIp}` : ""}`;
}

/** Hash a summary key into the 64-bit, two-halves id form summaryId has always used. */
function hashSummaryKey(key: string): string {
  let h1 = 5381;
  let h2 = 52711;
  for (let i = 0; i < key.length; i++) {
    const c = key.charCodeAt(i);
    h1 = ((h1 * 33) ^ c) >>> 0;
    h2 = ((h2 * 31) ^ (c + i)) >>> 0;
  }
  return `bulkread-${h1.toString(36)}${h2.toString(36)}`;
}

/**
 * The id a group's summary carried before #1356 (principal, address, client, start second only).
 * A case merged before the fix holds summaries under this id; the next merge replaces them under
 * the new id rather than leaving an orphan beside the new row — one migration, then never read.
 */
export function legacySummaryId(group: BulkGroup): string {
  return hashSummaryKey(
    `${lower(group.principal)}|${group.sourceIp}|${lower(group.userAgent)}|${group.first}`,
  );
}

/** A stable id for a group's summary, so a re-merge replaces its summary instead of adding another. */
export function summaryId(group: BulkGroup): string {
  // THE WINDOW'S START IS PART OF THE IDENTITY. Without it, one principal reading on Monday and
  // again on Friday from the same address produced ONE id, so the second summary replaced the
  // first and a whole session vanished from the record.
  //
  // And the hash is 64-bit, in two independent halves. A 32-bit djb2 collides on inputs an
  // attacker can choose — `principal-1r` and `principal-30` hashed identically — and a collision
  // here does not merely confuse two rows, it DELETES one, because replacement filters by id.
  //
  // THE KEY IS AS DISCRIMINATING AS groupKey (#1356). It once carried only principal, address,
  // client and start second — so two credentials under one role from one address, or one role
  // name in two accounts, whose densest windows started in the same second (CloudTrail is
  // second-granular; two sessions issued together start together) shared one id, and the
  // replaced-by-id filter kept one of them. Every component groupKey separates on is here.
  //
  // Serialized as a JSON array, not a delimiter-joined string: a `|` inside one component (a
  // credential id ending in one, an account beginning with one) would otherwise let two distinct
  // groups spell the same key. The legacy id keeps its joined form so it can still be matched.
  return hashSummaryKey(
    JSON.stringify([
      lower(group.principal),
      lower(group.credentialId),
      lower(group.account),
      lower(group.provider),
      group.sourceIp,
      lower(group.userAgent),
      group.first,
    ]),
  );
}
