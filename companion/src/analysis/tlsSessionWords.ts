// The words of a TLS session or certificate row (#933 item 6). Every record-written value — an
// SNI, a subject, an issuer, a chain-check string — is shown neutralised (brackets to parentheses,
// hash runs broken, clipped) inside its own named span, so no field can spell a tag beside the
// row's own and correlate.ts skips the span when it scrapes free text for a hash or a path. A
// certificate identity that came from the upload's x509 record (tlsGraphJoin.ts, #997) says so
// beside the identity; a join that could not be made says why.

import { breakHashRuns, showToken } from "./recordIdentity.js";
import type { CertJoinNote, CertRef, TlsObservation } from "./tlsSession.js";

const NAMES_SHOWN_MAX = 3;
const TEXT_SHOWN_MAX = 80;

export const show = (v: string): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > TEXT_SHOWN_MAX ? `${shown.slice(0, TEXT_SHOWN_MAX - 1)}…` : shown;
};
export const ends = (hex: string): string => (hex.length > 12 ? `${hex.slice(0, 8)}…${hex.slice(-4)}` : hex);

/** A certificate reference as words: a fingerprint by its ends, a cert identity by its ends. */
export const refWords = (r: CertRef): string =>
  r.kind === "identity"
    ? `cert identity ${breakHashRuns(r.value)}`
    : `${r.alg === "sha256" ? "sha256" : "fp"} ${ends(r.value)}`;

/** What the join with the upload's x509 record established, or why it did not. */
export function joinWords(from: "x509" | undefined, note: CertJoinNote | undefined): string {
  const parts: string[] = [];
  if (from === "x509") parts.push("identity from the x509 record");
  if (note === "records disagree") parts.push("x509 records for this chain disagree, not joined");
  if (note === "disagrees with this record") parts.push("x509 record for this chain disagrees, not joined");
  if (note === "not among those read") parts.push("x509 record not among those read");
  if (note === "subject/issuer differ") parts.push("subject/issuer differ from the x509 record");
  return parts.join("; ");
}

function certWords(o: TlsObservation): string {
  const ref = !o.cert ? "identity unavailable" : refWords(o.cert);
  const join = joinWords(o.certFrom, o.certJoinNote);
  return [
    o.subject !== undefined ? `subject ${show(o.subject)}` : "",
    o.issuer !== undefined ? `issuer ${show(o.issuer)}` : "",
    join ? `${ref} — ${join}` : ref,
  ]
    .filter(Boolean)
    .join("; ");
}

export function sessionTags(o: TlsObservation): string[] {
  const tags: string[] = [];
  tags.push(o.sni !== undefined ? `sni: ${show(o.sni)}` : "no SNI");
  const proto = [
    o.version !== undefined ? show(o.version) : "",
    o.cipher !== undefined ? `cipher ${show(o.cipher)}` : "",
    o.curve !== undefined ? `curve ${show(o.curve)}` : "",
  ]
    .filter(Boolean)
    .join(", ");
  if (proto) tags.push(proto);
  // A chain FUID is Zeek saying it saw a certificate, even when the export kept no other field.
  const hasCert =
    o.subject !== undefined ||
    o.issuer !== undefined ||
    o.cert !== undefined ||
    (o.certChainFuids?.length ?? 0) > 0 ||
    o.certificateSeen === true ||
    Object.keys(o.certificate ?? {}).length > 0;
  tags.push(hasCert ? `cert: ${certWords(o)}` : "no server certificate observed in this record");
  if (o.clientCert) {
    const cc = o.clientCert;
    const base = cc.ref ? refWords(cc.ref) : cc.chainFuids?.length || cc.seen ? "identity unavailable" : "";
    const join = joinWords(cc.from, cc.joinNote);
    const ref = base && join ? `${base} — ${join}` : base || join;
    tags.push(
      `client cert: ${[cc.subject !== undefined ? `subject ${show(cc.subject)}` : "", cc.issuer !== undefined ? `issuer ${show(cc.issuer)}` : "", ref].filter(Boolean).join("; ")}`,
    );
  }
  if (o.directionFlipped) tags.push("TLS client was the connection responder");
  if (o.validation !== undefined) tags.push(`chain check: ${show(o.validation)}`);
  if (o.sniMatchesCert !== undefined)
    tags.push(o.sniMatchesCert ? "SNI matches the certificate" : "SNI does not match the certificate");
  if (o.established === false) tags.push("not established");
  if (o.resumed === true) tags.push("session resumed");
  if (o.ja3 !== undefined) tags.push(`ja3 ${ends(o.ja3)}`);
  if (o.ja3s !== undefined) tags.push(`ja3s ${ends(o.ja3s)}`);
  return tags;
}

export function certificateTag(o: TlsObservation): string {
  const c = o.certificate ?? {};
  const names = c.names ?? [];
  const total = c.namesTotal ?? names.length;
  const shownNames = names.slice(0, NAMES_SHOWN_MAX).map(show).join(", ");
  const more = total > NAMES_SHOWN_MAX ? ` (+${total - NAMES_SHOWN_MAX} more)` : "";
  return [
    `certificate: ${o.role ? `${o.role}-presented; ` : ""}${certWords({ ...o, subject: undefined, issuer: undefined })}`,
    c.subject !== undefined ? `subject ${show(c.subject)}` : "",
    c.issuer !== undefined ? `issuer ${show(c.issuer)}` : "",
    c.notBefore || c.notAfter ? `valid ${show(c.notBefore ?? "?")}–${show(c.notAfter ?? "?")}` : "",
    total ? `covers ${total} name${total === 1 ? "" : "s"}: ${shownNames}${more}` : "",
    c.decoded ? "decoded from the DER" : "",
    ...(c.decodedDiffers ?? []).map((f) => `record ${f} differs from the DER's`),
  ]
    .filter(Boolean)
    .join("; ");
}

/** One bracketed tag, clipped inside its brackets so it can never end half-open. */
export function clipTag(tag: string, room: number): string {
  const inner = tag.length + 2 <= room ? tag : `${tag.slice(0, Math.max(0, room - 3))}…`;
  return `[${inner}]`;
}
