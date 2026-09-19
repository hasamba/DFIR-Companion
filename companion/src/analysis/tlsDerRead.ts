// A certificate's own facts read from its DER bytes (#997, "decoded chain members").
//
// A Suricata record carries the server's chain as base64 DER (`tls.chain`); the leaf's subject,
// issuer and serial are also the record's own fields, but an intermediate's and a root's are not —
// before this, a chain entry carried its sha256 and nothing else. Node's X.509 reader decodes them
// here: subject and issuer in the certificate's own RDN order, the serial, every SAN, the validity
// bounds and the CA bit. What it does not do: verify a signature, decide a chain is valid, or mint
// an indicator (a SAN is not an indicator — the rule tlsSession.ts already keeps).
//
// A stated field beside a decoded one is compared as a SET of RDN components, never as a string:
// Suricata writes `C=US, O=X, CN=Y`, Node `C=US\nO=X\nCN=Y`, and either order is the same name.

import { X509Certificate } from "node:crypto";

/** What the bytes say; tlsSession.ts bounds the names and picks the DNS ones with its own rules. */
export interface DerFacts {
  decoded: "der";
  subject: string;
  issuer: string;
  serial?: string;
  /** Every SAN value in certificate order — DNS names, IP literals, emails, URIs alike. */
  sanNames: string[];
  notBefore?: string;
  notAfter?: string;
  ca: boolean;
}

/** Node joins RDNs with "\n"; the record's own form is ", " — the order the certificate wrote. */
const rdnJoin = (dn: string): string =>
  dn
    .split("\n")
    .map((c) => c.trim())
    .filter(Boolean)
    .join(", ");

const rdnSet = (dn: string): Set<string> =>
  new Set(
    dn
      .split(/\n|,\s*(?=[A-Za-z][A-Za-z0-9.]*=)/)
      .map((c) => c.trim().toLowerCase())
      .filter(Boolean),
  );

/** True when two distinguished names do not name the same RDN components (order ignored). */
export function rdnSetDiffers(stated: string, decoded: string): boolean {
  const a = rdnSet(stated);
  const b = rdnSet(decoded);
  if (a.size !== b.size) return true;
  for (const c of a) if (!b.has(c)) return true;
  return false;
}

/** `DNS:a, IP Address:1.2.3.4, email:x, URI:u` → the values, in order. */
function sanValues(san: string | undefined): string[] {
  if (!san) return [];
  return san
    .split(/,\s*(?=[A-Za-z ]+:)/)
    .map((e) => e.replace(/^[A-Za-z ]+:/, "").trim())
    .filter(Boolean);
}

const iso = (d: string): string | undefined => {
  const t = Date.parse(d);
  return Number.isFinite(t) ? new Date(t).toISOString() : undefined;
};

/** The facts the DER carries, or nothing when it is not a readable certificate. */
export function readDerFacts(der: Buffer): DerFacts | undefined {
  if (!der.length) return undefined;
  let c: X509Certificate;
  try {
    c = new X509Certificate(der);
  } catch {
    return undefined;
  }
  const names = sanValues(c.subjectAltName);
  const serial = c.serialNumber.toLowerCase();
  return {
    decoded: "der",
    subject: rdnJoin(c.subject),
    issuer: rdnJoin(c.issuer),
    ...(serial ? { serial } : {}),
    sanNames: names,
    ...(iso(c.validFrom) ? { notBefore: iso(c.validFrom) } : {}),
    ...(iso(c.validTo) ? { notAfter: iso(c.validTo) } : {}),
    ca: c.ca,
  };
}

/** The leaf's stated fields beside the decoded ones: which of subject / issuer the two disagree on. */
export function decodedDiffersOf(
  stated: { subject?: string; issuer?: string },
  decoded: { subject?: string; issuer?: string },
): string[] {
  const out: string[] = [];
  if (
    stated.subject !== undefined &&
    decoded.subject !== undefined &&
    rdnSetDiffers(stated.subject, decoded.subject)
  )
    out.push("subject");
  if (
    stated.issuer !== undefined &&
    decoded.issuer !== undefined &&
    rdnSetDiffers(stated.issuer, decoded.issuer)
  )
    out.push("issuer");
  return out;
}
