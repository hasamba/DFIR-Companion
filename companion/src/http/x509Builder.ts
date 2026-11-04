/**
 * Build and sign an X.509 v3 certificate for the built-in HTTPS listener (#2285): the private local
 * CA and the server certificate it issues. Field layout per RFC 5280; signing is `node:crypto`
 * (sha256WithRSAEncryption). See der.ts for why the layout is not a library.
 */
import { createHash, randomBytes, sign, type KeyObject } from "node:crypto";
import { isIP } from "node:net";
import {
  bitString,
  boolean,
  explicit,
  implicitPrimitive,
  nullValue,
  objectIdentifier,
  octetString,
  sequence,
  set,
  smallInteger,
  time,
  unsignedInteger,
  utf8String,
} from "./der.js";

const OID = {
  sha256WithRsa: "1.2.840.113549.1.1.11",
  commonName: "2.5.4.3",
  organization: "2.5.4.10",
  subjectKeyId: "2.5.29.14",
  keyUsage: "2.5.29.15",
  subjectAltName: "2.5.29.17",
  basicConstraints: "2.5.29.19",
  authorityKeyId: "2.5.29.35",
  extKeyUsage: "2.5.29.37",
  serverAuth: "1.3.6.1.5.5.7.3.1",
} as const;

export const CERT_ORGANIZATION = "DFIR Companion";

export interface CertificateSpec {
  subjectCommonName: string;
  issuerCommonName: string;
  /** The key the certificate is FOR. */
  publicKey: KeyObject;
  /** The key that SIGNS it — the CA's private key (the subject's own for a self-signed CA). */
  signingKey: KeyObject;
  /** The issuer's public key, for the authority key identifier. */
  issuerPublicKey: KeyObject;
  notBefore: Date;
  notAfter: Date;
  isCa: boolean;
  dnsNames?: readonly string[];
  ipAddresses?: readonly string[];
}

const algorithm = (): Buffer => sequence(objectIdentifier(OID.sha256WithRsa), nullValue());

function name(commonName: string): Buffer {
  const attribute = (oid: string, value: string) => set(sequence(objectIdentifier(oid), utf8String(value)));
  return sequence(attribute(OID.organization, CERT_ORGANIZATION), attribute(OID.commonName, commonName));
}

function keyId(publicKey: KeyObject): Buffer {
  return createHash("sha1")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest();
}

function extension(oid: string, critical: boolean, value: Buffer): Buffer {
  return sequence(objectIdentifier(oid), ...(critical ? [boolean(true)] : []), octetString(value));
}

/** Network-order bytes of an IPv4 or IPv6 literal (already validated by the caller). */
export function ipBytes(address: string): Buffer {
  if (isIP(address) === 4) return Buffer.from(address.split(".").map(Number));
  const compressed = address.includes("::");
  const [head = "", tail = ""] = address.split("::");
  const headGroups = head ? head.split(":") : [];
  const tailGroups = compressed && tail ? tail.split(":") : [];
  const zeros: string[] = compressed ? new Array(8 - headGroups.length - tailGroups.length).fill("0") : [];
  const groups = [...headGroups, ...zeros, ...tailGroups];
  return Buffer.concat(
    groups.map((g) => {
      const value = parseInt(g, 16);
      return Buffer.from([(value >> 8) & 0xff, value & 0xff]);
    }),
  );
}

function subjectAltName(dnsNames: readonly string[], ipAddresses: readonly string[]): Buffer {
  return sequence(
    ...dnsNames.map((dns) => implicitPrimitive(2, Buffer.from(dns, "ascii"))),
    ...ipAddresses.map((ip) => implicitPrimitive(7, ipBytes(ip))),
  );
}

function extensions(spec: CertificateSpec): Buffer {
  const list = spec.isCa
    ? [
        extension(OID.basicConstraints, true, sequence(boolean(true), smallInteger(0))),
        // keyCertSign (bit 5) + cRLSign (bit 6): one byte 0b00000110, last bit unused.
        extension(OID.keyUsage, true, bitString(Buffer.from([0x06]), 1)),
      ]
    : [
        extension(OID.basicConstraints, true, sequence()),
        // digitalSignature (bit 0) + keyEncipherment (bit 2): 0b10100000, five bits unused.
        extension(OID.keyUsage, true, bitString(Buffer.from([0xa0]), 5)),
        extension(OID.extKeyUsage, false, sequence(objectIdentifier(OID.serverAuth))),
        extension(OID.subjectAltName, false, subjectAltName(spec.dnsNames ?? [], spec.ipAddresses ?? [])),
      ];
  return explicit(
    3,
    sequence(
      ...list,
      extension(OID.subjectKeyId, false, octetString(keyId(spec.publicKey))),
      extension(OID.authorityKeyId, false, sequence(implicitPrimitive(0, keyId(spec.issuerPublicKey)))),
    ),
  );
}

/** A positive, non-zero 128-bit serial (RFC 5280 caps serials at 20 octets). */
function serialNumber(): Buffer {
  const bytes = randomBytes(16);
  bytes[0] = (bytes[0] & 0x7f) | 0x01;
  return unsignedInteger(bytes);
}

/** The signed certificate as PEM. */
export function buildCertificatePem(spec: CertificateSpec): string {
  const tbs = sequence(
    explicit(0, smallInteger(2)), // v3
    serialNumber(),
    algorithm(),
    name(spec.issuerCommonName),
    sequence(time(spec.notBefore), time(spec.notAfter)),
    name(spec.subjectCommonName),
    spec.publicKey.export({ type: "spki", format: "der" }),
    extensions(spec),
  );
  const signature = sign("sha256", tbs, spec.signingKey);
  const der = sequence(tbs, algorithm(), bitString(signature));
  const body = der.toString("base64").replace(/.{1,64}/g, "$&\n");
  return `-----BEGIN CERTIFICATE-----\n${body}-----END CERTIFICATE-----\n`;
}
