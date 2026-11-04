/**
 * The handful of ASN.1 DER encoders the built-in HTTPS certificate builder needs (#2285).
 *
 * WHY HAND-ROLLED: the only job is to LAY OUT an X.509 certificate's fields. Every cryptographic
 * operation — key generation, signing, and parsing/verifying the result — is Node's own
 * (`node:crypto`, OpenSSL). The usual library for this, node-forge, carries its own crypto and a
 * steady stream of security advisories for code paths this feature would never call. Encoding is
 * checked end to end by tests that parse every certificate with `X509Certificate` and complete a
 * real TLS handshake against it. (analysis/tlsDerRead.ts is the READ side for evidence; it decodes
 * through Node and builds nothing.)
 */

function encodeLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let n = length; n > 0; n = Math.floor(n / 256)) bytes.unshift(n & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** One tag-length-value element. */
export function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

export const sequence = (...items: Buffer[]): Buffer => tlv(0x30, Buffer.concat(items));
export const set = (...items: Buffer[]): Buffer => tlv(0x31, Buffer.concat(items));
export const nullValue = (): Buffer => Buffer.from([0x05, 0x00]);
export const boolean = (value: boolean): Buffer => tlv(0x01, Buffer.from([value ? 0xff : 0x00]));
export const octetString = (content: Buffer): Buffer => tlv(0x04, content);
export const utf8String = (value: string): Buffer => tlv(0x0c, Buffer.from(value, "utf8"));

/** A BIT STRING whose last `unusedBits` bits are padding (0 for whole bytes such as a key). */
export function bitString(content: Buffer, unusedBits = 0): Buffer {
  return tlv(0x03, Buffer.concat([Buffer.from([unusedBits]), content]));
}

/** A non-negative INTEGER from big-endian magnitude bytes, minimally encoded. */
export function unsignedInteger(magnitude: Buffer): Buffer {
  let start = 0;
  while (start < magnitude.length - 1 && magnitude[start] === 0) start++;
  const trimmed = magnitude.subarray(start);
  if (trimmed.length === 0) return tlv(0x02, Buffer.from([0]));
  return tlv(0x02, trimmed[0] & 0x80 ? Buffer.concat([Buffer.from([0]), trimmed]) : trimmed);
}

export const smallInteger = (value: number): Buffer => unsignedInteger(Buffer.from([value]));

export function objectIdentifier(dotted: string): Buffer {
  const arcs = dotted.split(".").map(Number);
  const bytes: number[] = [arcs[0] * 40 + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const chunk: number[] = [arc & 0x7f];
    for (let n = Math.floor(arc / 128); n > 0; n = Math.floor(n / 128)) chunk.unshift((n & 0x7f) | 0x80);
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}

/** RFC 5280 §4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050. Whole seconds, always `Z`. */
export function time(date: Date): Buffer {
  const digits = date.toISOString().slice(0, 19).replace(/[-T:]/g, ""); // YYYYMMDDHHMMSS
  return date.getUTCFullYear() < 2050
    ? tlv(0x17, Buffer.from(`${digits.slice(2)}Z`, "ascii"))
    : tlv(0x18, Buffer.from(`${digits}Z`, "ascii"));
}

/** `[n] EXPLICIT` — the content keeps its own tag inside the context tag. */
export const explicit = (n: number, content: Buffer): Buffer => tlv(0xa0 | n, content);

/** `[n] IMPLICIT` primitive — the context tag replaces the content's own tag. */
export const implicitPrimitive = (n: number, content: Buffer): Buffer => tlv(0x80 | n, content);
