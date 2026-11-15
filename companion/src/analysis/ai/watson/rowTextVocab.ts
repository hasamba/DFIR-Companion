import { COMMON_WORDS } from "./hostLabel.js";

// The vocabularies the free-text host detector (rowTextHosts.ts) uses to keep false positives out of
// the roster. A roster name is masked in every later AI call and export on the case, so a word such as
// "Source" or an identifier such as RC4-HMAC must never be taken for a host (Review Focus 1).

/**
 * Words a labelled value can be that are not a host: a blank field's next label ("Source Network
 * Address"), a yes/no answer, an article, or a placeholder.
 */
const NOT_A_HOST_VALUE: ReadonlySet<string> = new Set([
  ...COMMON_WORDS,
  "a",
  "an",
  "yes",
  "no",
  "true",
  "false",
  "none",
  "null",
  "nil",
  "empty",
  "unknown",
  "localhost",
  "source",
  "destination",
  "network",
  "address",
  "account",
  "logon",
  "target",
  "client",
  "server",
  "workstation",
  "computer",
  "host",
  "hostname",
  "machine",
  "device",
  "name",
  "port",
  "process",
  "domain",
  "information",
  "type",
  "remote",
  "caller",
  "subject",
  "security",
]);

/** Whether a rule-1 value is a placeholder or a plain word, not a host name. */
export function isNonHostValue(value: string): boolean {
  const v = value.toLowerCase();
  if (NOT_A_HOST_VALUE.has(v)) return true;
  // A plain word under 3 characters (no digit, hyphen or dot) names no host.
  return v.length < 3 && /^[a-z]+$/.test(v);
}

/**
 * Algorithm, encoding, protocol, platform and advisory words. A machine-shaped token made only of
 * these and numbers (RC4-HMAC, UTF-16LE, HMAC-SHA256, DES-CBC-MD5, P-256, NTLM-V2) is an identifier.
 * A segment is checked as written, then without a trailing LE/BE, then without trailing digits.
 */
const IDENTIFIER_WORDS: ReadonlySet<string> = new Set(
  (
    "RC HMAC SHA SHAKE MD AES DES 3DES TDES RSA DSA ECDSA ECDH ECDHE EDDSA ED25519 CURVE25519 DH DHE P " +
    "SECP CBC CTS GCM ECB CTR OFB CFB CCM XTS PKCS X509 CRC BASE CHACHA POLY UTF UCS ISO ANSI ASCII " +
    "NTLM NTLMV LM KRB KERBEROS TLS SSL DTLS SSH SMB HTTP HTTPS TCP UDP ICMP IP IPV DNS LDAP RDP " +
    "CVE CWE CAPEC GHSA RFC MS KB APT EID VU X86 X64 AMD AMD64 ARM ARM64 WIN WIN32 WIN64 ERROR"
  ).split(" "),
);

/** A segment that is only a number, with an optional letter before or a short suffix after (V2, 16LE). */
const NUMBER_LIKE = /^[A-Z]?\d+(?:LE|BE|[A-Z])?$/;

function isIdentifierWord(segment: string): boolean {
  const noEndian = segment.replace(/(?:LE|BE)$/, "");
  const noDigits = noEndian.replace(/\d+$/, "");
  return [segment, noEndian, noDigits].some((s) => s !== "" && IDENTIFIER_WORDS.has(s));
}

/**
 * Whether a machine-shaped token is an identifier: one segment is an identifier word and every other
 * segment is one too, or a number. A default Windows name (WIN-7Q2K3J9LMN) keeps a non-numeric
 * segment, so it stays a host.
 */
export function isIdentifierToken(token: string): boolean {
  const segments = token.toUpperCase().split("-");
  if (!segments.some(isIdentifierWord)) return false;
  return segments.every((s) => isIdentifierWord(s) || NUMBER_LIKE.test(s));
}
