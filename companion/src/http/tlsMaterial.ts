/**
 * Certificates for the built-in HTTPS listener (#2285): the private local CA, the server certificate
 * it issues, and an operator's own certificate files.
 *
 * Storage: `<folder holding the cases root>/tls/` — `ca.pem` and `server.pem`, each ONE file holding
 * the private key and the certificate, so a crash can never leave half a pair. Both are written
 * owner-only from the first byte (exclusive temp file at 0600, fsync, rename) — never written at the
 * default mode and chmod'ed afterwards.
 *
 * The CA is the thing teammates trust, so it is created only when `ca.pem` does not exist and is
 * NEVER replaced automatically: a damaged or expired one stops HTTPS with recovery instructions.
 * The server certificate is disposable — re-issued from the same CA whenever it nears expiry, stops
 * matching the CA, or the machine's names/addresses change — and nobody who trusts the CA notices.
 */
import {
  X509Certificate,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeSync,
} from "node:fs";
import { networkInterfaces, hostname as osHostname } from "node:os";
import { isIP } from "node:net";
import { dirname, join, resolve } from "node:path";
import { buildCertificatePem } from "./x509Builder.js";

const DAY_MS = 86_400_000;
export const CA_VALIDITY_DAYS = 3650;
export const SERVER_VALIDITY_DAYS = 825; // Apple's ceiling for a TLS server certificate.
export const RENEW_BEFORE_DAYS = 30;
export const CA_WARN_BEFORE_DAYS = 180;

export class TlsMaterialError extends Error {}

export interface CertSummary {
  fingerprint256: string;
  validTo: Date;
  subject: string;
  names: string;
}

type PrivateKey = ReturnType<typeof createPrivateKey>;

export interface LocalCa {
  path: string;
  certPem: string;
  key: PrivateKey;
  cert: X509Certificate;
}

export interface ServerMaterial {
  keyPem: string;
  /** The certificate, plus any chain an operator supplied. */
  certPem: string;
  summary: CertSummary;
}

export interface CertNames {
  dns: string[];
  ips: string[];
  /** Configured extra names that are not a valid hostname or IP (wildcards, scoped IPv6, junk). */
  rejected: string[];
}

export const tlsDirFor = (casesRoot: string): string => join(dirname(resolve(casesRoot)), "tls");

export function summarize(cert: X509Certificate): CertSummary {
  return {
    fingerprint256: cert.fingerprint256,
    validTo: new Date(cert.validTo),
    subject: cert.subject.replace(/\n/g, ", "),
    names: cert.subjectAltName ?? "",
  };
}

/** Write a key-bearing file owner-only from creation, durably, replacing any previous one. */
export function writePrivateFile(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp.${process.pid}.${randomBytes(4).toString("hex")}`;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, content);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(tmp, path);
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
}

interface Bundle {
  keyPem?: string;
  certPems: string[];
  names?: string;
  encryptedKey: boolean;
}

function parseBundle(text: string): Bundle {
  const blocks = [...text.matchAll(/-----BEGIN ([A-Z ]+)-----[\s\S]+?-----END \1-----/g)];
  const keyBlock = blocks.find((b) => /PRIVATE KEY$/.test(b[1]) && b[1] !== "ENCRYPTED PRIVATE KEY");
  const names = /^# names: (.*)$/m.exec(text)?.[1]?.trim();
  return {
    ...(keyBlock ? { keyPem: `${keyBlock[0]}\n` } : {}),
    certPems: blocks.filter((b) => b[1] === "CERTIFICATE").map((b) => `${b[0]}\n`),
    ...(names !== undefined ? { names } : {}),
    encryptedKey: blocks.some((b) => b[1] === "ENCRYPTED PRIVATE KEY") || /Proc-Type: 4,ENCRYPTED/.test(text),
  };
}

const newKey = (): PrivateKey => generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
const keyPemOf = (key: PrivateKey): string => key.export({ type: "pkcs8", format: "pem" }).toString();

function readCa(text: string, now: Date): Omit<LocalCa, "path"> | string {
  const bundle = parseBundle(text);
  if (!bundle.keyPem || !bundle.certPems[0]) return "the key or the certificate is missing";
  try {
    const key = createPrivateKey(bundle.keyPem);
    const cert = new X509Certificate(bundle.certPems[0]);
    if (!cert.ca) return "the certificate is not a CA";
    if (!cert.checkPrivateKey(key)) return "the key does not match the certificate";
    if (!cert.verify(cert.publicKey)) return "the certificate's signature is invalid";
    if (new Date(cert.validTo) <= now) return `it expired on ${cert.validTo}`;
    return { certPem: bundle.certPems[0], key, cert };
  } catch (err) {
    return `it cannot be read (${(err as Error).message})`;
  }
}

/** Load the local CA, creating it only if it has never existed. */
export function loadOrCreateCa(
  dir: string,
  now: Date,
  host = osHostname(),
): { ca: LocalCa; created: boolean } {
  const path = join(dir, "ca.pem");
  if (existsSync(path)) {
    const ca = readCa(readFileSync(path, "utf8"), now);
    if (typeof ca !== "string") return { ca: { path, ...ca }, created: false };
    throw new TlsMaterialError(
      `The local certificate authority ${path} is unusable: ${ca}. It is never replaced ` +
        "automatically, because teammates trust it. To start over, move that file aside and restart; " +
        "everyone who installed the old certificate must then install the new one.",
    );
  }
  const key = newKey();
  const publicKey = createPublicKey(key);
  const commonName = `DFIR Companion Local CA (${host})`;
  const certPem = buildCertificatePem({
    subjectCommonName: commonName,
    issuerCommonName: commonName,
    publicKey,
    signingKey: key,
    issuerPublicKey: publicKey,
    notBefore: new Date(now.getTime() - 3_600_000), // tolerate a client clock a little behind
    notAfter: new Date(now.getTime() + CA_VALIDITY_DAYS * DAY_MS),
    isCa: true,
  });
  writePrivateFile(path, keyPemOf(key) + certPem);
  return { ca: { path, certPem, key, cert: new X509Certificate(certPem) }, created: true };
}

const DNS_NAME = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

function normalizeIp(raw: string): string | undefined {
  if (raw.includes("%")) return undefined; // scoped (link-local) IPv6 cannot go in a certificate
  if (isIP(raw) === 4) return raw;
  if (isIP(raw) !== 6) return undefined;
  return new URL(`http://[${raw}]`).hostname.slice(1, -1);
}

/** Every name the generated server certificate should cover, sorted so a change is detectable. */
export function certNamesFor(
  extra: readonly string[],
  host = osHostname(),
  interfaces: ReturnType<typeof networkInterfaces> = networkInterfaces(),
): CertNames {
  const dns = new Set(["localhost"]);
  const ips = new Set(["127.0.0.1", "::1"]);
  const rejected: string[] = [];
  if (DNS_NAME.test(host.toLowerCase())) dns.add(host.toLowerCase());
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.internal || entry.address.toLowerCase().startsWith("fe80:")) continue;
      const ip = normalizeIp(entry.address);
      if (ip) ips.add(ip);
    }
  }
  for (const raw of extra) {
    const ip = normalizeIp(raw.replace(/^\[|\]$/g, ""));
    if (ip) ips.add(ip);
    else if (DNS_NAME.test(raw.toLowerCase())) dns.add(raw.toLowerCase());
    else rejected.push(raw);
  }
  return { dns: [...dns].sort(), ips: [...ips].sort(), rejected };
}

const namesLine = (names: CertNames): string => [...names.dns, ...names.ips].join(",");

/** The current server certificate if it can be kept, else the reason it cannot. */
function keepable(text: string, ca: LocalCa, names: CertNames, now: Date): ServerMaterial | string {
  const bundle = parseBundle(text);
  if (!bundle.keyPem || !bundle.certPems[0]) return "unreadable";
  try {
    const cert = new X509Certificate(bundle.certPems[0]);
    if (!cert.checkPrivateKey(createPrivateKey(bundle.keyPem))) return "key mismatch";
    if (!cert.checkIssued(ca.cert) || !cert.verify(ca.cert.publicKey)) return "issued by a different CA";
    if (new Date(cert.validTo).getTime() - now.getTime() < RENEW_BEFORE_DAYS * DAY_MS) return "expiring";
    if (bundle.names !== namesLine(names)) return "names changed";
    return { keyPem: bundle.keyPem, certPem: bundle.certPems[0], summary: summarize(cert) };
  } catch {
    return "unreadable";
  }
}

function existingKey(text: string | undefined): PrivateKey | undefined {
  const keyPem = text ? parseBundle(text).keyPem : undefined;
  try {
    return keyPem ? createPrivateKey(keyPem) : undefined;
  } catch {
    return undefined;
  }
}

/** The server certificate, re-issued from `ca` only when the current one cannot be kept. */
export function ensureServerCert(
  dir: string,
  ca: LocalCa,
  names: CertNames,
  now: Date,
): ServerMaterial & { reissued?: string } {
  const path = join(dir, "server.pem");
  const text = existsSync(path) ? readFileSync(path, "utf8") : undefined;
  const kept = text === undefined ? "missing" : keepable(text, ca, names, now);
  if (typeof kept !== "string") return kept;

  const key = existingKey(text) ?? newKey();
  const caExpiry = new Date(ca.cert.validTo).getTime();
  const certPem = buildCertificatePem({
    subjectCommonName: names.dns.find((n) => n !== "localhost") ?? "localhost",
    issuerCommonName: /CN=([^\n]+)/.exec(ca.cert.subject)?.[1] ?? "DFIR Companion Local CA",
    publicKey: createPublicKey(key),
    signingKey: ca.key,
    issuerPublicKey: ca.cert.publicKey,
    notBefore: new Date(now.getTime() - 3_600_000),
    notAfter: new Date(Math.min(now.getTime() + SERVER_VALIDITY_DAYS * DAY_MS, caExpiry)),
    isCa: false,
    dnsNames: names.dns,
    ipAddresses: names.ips,
  });
  const keyPem = keyPemOf(key);
  writePrivateFile(path, `# names: ${namesLine(names)}\n${keyPem}${certPem}`);
  return { keyPem, certPem, summary: summarize(new X509Certificate(certPem)), reissued: kept };
}

function readTlsFile(file: string, what: string): string {
  try {
    return readFileSync(file, "utf8");
  } catch (err) {
    throw new TlsMaterialError(`cannot read the HTTPS ${what} file ${file}: ${(err as Error).message}`);
  }
}

/** An operator's own certificate + key files, validated. Never renewed here. */
export function loadUserCertificate(certFile: string, keyFile: string): ServerMaterial {
  const certPems = parseBundle(readTlsFile(certFile, "certificate")).certPems;
  const keyBundle = parseBundle(readTlsFile(keyFile, "key"));
  if (keyBundle.encryptedKey) {
    throw new TlsMaterialError(
      `the HTTPS key file ${keyFile} is password-protected; supply an unencrypted key`,
    );
  }
  if (!keyBundle.keyPem || !certPems[0]) {
    throw new TlsMaterialError("the HTTPS certificate or key file holds no PEM certificate/private key");
  }
  const cert = new X509Certificate(certPems[0]);
  if (!cert.checkPrivateKey(createPrivateKey(keyBundle.keyPem))) {
    throw new TlsMaterialError(`the HTTPS key ${keyFile} does not belong to the certificate ${certFile}`);
  }
  return { keyPem: keyBundle.keyPem, certPem: certPems.join(""), summary: summarize(cert) };
}
