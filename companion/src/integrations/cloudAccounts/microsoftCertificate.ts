// The PEM a Microsoft app-only sign-in needs (#2315), from either stored form of the certificate.
//
// @azure/identity's ClientCertificateCredential takes PEM only, and Node cannot read a PKCS#12
// (PFX) file's key out — so a PFX account is opened here with node-forge, IN MEMORY ONLY: the
// private key never touches the disk, not even a temp file. The key and certificate leave forge as
// DER and are turned into PEM by Node's own crypto (createPrivateKey / X509Certificate), so this
// file holds no PEM marker and handles RSA and EC keys alike (forge itself only models RSA).
//
// Every failure is a CertificateError with FIXED text: a PFX library's message can quote its input,
// and that input is a private key or its password.

import { createPrivateKey, X509Certificate, type KeyObject } from "node:crypto";
import forge, { type asn1, type pki, type pkcs12 } from "node-forge";
import type { MicrosoftSecrets, MicrosoftSettings } from "./types.js";
import { pemBodyLines } from "./types.js";

/** The stored certificate cannot be used. The message is fixed text, never a secret. */
export class CertificateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CertificateError";
  }
}

export const PFX_UNREADABLE =
  "the stored PFX certificate could not be opened (wrong password or unsupported format)";
const PFX_NO_KEY = "the stored PFX certificate holds no private key";
const PFX_NO_CERT = "the stored PFX certificate holds no certificate for its private key";
const NO_PEM = "the account has no stored certificate";

type Bag = { key?: unknown; cert?: unknown; asn1?: asn1.Asn1 };

function bagsOf(p12: pkcs12.Pkcs12Pfx, type: string): Bag[] {
  return p12.getBags({ bagType: type })[type] ?? [];
}

function keyDer(bag: Bag): Buffer {
  // forge parses RSA keys; any other algorithm stays as its decrypted PrivateKeyInfo ASN.1.
  const info = bag.key
    ? forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(bag.key as pki.rsa.PrivateKey))
    : bag.asn1;
  if (!info) throw new CertificateError(PFX_NO_KEY);
  return Buffer.from(forge.asn1.toDer(info).getBytes(), "binary");
}

function certDer(bag: Bag): Buffer | undefined {
  const asn1 = bag.cert ? forge.pki.certificateToAsn1(bag.cert as pki.Certificate) : bag.asn1;
  return asn1 ? Buffer.from(forge.asn1.toDer(asn1).getBytes(), "binary") : undefined;
}

function openPfx(pfxBase64: string, password: string): pkcs12.Pkcs12Pfx {
  try {
    const der = Buffer.from(pfxBase64, "base64").toString("binary");
    return forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(der), password);
  } catch {
    throw new CertificateError(PFX_UNREADABLE);
  }
}

function privateKeyOf(p12: pkcs12.Pkcs12Pfx): KeyObject {
  const oids = forge.pki.oids;
  const bags = [...bagsOf(p12, oids.pkcs8ShroudedKeyBag), ...bagsOf(p12, oids.keyBag)];
  if (!bags.length) throw new CertificateError(PFX_NO_KEY);
  try {
    return createPrivateKey({ key: keyDer(bags[0]), format: "der", type: "pkcs8" });
  } catch (err) {
    if (err instanceof CertificateError) throw err;
    throw new CertificateError(PFX_UNREADABLE);
  }
}

/** The certificates in the PFX, the one matching the private key first (the chain after it). */
function certificatesFor(p12: pkcs12.Pkcs12Pfx, key: KeyObject): X509Certificate[] {
  const certs: X509Certificate[] = [];
  for (const bag of bagsOf(p12, forge.pki.oids.certBag)) {
    const der = certDer(bag);
    if (!der) continue;
    try {
      certs.push(new X509Certificate(der));
    } catch {
      // A bag that is not an X.509 certificate is skipped, never guessed at.
    }
  }
  const leaf = certs.find((c) => c.checkPrivateKey(key));
  if (!leaf) throw new CertificateError(PFX_NO_CERT);
  return [leaf, ...certs.filter((c) => c !== leaf)];
}

/** A PFX (base64) and its password → one PEM text: the leaf certificate, its chain, the key. */
export function pfxToPem(pfxBase64: string, password: string): string {
  const p12 = openPfx(pfxBase64, password);
  const key = privateKeyOf(p12);
  const certs = certificatesFor(p12, key);
  const keyPem = key.export({ type: "pkcs8", format: "pem" }).toString();
  return [...certs.map((c) => c.toString().trim()), keyPem.trim()].join("\n") + "\n";
}

/** The account's certificate as PEM: stored PEM as is, or a PFX opened in memory. */
export function microsoftCertificatePem(settings: MicrosoftSettings, secrets: MicrosoftSecrets): string {
  if (settings.certificateFormat === "pfx") {
    if (!secrets.pfxBase64) throw new CertificateError(NO_PEM);
    return pfxToPem(secrets.pfxBase64, secrets.pfxPassword ?? "");
  }
  if (!secrets.certificatePem) throw new CertificateError(NO_PEM);
  return secrets.certificatePem;
}

/** The pieces of a derived PEM a log line could carry, for the redaction list. */
export function derivedSecretParts(pem: string): string[] {
  return [pem, ...pemBodyLines(pem)];
}
