import { createPrivateKey, X509Certificate } from "node:crypto";
import * as realFs from "node:fs";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CertificateError,
  PFX_UNREADABLE,
  derivedSecretParts,
  microsoftCertificatePem,
  pfxToPem,
} from "../../src/integrations/cloudAccounts/microsoftCertificate.js";
import type { MicrosoftSettings } from "../../src/integrations/cloudAccounts/types.js";
import { makeCertPem, makePfxBase64, makePfxBase64InMemory } from "../helpers/cloudAccountFixtures.js";

// #2315: a PFX account's PEM is made IN MEMORY — the private key never reaches the disk.

const writes = vi.hoisted(() => ({ calls: [] as string[] }));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const spy =
    (name: string, fn: (...a: never[]) => unknown) =>
    (...args: never[]) => {
      writes.calls.push(name);
      return fn(...args);
    };
  return {
    ...actual,
    writeFileSync: spy("writeFileSync", actual.writeFileSync),
    writeFile: spy("writeFile", actual.writeFile),
    appendFileSync: spy("appendFileSync", actual.appendFileSync),
    createWriteStream: spy("createWriteStream", actual.createWriteStream),
    openSync: spy("openSync", actual.openSync),
  };
});

const BEGIN = ["-----", "BEGIN"].join(""); // built at runtime: no PEM marker in the source
const settings = (format: "pem" | "pfx"): MicrosoftSettings => ({
  tenantId: "00000000-0000-4000-8000-000000000001",
  clientId: "00000000-0000-4000-8000-000000000002",
  certificateFormat: format,
});

function withEmptyTemp<T>(fn: () => T): { value: T; leftovers: string[] } {
  const dir = mkdtempSync(join(tmpdir(), "pfx-mem-"));
  const saved = { TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP };
  Object.assign(process.env, { TMPDIR: dir, TMP: dir, TEMP: dir });
  try {
    const value = fn();
    return { value, leftovers: readdirSync(dir) };
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    rmSync(dir, { recursive: true, force: true });
  }
}

afterEach(() => {
  writes.calls = [];
});

describe("pfxToPem", () => {
  it("turns a PFX into the leaf certificate and its key, in memory, writing no file", () => {
    const { pem } = makeCertPem();
    const pfx = makePfxBase64InMemory(pem, "pfx-pass-1"); // fixture first: the spies only watch the conversion
    writes.calls = [];
    const { value: out, leftovers } = withEmptyTemp(() => pfxToPem(pfx, "pfx-pass-1"));
    expect(writes.calls).toEqual([]);
    expect(leftovers).toEqual([]);
    expect(out.startsWith(`${BEGIN} CERTIFICATE`)).toBe(true);
    const cert = new X509Certificate(out);
    const key = createPrivateKey(out);
    expect(cert.checkPrivateKey(key)).toBe(true);
    expect(cert.fingerprint256).toBe(new X509Certificate(pem).fingerprint256);
  });

  it("reads an OpenSSL-made PFX (modern AES/PBKDF2 encryption) where openssl is installed", () => {
    const { pem } = makeCertPem();
    const pfx = makePfxBase64(pem, "pfx-pass-2");
    if (!pfx) return; // openssl is not installed here; the in-memory fixture above still runs
    const cert = new X509Certificate(pfxToPem(pfx, "pfx-pass-2"));
    expect(cert.fingerprint256).toBe(new X509Certificate(pem).fingerprint256);
  });

  it("refuses a wrong password with fixed text that quotes neither the password nor the file", () => {
    const pfx = makePfxBase64InMemory(makeCertPem().pem, "right-pass-sentinel");
    let caught: unknown;
    try {
      pfxToPem(pfx, "wrong-pass-sentinel");
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(CertificateError);
    const message = (caught as Error).message;
    expect(message).toBe(PFX_UNREADABLE);
    expect(message).not.toContain("sentinel");
    expect(message).not.toContain(pfx.slice(0, 16));
  });

  it("refuses bytes that are not a PFX", () => {
    expect(() => pfxToPem(Buffer.from("not a pfx").toString("base64"), "")).toThrow(PFX_UNREADABLE);
  });
});

describe("microsoftCertificatePem", () => {
  it("passes a stored PEM through unchanged", () => {
    const { pem } = makeCertPem();
    expect(microsoftCertificatePem(settings("pem"), { certificatePem: pem })).toBe(pem);
  });

  it("opens a stored PFX with its password", () => {
    const { pem } = makeCertPem();
    const pfxBase64 = makePfxBase64InMemory(pem, "pw-3");
    const out = microsoftCertificatePem(settings("pfx"), { pfxBase64, pfxPassword: "pw-3" });
    expect(new X509Certificate(out).fingerprint256).toBe(new X509Certificate(pem).fingerprint256);
  });

  it("refuses an account with no certificate", () => {
    expect(() => microsoftCertificatePem(settings("pem"), {})).toThrow(CertificateError);
    expect(() => microsoftCertificatePem(settings("pfx"), {})).toThrow(CertificateError);
  });

  it("lists the derived key's body lines for redaction", () => {
    const { pem, keyLines } = makeCertPem();
    const out = pfxToPem(makePfxBase64InMemory(pem, "pw-4"), "pw-4");
    const parts = derivedSecretParts(out);
    for (const line of keyLines) expect(parts).toContain(line);
  });
});

describe("the conversion module", () => {
  it("imports no filesystem module", () => {
    const src = readFileSync(
      join(import.meta.dirname, "../../src/integrations/cloudAccounts/microsoftCertificate.ts"),
      "utf8",
    );
    expect(src).not.toMatch(/from "(node:)?fs(\/promises)?"/);
    expect(realFs).toBeDefined();
  });
});
