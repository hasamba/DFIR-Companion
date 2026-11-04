import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { X509Certificate, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TlsMaterialError,
  certNamesFor,
  ensureServerCert,
  loadOrCreateCa,
  loadUserCertificate,
} from "../../src/http/tlsMaterial.js";

const DAY = 86_400_000;
const NOW = new Date("2026-11-04T10:00:00Z");
const NO_INTERFACES = {};
const names = certNamesFor([], "dfir-box", NO_INTERFACES);

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "dfir-tls-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("local CA (#2285)", () => {
  it("is created once, owner-only, and reused on the next start", () => {
    const first = loadOrCreateCa(dir, NOW, "dfir-box");
    expect(first.created).toBe(true);
    if (process.platform !== "win32") expect(statSync(join(dir, "ca.pem")).mode & 0o777).toBe(0o600);
    const second = loadOrCreateCa(dir, NOW, "dfir-box");
    expect(second.created).toBe(false);
    expect(second.ca.cert.fingerprint256).toBe(first.ca.cert.fingerprint256);
    expect(second.ca.cert.ca).toBe(true);
  });

  it("is never silently replaced when damaged or expired", () => {
    loadOrCreateCa(dir, NOW, "dfir-box");
    const path = join(dir, "ca.pem");
    expect(() => loadOrCreateCa(dir, new Date(NOW.getTime() + 3651 * DAY))).toThrow(TlsMaterialError);
    const damaged = readFileSync(path, "utf8").replace(
      /-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----\n/,
      "",
    );
    writeFileSync(path, damaged);
    expect(() => loadOrCreateCa(dir, NOW)).toThrow(/never replaced automatically/);
    expect(readFileSync(path, "utf8")).toBe(damaged); // the failed load wrote nothing
  });
});

describe("server certificate (#2285)", () => {
  it("chains to the CA, covers the names, and is reused while healthy", () => {
    const { ca } = loadOrCreateCa(dir, NOW, "dfir-box");
    const first = ensureServerCert(dir, ca, names, NOW);
    expect(first.reissued).toBe("missing");
    const cert = new X509Certificate(first.certPem);
    expect(cert.checkIssued(ca.cert)).toBe(true);
    expect(cert.checkHost("dfir-box")).toBe("dfir-box");
    expect(cert.checkIP("127.0.0.1")).toBe("127.0.0.1");
    if (process.platform !== "win32") expect(statSync(join(dir, "server.pem")).mode & 0o777).toBe(0o600);
    const again = ensureServerCert(dir, ca, names, NOW);
    expect(again.reissued).toBeUndefined();
    expect(again.summary.fingerprint256).toBe(first.summary.fingerprint256);
  });

  it("renews silently from the same CA 30 days before expiry, keeping the key", () => {
    const { ca } = loadOrCreateCa(dir, NOW, "dfir-box");
    const first = ensureServerCert(dir, ca, names, NOW);
    const later = new Date(NOW.getTime() + 800 * DAY);
    const renewed = ensureServerCert(dir, ca, names, later);
    expect(renewed.reissued).toBe("expiring");
    expect(renewed.keyPem).toBe(first.keyPem);
    expect(new X509Certificate(renewed.certPem).checkIssued(ca.cert)).toBe(true);
    expect(renewed.summary.validTo.getTime()).toBeGreaterThan(first.summary.validTo.getTime());
  });

  it("re-issues when the names change, including a removed name", () => {
    const { ca } = loadOrCreateCa(dir, NOW, "dfir-box");
    ensureServerCert(dir, ca, certNamesFor(["dfir.lab"], "dfir-box", NO_INTERFACES), NOW);
    const dropped = ensureServerCert(dir, ca, names, NOW);
    expect(dropped.reissued).toBe("names changed");
    expect(new X509Certificate(dropped.certPem).checkHost("dfir.lab")).toBeUndefined();
  });

  it("never outlives the CA", () => {
    const { ca } = loadOrCreateCa(dir, NOW, "dfir-box");
    const nearCaEnd = new Date(NOW.getTime() + 3600 * DAY);
    const leaf = ensureServerCert(dir, ca, names, nearCaEnd);
    expect(leaf.summary.validTo.getTime()).toBeLessThanOrEqual(new Date(ca.cert.validTo).getTime());
  });

  it("re-issues a certificate signed by a different CA", () => {
    const { ca } = loadOrCreateCa(dir, NOW, "dfir-box");
    ensureServerCert(dir, ca, names, NOW);
    const otherDir = mkdtempSync(join(tmpdir(), "dfir-tls-other-"));
    try {
      const other = loadOrCreateCa(otherDir, NOW, "other").ca;
      expect(ensureServerCert(dir, other, names, NOW).reissued).toBe("issued by a different CA");
    } finally {
      rmSync(otherDir, { recursive: true, force: true });
    }
  });
});

describe("certNamesFor", () => {
  it("collects host, interfaces and extras; rejects wildcards and scoped IPv6", () => {
    const result = certNamesFor(["DFIR.Lab", "*.lab", "fe80::1%eth0", "[fd00::0:5]", "10.9.8.7"], "Box-1", {
      eth0: [
        { address: "192.168.1.50", family: "IPv4", internal: false } as never,
        { address: "fe80::abcd", family: "IPv6", internal: false } as never,
      ],
      lo: [{ address: "127.0.0.1", family: "IPv4", internal: true } as never],
    });
    expect(result.dns).toEqual(["box-1", "dfir.lab", "localhost"]);
    expect(result.ips).toEqual(["10.9.8.7", "127.0.0.1", "192.168.1.50", "::1", "fd00::5"]);
    expect(result.rejected).toEqual(["*.lab", "fe80::1%eth0"]);
  });
});

describe("loadUserCertificate", () => {
  it("accepts a matching pair with its chain and refuses a mismatched key", () => {
    const { ca } = loadOrCreateCa(dir, NOW, "dfir-box");
    const leaf = ensureServerCert(dir, ca, names, NOW);
    writeFileSync(join(dir, "c.pem"), leaf.certPem + ca.certPem);
    writeFileSync(join(dir, "k.pem"), leaf.keyPem);
    const loaded = loadUserCertificate(join(dir, "c.pem"), join(dir, "k.pem"));
    expect(loaded.summary.fingerprint256).toBe(leaf.summary.fingerprint256);
    expect(loaded.certPem).toContain(ca.certPem.trim());

    const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
    writeFileSync(join(dir, "k2.pem"), other.export({ type: "pkcs8", format: "pem" }).toString());
    expect(() => loadUserCertificate(join(dir, "c.pem"), join(dir, "k2.pem"))).toThrow(/does not belong/);
    expect(() => loadUserCertificate(join(dir, "nope.pem"), join(dir, "k.pem"))).toThrow(/cannot read/);
  });

  it("refuses a password-protected key with a clear message", () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const enc = privateKey.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: "x" });
    writeFileSync(join(dir, "enc.pem"), enc.toString());
    writeFileSync(join(dir, "c.pem"), "");
    expect(() => loadUserCertificate(join(dir, "c.pem"), join(dir, "enc.pem"))).toThrow(/password-protected/);
  });
});
