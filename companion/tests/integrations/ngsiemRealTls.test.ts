import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:https";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { X509Certificate } from "node:crypto";
import { ensureServerCert, loadOrCreateCa } from "../../src/http/tlsMaterial.js";
import { classifyFailure } from "../../src/integrations/crowdstrike/fetchFailure.js";
import { describeNgsiemFailure } from "../../src/integrations/crowdstrike/ngsiemSearch.js";
import { ngsiemFetchFor } from "../../src/integrations/crowdstrike/ngsiemTransport.js";
import { peerIssuer } from "../../src/integrations/crowdstrike/tlsPeerIssuer.js";

// #2685, the user's real failure: a TLS-inspecting proxy presents a certificate from a private CA.
// A real local HTTPS server on a private CA — Node's real error shape, the real issuer check and
// the real DFIR_CROWDSTRIKE_SIEM_CA bundle, no stubs.

let dir: string;
let server: Server;
let base: string;
let caPath: string;
let caSubject: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "dfir-ngsiem-tls-"));
  const now = new Date();
  const { ca } = loadOrCreateCa(dir, now, "ngsiem-test");
  const leaf = ensureServerCert(dir, ca, { dns: ["localhost"], ips: ["127.0.0.1"], rejected: [] }, now);
  caPath = join(dir, "proxy-ca.pem");
  writeFileSync(caPath, ca.certPem);
  caSubject = new X509Certificate(ca.certPem).subject;
  server = createServer({ key: leaf.keyPem, cert: leaf.certPem }, (_req, res) => {
    res.writeHead(201, { "content-type": "application/json" });
    res.end(JSON.stringify({ access_token: "t", expires_in: 1799 }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  base = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  rmSync(dir, { recursive: true, force: true });
});

describe("NG-SIEM against a real private-CA TLS server (#2685)", () => {
  it("without the bundle the request fails, classified as a trust failure naming the real issuer", async () => {
    const err = await ngsiemFetchFor(undefined)(`${base}/oauth2/token`, { method: "POST" }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeDefined();
    expect(classifyFailure(err).kind).toBe("trust");
    const issuer = await peerIssuer("127.0.0.1", Number(new URL(base).port));
    expect(issuer).toBeTruthy();
    const cn = /CN=([^\n]+)/.exec(caSubject)?.[1] ?? "";
    expect(issuer).toContain(cn);
    const sentence = await describeNgsiemFailure(err, base);
    expect(sentence).toContain(`issued by "${issuer}"`);
    expect(sentence).toContain("DFIR_CROWDSTRIKE_SIEM_CA");
  });

  it("with DFIR_CROWDSTRIKE_SIEM_CA pointing at the proxy's root, the same request succeeds", async () => {
    const res = await ngsiemFetchFor(caPath)(`${base}/oauth2/token`, { method: "POST" });
    expect(res.status).toBe(201);
  });
});
