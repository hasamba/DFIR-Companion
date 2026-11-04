/**
 * Built-in HTTPS routes (#2285).
 *
 *   GET /tls/ca.crt  — the local CA certificate, so a teammate installs it from the server itself
 *                      instead of having files emailed around. PUBLIC (auth/policy.ts): the login
 *                      page links it before anyone signs in, and it is a public certificate — the
 *                      CA's private key never leaves the server. 404 when the server presents an
 *                      operator's own certificate, which this CA does not vouch for.
 *   GET /tls/info    — what is being served: mode, fingerprints, expiry, warnings. Signed-in users.
 *
 * A CA fetched over a connection the browser does not trust yet is only as good as its fingerprint:
 * the docs tell teammates to compare it with the one the server prints at startup.
 */
import type { Express, Request, Response } from "express";
import type { PreparedHttps } from "../http/httpsStartup.js";

export function registerTlsRoutes(app: Express, https: Pick<PreparedHttps, "status" | "caCertPem">): void {
  app.get("/tls/ca.crt", (_req: Request, res: Response) => {
    const pem = https.caCertPem();
    if (!pem) {
      res
        .status(404)
        .type("text/plain")
        .send("This server presents its own certificate files; there is no local CA to download.\n");
      return;
    }
    res
      .set({
        "Content-Type": "application/x-x509-ca-cert",
        "Content-Disposition": 'attachment; filename="dfir-companion-ca.crt"',
        "Cache-Control": "no-cache",
      })
      .send(pem);
  });

  app.get("/tls/info", (_req: Request, res: Response) => {
    res.json(https.status());
  });
}
