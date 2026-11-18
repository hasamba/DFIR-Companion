// Who issued the certificate this server is shown for a host (#2685) — asked only after a request
// failed with a certificate-trust error, so the analyst can see "issued by <proxy CA>" instead of
// guessing. Node's TLS error carries no certificate, so this opens a SEPARATE connection that
// completes the handshake without verifying, reads the leaf's issuer, and closes at once. Nothing
// is ever written to that socket: no HTTP request, no token, no secret.

import { isIP } from "node:net";
import { connect, type PeerCertificate } from "node:tls";

export type PeerIssuerFn = (hostname: string, port: number) => Promise<string | undefined>;

const ISSUER_TIMEOUT_MS = 5_000;
const ISSUER_MAX = 200;

/** "O=…, CN=…" from a certificate's issuer, or undefined. */
export function issuerLabel(cert: Partial<PeerCertificate> | undefined): string | undefined {
  const issuer = cert?.issuer as Record<string, unknown> | undefined;
  if (!issuer) return undefined;
  const parts = (["O", "CN"] as const)
    .map((k) => {
      const v = issuer[k];
      const s = Array.isArray(v) ? v.join(" / ") : typeof v === "string" ? v : "";
      return s ? `${k}=${s}` : "";
    })
    .filter(Boolean);
  const label = parts
    .join(", ")
    .replace(/[\p{Cc}"]/gu, "")
    .slice(0, ISSUER_MAX);
  return label || undefined;
}

/** The leaf certificate's issuer as this server sees it, or undefined on any failure. */
export const peerIssuer: PeerIssuerFn = (hostname, port) =>
  new Promise((resolve) => {
    let settled = false;
    const done = (v: string | undefined) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(v);
    };
    // Diagnostic only: the handshake is not trusted and the socket carries no data.
    const socket = connect({
      host: hostname,
      port,
      ...(isIP(hostname) ? {} : { servername: hostname }),
      rejectUnauthorized: false,
    });
    const timer = setTimeout(() => done(undefined), ISSUER_TIMEOUT_MS);
    socket.once("secureConnect", () => done(issuerLabel(socket.getPeerCertificate())));
    socket.once("error", () => done(undefined));
  });
