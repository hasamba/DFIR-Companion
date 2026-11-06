import { isIP } from "node:net";
import { CloudTransportError } from "./destinationTls.js";

// Cloud metadata endpoints and the cloud transport (#2309 review).
//
// Ambient credentials on a cloud VM or container come from a METADATA endpoint on the machine's own
// link — AWS IMDS (169.254.169.254, fd00:ec2::254), the ECS/EKS container credential endpoints
// (169.254.170.2, 169.254.170.23) and the GCE metadata server (metadata.google.internal,
// 169.254.169.254). Those requests go DIRECT, never through DFIR_CLOUD_PROXY_URL: a proxy cannot
// reach a link-local address, and the endpoint only answers the machine it runs on. That is by
// design, and the SDKs send them with their own HTTP clients.
//
// Every one of those endpoints can be moved by an environment variable. Pointed at a normal host,
// the "metadata" request would leave the machine on the default trust and no proxy, bypassing the
// transport. So an override is accepted only when it still names a link-local or loopback address
// (or the GCE metadata name); anything else refuses the run with a message naming the variable.

const METADATA_NAMES = new Set(["localhost", "metadata.google.internal", "metadata.google.internal."]);

function hostOf(value: string): string | undefined {
  try {
    const url = new URL(value.includes("://") ? value : `http://${value}`);
    return url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  } catch {
    return undefined;
  }
}

/** True for a loopback or link-local address, or a metadata host name that resolves on-link. */
export function isOnLinkHost(host: string): boolean {
  if (METADATA_NAMES.has(host)) return true;
  const kind = isIP(host);
  if (kind === 4) return host.startsWith("127.") || host.startsWith("169.254.");
  if (kind === 6) {
    // ::1 loopback, fe80::/10 link-local, and AWS's own IPv6 metadata range fd00:ec2::/32.
    return host === "::1" || /^fe[89ab][0-9a-f]:/.test(host) || host.startsWith("fd00:ec2:");
  }
  return false;
}

/** Refuses the run when one of `names` in `env` moves a metadata endpoint off the machine's link. */
export function assertOnLinkMetadataEnv(env: NodeJS.ProcessEnv, names: readonly string[]): void {
  for (const name of names) {
    const value = env[name]?.trim();
    if (!value) continue;
    const host = hostOf(value);
    if (host && isOnLinkHost(host)) continue;
    throw new CloudTransportError(
      `${name} points the cloud metadata endpoint at a host off this machine's link. Metadata requests ` +
        "do not go through the cloud proxy and TLS settings, so cloud collection refuses it. Unset it, " +
        "or use a stored credential.",
    );
  }
}
