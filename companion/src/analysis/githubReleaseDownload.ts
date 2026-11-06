// One verified download of a GitHub release asset, shared by the two rule updaters: the Sigma rule
// updater (#2204) and the detection-rule pack updater (#2349). The rules are the same for both:
//
//   - only GitHub's release hosts (isAllowedAssetUrl), checked on the URL the release named AND on
//     the URL the redirect chain landed on;
//   - only up to a size cap, read as a stream and cut off the moment it is exceeded;
//   - only when the bytes match the SHA-256 GitHub published for the asset. No digest → refused:
//     the analyst can download the file and use Install from file instead.
//
// The network call is injected (routes pass the SSRF-guarded fetchOutbound), so this file never
// decides how a connection is made and is testable without the network.

import { createHash } from "node:crypto";
import { isAllowedAssetUrl } from "./velociraptorRelease.js";

/** The shape of fetchOutbound's result that a download needs. */
export type ReleaseAssetFetch = (
  url: string,
  timeoutMs: number,
) => Promise<{ response: Response; url: URL; dispose: () => Promise<void> }>;

export interface VerifiedAssetRequest {
  url: string;
  /** Lower-case hex SHA-256 GitHub published for the asset. */
  sha256?: string;
  maxBytes: number;
  /** Names the download in every message, e.g. "Sigma release", "rule pack manifest". */
  label: string;
  timeoutMs: number;
}

export const sha256Hex = (bytes: Buffer | string): string => createHash("sha256").update(bytes).digest("hex");

const unexpectedHost = (label: string, where: string): Error =>
  new Error(
    `refusing the ${label} from an unexpected host (${where}); only GitHub's release hosts are accepted`,
  );

/** Read a response body, refusing as soon as it passes `maxBytes`. */
export async function readCappedBody(
  body: ReadableStream<Uint8Array>,
  maxBytes: number,
  label: string,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  const reader = body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      const size = maxBytes >= 1024 * 1024 ? `${maxBytes / (1024 * 1024)} MB` : `${maxBytes} bytes`;
      throw new Error(`the ${label} download is larger than ${size}`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

/** The asset's bytes, from GitHub's release hosts only, size-capped, verified against GitHub's digest. */
export async function downloadVerifiedAsset(
  req: VerifiedAssetRequest,
  fetchAsset: ReleaseAssetFetch,
): Promise<Buffer> {
  if (!req.sha256)
    throw new Error(
      `GitHub published no SHA-256 for this ${req.label}, so it cannot be verified; download it yourself and use Install from file`,
    );
  if (!isAllowedAssetUrl(req.url)) throw unexpectedHost(req.label, "as listed by the release");
  const fetched = await fetchAsset(req.url, req.timeoutMs);
  try {
    if (!isAllowedAssetUrl(fetched.url.href)) {
      await fetched.response.body?.cancel().catch(() => {});
      throw unexpectedHost(req.label, "after redirect");
    }
    if (!fetched.response.ok || !fetched.response.body)
      throw new Error(`GitHub returned ${fetched.response.status} downloading the ${req.label}`);
    const bytes = await readCappedBody(fetched.response.body, req.maxBytes, req.label);
    if (sha256Hex(bytes) !== req.sha256.toLowerCase())
      throw new Error(
        `the downloaded ${req.label} does not match GitHub's published SHA-256; nothing was installed`,
      );
    return bytes;
  } finally {
    await fetched.dispose();
  }
}
