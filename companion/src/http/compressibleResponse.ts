import { gzip } from "node:zlib";
import { promisify } from "node:util";
import type { Request, Response } from "express";

/**
 * Gzip a static text response when the client asks for it.
 *
 * The dashboard document is ~507 KB of markup and inline script and was served uncompressed, along
 * with the ~140 first-party JS files beside it. On the loopback the tool is designed for that costs
 * nothing, but it is the whole cost on the public demo, on a VPN-hosted deployment, and for an
 * analyst opening a case over field connectivity — a throttled run measured 57 s to first paint.
 *
 * Built on node:zlib rather than the `compression` middleware on purpose: this ships as a
 * single-file SEA binary, and one more runtime dependency in that bundle needs to earn itself. Two
 * call sites and roughly forty lines do not justify it.
 *
 * Correctness notes:
 *  - `Vary: Accept-Encoding` is set on EVERY response, compressed or not. Without it a shared cache
 *    can hand a gzipped body to a client that never asked for one.
 *  - Express computes its ETag over what is actually sent, so the encoded body gets its own tag and
 *    conditional requests stay consistent.
 *  - A client that does not offer gzip gets the identity bytes unchanged.
 */
const gzipAsync = promisify(gzip);

/** Below this, framing and CPU cost more than the transfer saves. */
const MIN_COMPRESS_BYTES = 1024;

/**
 * Whether this client will actually take gzip.
 *
 * Deliberately not a substring test for "gzip": `Accept-Encoding: gzip;q=0` NAMES gzip in order to
 * FORBID it, and matching the token would send that client a body it has said it cannot use. The
 * quality values are what carry the meaning, so the negotiation is delegated to Express, which
 * parses them.
 */
function acceptsGzip(req: Request): boolean {
  if (typeof req.acceptsEncodings === "function") {
    return req.acceptsEncodings("gzip") === "gzip";
  }
  // Only reached by a hand-rolled request object in a test; keep the q=0 rule rather than
  // falling back to a plain token match that contradicts the function above.
  const header = req.headers["accept-encoding"];
  const raw = Array.isArray(header) ? header.join(",") : (header ?? "");
  return raw
    .split(",")
    .map((part) => part.trim())
    .some((part) => {
      const [token, ...params] = part.split(";").map((s) => s.trim());
      if (!/^gzip$/i.test(token)) return false;
      const q = params.find((p) => /^q=/i.test(p));
      return !q || Number(q.slice(2)) > 0;
    });
}

/**
 * Send `body` as `contentType`, gzipped when the request allows it.
 *
 * Never throws on a compression failure: it falls back to the identity body, because failing to
 * shrink a response is not a reason to fail the request.
 */
export async function sendMaybeGzipped(
  req: Request,
  res: Response,
  contentType: string,
  body: string | Buffer,
): Promise<void> {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  // vary() APPENDS; set() would replace. originGuard has already written `Vary: Origin` on an
  // allowed cross-origin request, because Access-Control-Allow-Origin echoes the caller — dropping
  // it lets a shared cache hand one origin's response to another, carrying a CORS header that
  // makes it unreadable.
  res.type(contentType).vary("Accept-Encoding");
  if (buf.byteLength < MIN_COMPRESS_BYTES || !acceptsGzip(req)) {
    res.send(buf);
    return;
  }
  try {
    const encoded = await gzipAsync(buf);
    res.set("Content-Encoding", "gzip").send(encoded);
  } catch {
    res.send(buf);
  }
}
