import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";

/**
 * geoTiles domain: the basemap under the Geographic Map panel (#133), fetched by the SERVER and
 * served from this origin.
 *
 *   - GET /geo-tiles/:z/:x/:y.png  — one OpenStreetMap-scheme raster tile.
 *
 * ── WHY A PROXY AND NOT A CSP EXCEPTION ──────────────────────────────────────────────────────
 * Leaflet loads tiles as plain <img>, and http/securityHeaders.ts sends `img-src 'self' data:`.
 * A browser therefore refused every tile the moment the panel pointed straight at
 * tile.openstreetmap.org: the panel drew its markers (SVG, same-origin) over an empty gray canvas
 * and looked broken with nothing in the UI to say why.
 *
 * Widening img-src to the tile host would fix the symptom and break the invariant that CSP module
 * exists to hold — the dashboard makes zero cross-origin requests, so a missed rendering escape has
 * no channel to beacon case data out. It would also point the analyst's browser at a third party:
 * a tile request stream is a coarse but real record of which part of the world a live case is
 * looking at, keyed to the examiner's own IP.
 *
 * Proxying keeps both. The CSP is untouched, the browser talks only to the companion, and the one
 * process that reaches the internet is the one already doing every enrichment lookup.
 *
 * ── WHAT THIS WILL NOT PROXY ─────────────────────────────────────────────────────────────────
 * The URL is built from operator config (DFIR_GEOMAP_TILE_URL) plus three integers parsed out of
 * the path, so a request cannot steer the destination. On the way back, only an `image/*` response
 * under {@link MAX_TILE_BYTES} is forwarded: serving arbitrary upstream bytes from this origin is
 * precisely the hole the proxy is meant to avoid opening, so a tile server answering with an HTML
 * captive-portal page gets a 502 rather than a same-origin document.
 */

/** OpenStreetMap's public tile servers — the default when the operator names no tile server. */
export const DEFAULT_TILE_TEMPLATE = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";

/** `{s}` rotation. Picked from the tile's own coordinates, so a tile always maps to one host. */
const SUBDOMAINS = ["a", "b", "c"] as const;

/** Deepest zoom accepted. OSM raster ends at 19; anything past it is a malformed request. */
const MAX_ZOOM = 19;

/** Upstream timeout. A tile the analyst is waiting on is worth less the longer it takes. */
const TILE_TIMEOUT_MS = 8_000;

/** A 256px PNG tile is tens of KB. Anything past this is not a tile. */
const MAX_TILE_BYTES = 2 * 1024 * 1024;

/** In-process tile cache — bounds the load a pan/zoom session puts on the upstream server. */
const CACHE_MAX_TILES = 512;

/**
 * OSM's tile usage policy requires a User-Agent identifying the application, and answers a generic
 * one with 403. Sent to every configured tile server, not just OSM: an internal one logging who
 * asked is a feature.
 */
const TILE_USER_AGENT = "DFIR-Companion/1.0 (+https://github.com/hasamba/DFIR-Companion)";

/** The configured tile-URL template, read at request time so /settings/reload takes effect. */
export function tileTemplate(env: NodeJS.ProcessEnv = process.env): string {
  return (env.DFIR_GEOMAP_TILE_URL || "").trim() || DEFAULT_TILE_TEMPLATE;
}

/**
 * A path segment that is exactly a small non-negative integer, or null.
 *
 * NOT `parseInt`: it reads "12abc" as 12 and "0x10" as 0, so a segment carrying a payload would be
 * silently accepted and echoed back into a cache key. Match the whole segment or reject it.
 */
function parseTileInt(raw: string): number | null {
  if (!/^\d{1,3}$/.test(raw)) return null;
  return Number(raw);
}

/**
 * The upstream URL for one tile, or null if the coordinates are not a real tile.
 *
 * Zoom z has 2^z tiles per axis, so x and y are bounded BY z — not by a constant. Rejecting
 * out-of-range coordinates here keeps a scripted client from turning the proxy into a request
 * generator aimed at the tile server on our behalf.
 */
export function buildTileUrl(template: string, z: number, x: number, y: number): string | null {
  if (!Number.isInteger(z) || z < 0 || z > MAX_ZOOM) return null;
  const span = 2 ** z;
  if (!Number.isInteger(x) || x < 0 || x >= span) return null;
  if (!Number.isInteger(y) || y < 0 || y >= span) return null;
  const substituted = template
    .replaceAll("{s}", SUBDOMAINS[(x + y) % SUBDOMAINS.length])
    .replaceAll("{z}", String(z))
    .replaceAll("{x}", String(x))
    .replaceAll("{y}", String(y))
    // Leaflet's retina placeholder. The proxy asks for the 1x tile, so it resolves to nothing.
    .replaceAll("{r}", "");
  let parsed: URL;
  try {
    parsed = new URL(substituted);
  } catch {
    return null;
  }
  // file: and data: would read the server's own disk or smuggle bytes through this origin. The
  // template is operator config rather than user input, so this catches a typo, not an attack.
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  return parsed.toString();
}

interface CachedTile {
  body: Buffer;
  contentType: string;
}

/** Insertion-ordered, refreshed on hit — a Map iterates oldest-first, which is the eviction order. */
const tileCache = new Map<string, CachedTile>();

function cacheGet(key: string): CachedTile | undefined {
  const hit = tileCache.get(key);
  if (!hit) return undefined;
  tileCache.delete(key);
  tileCache.set(key, hit);
  return hit;
}

function cachePut(key: string, tile: CachedTile): void {
  tileCache.set(key, tile);
  while (tileCache.size > CACHE_MAX_TILES) {
    const oldest = tileCache.keys().next().value;
    if (oldest === undefined) break;
    tileCache.delete(oldest);
  }
}

/** Test seam: drop the cache so one test's tiles cannot answer another's request. */
export function clearTileCache(): void {
  tileCache.clear();
}

function sendTile(res: Response, tile: CachedTile): void {
  res.setHeader("Content-Type", tile.contentType);
  // The bytes came from another server. nosniff stops a browser second-guessing the type we
  // verified above and rendering them as something executable.
  res.setHeader("X-Content-Type-Options", "nosniff");
  // A tile for a given z/x/y is stable. One day is long enough to make panning cheap and short
  // enough that repointing DFIR_GEOMAP_TILE_URL shows up without clearing the browser cache.
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.status(200).send(tile.body);
}

export function registerGeoTileRoutes(app: Express, ctx: RouteContext): void {
  const fetchTile = ctx.options.geoTileFetch ?? fetch;

  app.get("/geo-tiles/:z/:x/:y.png", async (req: Request, res: Response) => {
    const z = parseTileInt(req.params.z);
    const x = parseTileInt(req.params.x);
    const y = parseTileInt(req.params.y);
    if (z === null || x === null || y === null) {
      return res.status(400).json({ error: "tile coordinates must be integers" });
    }
    const template = tileTemplate();
    const url = buildTileUrl(template, z, x, y);
    if (!url) return res.status(400).json({ error: `no such tile: ${z}/${x}/${y}` });

    // Keyed by the template too, so repointing at an internal tile server does not serve the
    // previous server's tiles out of memory until the process restarts.
    const key = `${template}|${z}/${x}/${y}`;
    const cached = cacheGet(key);
    if (cached) return sendTile(res, cached);

    let upstream: Awaited<ReturnType<typeof fetch>>;
    try {
      upstream = await fetchTile(url, {
        signal: AbortSignal.timeout(TILE_TIMEOUT_MS),
        headers: { "User-Agent": TILE_USER_AGENT, Accept: "image/*" },
      });
    } catch (err) {
      return res.status(502).json({
        error: `tile server unreachable (${(err as Error).message}) — set DFIR_GEOMAP_TILE_URL to an internal tile server, or work with the map closed`,
      });
    }
    if (!upstream.ok) {
      return res.status(502).json({ error: `tile server returned HTTP ${upstream.status}` });
    }
    const contentType = (upstream.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    if (!contentType.startsWith("image/")) {
      return res.status(502).json({
        error: `tile server returned ${contentType || "no content type"}, not an image — check DFIR_GEOMAP_TILE_URL`,
      });
    }
    const declared = Number(upstream.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > MAX_TILE_BYTES) {
      return res.status(502).json({ error: "tile server returned an oversized response" });
    }
    let body: Buffer;
    try {
      body = Buffer.from(await upstream.arrayBuffer());
    } catch (err) {
      return res.status(502).json({ error: `tile download failed: ${(err as Error).message}` });
    }
    // Re-checked after reading: content-length is a claim, and a chunked response has none.
    if (body.byteLength > MAX_TILE_BYTES) {
      return res.status(502).json({ error: "tile server returned an oversized response" });
    }
    const tile: CachedTile = { body, contentType };
    cachePut(key, tile);
    return sendTile(res, tile);
  });
}
