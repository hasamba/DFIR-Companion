import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import {
  buildTileUrl,
  tileTemplate,
  clearTileCache,
  DEFAULT_TILE_TEMPLATE,
} from "../../src/routes/geoTiles.js";
import { CSP_POLICY } from "../../src/http/securityHeaders.js";

// The basemap proxy behind the Geographic Map panel (#133).
//
// THE BUG THIS ROUTE EXISTS FOR: the panel pointed Leaflet straight at tile.openstreetmap.org
// while the companion served `img-src 'self' data:`. Leaflet loads tiles as <img>, so every tile
// was refused and the panel rendered its markers over an empty gray canvas. The first test below
// is the regression: the CSP still forbids a third-party image, so the tile URL has to be ours.

/** A one-pixel PNG — enough bytes for the proxy to treat as a real tile. */
const PNG_1PX = Buffer.from(
  "89504e470d0a1a0a0000000d4948445200000001000000010806000000" +
    "1f15c4890000000a49444154789c6360000002000100" +
    "05fe02fea7c1d9000000000049454e44ae426082",
  "hex",
);

function pngResponse(): Response {
  return new Response(PNG_1PX, { status: 200, headers: { "content-type": "image/png" } });
}

let app: ReturnType<typeof createApp>;
let cases: CaseStore;
let requested: string[];

async function appWith(geoTileFetch: typeof fetch): Promise<ReturnType<typeof createApp>> {
  const root = await mkdtemp(join(tmpdir(), "dfir-geotiles-"));
  cases = new CaseStore(root);
  return createApp(cases, { geoTileFetch });
}

beforeEach(async () => {
  clearTileCache();
  requested = [];
  app = await appWith(async (url) => {
    requested.push(String(url));
    return pngResponse();
  });
});

afterEach(() => {
  delete process.env.DFIR_GEOMAP_TILE_URL;
  clearTileCache();
});

describe("GET /geo-tiles/:z/:x/:y.png — the basemap the CSP allows", () => {
  // The regression test. If someone re-points the client at an external tile host, this is the
  // assertion that says why it will not render.
  it("keeps the CSP that made a third-party tile impossible", () => {
    expect(CSP_POLICY).toContain("img-src 'self' data:");
    expect(CSP_POLICY).not.toContain("tile.openstreetmap.org");
  });

  it("serves an upstream tile as a same-origin image", async () => {
    const res = await request(app).get("/geo-tiles/3/4/5.png");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("image/png");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["cache-control"]).toContain("max-age=");
    expect(Buffer.from(res.body).equals(PNG_1PX)).toBe(true);
    expect(requested).toEqual(["https://a.tile.openstreetmap.org/3/4/5.png"]);
  });

  it("answers a repeat request from cache instead of the tile server", async () => {
    await request(app).get("/geo-tiles/3/4/5.png");
    const res = await request(app).get("/geo-tiles/3/4/5.png");
    expect(res.status).toBe(200);
    expect(Buffer.from(res.body).equals(PNG_1PX)).toBe(true);
    expect(requested).toHaveLength(1);
  });

  // A tile at z=2 has 4 tiles per axis. x=9 is not a tile, and forwarding it would make the proxy
  // a request generator aimed at someone else's server.
  it("rejects coordinates that are not a tile at that zoom", async () => {
    const res = await request(app).get("/geo-tiles/2/9/0.png");
    expect(res.status).toBe(400);
    expect(requested).toEqual([]);
  });

  it("rejects a coordinate that is not a plain integer", async () => {
    const res = await request(app).get("/geo-tiles/3/4/5abc.png");
    expect(res.status).toBe(400);
    expect(requested).toEqual([]);
  });

  it("reports an unreachable tile server rather than serving a blank tile", async () => {
    const dead = await appWith(async () => {
      throw new Error("ENOTFOUND");
    });
    const res = await request(dead).get("/geo-tiles/3/4/5.png");
    expect(res.status).toBe(502);
    expect(res.body.error).toContain("DFIR_GEOMAP_TILE_URL");
  });

  it("refuses to serve a non-image response from this origin", async () => {
    const portal = await appWith(
      async () =>
        new Response("<html>sign in</html>", { status: 200, headers: { "content-type": "text/html" } }),
    );
    const res = await request(portal).get("/geo-tiles/3/4/5.png");
    expect(res.status).toBe(502);
    expect(res.body.error).toContain("not an image");
  });

  it("refuses an oversized response", async () => {
    const big = await appWith(
      async () =>
        new Response(Buffer.alloc(3 * 1024 * 1024), {
          status: 200,
          headers: { "content-type": "image/png" },
        }),
    );
    const res = await request(big).get("/geo-tiles/3/4/5.png");
    expect(res.status).toBe(502);
    expect(res.body.error).toContain("oversized");
  });

  it("uses the operator's tile server when one is configured", async () => {
    process.env.DFIR_GEOMAP_TILE_URL = "http://tiles.test:8080/osm/{z}/{x}/{y}.png";
    const res = await request(app).get("/geo-tiles/3/4/5.png");
    expect(res.status).toBe(200);
    expect(requested).toEqual(["http://tiles.test:8080/osm/3/4/5.png"]);
  });

  // Same z/x/y, different tile server: the cache must not answer the second with the first's bytes.
  it("does not serve one tile server's tiles after the operator repoints at another", async () => {
    await request(app).get("/geo-tiles/3/4/5.png");
    process.env.DFIR_GEOMAP_TILE_URL = "http://tiles.test:8080/osm/{z}/{x}/{y}.png";
    await request(app).get("/geo-tiles/3/4/5.png");
    expect(requested).toEqual([
      "https://a.tile.openstreetmap.org/3/4/5.png",
      "http://tiles.test:8080/osm/3/4/5.png",
    ]);
  });
});

describe("buildTileUrl", () => {
  it("substitutes every placeholder Leaflet writes", () => {
    expect(buildTileUrl("https://{s}.tiles.test/{z}/{x}/{y}{r}.png", 3, 4, 5)).toBe(
      "https://a.tiles.test/3/4/5.png",
    );
  });

  it("maps a tile to a stable subdomain", () => {
    const first = buildTileUrl(DEFAULT_TILE_TEMPLATE, 3, 4, 5);
    expect(buildTileUrl(DEFAULT_TILE_TEMPLATE, 3, 4, 5)).toBe(first);
    expect(buildTileUrl(DEFAULT_TILE_TEMPLATE, 3, 4, 6)).not.toBe(first);
  });

  it("rejects a zoom past the raster range and a negative coordinate", () => {
    expect(buildTileUrl(DEFAULT_TILE_TEMPLATE, 20, 0, 0)).toBeNull();
    expect(buildTileUrl(DEFAULT_TILE_TEMPLATE, 3, -1, 0)).toBeNull();
  });

  // The template is operator config, so this catches a typo rather than an attack — but a file:
  // template would have the server read its own disk and hand the bytes back over HTTP.
  it("rejects a template that is not http(s)", () => {
    expect(buildTileUrl("file:///etc/{z}{x}{y}", 1, 0, 0)).toBeNull();
    expect(buildTileUrl("not a url {z}/{x}/{y}", 1, 0, 0)).toBeNull();
  });
});

describe("tileTemplate", () => {
  it("falls back to OpenStreetMap when the operator names no tile server", () => {
    expect(tileTemplate({})).toBe(DEFAULT_TILE_TEMPLATE);
    expect(tileTemplate({ DFIR_GEOMAP_TILE_URL: "   " })).toBe(DEFAULT_TILE_TEMPLATE);
  });
});
