import { test, expect } from "../fixtures/test.js";

// Covers: US-342, US-343, US-344, US-345, US-346, US-347, US-348, US-349, US-350
// (feature-user-stories.csv) — the static files the dashboard cannot run without: the two icon
// images, the vendored mapping/graph libraries, and the extracted browser modules including every
// a11y module.
//
// These look too small to test until one breaks the way static assets actually break: a server
// that answers 200 with an HTML error page, an empty file after a bad build, or text/plain that
// makes the browser refuse to execute the module under CSP. Each of those keeps the network tab
// green while the panel that needed the file dies. The assertions below are exactly those three
// failure modes: status, declared type, and a body that is plausibly the real file.

const IMAGE_ASSETS: ReadonlyArray<{ path: string; story: string }> = [
  { path: "/favicon-16.png", story: "US-342" },
  { path: "/apple-touch-icon.png", story: "US-343" },
];

const SCRIPT_ASSETS: ReadonlyArray<{ path: string; story: string; marker: string }> = [
  // The vendored libraries: a truncated or HTML-substituted copy kills the map / graph panels.
  { path: "/vendor/leaflet/leaflet.js", story: "US-344", marker: "Leaflet" },
  { path: "/vendor/cytoscape/dagre.min.js", story: "US-345", marker: "dagre" },
  // Extracted dashboard modules — served from the allowlist in src/http/staticAssets.ts. A module
  // missing from that allowlist 404s and its feature silently never initializes (#415).
  { path: "/js/dashboard-wizard-ai-step.js", story: "US-346", marker: "function" },
  { path: "/js/a11y/modal-autowire.js", story: "US-347", marker: "dialog" },
  { path: "/js/a11y/announcer.js", story: "US-348", marker: "aria-live" },
  { path: "/js/a11y/landmarks.js", story: "US-349", marker: "landmark" },
  { path: "/js/a11y/tooltips.js", story: "US-350", marker: "tooltip" },
];

test("both icons serve as real PNG images", async ({ page }) => {
  for (const asset of IMAGE_ASSETS) {
    const res = await page.request.get(asset.path);
    expect(res.status(), `${asset.story} ${asset.path}`).toBe(200);
    expect(res.headers()["content-type"], `${asset.story} ${asset.path} type`).toContain("image/png");
    const body = await res.body();
    // The PNG magic bytes. A 200 that is actually an HTML fallback page fails here, not in a
    // browser tab three panels away.
    expect(body.subarray(0, 4).toString("hex"), `${asset.story} ${asset.path} magic`).toBe("89504e47");
  }
});

test("every vendored library and browser module serves as executable JavaScript", async ({ page }) => {
  for (const asset of SCRIPT_ASSETS) {
    const res = await page.request.get(asset.path);
    expect(res.status(), `${asset.story} ${asset.path}`).toBe(200);
    // The declared type is what lets the browser execute the file at all — under the dashboard's
    // CSP a script served as text/plain is refused, which presents as a feature that never wired.
    expect(res.headers()["content-type"], `${asset.story} ${asset.path} type`).toContain(
      "application/javascript",
    );
    const text = await res.text();
    expect(text.length, `${asset.story} ${asset.path} is empty`).toBeGreaterThan(100);
    expect(text.trimStart().startsWith("<"), `${asset.story} ${asset.path} is HTML, not JS`).toBe(false);
    // One content word per file, chosen from what the file is FOR — enough to catch the wrong
    // file being served at the right path after a rename or an allowlist typo.
    expect(text.toLowerCase(), `${asset.story} ${asset.path} content`).toContain(asset.marker.toLowerCase());
  }
});
