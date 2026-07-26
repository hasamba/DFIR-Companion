// Derives the Firefox manifest from manifest.json.
//
// There is deliberately no manifest-firefox.json on disk. A second hand-maintained manifest drifts:
// it carries its own `version`, which the release version check (release-artifacts.yml) and the
// CHANGELOG bump checklist both read from manifest.json only, so a release would bump one and ship
// the other stale (#300). Generating means every shared field has exactly one source.
//
// Keep this transform minimal. Everything it does NOT touch is shared by both browsers, and the
// test suite asserts that the ONLY keys it changes are the ones listed here — so adding a divergence
// requires saying so out loud in both places.

/**
 * Permanent add-on identity on AMO. Also scopes storage.local, so changing it after publication
 * orphans every analyst's saved settings — see #301, which tracks replacing the placeholder domain.
 */
export const GECKO_ID = "dfir-companion@example.com";

/**
 * Firefox 128 (the current ESR) is the floor because it is where scripting.executeScript gained
 * world: "MAIN". serviceWorker.ts injects pageHook.js into MAIN unconditionally; on an older
 * Firefox that call would quietly land in the isolated world, wrap a `fetch` no page script calls,
 * report ready, and then capture nothing (#298). Do not lower this.
 */
export const MIN_FIREFOX_VERSION = "128.0";

/** The manifest keys this transform is allowed to change. Asserted by tests/firefox.test.ts. */
export const FIREFOX_ONLY_KEYS = ["browser_specific_settings", "background"];

/**
 * @param {object} base Parsed manifest.json.
 * @returns {object} The Firefox MV3 manifest.
 */
export function toFirefoxManifest(base) {
  // Firefox has no MV3 service worker (bugzil.la/1573659); it runs an event page instead. The entry
  // file is the same bundle either way, so read it off the Chrome key rather than repeating the
  // filename here and letting the two fall out of step.
  if (!base.background?.service_worker) {
    throw new Error("manifest.json has no background.service_worker to derive Firefox's background.scripts from");
  }

  // Rebuilt key-by-key rather than spread-then-override so the result keeps manifest.json's field
  // order: the generated file then reads as the Chrome manifest with two edits, which is what
  // someone diffing the two — or reviewing the add-on for AMO — actually wants to see.
  const out = {};
  for (const [key, value] of Object.entries(base)) {
    out[key] = value;
    if (key === "manifest_version") {
      out.browser_specific_settings = {
        gecko: { id: GECKO_ID, strict_min_version: MIN_FIREFOX_VERSION },
      };
    }
    if (key === "background") {
      // `type: "module"` carries over — Firefox has supported ES module background scripts since
      // well before the 128 floor.
      out[key] = { scripts: [value.service_worker], type: value.type };
    }
  }
  return out;
}
