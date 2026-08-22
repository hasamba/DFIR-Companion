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
 * both orphans every analyst's saved settings and reads to Firefox as a different add-on that
 * existing installs never update to — which is why it is settled here, before the first submission,
 * rather than left as a placeholder (#301).
 *
 * `hasamba.github.io` is the project's own GitHub Pages domain, where the manual is published. The
 * address itself receives no mail: an AMO add-on ID only has to be shaped like an email and sit
 * under a domain the project actually controls, which the IANA-reserved `example.com` never was.
 */
export const GECKO_ID = "dfir-companion@hasamba.github.io";

/**
 * Two independent floors, and the higher one wins.
 *
 * 128 is where scripting.executeScript gained world: "MAIN". serviceWorker.ts injects pageHook.js
 * into MAIN unconditionally; on an older Firefox that call would quietly land in the isolated
 * world, wrap a `fetch` no page script calls, report ready, and then capture nothing (#298).
 *
 * 140 is where Firefox learned to READ data_collection_permissions below and show the consent
 * screen it drives. Mozilla gives exactly three ways to ship a data-collecting add-on to older
 * releases — raise the floor, turn the collection off there, or build a replacement consent screen
 * — and "declare it and let the old prompt say nothing" is not among them. Turning collection off
 * would mean shipping an add-on that cannot capture, which is the whole product; a hand-rolled
 * consent screen is real UI in the one component that touches evidence, written for browsers
 * nobody should still be running. So the floor moves, which is also what Mozilla recommends for a
 * first submission.
 *
 * The users this costs are close to none: 140 is itself an ESR, and 128 ESR went end-of-life in
 * September 2025, so an enterprise pinned to ESR is already at or above this line.
 *
 * Do not lower this. Below 140 the add-on collects without disclosing; below 128 it silently
 * captures nothing.
 */
export const MIN_FIREFOX_VERSION = "140.0";

/**
 * AMO has required a data-collection declaration in every submission since 2025-11-03; a package
 * without one is rejected by the validator ("The data_collection_permissions property is missing"),
 * not merely flagged. Firefox 140+ turns it into the install-time consent screen; older Firefox
 * ignores the key, which is why the 128 floor below can stay where it is.
 *
 * `none` would be the easier claim and it is the wrong one. Mozilla scopes collection to data
 * "handled outside the add-on or the local browser" — not to data that leaves the machine — so the
 * default 127.0.0.1 companion already settles it: every capture POSTs the tab URL, its title and a
 * full screenshot to a separate process. The companion address is also just a setting, and team
 * mode exists for a companion another machine can reach, so the destination is not even reliably
 * local. A reviewer reading companionClient.ts next to a `none` declaration would be reading a
 * false statement.
 *
 * - browsingActivity — CapturePayload carries `url` and `tabTitle` for every capture.
 * - websiteContent   — the screenshot itself, plus the console rows a Push scrapes.
 *
 * Deliberately absent: `websiteActivity` (a capture's `triggerType` records why the capture fired,
 * never what the analyst clicked or typed) and `technicalAndInteraction` (no telemetry exists to
 * declare, and PRIVACY.md promises there never will be).
 */
/*
 * There is deliberately no `gecko_android` key. Omitting it is what keeps the add-on desktop-only:
 * per MDN, an extension is offered on Firefox for Android only if the key is present, even as an
 * empty object. Adding one to silence web-ext's Android version warning would opt a screenshot-and
 * -context-menu tool into a browser it was never built or tested for — and since no Android user
 * can install it, the consent floor Android would need (142) is moot.
 */
export const DATA_COLLECTION_PERMISSIONS = Object.freeze({
  required: Object.freeze(["browsingActivity", "websiteContent"]),
});

/** The manifest keys this transform is allowed to change. Asserted by tests/firefox.test.ts. */
export const FIREFOX_ONLY_KEYS = ["browser_specific_settings", "background", "incognito"];

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
        gecko: {
          id: GECKO_ID,
          strict_min_version: MIN_FIREFOX_VERSION,
          // Cloned, not referenced: the exported constant is frozen, and handing callers a live
          // reference to it would make one build's manifest mutable through another's import.
          data_collection_permissions: { required: [...DATA_COLLECTION_PERMISSIONS.required] },
        },
      };
      // Chrome rejects `not_allowed`; Firefox supports it and then makes private windows entirely
      // invisible to the add-on. Chrome stays excluded by default and the runtime independently
      // refuses every incognito Tab even if an analyst later enables the extension there.
      out.incognito = "not_allowed";
    }
    if (key === "background") {
      // `type: "module"` carries over — Firefox has supported ES module background scripts since
      // well before the 128 floor.
      out[key] = { scripts: [value.service_worker], type: value.type };
    }
  }
  return out;
}
