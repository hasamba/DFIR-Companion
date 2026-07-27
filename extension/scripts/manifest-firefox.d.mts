// Hand-written types for manifest-firefox.mjs so tests/firefox.test.ts can import the transform
// under `tsc --noEmit` (which has allowJs off, and would otherwise fail with TS7016).

export declare const GECKO_ID: string;
export declare const MIN_FIREFOX_VERSION: string;
export declare const FIREFOX_ONLY_KEYS: string[];

export interface FirefoxManifest {
  browser_specific_settings: { gecko: { id: string; strict_min_version: string } };
  // `service_worker?: undefined` is deliberate: Firefox has no MV3 service worker, so the key must
  // never be present. Declaring it as always-undefined lets callers assert that at runtime while
  // still making any attempt to populate it a type error.
  background: { scripts: string[]; type?: string; service_worker?: undefined };
  permissions: string[];
  host_permissions?: string[];
  commands: Record<string, { suggested_key?: { default?: string }; description?: string }>;
  [key: string]: unknown;
}

export declare function toFirefoxManifest(base: Record<string, unknown>): FirefoxManifest;
