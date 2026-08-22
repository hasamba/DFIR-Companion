// Hand-written types for manifest-firefox.mjs so tests/firefox.test.ts can import the transform
// under `tsc --noEmit` (which has allowJs off, and would otherwise fail with TS7016).

export declare const GECKO_ID: string;
export declare const MIN_FIREFOX_VERSION: string;
export declare const FIREFOX_ONLY_KEYS: string[];

/** Every category AMO accepts in `required`. `technicalAndInteraction` is optional-only. */
export type DataCollectionCategory =
  | "none"
  | "authenticationInfo"
  | "bookmarksInfo"
  | "browsingActivity"
  | "financialAndPaymentInfo"
  | "healthInfo"
  | "locationInfo"
  | "personalCommunications"
  | "personallyIdentifyingInfo"
  | "searchTerms"
  | "websiteActivity"
  | "websiteContent";

export interface DataCollectionPermissions {
  required: DataCollectionCategory[];
  optional?: (Exclude<DataCollectionCategory, "none"> | "technicalAndInteraction")[];
}

export declare const DATA_COLLECTION_PERMISSIONS: {
  readonly required: readonly DataCollectionCategory[];
};

export interface FirefoxManifest {
  browser_specific_settings: {
    gecko: {
      id: string;
      strict_min_version: string;
      // Not optional. AMO rejects a submission that omits it, so a build that could type-check
      // without it would be a build that type-checks its way to an upload failure.
      data_collection_permissions: DataCollectionPermissions;
    };
    // Always-undefined for the same reason `service_worker` below is: presence is the whole
    // meaning. Any `gecko_android` value — `{}` included — publishes the add-on to Firefox for
    // Android, so declaring it as never-present makes adding one a type error rather than a
    // one-line manifest edit nobody reviews.
    gecko_android?: undefined;
  };
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
