// Hand-written types for amoApi.mjs so the tests can import it under `tsc --noEmit`
// (allowJs is off, exactly as for manifest-firefox.d.mts).

export declare function mintJwt(
  issuer: string,
  secret: string,
  opts?: { now?: number; jti?: string },
): Promise<string>;

export interface VersionLookup {
  status: "yes" | "no" | "unknown";
  seen: string[];
  reason?: string;
}

export declare function findVersion(raw: string, version: string): VersionLookup;

export declare function versionsUrl(addonId: string): string;
