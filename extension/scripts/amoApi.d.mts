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

export declare function isAmoUrl(url: string): boolean;

export declare const MAX_PAGES: number;

export interface PagedLookup extends VersionLookup {
  pages: number;
}

export declare function hasVersion(args: {
  addonId: string;
  version: string;
  /** Called once per request. Must return a FRESH JWT — AMO rejects a replayed `jti`. */
  mintToken: () => Promise<string>;
  fetchImpl?: typeof fetch;
  maxPages?: number;
}): Promise<PagedLookup>;

export type NextPage =
  | { kind: "url"; url: string }
  | { kind: "end" }
  | { kind: "malformed"; reason: string };

export declare function readNext(raw: string): NextPage;

export type PageTotal =
  | { kind: "number"; value: number }
  | { kind: "absent" }
  | { kind: "malformed"; reason: string };

export declare function readCount(raw: string): PageTotal;

export declare function isReadableVersion(value: unknown): boolean;

export declare const AMO_VERSION_RE: RegExp;

export declare function isValidAddonVersion(value: unknown): boolean;
