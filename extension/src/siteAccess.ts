export const SITE_ACCESS_AUDIT_KEY = "siteAccessAudit";
const MAX_AUDIT_ENTRIES = 100;

export interface PermissionGateway {
  contains(permissions: chrome.permissions.Permissions): Promise<boolean>;
  request(permissions: chrome.permissions.Permissions): Promise<boolean>;
  remove(permissions: chrome.permissions.Permissions): Promise<boolean>;
}

export type SiteAccessResult =
  | { status: "granted" | "denied"; origin: string }
  | { status: "restricted"; origin: null };

export type SiteAccessAuditAction = "granted" | "denied" | "revoked";

export interface SiteAccessAuditEntry {
  at: string;
  origin: string;
  action: SiteAccessAuditAction;
}

export interface SiteTab {
  url?: string;
  incognito?: boolean;
}

/** Return the smallest host pattern that covers one ordinary web origin. */
export function originPatternFromUrl(rawUrl: string): string | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  return `${url.origin}/*`;
}

export function originPatternMatchesUrl(pattern: string, rawUrl: string): boolean {
  const current = originPatternFromUrl(rawUrl);
  if (!current) return false;
  if (pattern === "<all_urls>" || pattern === current) return true;
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  const match = /^(\*|https?|file):\/\/([^/]+)\/\*$/.exec(pattern);
  if (!match) return false;
  const [, scheme, host] = match;
  if (scheme !== "*" && `${scheme}:` !== url.protocol) return false;
  if (host === "*") return true;
  if (host.startsWith("*.")) {
    const suffix = host.slice(2).toLowerCase();
    return url.hostname === suffix || url.hostname.endsWith(`.${suffix}`);
  }
  return url.host.toLowerCase() === host.toLowerCase();
}

export function isCapturableTab(tab: SiteTab): boolean {
  return tab.incognito !== true && typeof tab.url === "string" && originPatternFromUrl(tab.url) !== null;
}

export async function hasSiteAccess(rawUrl: string, gateway: PermissionGateway): Promise<boolean> {
  const origin = originPatternFromUrl(rawUrl);
  if (!origin) return false;
  return gateway.contains({ origins: [origin] });
}

export async function requestSiteAccess(
  rawUrl: string,
  gateway: PermissionGateway,
): Promise<SiteAccessResult> {
  const origin = originPatternFromUrl(rawUrl);
  if (!origin) return { status: "restricted", origin: null };
  const granted = await gateway.request({ origins: [origin] });
  return { status: granted ? "granted" : "denied", origin };
}

export async function revokeSiteAccess(rawUrl: string, gateway: PermissionGateway): Promise<boolean> {
  const origin = originPatternFromUrl(rawUrl);
  if (!origin) return false;
  return gateway.remove({ origins: [origin] });
}

export function readAuditEntries(value: unknown): SiteAccessAuditEntry[] {
  if (!Array.isArray(value)) return [];
  return value.filter(isAuditEntry).slice(-MAX_AUDIT_ENTRIES);
}

export function appendAuditEntry(
  existing: unknown,
  entry: SiteAccessAuditEntry,
): SiteAccessAuditEntry[] {
  return [...readAuditEntries(existing), entry].slice(-MAX_AUDIT_ENTRIES);
}

function isAuditEntry(value: unknown): value is SiteAccessAuditEntry {
  if (!value || typeof value !== "object") return false;
  const item = value as Record<string, unknown>;
  return typeof item.at === "string"
    && typeof item.origin === "string"
    && (item.action === "granted" || item.action === "denied" || item.action === "revoked");
}
