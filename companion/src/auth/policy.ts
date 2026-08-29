import type { CaseRole, ServicePermission } from "./types.js";

export type CasePermission = "read" | "write" | "review" | "admin" | "export";

export type RequestPolicy =
  | { kind: "public" }
  | { kind: "authenticated" }
  | { kind: "case-list" }
  | { kind: "global"; permission: "admin" }
  | { kind: "case"; permission: CasePermission; caseId: string }
  | { kind: "capture" };

const PUBLIC_GET = new Set([
  "/health",
  "/login",
  "/favicon.ico",
  "/favicon-16.png",
  "/favicon-32.png",
  "/apple-touch-icon.png",
  "/dfir-companion-logo.jpg",
  "/js/safe-dom.js",
]);
const AUTHENTICATED_SHELLS = new Set(["/", "/dashboard", "/mobile"]);
// "/geo-tiles" is the proxied basemap under the Geographic Map (routes/geoTiles.ts). It carries no
// case data — a tile is the same picture of the world for every user — so it sits with the other
// static assets rather than falling through to the global-admin default, which would blank the map
// for every non-admin role.
const AUTHENTICATED_ASSET_PREFIXES = ["/js", "/vendor", "/geo-tiles"];
const AUTHENTICATED_GLOBAL_READ_PREFIXES = [
  "/templates",
  "/report-templates",
  "/dashboard-views",
  "/incident-types",
  "/bundles",
  "/tools/status",
  "/enrich-health",
];
const GLOBAL_ADMIN_PREFIXES = [
  "/settings",
  "/diagnostics",
  "/log-level",
  "/update-check",
  "/tagger",
  "/ioc-whitelist",
  "/nsrl",
  "/kev",
  "/mcp",
  "/notifications",
  "/velociraptor",
  "/importers",
];
const CASE_ADMIN_SEGMENTS = [
  "/password",
  "/push-token",
  "/archive",
  "/restore",
  "/delete",
  "/restore-backup",
];
// Case-scoped routes that nonetheless read the SERVER's own filesystem at an operator-named path.
// Holding "write" on one case must not let a user name a path outside that case and have its bytes
// copied in as evidence. Same trust as /nsrl and /kev import-file, already global-admin prefixes.
const CASE_GLOBAL_ADMIN_SEGMENTS = ["/import-file"];
// The only /cases/* paths that are NOT a case: the encrypted-bundle import and the demo seeder.
// "import" and "seed-demo" are themselves valid case ids (isValidCaseId accepts both) and any
// authenticated user can create a case so named, so the exemption has to be these exact paths.
// Exempting the whole /cases/import subtree would hand /cases/import/delete and
// /cases/import/import-file to any authenticated session.
const NON_CASE_PATHS = new Set(["/cases/import/encrypted", "/cases/seed-demo"]);

/**
 * The spelling Express itself would route by: case-insensitive, trailing slash optional (neither
 * "case sensitive routing" nor "strict routing" is enabled). Matching NON_CASE_PATHS byte-exactly
 * would miss /cases/seed-demo/ and /cases/import/ENCRYPTED, which the router still serves — the
 * seeder would then read as a case named "seed-demo" and drop from global admin to case write.
 */
function collectionPath(path: string): string {
  return (path.length > 1 ? path.replace(/\/+$/, "") : path).toLowerCase();
}
const CASE_READ_SEGMENTS = ["/unlock", "/lock-status", "/lock-forget"];
/**
 * A BUCKET IS CHOSEN BY THE ROUTE, NEVER BY A VALUE THE ROUTE CARRIES.
 *
 * These were an unanchored substring scan over the whole suffix — `suffix.includes("/review")`,
 * `/\/report(?:\.docx|\/|$)/`. The suffix contains user-named segments (an MCP server id, a
 * hostname read out of evidence), so the value picked the permission: an MCP server named "report"
 * put POST /cases/:id/mcp/report/run in the EXPORT bucket, which a reader holds, and one named
 * "review" put it in the reviewer's. The scan was also case-sensitive while Express routing is not,
 * so POST /cases/c1/SECOND-OPINION/APPLY matched nothing and fell through to the "write" default —
 * an investigator performing a reviewer-only action by holding down shift.
 *
 * Anchored patterns fix both at once. Every dynamic segment is written out as `[^/]+`, so a
 * user-named value can only ever fill the slot the route actually has, and folding case is then
 * safe because a folded value still cannot reach past its own segment. Matched against the
 * LOWERCASED suffix.
 *
 * Adding a route to either bucket means adding its pattern here. tests/http/teamAuthPolicy.test.ts
 * pins every route that is meant to be in one, and pins that an adversarial segment value stays out.
 */
const CASE_REVIEW_PATTERNS = [
  /^\/cockpit\/review$/,
  /^\/presidio-pending\/(?:approve|suppress)$/,
  /^\/second-opinion\/apply(?:-all)?$/,
  // The whole report-version review workflow, not just approve: /review/annotations and
  // /review/request-changes are the reviewer's day job, and a reviewer holds "review" but NOT
  // "write" — so naming only approve here locks the assigned reviewer out of the other two with a
  // 403. Matching the rest of the segment keeps a later addition covered; the versionId can still
  // only fill its own slot, which is what anchoring buys.
  /^\/report-versions\/[^/]+\/review(?:\/[^/]+)?$/,
];
const CASE_EXPORT_PATTERNS = [
  /^\/export(?:\/|$)/,
  /^\/report(?:\.docx|\/|$)/,
  /^\/present\/export$/,
  /^\/incident-timeline\.csv$/,
  /^\/timeline\.jsonl$/,
  /^\/super-timeline\.jsonl$/,
  /^\/attack-layer\.json$/,
  /^\/geo-map\.csv$/,
  /^\/custody\/manifest$/,
];

const ROLE_PERMISSIONS: Record<CaseRole, ReadonlySet<CasePermission>> = {
  reader: new Set(["read", "export"]),
  investigator: new Set(["read", "write", "export"]),
  reviewer: new Set(["read", "review", "export"]),
  administrator: new Set(["read", "write", "review", "admin", "export"]),
};

export function caseRoleAllows(role: CaseRole, permission: CasePermission): boolean {
  return ROLE_PERMISSIONS[role].has(permission);
}

function pathStarts(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(`${prefix}/`);
}

function casePolicy(method: string, path: string, caseId: string): RequestPolicy {
  const suffix = path.slice(`/cases/${caseId}`.length);
  // Express routing is case-insensitive by default, so /PassWord and /IMPORT-FILE reach the same
  // handlers as their lowercase spellings; an unfolded compare would leave an elevated route one
  // shift key from the permissive "write" default. EVERY check below folds case — including review
  // and export, which used not to. The reason they could not was that they scanned the whole suffix
  // for a substring, so folding would have let an MCP server named "Report" pull POST /mcp/:id/run
  // into the reader's export bucket. Those two are anchored patterns now (see above), which closes
  // that hole at the source and makes folding safe for them too.
  const lowerSuffix = suffix.toLowerCase();
  // Express is not in "strict routing" mode, so /cockpit/review/ reaches the same handler as
  // /cockpit/review. The anchored patterns below end in `$`, so the trailing-slash spelling would
  // miss every one of them and fall through to the permissive "write" default — the same bypass
  // anchoring was added to close, wearing a different hat. Strip it once, here. The pathStarts
  // checks above do not need it (a prefix match already tolerates a trailing segment separator),
  // and collectionPath() does the same job for NON_CASE_PATHS.
  const matchSuffix = lowerSuffix.replace(/\/+$/, "") || "/";
  if (CASE_GLOBAL_ADMIN_SEGMENTS.some((segment) => pathStarts(lowerSuffix, segment))) {
    return { kind: "global", permission: "admin" };
  }
  if (CASE_READ_SEGMENTS.some((segment) => pathStarts(lowerSuffix, segment))) {
    return { kind: "case", permission: "read", caseId };
  }
  if (CASE_ADMIN_SEGMENTS.some((segment) => pathStarts(lowerSuffix, segment))) {
    return { kind: "case", permission: "admin", caseId };
  }
  if (CASE_REVIEW_PATTERNS.some((pattern) => pattern.test(matchSuffix))) {
    return { kind: "case", permission: "review", caseId };
  }
  if (CASE_EXPORT_PATTERNS.some((pattern) => pattern.test(matchSuffix))) {
    return { kind: "case", permission: "export", caseId };
  }
  return {
    kind: "case",
    permission: method === "GET" || method === "HEAD" ? "read" : "write",
    caseId,
  };
}

export function resolveRequestPolicy(method: string, rawPath: string): RequestPolicy {
  const normalizedMethod = method.toUpperCase();
  let path: string;
  try {
    path = decodeURIComponent(rawPath);
  } catch {
    return { kind: "global", permission: "admin" };
  }
  if (normalizedMethod === "GET" && PUBLIC_GET.has(path)) return { kind: "public" };
  if (
    pathStarts(path, "/integrations/slack/command") ||
    pathStarts(path, "/integrations/teams/command") ||
    pathStarts(path, "/integrations/telegram/command")
  ) {
    return { kind: "public" };
  }
  if (normalizedMethod === "POST" && path === "/captures") return { kind: "capture" };
  const match = /^\/cases\/([^/]+)(?:\/|$)/.exec(path);
  if (match && !NON_CASE_PATHS.has(collectionPath(path))) {
    let caseId: string;
    try {
      caseId = decodeURIComponent(match[1]);
    } catch {
      caseId = "";
    }
    return casePolicy(normalizedMethod, path, caseId);
  }
  if (normalizedMethod === "GET" && path === "/cases") return { kind: "case-list" };
  // The cross-case IOC pivot (#679). It names cases, exactly like GET /cases, and it is gated
  // exactly like GET /cases: the route filters its own answer through visibleCaseIds(), so a
  // reader on one case learns nothing about a case they hold no role on. Without this line it
  // would fall through to the global-admin default and be useless to every non-admin — the one
  // role the feature exists for. GET only; any other method on /global/* stays global-admin.
  if (normalizedMethod === "GET" && collectionPath(path) === "/global/iocs") {
    return { kind: "case-list" };
  }
  if (
    path === "/cases" ||
    path === "/captures/recent" ||
    // The new-case wizard's suggested id. Same policy as POST /cases directly above: anyone who
    // may create a case may ask what the next free number is.
    (normalizedMethod === "GET" && path === "/api/next-case-id") ||
    collectionPath(path) === "/cases/import/encrypted" ||
    pathStarts(path, "/api/jobs") ||
    AUTHENTICATED_SHELLS.has(path) ||
    (normalizedMethod === "GET" &&
      (AUTHENTICATED_ASSET_PREFIXES.some((prefix) => pathStarts(path, prefix)) ||
        path === "/manifest.webmanifest" ||
        path === "/sw.js"))
  ) {
    return { kind: "authenticated" };
  }
  if (
    normalizedMethod === "GET" &&
    AUTHENTICATED_GLOBAL_READ_PREFIXES.some((prefix) => pathStarts(path, prefix))
  ) {
    return { kind: "authenticated" };
  }
  if (GLOBAL_ADMIN_PREFIXES.some((prefix) => pathStarts(path, prefix))) {
    return { kind: "global", permission: "admin" };
  }
  return { kind: "global", permission: "admin" };
}

export function servicePermissionAllows(
  permissions: readonly ServicePermission[],
  permission: CasePermission,
): boolean {
  if (permission === "read") return permissions.includes("read") || permissions.includes("write");
  if (permission === "write") return permissions.includes("write");
  if (permission === "review") return permissions.includes("review");
  if (permission === "export") return permissions.includes("export");
  return false;
}
