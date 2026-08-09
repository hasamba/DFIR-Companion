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
const AUTHENTICATED_ASSET_PREFIXES = ["/js", "/vendor"];
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
const CASE_READ_SEGMENTS = ["/unlock", "/lock-status", "/lock-forget"];
const CASE_REVIEW_SEGMENTS = [
  "/review",
  "/presidio-pending/approve",
  "/presidio-pending/suppress",
  "/second-opinion/apply",
];
const CASE_EXPORT_PATTERNS = [
  /\/export(?:\/|$)/,
  /\/report(?:\.docx|\/|$)/,
  /\/incident-timeline\.csv$/,
  /\/timeline\.jsonl$/,
  /\/super-timeline\.jsonl$/,
  /\/attack-layer\.json$/,
  /\/geo-map\.csv$/,
  /\/custody\/manifest$/,
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
  if (CASE_GLOBAL_ADMIN_SEGMENTS.some((segment) => pathStarts(suffix, segment))) {
    return { kind: "global", permission: "admin" };
  }
  if (CASE_READ_SEGMENTS.some((segment) => pathStarts(suffix, segment))) {
    return { kind: "case", permission: "read", caseId };
  }
  if (CASE_ADMIN_SEGMENTS.some((segment) => pathStarts(suffix, segment))) {
    return { kind: "case", permission: "admin", caseId };
  }
  if (CASE_REVIEW_SEGMENTS.some((segment) => suffix.includes(segment))) {
    return { kind: "case", permission: "review", caseId };
  }
  if (CASE_EXPORT_PATTERNS.some((pattern) => pattern.test(suffix))) {
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
  if (match && match[1] !== "import" && match[1] !== "seed-demo") {
    let caseId: string;
    try {
      caseId = decodeURIComponent(match[1]);
    } catch {
      caseId = "";
    }
    return casePolicy(normalizedMethod, path, caseId);
  }
  if (normalizedMethod === "GET" && path === "/cases") return { kind: "case-list" };
  if (
    path === "/cases" ||
    path === "/captures/recent" ||
    pathStarts(path, "/cases/import") ||
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
