export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  scopes: string[];
}

export interface TeamAuthConfig {
  enabled: boolean;
  bootstrapToken?: string;
  cookieSecure: boolean;
  sessionTtlMs: number;
  oidc?: OidcConfig;
}

const DEFAULT_SESSION_HOURS = 12;
const MIN_SESSION_HOURS = 0.25;
const MAX_SESSION_HOURS = 168;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);

function enabled(value: string | undefined): boolean {
  return ["1", "on", "true", "yes"].includes((value ?? "").trim().toLowerCase());
}

function sessionTtlMs(raw: string | undefined): number {
  const parsed = Number(raw);
  const hours = Number.isFinite(parsed)
    ? Math.min(MAX_SESSION_HOURS, Math.max(MIN_SESSION_HOURS, parsed))
    : DEFAULT_SESSION_HOURS;
  return hours * 60 * 60_000;
}

function oidcConfig(env: NodeJS.ProcessEnv): OidcConfig | undefined {
  const issuer = (env.DFIR_AUTH_OIDC_ISSUER ?? "").trim().replace(/\/+$/, "");
  const clientId = (env.DFIR_AUTH_OIDC_CLIENT_ID ?? "").trim();
  if (!issuer && !clientId) return undefined;
  if (!issuer || !clientId) {
    throw new Error("DFIR_AUTH_OIDC_ISSUER and DFIR_AUTH_OIDC_CLIENT_ID must be configured together");
  }
  let parsed: URL;
  try {
    parsed = new URL(issuer);
  } catch {
    throw new Error("DFIR_AUTH_OIDC_ISSUER must be an absolute HTTPS URL");
  }
  if (parsed.protocol !== "https:") throw new Error("DFIR_AUTH_OIDC_ISSUER must use HTTPS");
  const scopes = (env.DFIR_AUTH_OIDC_SCOPES ?? "openid profile email")
    .split(/\s+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
  if (!scopes.includes("openid")) scopes.unshift("openid");
  return {
    issuer,
    clientId,
    ...(env.DFIR_AUTH_OIDC_CLIENT_SECRET?.trim()
      ? { clientSecret: env.DFIR_AUTH_OIDC_CLIENT_SECRET.trim() }
      : {}),
    ...(env.DFIR_AUTH_OIDC_REDIRECT_URI?.trim()
      ? { redirectUri: env.DFIR_AUTH_OIDC_REDIRECT_URI.trim() }
      : {}),
    scopes,
  };
}

export function resolveTeamAuthConfig(env: NodeJS.ProcessEnv = process.env): TeamAuthConfig {
  const mode = (env.DFIR_AUTH_MODE ?? "single-user").trim().toLowerCase();
  if (mode !== "single-user" && mode !== "team") {
    throw new Error("DFIR_AUTH_MODE must be single-user or team");
  }
  const team = mode === "team";
  const oidc = team ? oidcConfig(env) : undefined;
  return {
    enabled: team,
    ...(env.DFIR_AUTH_BOOTSTRAP_TOKEN?.trim()
      ? { bootstrapToken: env.DFIR_AUTH_BOOTSTRAP_TOKEN.trim() }
      : {}),
    cookieSecure: env.DFIR_AUTH_COOKIE_SECURE === undefined ? team : enabled(env.DFIR_AUTH_COOKIE_SECURE),
    sessionTtlMs: sessionTtlMs(env.DFIR_AUTH_SESSION_HOURS),
    ...(oidc ? { oidc } : {}),
  };
}

function normalizedHost(host: string): string {
  return host
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, "");
}

/**
 * Demo mode, read the same way runtimeStores.ts reads it — the two must agree, because this
 * function decides whether the server may bind and that one decides whether the read-only gate is
 * mounted. Disagreeing would either expose a writable server or refuse to start a safe one.
 */
export function isDemoModeEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.DFIR_DEMO_MODE === "true" || env.DFIR_DEMO_MODE === "1";
}

export function isLoopbackBinding(host: string): boolean {
  return LOOPBACK_HOSTS.has(normalizedHost(host));
}

export function assertRemoteBindingSafe(
  host: string,
  config: TeamAuthConfig,
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (isLoopbackBinding(host) || config.enabled) return;
  if (env.DFIR_ALLOW_UNAUTHENTICATED_REMOTE === "container-loopback-proxy") return;
  // Demo mode is the fourth safe posture, and the reason the public demo can exist at all. What
  // makes an exposed single-user server dangerous is that it is WRITABLE by anyone who reaches it;
  // demoModeReadOnlyGate answers every non-GET with 403 before any route sees it, so the thing this
  // guard protects against is already gone. Without this branch the advertised demo cannot start,
  // and the only ways to run it would be to bypass the guard entirely or to put a login in front of
  // a demo whose whole point is that anyone can open it.
  if (isDemoModeEnabled(env)) return;
  throw new Error(
    `refusing to bind without authentication in single-user mode to ${host}; ` +
      "set DFIR_AUTH_MODE=team, bind to 127.0.0.1, enable DFIR_DEMO_MODE for a read-only public " +
      "demo, or use the documented container loopback-proxy override",
  );
}
