import { createHash } from "node:crypto";
import { isAbsolute, dirname, join, resolve } from "node:path";
import {
  assertRemoteBindingSafe,
  isLoopbackBinding,
  resolveTeamAuthConfig,
  type OidcConfig,
} from "./authConfig.js";
import { AuthStore } from "./authStore.js";
import { OidcClient } from "./oidcClient.js";
import { TeamAuth } from "./teamAuth.js";
import { acquireWriterGuard, type WriterGuard } from "./writerGuard.js";

export interface TeamAuthRuntime {
  teamAuth?: TeamAuth;
  writerGuard?: WriterGuard;
}

function authDataDir(casesRoot: string, env: NodeJS.ProcessEnv): string {
  const configured = env.DFIR_AUTH_DATA_DIR?.trim();
  if (configured) return isAbsolute(configured) ? configured : resolve(dirname(casesRoot), configured);
  const key = createHash("sha256").update(resolve(casesRoot)).digest("hex").slice(0, 12);
  return join(dirname(resolve(casesRoot)), `.dfir-auth-${key}`);
}

function callbackUri(oidc: OidcConfig, host: string, port: number, env: NodeJS.ProcessEnv): string {
  const configured =
    oidc.redirectUri ??
    (env.DFIR_PUBLIC_URL?.trim()
      ? `${env.DFIR_PUBLIC_URL.trim().replace(/\/+$/, "")}/auth/oidc/callback`
      : undefined);
  if (!configured && !isLoopbackBinding(host)) {
    throw new Error("OIDC on a non-loopback binding requires DFIR_PUBLIC_URL or DFIR_AUTH_OIDC_REDIRECT_URI");
  }
  const value = configured ?? `http://${host}:${port}/auth/oidc/callback`;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("the OIDC redirect URI must be an absolute URL");
  }
  const loopback = isLoopbackBinding(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new Error("the OIDC redirect URI must use HTTPS, except for a loopback callback");
  }
  return parsed.toString();
}

export function createTeamAuthRuntime(
  casesRoot: string,
  host: string,
  port: number,
  env: NodeJS.ProcessEnv = process.env,
): TeamAuthRuntime {
  const config = resolveTeamAuthConfig(env);
  assertRemoteBindingSafe(host, config, env);
  if (!config.enabled) return {};

  const dataDir = authDataDir(casesRoot, env);
  const writerGuard = acquireWriterGuard(join(resolve(casesRoot), ".dfir-team-writer.lock"));
  let store: AuthStore | undefined;
  try {
    store = new AuthStore(join(dataDir, "auth.sqlite"));
    if (store.countIdentities() === 0 && !isLoopbackBinding(host) && !config.bootstrapToken) {
      throw new Error("first team-mode startup on a non-loopback binding requires DFIR_AUTH_BOOTSTRAP_TOKEN");
    }
    const oidcClient = config.oidc
      ? new OidcClient({
          ...config.oidc,
          redirectUri: callbackUri(config.oidc, host, port, env),
        })
      : undefined;
    return {
      teamAuth: new TeamAuth({
        store,
        bootstrapToken: config.bootstrapToken,
        cookieSecure: config.cookieSecure,
        sessionTtlMs: config.sessionTtlMs,
        oidcClient,
      }),
      writerGuard,
    };
  } catch (err) {
    store?.close();
    writerGuard.release();
    throw err;
  }
}
