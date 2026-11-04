/**
 * Built-in HTTPS settings (#2285), parsed once at startup. Pure: env in, config out, and a bad value
 * throws so the server refuses to start rather than quietly serving the wrong protocol.
 *
 *   DFIR_HTTPS              auto (default) | on | off — auto turns HTTPS on when team mode is on,
 *                           because team mode is exactly when people connect over a network.
 *   DFIR_HTTPS_CERT / _KEY  your own PEM certificate (may include the chain) and unencrypted key.
 *                           Both or neither. Unset → the generated local CA issues one.
 *   DFIR_HTTPS_HOSTNAMES    extra names/IPs the generated certificate must cover (comma-separated).
 *   DFIR_HTTPS_PLAIN_HTTP   off (default) | redirect | serve — an optional SECOND, plain-HTTP port.
 *   DFIR_HTTPS_PLAIN_HTTP_PORT   that port (default 4774).
 *   DFIR_HTTPS_PLAIN_HTTP_HOST   where `serve` binds. Default 127.0.0.1: plain HTTP to the network
 *                                leaks team session cookies, so opening it takes this explicit step.
 */
import { isAbsolute, resolve } from "node:path";

export type HttpsMode = "auto" | "on" | "off";
export type PlainHttpMode = "off" | "redirect" | "serve";

export const DEFAULT_PLAIN_HTTP_PORT = 4774;

export interface HttpsConfig {
  mode: HttpsMode;
  /** The decision: is the main port HTTPS? */
  enabled: boolean;
  /** Why it is on — the startup log says so when auto made the call. */
  enabledBy: "team-mode" | "setting" | undefined;
  certFile?: string;
  keyFile?: string;
  extraNames: string[];
  plainHttp: PlainHttpMode;
  plainHttpPort: number;
  /** Bind address for the plain-HTTP port; undefined → the caller's default for the mode. */
  plainHttpHost?: string;
}

function choice<T extends string>(
  name: string,
  raw: string | undefined,
  allowed: readonly T[],
  fallback: T,
): T {
  const value = raw?.trim().toLowerCase();
  if (!value) return fallback;
  if ((allowed as readonly string[]).includes(value)) return value as T;
  throw new Error(`${name} must be one of ${allowed.join(" | ")} (got "${raw}")`);
}

function port(name: string, raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const parsed = Number(raw);
  if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535) return parsed;
  throw new Error(`${name} must be a port number 1-65535 (got "${raw}")`);
}

function path(raw: string | undefined, baseDir: string): string | undefined {
  const value = raw?.trim();
  if (!value) return undefined;
  return isAbsolute(value) ? value : resolve(baseDir, value);
}

export interface HttpsConfigContext {
  teamMode: boolean;
  /** The main (HTTPS) port — the plain-HTTP port must differ. */
  mainPort: number;
  /** Relative certificate paths resolve against this (the folder holding the cases root). */
  baseDir: string;
}

export function resolveHttpsConfig(env: NodeJS.ProcessEnv, ctx: HttpsConfigContext): HttpsConfig {
  const mode = choice("DFIR_HTTPS", env.DFIR_HTTPS, ["auto", "on", "off"] as const, "auto");
  const enabled = mode === "on" || (mode === "auto" && ctx.teamMode);
  const certFile = path(env.DFIR_HTTPS_CERT, ctx.baseDir);
  const keyFile = path(env.DFIR_HTTPS_KEY, ctx.baseDir);
  if (!!certFile !== !!keyFile) {
    throw new Error("DFIR_HTTPS_CERT and DFIR_HTTPS_KEY must be set together (or both left empty)");
  }
  const plainHttp = choice(
    "DFIR_HTTPS_PLAIN_HTTP",
    env.DFIR_HTTPS_PLAIN_HTTP,
    ["off", "redirect", "serve"] as const,
    "off",
  );
  const plainHttpPort = port(
    "DFIR_HTTPS_PLAIN_HTTP_PORT",
    env.DFIR_HTTPS_PLAIN_HTTP_PORT,
    DEFAULT_PLAIN_HTTP_PORT,
  );
  if (enabled && plainHttp !== "off" && plainHttpPort === ctx.mainPort) {
    throw new Error(`DFIR_HTTPS_PLAIN_HTTP_PORT (${plainHttpPort}) must differ from the main port`);
  }
  const plainHttpHost = env.DFIR_HTTPS_PLAIN_HTTP_HOST?.trim() || undefined;
  const extraNames = (env.DFIR_HTTPS_HOSTNAMES ?? "")
    .split(",")
    .map((n) => n.trim())
    .filter(Boolean);
  return {
    mode,
    enabled,
    enabledBy: !enabled ? undefined : mode === "on" ? "setting" : "team-mode",
    ...(certFile ? { certFile } : {}),
    ...(keyFile ? { keyFile } : {}),
    extraNames,
    plainHttp,
    plainHttpPort,
    ...(plainHttpHost ? { plainHttpHost } : {}),
  };
}
