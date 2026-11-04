/**
 * Built-in HTTPS at startup and while running (#2285): decide whether HTTPS is on, make sure the
 * local CA and server certificate exist (always — even with HTTPS off, so the CA can be handed to
 * teammates before it is switched on), say what is being served, and keep the certificate fresh.
 *
 * Failure policy: with HTTPS ON, an unusable certificate stops startup with the reason — serving
 * plain HTTP to people who expect HTTPS would be worse. With HTTPS OFF, certificate trouble is only
 * a warning; it must never block the server an analyst is already using.
 */
import { statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createSecureContext } from "node:tls";
import type { RequestListener, Server as HttpServer } from "node:http";
import type { Server as HttpsServer } from "node:https";
import { resolveHttpsConfig, type HttpsConfig } from "./httpsConfig.js";
import { listenPlainHttp, redirectToHttps } from "./httpsListener.js";
import {
  CA_WARN_BEFORE_DAYS,
  RENEW_BEFORE_DAYS,
  certNamesFor,
  ensureServerCert,
  loadOrCreateCa,
  loadUserCertificate,
  tlsDirFor,
  summarize,
  type CertSummary,
  type ServerMaterial,
} from "./tlsMaterial.js";

const DAY_MS = 86_400_000;
export const RENEWAL_CHECK_MS = DAY_MS;

export interface HttpsStatus {
  enabled: boolean;
  mode: HttpsConfig["mode"];
  enabledBy: HttpsConfig["enabledBy"];
  source: "generated" | "user" | undefined;
  /** The certificate the server is presenting right now. */
  server?: CertSummary;
  /** The local CA — offered for download only when it vouches for what is served (or HTTPS is off). */
  ca?: CertSummary;
  caDownload: boolean;
  plainHttp: HttpsConfig["plainHttp"];
  plainHttpPort: number;
  warnings: string[];
}

export interface HttpsDeps {
  env: NodeJS.ProcessEnv;
  casesRoot: string;
  teamMode: boolean;
  port: number;
  log: (msg: string) => void;
  warn: (msg: string) => void;
  now?: () => Date;
}

export interface PreparedHttps {
  config: HttpsConfig;
  /** What the main port serves when HTTPS is on. */
  material?: ServerMaterial;
  status(): HttpsStatus;
  /** The local CA certificate (public part only), when it may be downloaded. */
  caCertPem(): string | undefined;
  /** Renewal / external-file reload against the live server; `check` runs one pass now. */
  startRenewal(server: Pick<HttpsServer, "setSecureContext">): { stop: () => void; check: () => void };
}

type Source = HttpsStatus["source"];

function expiryWarnings(
  source: Source,
  server: CertSummary | undefined,
  ca: CertSummary | undefined,
  now: Date,
) {
  const warnings: string[] = [];
  const daysLeft = (s: CertSummary) => Math.floor((s.validTo.getTime() - now.getTime()) / DAY_MS);
  if (source === "user" && server) {
    const days = daysLeft(server);
    if (days < 0)
      warnings.push(`Your HTTPS certificate EXPIRED on ${server.validTo.toISOString().slice(0, 10)}.`);
    else if (days <= RENEW_BEFORE_DAYS)
      warnings.push(`Your HTTPS certificate expires in ${days} day(s); replace it.`);
  }
  if (ca && daysLeft(ca) <= CA_WARN_BEFORE_DAYS) {
    warnings.push(`The local CA expires in ${daysLeft(ca)} day(s); plan a new one (see the HTTPS docs).`);
  }
  return warnings;
}

const describeCert = (label: string, s: CertSummary): string =>
  `${label} SHA-256 ${s.fingerprint256} · expires ${s.validTo.toISOString().slice(0, 10)}`;

function logEnabled(
  deps: HttpsDeps,
  config: HttpsConfig,
  active: ServerMaterial,
  source: Source,
  ca?: CertSummary,
) {
  const why = config.enabledBy === "team-mode" ? " because team mode is on (DFIR_HTTPS=auto)" : "";
  deps.log(`[https] HTTPS is on${why}. ${describeCert("certificate", active.summary)}`);
  if (config.enabledBy === "team-mode") {
    deps.log("[https] behind a reverse proxy that speaks plain HTTP to the companion? set DFIR_HTTPS=off");
  }
  if (source === "generated" && ca) {
    deps.log(
      `[https] teammates trust this server via the local CA — ${describeCert("CA", ca)}; download /tls/ca.crt`,
    );
  }
}

/** The CA + generated server certificate; throws only when `fatal` (HTTPS on, no own files). */
function prepareGenerated(deps: HttpsDeps, config: HttpsConfig, dir: string, now: Date, fatal: boolean) {
  try {
    const loaded = loadOrCreateCa(dir, now);
    if (loaded.created) deps.log(`[https] created the local certificate authority in ${dir}`);
    const names = certNamesFor(config.extraNames);
    if (names.rejected.length)
      deps.warn(`[https] ignoring invalid DFIR_HTTPS_HOSTNAMES: ${names.rejected.join(", ")}`);
    return { ca: loaded.ca, generated: ensureServerCert(dir, loaded.ca, names, now) };
  } catch (err) {
    if (fatal) throw err;
    deps.warn(`[https] ${(err as Error).message}`);
    return {};
  }
}

/** Everything that can fail at startup, decided before the server listens. */
export function prepareHttps(deps: HttpsDeps): PreparedHttps {
  const now = deps.now ?? (() => new Date());
  const config = resolveHttpsConfig(deps.env, {
    teamMode: deps.teamMode,
    mainPort: deps.port,
    baseDir: dirname(resolve(deps.casesRoot)),
  });
  const dir = tlsDirFor(deps.casesRoot);
  const source: Source = !config.enabled ? undefined : config.certFile ? "user" : "generated";
  const { ca, generated } = prepareGenerated(deps, config, dir, now(), source === "generated");
  let active: ServerMaterial | undefined =
    source === "user"
      ? loadUserCertificate(config.certFile!, config.keyFile!)
      : source
        ? generated
        : undefined;
  const caSummary = ca ? summarize(ca.cert) : undefined;
  if (active) logEnabled(deps, config, active, source, caSummary);

  let warnings = expiryWarnings(source, active?.summary, caSummary, now());
  for (const w of warnings) deps.warn(`[https] ${w}`);
  const caDownload = !!ca && source !== "user";

  // The replacement certificate, if one is due: a re-issue from the CA, or the operator's files
  // after they changed on disk (`seenStamp` is the files' last-seen modification times).
  const renewOnce = (seenStamp: string, currentStamp: string): ServerMaterial | undefined => {
    if (source === "generated" && ca) {
      // Compared with what is SERVED, not "was it re-issued just now": a replacement written to disk
      // by a pass whose swap then failed must still be picked up by the next pass.
      const onDisk = ensureServerCert(dir, ca, certNamesFor(config.extraNames), now());
      return onDisk.summary.fingerprint256 !== active?.summary.fingerprint256 ? onDisk : undefined;
    }
    return source === "user" && currentStamp !== seenStamp
      ? loadUserCertificate(config.certFile!, config.keyFile!)
      : undefined;
  };

  return {
    config,
    ...(active ? { material: active } : {}),
    caCertPem: () => (caDownload ? ca?.certPem : undefined),
    status: () => ({
      enabled: config.enabled,
      mode: config.mode,
      enabledBy: config.enabledBy,
      source,
      ...(active ? { server: active.summary } : {}),
      ...(caSummary ? { ca: caSummary } : {}),
      caDownload,
      plainHttp: config.plainHttp,
      plainHttpPort: config.plainHttpPort,
      warnings,
    }),
    startRenewal(server) {
      const fileStamp = () =>
        config.certFile ? `${statSync(config.certFile).mtimeMs}:${statSync(config.keyFile!).mtimeMs}` : "";
      let stamp = source === "user" ? fileStamp() : "";
      let running = false;
      const check = () => {
        if (!config.enabled || running) return;
        running = true;
        try {
          const currentStamp = fileStamp();
          const next = renewOnce(stamp, currentStamp);
          if (next) {
            createSecureContext({ key: next.keyPem, cert: next.certPem }); // validate before swapping
            server.setSecureContext({ key: next.keyPem, cert: next.certPem, minVersion: "TLSv1.2" });
            active = next;
            deps.log(
              `[https] now serving a renewed certificate — ${describeCert("certificate", next.summary)}`,
            );
          }
          stamp = currentStamp; // only once the swap succeeded, so a failed one is retried next pass
          warnings = expiryWarnings(source, active?.summary, caSummary, now());
          for (const w of warnings) deps.warn(`[https] ${w}`);
        } catch (err) {
          deps.warn(
            `[https] certificate renewal failed; still serving the current one: ${(err as Error).message}`,
          );
        } finally {
          running = false;
        }
      };
      const timer = setInterval(check, RENEWAL_CHECK_MS);
      timer.unref();
      return { stop: () => clearInterval(timer), check };
    },
  };
}

export interface SideTaskDeps {
  /** The main listener — undefined when HTTPS is off, which makes this a no-op. */
  server: HttpsServer | undefined;
  app: RequestListener;
  host: string;
  port: number;
  env: NodeJS.ProcessEnv;
  isHostAllowed: (host: string) => boolean;
  log: (msg: string) => void;
  warn: (msg: string) => void;
}

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

function publicHttpsOrigin(env: NodeJS.ProcessEnv): string | undefined {
  try {
    const url = new URL(env.DFIR_PUBLIC_URL?.trim() ?? "");
    return url.protocol === "https:" ? url.origin : undefined;
  } catch {
    return undefined;
  }
}

/** Once the HTTPS port is up: the daily renewal check and the optional plain-HTTP port. */
export function startHttpsSideTasks(prepared: PreparedHttps, deps: SideTaskDeps): () => void {
  if (!deps.server || !prepared.config.enabled) return () => {};
  const renewal = prepared.startRenewal(deps.server);
  const { plainHttp, plainHttpPort, plainHttpHost } = prepared.config;
  let plain: HttpServer | undefined;
  if (plainHttp !== "off") {
    const serve = plainHttp === "serve";
    const bindHost = plainHttpHost ?? (serve ? "127.0.0.1" : deps.host);
    const origin = publicHttpsOrigin(deps.env);
    const handler = serve
      ? deps.app
      : redirectToHttps({
          httpsPort: deps.port,
          isHostAllowed: deps.isHostAllowed,
          ...(origin ? { publicOrigin: origin } : {}),
        });
    plain = listenPlainHttp(handler, plainHttpPort, bindHost, () =>
      deps.log(`[https] plain HTTP (${plainHttp}) on http://${bindHost}:${plainHttpPort}`),
    );
    plain.on("error", (err) =>
      deps.warn(`[https] the plain-HTTP port ${plainHttpPort} did not start: ${err.message}`),
    );
    if (serve && !LOOPBACK.has(bindHost)) {
      deps.warn(
        `[https] DFIR_HTTPS_PLAIN_HTTP=serve on ${bindHost}: the dashboard is ALSO served unencrypted to the ` +
          "network — logins, session cookies and case data cross it in clear text.",
      );
    }
  }
  return () => {
    renewal.stop();
    plain?.close();
  };
}
