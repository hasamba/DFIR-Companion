import { readFileSync } from "node:fs";
import { Agent, fetch as undiciFetch } from "undici";
import type { FetchFn } from "./provider.js";
import { isLoopbackHost } from "../providers/urlValidation.js";

function isLoopbackUrl(url: string): boolean {
  try { return isLoopbackHost(new URL(url).host); } catch { return false; }
}

// Custom TLS trust for self-hosted intel servers (MISP / YETI) that present an internal-CA
// or self-signed certificate. We scope this to ONE provider's fetch (not the whole process)
// so VirusTotal/AbuseIPDB and the AI calls keep the default, fully-verified trust store.
//
// Two modes, in order of preference:
//   - caCertPath: trust an internal/private CA bundle (PEM). Verification stays ON — secure.
//   - insecureSkipVerify: accept any cert without verifying (self-signed). Insecure; lab only.

export interface TlsFetchOptions {
  caCertPath?: string;          // PEM bundle for an internal/private CA
  insecureSkipVerify?: boolean; // skip cert verification entirely (self-signed)
  hostUrl?: string;            // the provider's base URL, used to check if insecureSkipVerify targets a loopback host
  onWarn?: (message: string) => void;
}

interface TlsConnectOptions {
  ca?: string;
  rejectUnauthorized?: boolean;
}

// Injectable seams so the construction logic is unit-testable without disk or network.
export interface TlsFetchDeps {
  readFile?: (path: string) => string;
  makeDispatcher?: (connect: TlsConnectOptions) => unknown;
  baseFetch?: FetchFn;
}

// Build a fetch bound to a custom TLS trust config, or undefined when no customization is
// requested (the caller then falls back to the global fetch — see each provider's
// `opts.fetchFn ?? fetch`). undici's Agent is the same engine that powers global fetch.
export function buildTlsFetch(opts: TlsFetchOptions, deps: TlsFetchDeps = {}): FetchFn | undefined {
  const read = deps.readFile ?? ((p: string) => readFileSync(p, "utf8"));
  const connect: TlsConnectOptions = {};

  if (opts.caCertPath) connect.ca = read(opts.caCertPath);
  if (opts.insecureSkipVerify) {
    // Guard: only allow insecureSkipVerify for loopback hosts. A non-loopback host with cert
    // verification disabled is a MITM risk — an on-path attacker can harvest the API key and
    // every queried IOC. The operator can override with DFIR_TLS_ALLOW_INSECURE_EXTERNAL=true,
    // but they must explicitly opt in.
    const allowInsecureExternal = process.env.DFIR_TLS_ALLOW_INSECURE_EXTERNAL === "true";
    const isLoopback = opts.hostUrl ? isLoopbackUrl(opts.hostUrl) : true;
    if (!isLoopback && !allowInsecureExternal) {
      throw new Error(
        "TLS certificate verification DISABLED for a non-loopback host. This is a MITM risk — an on-path attacker can harvest the API key. " +
        "Set DFIR_TLS_ALLOW_INSECURE_EXTERNAL=true to override (not recommended), or use a CA bundle (DFIR_*_CA) instead.",
      );
    }
    connect.rejectUnauthorized = false;
    opts.onWarn?.(
      "TLS certificate verification DISABLED for a self-hosted intel host (accepting self-signed certs). Insecure — lab use only; prefer an internal-CA bundle.",
    );
  }

  if (connect.ca === undefined && connect.rejectUnauthorized === undefined) return undefined;

  const dispatcher = (deps.makeDispatcher ?? ((c) => new Agent({ connect: c })))(connect);
  const base = deps.baseFetch ?? (undiciFetch as unknown as FetchFn);
  return ((input, init) =>
    base(input, { ...(init ?? {}), dispatcher } as RequestInit)) as FetchFn;
}
