// Settings → CrowdStrike Next-Gen SIEM → Test (#2685). Checks the SIEM API client one step at a
// time, so the analyst learns WHICH part is wrong before a real search fails inside a case:
//
//   reach   — the API host answered at all (DNS, network, TLS)
//   signin  — the client ID / secret / cloud were accepted (a token came back)
//   write   — a tiny query job started on the configured repository   (scope NGSIEM: Write)
//   read    — that job was polled once                                  (scope NGSIEM: Read)
//
// The job is `count()` over the last five minutes and is always cancelled. Nothing is imported and
// no case is read or written — this module has no store at all. Steps after the first failure are
// left out rather than marked failed: they were never tried.

import { readBoundedJson, readBoundedText, RESPONSE_SIZE_LIMITS } from "../../providers/boundedResponse.js";
import { FalconAuthError, FalconTokenSource, type FalconFetch } from "./falconAuth.js";
import { fetchFailureLogLine, redact } from "./fetchFailure.js";
import { hostLabel, ngsiemBase, type NgsiemCredentials } from "./ngsiemConfig.js";
import { describeNgsiemFailure, NGSIEM_LABEL, queryJobsPath } from "./ngsiemSearch.js";
import { NgsiemCaError, ngsiemFetchFor } from "./ngsiemTransport.js";
import type { PeerIssuerFn } from "./tlsPeerIssuer.js";

const STEP_TIMEOUT_MS = 10_000;
const PROBE_WINDOW_MS = 5 * 60_000;
const MESSAGE_MAX = 300;

export type ProbeStepId = "settings" | "reach" | "signin" | "write" | "read";

export interface ProbeStep {
  id: ProbeStepId;
  label: string;
  ok: boolean;
  detail?: string;
}

export interface ProbeResult {
  configured: true;
  ok: boolean;
  host?: string;
  repository: string;
  steps: ProbeStep[];
  warnings: string[];
  error?: string;
}

export interface ProbeOptions extends NgsiemCredentials {
  repository: string;
  fetchFn?: FalconFetch;
  peerIssuer?: PeerIssuerFn;
  log?: (line: string) => void;
  now?: () => number;
}

const LABELS: Record<ProbeStepId, string> = {
  settings: "settings",
  reach: "reached",
  signin: "signed in",
  write: "NGSIEM: Write (job started)",
  read: "NGSIEM: Read (job polled)",
};

/** Falcon's own words from an error body, bounded and on one line. */
async function falconWords(res: Response): Promise<string> {
  const text = await readBoundedText(res, { maxBytes: 16 * 1024, context: NGSIEM_LABEL }).catch(() => "");
  try {
    const j = JSON.parse(text) as Record<string, unknown>;
    const errs = Array.isArray(j.errors) ? (j.errors as Array<Record<string, unknown>>) : [];
    const m = errs[0]?.message ?? j.message ?? j.error;
    if (typeof m === "string") return m.replace(/\s+/g, " ").trim().slice(0, MESSAGE_MAX);
  } catch {
    /* not JSON */
  }
  return text.replace(/\s+/g, " ").trim().slice(0, MESSAGE_MAX);
}

function httpMeaning(status: number, step: "write" | "read", repository: string): string {
  const scope = step === "write" ? "NGSIEM: Write" : "NGSIEM: Read";
  if (status === 401)
    return `Falcon rejected the token for this call (HTTP 401) — the API client may lack ${scope}.`;
  if (status === 403) return `The SIEM API client is missing the ${scope} scope (HTTP 403).`;
  if (status === 404 && step === "write")
    return `Falcon has no repository "${repository}" visible to this API client (HTTP 404). Check DFIR_CROWDSTRIKE_SIEM_REPOSITORY.`;
  if (status === 404) return "The test job disappeared before it could be polled (HTTP 404).";
  if (status === 429) return "CrowdStrike rate-limited the test (HTTP 429). Try again in a minute.";
  return `CrowdStrike NG-SIEM answered HTTP ${status}.`;
}

/** Run the four steps. Never throws for a Falcon or network problem — it reports it as a step. */
export async function probeNgsiem(opts: ProbeOptions): Promise<ProbeResult> {
  const steps: ProbeStep[] = [];
  const warnings: string[] = [];
  const secrets = [opts.clientSecret, opts.clientId];
  const clean = (s: string) => redact(s, secrets);
  const result = (): ProbeResult => {
    const failed = steps.find((s) => !s.ok);
    return {
      configured: true,
      ok: !failed,
      ...(host ? { host } : {}),
      repository: opts.repository,
      steps,
      warnings,
      ...(failed?.detail ? { error: failed.detail } : {}),
    };
  };
  const pass = (id: ProbeStepId, detail?: string) =>
    steps.push({ id, label: LABELS[id], ok: true, ...(detail ? { detail: clean(detail) } : {}) });
  const fail = (id: ProbeStepId, detail: string) => {
    steps.push({ id, label: LABELS[id], ok: false, detail: clean(detail) });
    return result();
  };

  let host = "";
  const base = ngsiemBase(opts);
  if (!base.ok) return fail("settings", base.error);
  host = hostLabel(base.base);
  let fetchFn: FalconFetch;
  try {
    fetchFn = opts.fetchFn ?? ngsiemFetchFor(opts.ca);
  } catch (err) {
    if (err instanceof NgsiemCaError) return fail("settings", err.message);
    throw err;
  }
  const network = async (err: unknown): Promise<string> => {
    opts.log?.(`${host}: ${fetchFailureLogLine(err, secrets)}`);
    const name = (err as { name?: string })?.name;
    if (name === "TimeoutError" || name === "AbortError")
      return `${NGSIEM_LABEL} (${host}) did not answer in time.`;
    return describeNgsiemFailure(err, base.base, opts.peerIssuer);
  };

  const tokens = new FalconTokenSource({
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    base: base.base,
    fetchFn,
    timeoutMs: STEP_TIMEOUT_MS,
    authFailedMessage:
      "Falcon rejected the sign-in — check DFIR_CROWDSTRIKE_SIEM_CLIENT_ID / _SECRET and the cloud region.",
    label: NGSIEM_LABEL,
  });
  let token: string;
  try {
    token = await tokens.get(true);
  } catch (err) {
    if (err instanceof FalconAuthError) {
      pass("reach", host);
      return fail("signin", err.message);
    }
    if (err instanceof Error && /token HTTP \d+/.test(err.message)) {
      pass("reach", host);
      return fail("signin", `${err.message.replace(/^.*token /, "Sign-in answered ")}.`);
    }
    return fail("reach", await network(err));
  }
  pass("reach", host);
  pass("signin");

  const call = (method: string, path: string, body?: string) =>
    fetchFn(`${base.base}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/json",
        ...(body ? { "content-type": "application/json" } : {}),
      },
      ...(body ? { body } : {}),
      signal: AbortSignal.timeout(STEP_TIMEOUT_MS),
    });

  const now = (opts.now ?? Date.now)();
  let jobId: string | undefined;
  try {
    let res: Response;
    try {
      const body = JSON.stringify({
        queryString: "count()",
        start: now - PROBE_WINDOW_MS,
        end: now,
        isLive: false,
      });
      res = await call("POST", queryJobsPath(opts.repository), body);
    } catch (err) {
      return fail("write", await network(err));
    }
    if (res.status === 400 || res.status === 422)
      return fail(
        "write",
        `Falcon refused the test query: "${(await falconWords(res)) || `HTTP ${res.status}`}"`,
      );
    if (!res.ok) return fail("write", httpMeaning(res.status, "write", opts.repository));
    const empty: { id?: unknown } = {};
    const started = await readBoundedJson<{ id?: unknown }>(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.json,
      context: NGSIEM_LABEL,
    }).catch(() => empty);
    if (typeof started.id !== "string" || !started.id || started.id.length > 512)
      return fail("write", "CrowdStrike NG-SIEM did not return a search job id.");
    jobId = started.id;
    pass("write");

    try {
      res = await call("GET", queryJobsPath(opts.repository, jobId));
    } catch (err) {
      return fail("read", await network(err));
    }
    if (!res.ok) return fail("read", httpMeaning(res.status, "read", opts.repository));
    const polled = await readBoundedJson<unknown>(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.json,
      context: NGSIEM_LABEL,
    }).catch(() => undefined);
    if (!polled || typeof polled !== "object" || Array.isArray(polled))
      return fail(
        "read",
        "CrowdStrike NG-SIEM answered the poll with something that is not a search status.",
      );
    pass("read");
    return result();
  } finally {
    if (jobId) await cancel(call, queryJobsPath(opts.repository, jobId), warnings);
  }
}

async function cancel(
  call: (method: string, path: string) => Promise<Response>,
  path: string,
  warnings: string[],
): Promise<void> {
  try {
    const res = await call("DELETE", path);
    if (!res.ok && res.status !== 404)
      warnings.push(`Falcon did not confirm the cancel of the test job (HTTP ${res.status}).`);
  } catch {
    warnings.push(
      "Falcon did not confirm the cancel of the test job; it expires on its own in about 90 seconds.",
    );
  }
}
