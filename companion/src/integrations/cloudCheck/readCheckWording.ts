// The words a cloud read check reports (#2309), and the scrubbed reason a failed call gives.
//
// The summary has a fixed form so the analyst always reads the same three things — what worked,
// what did not, and that writes were never tested:
//
//   Tested reads succeeded for: A, B. Failed: C (reason). The companion did not test whether this
//   identity can also write. Use the minimum policy.
//
// A "Not tested: …" sentence sits before the closing sentence only when a source could not be tried
// (no bucket named, no Data Access entry to read). The check never says an account is read-only or verified.

import type { SourceCheckResult } from "./readCheckTypes.js";

export const WRITE_NOT_TESTED =
  "The companion did not test whether this identity can also write. Use the minimum policy.";

const MAX_DETAIL = 300;

function listed(results: SourceCheckResult[], withDetail: boolean): string {
  if (results.length === 0) return "none";
  return results.map((r) => (withDetail && r.detail ? `${r.label} (${r.detail})` : r.label)).join(", ");
}

/** The report's one-paragraph summary, in the fixed form above. */
export function checkSummary(results: SourceCheckResult[]): string {
  const ok = results.filter((r) => r.status === "succeeded");
  const failed = results.filter((r) => r.status === "failed");
  const skipped = results.filter((r) => r.status === "not-tested");
  const parts = [`Tested reads succeeded for: ${listed(ok, false)}.`, `Failed: ${listed(failed, true)}.`];
  if (skipped.length > 0) parts.push(`Not tested: ${listed(skipped, true)}.`);
  parts.push(WRITE_NOT_TESTED);
  return parts.join(" ");
}

interface ErrorShape {
  name?: unknown;
  code?: unknown;
  message?: unknown;
  status?: unknown;
  $metadata?: { httpStatusCode?: unknown };
  response?: { status?: unknown; data?: { error?: { status?: unknown; message?: unknown } } };
}

// Error class names that say nothing to an analyst; the status and message carry the reason.
const GENERIC_NAMES = new Set(["", "Error", "GraphError", "GaxiosError"]);

function text(v: unknown): string {
  return typeof v === "string" ? v : typeof v === "number" ? String(v) : "";
}

function rawReason(err: unknown): string {
  if (err instanceof SyntaxError) return "the stored credential could not be read";
  const e = (err ?? {}) as ErrorShape;
  if (e.name === "AbortError" || e.name === "TimeoutError") return "no answer in time";
  // The check's own refusals (an account stored without what it needs, a PFX that will not open)
  // are fixed text already.
  if (e.name === "CheckSetupError" || e.name === "CertificateError") return text(e.message);
  const gcp = e.response?.data?.error;
  const status = text(e.$metadata?.httpStatusCode) || text(e.response?.status) || text(e.status);
  const name = GENERIC_NAMES.has(text(e.name)) ? "" : text(e.name);
  const code = text(gcp?.status) || text(e.code) || name;
  const message = text(gcp?.message) || text(e.message);
  const head = [status && `HTTP ${status}`, code].filter(Boolean).join(" ");
  return [head, message].filter(Boolean).join(": ") || "unknown error";
}

/**
 * A short, single-line reason for a failed call, with every secret of the account cut out. Cloud
 * error text names actions, resources and the caller's ARN — useful to the analyst and not secret —
 * but a credential library can quote its input, so every stored secret value is redacted anyway.
 */
export function checkFailureReason(err: unknown, secrets: readonly string[]): string {
  let reason = rawReason(err).replace(/\s+/g, " ").trim();
  // Longest first, so a secret that contains a shorter one is cut whole.
  for (const s of [...secrets].filter((v) => v.length >= 4).sort((a, b) => b.length - a.length)) {
    reason = reason.split(s).join("[redacted]");
  }
  return reason.length > MAX_DETAIL ? `${reason.slice(0, MAX_DETAIL - 1)}…` : reason;
}
