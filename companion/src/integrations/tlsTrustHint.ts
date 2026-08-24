// Turns a TLS certificate rejection into the two settings that actually fix it.
//
// A self-signed or private-CA certificate is the most common way a self-hosted integration fails
// its very first connection, and Node describes it in a way that names no fix we own:
//
//   Timesketch request failed: fetch failed -> self-signed certificate; if the root CA is
//   installed locally, try running Node.js with --use-system-ca (DEPTH_ZERO_SELF_SIGNED_CERT)
//
// That `--use-system-ca` advice is Node's own, and it is the wrong one here: the Companion already
// has per-integration TLS trust (DFIR_<NAME>_CA / DFIR_<NAME>_INSECURE, resolved in
// composition/tlsFetch.ts), and neither is discoverable from that sentence — so the analyst reads a
// dead end while the knob sits one Settings tab away. Same class of fix as the MISP connectivity
// diagnostics (integrations/misp/mispConnectivity.ts): name the likely cause, and ONLY when the
// evidence supports it — an ECONNREFUSED must never be answered with certificate advice.

// undici rejects with TypeError("fetch failed") and hides the actionable reason on `cause`,
// sometimes one level deeper still. "" when no code is found anywhere in the chain.
export function tlsCauseCode(err: unknown): string {
  let cur: unknown = err;
  for (let depth = 0; cur && depth < 5; depth++) {
    const e = cur as { code?: unknown; cause?: unknown };
    if (typeof e.code === "string" && e.code) return e.code;
    cur = e.cause;
  }
  return "";
}

// Node surfaces certificate problems as a family of OpenSSL codes rather than one value:
// DEPTH_ZERO_SELF_SIGNED_CERT, SELF_SIGNED_CERT_IN_CHAIN, CERT_HAS_EXPIRED,
// ERR_TLS_CERT_ALTNAME_INVALID, … UNABLE_TO_VERIFY_LEAF_SIGNATURE is spelled out because it
// contains neither "CERT" nor "SELF_SIGNED" — and it is exactly the private-CA case a
// DFIR_<NAME>_CA bundle fixes, so a substring-only rule would stay silent on the one failure the
// hint is most useful for.
export function isCertFailureCode(code: string): boolean {
  return code.includes("CERT") || code.includes("SELF_SIGNED") || code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE";
}

/**
 * Suffix naming the fix for a certificate rejection, or "" for any other failure.
 *
 * `name` is the DFIR_<NAME>_ family the caller's client is wired to in composition/tlsFetch.ts —
 * "TIMESKETCH", "IRIS", … — so the message quotes the env vars that this integration reads, not a
 * generic pair the operator then has to translate.
 *
 * The DFIR_TLS_ALLOW_INSECURE_EXTERNAL clause is not padding: the insecure flag alone is REFUSED
 * for a non-loopback host (#246), so an operator told only about DFIR_<NAME>_INSECURE=1 sets it,
 * retries, and hits the identical certificate error with no new information.
 */
export function tlsTrustHint(err: unknown, name: string): string {
  const code = tlsCauseCode(err);
  if (!isCertFailureCode(code)) return "";
  return (
    ` — the certificate is not trusted. Settings › Integrations: set DFIR_${name}_CA to a PEM CA` +
    ` bundle to keep verification ON, or "Skip TLS verify" (DFIR_${name}_INSECURE=1) to accept it` +
    ` unverified (lab only — a non-loopback host also needs DFIR_TLS_ALLOW_INSECURE_EXTERNAL=true).`
  );
}
