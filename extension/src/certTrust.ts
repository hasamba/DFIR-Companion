// Why the companion could not be reached, worded for the two causes that look identical (#2473).
//
// In team mode the companion serves HTTPS with its own certificate authority. A browser that does
// not trust that CA makes fetch() throw "Failed to fetch" with no detail — exactly what a stopped
// server produces — so "companion offline" sent analysts to restart a healthy server. Over https
// both causes are named, and the CA download (a public route on the companion, /tls/ca.crt) is
// offered. Over plain http there is no certificate, so the old wording stays.

const CA_PATH = "/tls/ca.crt";

/** Explanation and CA link, split so the popup can render the URL as a link between two texts. */
export interface UntrustedCertHint {
  before: string;
  caUrl: string;
  after: string;
}

function isHttps(companionUrl: string): boolean {
  return /^https:\/\//i.test(companionUrl.trim());
}

function caUrlFor(companionUrl: string): string {
  return `${companionUrl.trim().replace(/\/+$/, "")}${CA_PATH}`;
}

/** The short reason a request got no response at all. */
export function unreachableReason(companionUrl: string): string {
  return isHttps(companionUrl)
    ? "can't reach the companion — it isn't running, or this browser doesn't trust its certificate"
    : "companion offline";
}

/** How to install the companion's CA, or null for an http companion (nothing to trust). */
export function untrustedCertHint(companionUrl: string): UntrustedCertHint | null {
  if (!isHttps(companionUrl)) return null;
  return {
    before:
      "If the companion is running, this browser probably doesn't trust its team-mode certificate. Download ",
    caUrl: caUrlFor(companionUrl),
    after:
      ", install it as a trusted certificate authority (your operating system's store, or Firefox's own"
      + " Authorities list), restart the browser, then Refresh. See Team authentication in the user manual.",
  };
}

/** One-line form of the hint, for surfaces that cannot hold a link (console push error). */
export function untrustedCertMessage(companionUrl: string): string | null {
  const hint = untrustedCertHint(companionUrl);
  return hint ? `${hint.before}${hint.caUrl}${hint.after}` : null;
}
