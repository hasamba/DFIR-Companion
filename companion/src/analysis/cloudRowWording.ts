// How cloud rows word two things the raw record spells badly (#2486), and the older wording mapped
// to the current one. PURE, with no imports: the importers write the current wording, and the Sigma
// re-grade (sigmaRegrade.ts) reads a row stored in the old wording as the same row.

/**
 * What a "hidden" Entra risk level means, in words. Graph returns `hidden` when the tenant has no
 * Entra ID P2 licence: no risk check was possible, which is not the same as a risk that is hidden.
 */
export const ENTRA_RISK_HIDDEN_WORDS = "not visible (no Entra ID P2)";

/** The sign-in row's marker for a hidden risk level. Before #2486 it read "[risk: hidden]". */
export const ENTRA_RISK_HIDDEN_MARKER = `[risk level ${ENTRA_RISK_HIDDEN_WORDS}]`;

// The versioned API package in front of a GCP method ("google.iam.admin.v1.", "google.cloud.orgpolicy.v2.").
const GCP_METHOD_PACKAGE_RE = /^google\.(?:[a-z0-9_]+\.)*?v\d+[a-z0-9]*\./;

/**
 * The method as a GCP row's title shows it: the versioned `google.<svc>.<ver>.` package is left
 * out, so `google.iam.admin.v1.CreateServiceAccount` reads `CreateServiceAccount` like
 * `SetIamPolicy` already does. A method without that package is shown as it is. The canonical
 * record keeps the full method.
 */
export function shortGcpMethod(method: string): string {
  return method.replace(GCP_METHOD_PACKAGE_RE, "") || method;
}

const LEGACY_GCP_HEAD_RE = /^GCP (\S+)/;
const LEGACY_RISK_HIDDEN_RE = /\[risk: hidden\]/i;

/** A stored row's text in the current wording: a pre-#2486 GCP head or hidden-risk marker rewritten. */
export function currentCloudWording(text: string): string {
  return text
    .replace(LEGACY_GCP_HEAD_RE, (_m, method: string) => `GCP ${shortGcpMethod(method)}`)
    .replace(LEGACY_RISK_HIDDEN_RE, ENTRA_RISK_HIDDEN_MARKER);
}
