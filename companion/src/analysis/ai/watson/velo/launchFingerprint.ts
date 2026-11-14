import { normalizeVql, vqlFingerprint } from "../../../huntOutcomes.js";
import { canonicalVqlFingerprint } from "./vqlAllowed.js";

// What a launch is remembered by in the durable index (huntFingerprintStore.ts). A fleet hunt is
// keyed by its VQL alone — the same key the hunt-outcome ledger uses. A single-host collection is
// keyed by VQL + the resolved host (lowercased), so the same VQL on another host is a new run.
// Each launch has two keys: the ledger's whitespace-normalised fingerprint and the canonical one
// that ignores comments and keyword case (vqlAllowed.ts), so a comment-only variant is a re-run.

const hostKey = (host: string): string => host.trim().toLowerCase();

/** The primary fingerprint of a launch: VQL alone for a fleet hunt, VQL + host for a collection. */
export function launchFingerprint(vql: string, host?: string): string {
  if (!host?.trim()) return vqlFingerprint(vql);
  return vqlFingerprint(`${normalizeVql(vql)} @host=${hostKey(host)}`);
}

/** Every fingerprint a launch is recorded and checked under (primary + canonical). */
export function launchFingerprints(vql: string | undefined, host?: string): string[] {
  if (!vql?.trim()) return [];
  const canonical = canonicalVqlFingerprint(vql);
  const canonicalKey =
    canonical && host?.trim() ? `c${vqlFingerprint(`${canonical} @host=${hostKey(host)}`)}` : canonical;
  return [launchFingerprint(vql, host), canonicalKey].filter(Boolean);
}
