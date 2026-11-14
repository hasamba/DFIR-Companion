import { normalizeVql, vqlFingerprint } from "../../../huntOutcomes.js";
import { canonicalVqlFingerprint } from "./vqlAllowed.js";

// What a launch is remembered by in the durable index (huntFingerprintStore.ts). A fleet hunt is
// keyed by its VQL alone — the same key the hunt-outcome ledger uses. A single-host collection is
// keyed by VQL + the host's key (below), so the same VQL on another host is a new run.
// Each launch has two keys: the ledger's whitespace-normalised fingerprint and the canonical one
// that ignores comments and keyword case (vqlAllowed.ts), so a comment-only variant is a re-run.

// A host's key is its first DNS label, lowercased (an IPv4 address is kept whole): the route passes
// the name the analyst typed ("host-a.corp.example.com") while checkLaunch has the inventory's
// ("HOST-A"), and both must key the same run. Two hosts sharing a short name share a key — that only
// ever refuses more, and checkLaunch already refuses an ambiguous short name.
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
export function hostKey(host: string): string {
  const h = host.trim().toLowerCase();
  return IPV4.test(h) ? h : h.split(".")[0];
}

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
