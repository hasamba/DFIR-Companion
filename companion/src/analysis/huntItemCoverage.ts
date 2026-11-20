import type { HuntFields } from "./huntArtifactFields.js";

/**
 * Per-host coverage of the values a client approval can match on an inventory item (#2670, #2731):
 * the SHA-256, the usable Amcache SHA1 and the verified signer. PURE.
 *
 * The rule is the same for each value: one host's approved value says nothing about a host seen only
 * through rows without it. So the item keeps, per value, the hosts that have NO observation carrying
 * it (a host leaves that list at its first such observation), and whether the value list lost an entry
 * to its cap. A list that is ABSENT (an item stored before the value was tracked) means "unknown", and
 * an approval by that value never covers the item.
 */
export const COVERAGE_MAX_VALUES = 20;

export interface CoverageStep {
  hostKey: string;
  knownHost: boolean;
  maxHosts: number;
}

/** The hosts still missing the value after one observation; undefined stays undefined (legacy). */
export function nextMissing(
  list: readonly string[] | undefined,
  covered: boolean,
  s: CoverageStep,
): string[] | undefined {
  if (!list) return undefined;
  if (covered) return list.filter((k) => k !== s.hostKey);
  // A known host is either already listed or has a covered observation; past the host cap,
  // hostOverflow says the item is incomplete.
  return s.knownHost || list.includes(s.hostKey) || list.length >= s.maxHosts
    ? [...list]
    : [...list, s.hostKey];
}

/** A value list is capped once a distinct value is dropped; an unrecorded flag (legacy) counts as capped. */
export function nextCapped(
  capped: boolean | undefined,
  list: readonly string[],
  value: string | undefined,
): boolean {
  return capped !== false || (!!value && !list.includes(value) && list.length >= COVERAGE_MAX_VALUES);
}

export function addCovered(list: readonly string[], v: string | undefined): string[] {
  return !v || list.includes(v) || list.length >= COVERAGE_MAX_VALUES ? [...list] : [...list, v];
}

/** The SHA1 and signer coverage an inventory item carries (#2731). */
export interface IdentityCoverage {
  /** Usable Amcache SHA1s (size recorded and within 30 MiB). Absent on an item stored before #2731. */
  sha1?: string[];
  /** Hosts with no usable SHA1 observation. Absent = unknown, never approved by SHA1. */
  noSha1Hosts?: string[];
  sha1Capped?: boolean;
  /** Some observation's SHA1 was for a file over 30 MiB: Amcache hashed only part of it. */
  sha1OverLimit?: true;
  /** Some observation's SHA1 came without a recorded file size. */
  sha1NoSize?: true;
  /** Distinct VERIFIED signers seen. Absent on an item stored before #2731. */
  signers?: string[];
  /** Hosts with no verified-signer observation. Absent = unknown, never approved by signer. */
  unsignedHosts?: string[];
  signersCapped?: boolean;
  /** Some observation's signature was checked and NOT verified. Sticky: no signer approval applies. */
  signatureUnverified?: true;
}

export const EMPTY_IDENTITY_COVERAGE: IdentityCoverage = {
  sha1: [],
  noSha1Hosts: [],
  sha1Capped: false,
  signers: [],
  unsignedHosts: [],
  signersCapped: false,
};

/** The item's SHA1 and signer coverage with one observation folded in. */
export function observeIdentity(base: IdentityCoverage, f: HuntFields, s: CoverageStep): IdentityCoverage {
  const sha1s = base.sha1 ?? [];
  const signers = base.signers ?? [];
  const signer = f.signatureUnverified ? undefined : f.signer;
  return {
    sha1: addCovered(sha1s, f.sha1),
    noSha1Hosts: nextMissing(base.noSha1Hosts, !!f.sha1, s),
    sha1Capped: nextCapped(base.sha1 ? base.sha1Capped : undefined, sha1s, f.sha1),
    ...(base.sha1OverLimit || f.sha1Unusable === "over-limit" ? { sha1OverLimit: true as const } : {}),
    ...(base.sha1NoSize || f.sha1Unusable === "no-size" ? { sha1NoSize: true as const } : {}),
    signers: addCovered(signers, signer),
    unsignedHosts: nextMissing(base.unsignedHosts, !!signer, s),
    signersCapped: nextCapped(base.signers ? base.signersCapped : undefined, signers, signer),
    ...(base.signatureUnverified || f.signatureUnverified ? { signatureUnverified: true as const } : {}),
  };
}
