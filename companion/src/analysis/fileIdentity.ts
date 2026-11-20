import { z } from "zod";

/**
 * What an endpoint artifact recorded about ONE file, beyond its path (#2731): the Amcache SHA1 with
 * the file size Amcache recorded, and the Authenticode verdict Autoruns reported. Kept together on
 * one field so the hash and the size it depends on can never be carried apart.
 *
 * Importer-only, like `timeBasis`: a model must never assert a signer or a hash that a client
 * approval could match, so `stripAiExtractedFrom` drops this field from every model delta.
 *
 *   sha1                 — the Amcache InventoryApplicationFile SHA1. Windows computes it over only the
 *                          FIRST 30 MiB of the file, so it identifies a larger file only partly.
 *   size                 — the file size in bytes Amcache recorded beside that SHA1.
 *   signer               — a VERIFIED Authenticode signer: only an Autoruns "Signer" value that starts
 *                          with "(Verified) ". Never Company, Publisher or version-info text.
 *   signatureUnverified  — Autoruns checked the signature and did NOT verify it.
 */
export interface FileIdentity {
  sha1?: string;
  size?: number;
  signer?: string;
  signatureUnverified?: true;
}

/** Amcache hashes only the first 31,457,280 bytes of a file: a SHA1 identifies a file up to this size. */
export const AMCACHE_SHA1_MAX_BYTES = 30 * 1024 * 1024;

const SHA1_RE = /^[0-9a-f]{40}$/;

export const fileIdentitySchema = z.object({
  sha1: z.string().regex(SHA1_RE).optional().catch(undefined),
  size: z.number().int().nonnegative().optional().catch(undefined),
  signer: z.string().min(1).max(260).optional().catch(undefined),
  signatureUnverified: z.literal(true).optional().catch(undefined),
});

/** The SHA1 a client approval may use: only when the size is recorded and within the Amcache limit. */
export function usableSha1(f: FileIdentity | undefined): string | undefined {
  if (!f?.sha1 || f.size === undefined) return undefined;
  return f.size <= AMCACHE_SHA1_MAX_BYTES ? f.sha1 : undefined;
}

/** Why a recorded SHA1 cannot approve its file, or undefined when it can (or there is none). */
export function sha1Unusable(f: FileIdentity | undefined): "no-size" | "over-limit" | undefined {
  if (!f?.sha1) return undefined;
  if (f.size === undefined) return "no-size";
  return f.size > AMCACHE_SHA1_MAX_BYTES ? "over-limit" : undefined;
}

const sameIdentity = (a: FileIdentity, b: FileIdentity): boolean =>
  a.sha1 === b.sha1 && a.size === b.size && a.signer === b.signer;

/**
 * Two rows folded into one event (one aggregation group): a row with no identity adds nothing, and
 * rows that DISAGREE on the hash, size or signer keep none of them, so a replaced binary is never
 * covered by the other row's approval. A failed signature check is sticky.
 */
export function mergeFileIdentity(
  a: FileIdentity | undefined,
  b: FileIdentity | undefined,
): FileIdentity | undefined {
  if (!a || !b) return a ?? b;
  const unverified = a.signatureUnverified || b.signatureUnverified;
  if (sameIdentity(a, b)) return unverified ? { ...a, signatureUnverified: true } : a;
  return unverified ? { signatureUnverified: true } : undefined;
}
