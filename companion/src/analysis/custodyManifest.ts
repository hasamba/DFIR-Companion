import { createHmac, timingSafeEqual } from "node:crypto";
import type { CaseStore } from "../storage/caseStore.js";
import { toCaseRelative, type CustodyStore, type CustodyRecord, type CustodyChainBreak, type CustodyChainHead } from "./custody.js";
import { getAppVersion } from "../version.js";

/** Filename the manifest ships under, inside an export and in the case's reports dir. */
export const CUSTODY_MANIFEST_FILENAME = "custody-manifest.json";

export interface CustodyManifestArtifact {
  /** Relative to the case dir when the artifact lives inside it, absolute otherwise. */
  path: string;
  /** Hash from the most recent record for this artifact — what it was last known to be. */
  sha256: string;
  /** Every custody event for this artifact, in log order. */
  chain: CustodyRecord[];
}

export interface CustodyManifestSignature {
  algorithm: "HMAC-SHA256";
  value: string;
}

export interface CustodyManifest {
  version: 1;
  caseId: string;
  generatedAt: string;
  generatedBy: string;
  chain: CustodyChainHead & { breaks: CustodyChainBreak[] };
  artifacts: CustodyManifestArtifact[];
  signature: CustodyManifestSignature;
}

/**
 * Deterministic JSON: object keys sorted at every depth, arrays left in order. A signature over
 * plain JSON.stringify would depend on key insertion order, so a manifest that had merely been
 * parsed and re-serialized somewhere along the way could fail to verify while being untouched.
 */
function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",")}}`;
}

function sign(unsigned: Omit<CustodyManifest, "signature">, secret: Buffer): string {
  return createHmac("sha256", secret).update(canonicalize(unsigned), "utf8").digest("hex");
}

/**
 * Build the signed chain-of-custody manifest for a case: every artifact with its full chain, plus
 * where the log currently ends, HMAC'd with this installation's instance secret (#231).
 *
 * The signature is what makes tampering detectable without external PKI — an HSM-backed signature is
 * a deployment concern and deliberately out of scope. It covers the chain head as well as the
 * records, which is the point: verifyChain alone cannot see lines lopped off the end of the log,
 * because what remains is still a valid chain. The manifest pins the length and the final hash.
 */
export async function buildCustodyManifest(
  cases: CaseStore,
  custody: CustodyStore,
  caseId: string,
  secret: Buffer,
): Promise<CustodyManifest> {
  const [records, head, breaks] = await Promise.all([
    custody.load(caseId),
    custody.chainHead(caseId),
    custody.verifyChain(caseId),
  ]);

  const caseDir = cases.caseDir(caseId);
  // Insertion order = first-seen order, so artifacts appear as they entered the case.
  const byArtifact = new Map<string, CustodyRecord[]>();
  for (const record of records) {
    const existing = byArtifact.get(record.artifactPath);
    if (existing) existing.push(record);
    else byArtifact.set(record.artifactPath, [record]);
  }

  const artifacts: CustodyManifestArtifact[] = [...byArtifact].map(([artifactPath, chain]) => ({
    path: toCaseRelative(caseDir, artifactPath) ?? artifactPath,
    sha256: chain[chain.length - 1].sha256,
    chain,
  }));

  const unsigned: Omit<CustodyManifest, "signature"> = {
    version: 1,
    caseId,
    generatedAt: new Date().toISOString(),
    generatedBy: getAppVersion(),
    chain: { ...head, breaks },
    artifacts,
  };
  return { ...unsigned, signature: { algorithm: "HMAC-SHA256", value: sign(unsigned, secret) } };
}

/**
 * Recompute the manifest's HMAC and compare. False means the manifest was altered after signing, or
 * was signed by a different installation — the two are indistinguishable from the manifest alone,
 * which is the expected property of a shared-secret signature.
 */
export function verifyCustodyManifest(manifest: CustodyManifest, secret: Buffer): boolean {
  const { signature, ...unsigned } = manifest;
  if (!signature || signature.algorithm !== "HMAC-SHA256" || typeof signature.value !== "string") return false;
  const expected = Buffer.from(sign(unsigned, secret), "hex");
  const actual = Buffer.from(signature.value, "hex");
  // Lengths differ on a malformed signature, where timingSafeEqual throws rather than returning false.
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
