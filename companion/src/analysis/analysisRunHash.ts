import { createHash } from "node:crypto";
import type { AnalysisRunClaim, ManifestValue } from "./analysisRunTypes.js";

const SENSITIVE_KEY = /(api[-_]?key|secret|token|credential|password|authorization|cookie)/i;
const BEARER_VALUE = /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi;
const URI_CREDENTIALS = /([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/gi;
const OPENAI_STYLE_KEY = /\bsk-[A-Za-z0-9_-]{12,}\b/g;

function sanitizedString(value: string): string {
  return value
    .replace(BEARER_VALUE, "Bearer [REDACTED]")
    .replace(URI_CREDENTIALS, "$1[REDACTED]@")
    .replace(OPENAI_STYLE_KEY, "[REDACTED]");
}

/** Remove credentials defensively even if a caller accidentally includes a provider config object. */
export function sanitizeManifestValue(value: ManifestValue, key = ""): ManifestValue {
  if (SENSITIVE_KEY.test(key)) return "[REDACTED]";
  if (typeof value === "string") return sanitizedString(value);
  if (Array.isArray(value)) return value.map((item) => sanitizeManifestValue(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, child]) => [childKey, sanitizeManifestValue(child, childKey)]),
    );
  }
  return value;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, canonicalize(record[key])]),
    );
  }
  return value;
}

export function hashManifestValue(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(canonicalize(value)))
    .digest("hex");
}

export function hashClaim(value: {
  title?: string;
  severity?: string;
  description?: string;
  evidenceEventIds?: readonly string[];
}): string {
  return hashManifestValue({
    title: value.title ?? "",
    severity: value.severity ?? "",
    description: value.description ?? "",
    evidenceEventIds: [...(value.evidenceEventIds ?? [])].sort(),
  });
}

export function claimSnapshot(id: string, value: Parameters<typeof hashClaim>[0]): AnalysisRunClaim {
  return {
    id,
    hash: hashClaim(value),
    evidenceEventIds: [...(value.evidenceEventIds ?? [])],
  };
}
