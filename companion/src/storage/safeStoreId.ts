import { join, resolve, sep } from "node:path";

/**
 * Caller-supplied id validation for the flat-file JSON stores (issue #213).
 *
 * TemplateStore, ReportTemplateStore, DashboardViewStore and ArtifactBundleStore all address their
 * records as `<root>/<id>.json`, and all of them took the id straight from a request body or a
 * `:id` route param. A traversal component in that id (`../../…`) walked the write, read, or delete
 * out of the store directory — reachable from a browser page before the origin guard landed, and
 * still reachable from any scripted caller.
 *
 * Two independent defenses, because either one alone is a single point of failure:
 *   1. A strict allowlist charset — an id can only ever be a flat filename.
 *   2. A containment check on the resolved path — whatever slipped through, the file stays in root.
 */

/** Thrown when an id could address something outside its store. Routes map this to a 400. */
export class UnsafeStoreIdError extends Error {
  constructor(id: unknown, reason: string) {
    super(`invalid store id ${JSON.stringify(String(id))}: ${reason}`);
    this.name = "UnsafeStoreIdError";
  }
}

// Alphanumeric start (so `.`, `..` and dotfiles are out), then alphanumerics, dot, dash, underscore.
// Covers every id the stores actually mint or ship: UUIDs and kebab-case built-ins like
// "super-timeline-triage". Deliberately excludes both separators, `:` (drive letters), `%`
// (encoded traversal), whitespace and control characters.
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** Validate and normalize a store id, or throw {@link UnsafeStoreIdError}. */
export function assertSafeStoreId(id: string): string {
  if (typeof id !== "string") throw new UnsafeStoreIdError(id, "must be a string");
  const trimmed = id.trim();
  if (!trimmed) throw new UnsafeStoreIdError(id, "must not be empty");
  if (!SAFE_ID.test(trimmed)) {
    throw new UnsafeStoreIdError(id, "may contain only letters, digits, dot, dash and underscore, and must start with a letter or digit");
  }
  return trimmed;
}

/**
 * Resolve `<root>/<id>.json`, guaranteeing the result is beneath `root`.
 *
 * The containment check is not redundant with the charset check — it is what keeps this correct if
 * the charset is ever loosened, and it costs nothing.
 */
export function storeFilePath(root: string, id: string): string {
  const safeId = assertSafeStoreId(id);
  const rootResolved = resolve(root);
  const full = resolve(join(rootResolved, `${safeId}.json`));
  if (full !== rootResolved && !full.startsWith(rootResolved + sep)) {
    throw new UnsafeStoreIdError(id, "resolves outside its store directory");
  }
  return full;
}
