import { createHash } from "node:crypto";

/**
 * The provenance record a `.dfircase` package carries, and the check that the package matches it.
 *
 * Export writes `archive-manifest.json` listing every entry with its SHA-256 (caseExportArchive.ts).
 * Import used to read the `counts` field out of it and drop the rest, so nothing ever compared the
 * bytes that arrived against the list the exporter recorded, and the imported case kept no record
 * of where it came from (#904).
 *
 * What this is: an integrity and chain-of-custody control. It proves the received package matches
 * the manifest its exporter signed off on, and it catches an archive assembled, truncated or
 * re-zipped incorrectly.
 *
 * What this is NOT: a defence against a hostile modifier. The container is AES-256-GCM, so tampering
 * in transit already fails at decryption (caseEncryption.ts) — and anyone able to re-seal the
 * archive holds the password and could recompute the manifest to match. Do not describe it as one.
 */

/**
 * One entry of an opened archive — structurally the entry type analysis/zipArchive.ts produces,
 * restated here rather than imported: this module sits in analysis/case, which may not depend on
 * analysis/ingest (see ARCHITECTURE.md), and the shape is all it needs.
 */
export interface ArchiveEntry {
  path: string;
  data: Buffer;
}

export const ARCHIVE_MANIFEST_PATH = "archive-manifest.json";

/** Where an imported case keeps the manifest of the archive it came from. */
export const SOURCE_MANIFEST_PATH = "metadata/source-manifest.json";

export interface CaseArchiveManifestFile {
  path: string;
  sha256: string;
  bytes: number;
  /** Present only when the case-directory name could not be an archive entry name unchanged. */
  originalPath?: string;
}

export interface CaseArchiveManifest {
  caseId: string;
  exportedAt: string;
  generatedBy: string;
  files: CaseArchiveManifestFile[];
  totalFiles: number;
  totalBytes: number;
}

/** What the importer tells the analyst about where a case came from. */
export interface CaseArchiveProvenance {
  /** The case id the archive was exported under — stale if the import renamed it. */
  sourceCaseId: string;
  exportedAt: string;
  /** App version of the build that wrote the archive. */
  generatedBy: string;
  totalFiles: number;
  totalBytes: number;
}

function isManifestFile(value: unknown): value is CaseArchiveManifestFile {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const file = value as Record<string, unknown>;
  return (
    typeof file.path === "string" &&
    file.path.length > 0 &&
    typeof file.sha256 === "string" &&
    file.sha256.length > 0 &&
    Number.isSafeInteger(file.bytes) &&
    Number(file.bytes) >= 0
  );
}

/**
 * The manifest, or null when the archive has none, it does not parse, or it lacks the fields
 * verification needs.
 *
 * Null is deliberately permissive: archives written before the manifest carried checksums must stay
 * importable forever, exactly as v1 containers stay readable forever. It costs nothing against the
 * threat model above — a party who can strip the manifest can also rewrite it.
 */
export function parseArchiveManifest(entry: ArchiveEntry | undefined): CaseArchiveManifest | null {
  if (!entry) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(entry.data.toString("utf8"));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const manifest = parsed as Record<string, unknown>;
  if (typeof manifest.caseId !== "string" || !manifest.caseId) return null;
  if (!Array.isArray(manifest.files) || !manifest.files.every(isManifestFile)) return null;
  return {
    caseId: manifest.caseId,
    exportedAt: typeof manifest.exportedAt === "string" ? manifest.exportedAt : "",
    generatedBy: typeof manifest.generatedBy === "string" ? manifest.generatedBy : "",
    files: manifest.files,
    totalFiles: Number.isSafeInteger(manifest.totalFiles)
      ? Number(manifest.totalFiles)
      : manifest.files.length,
    totalBytes: Number.isSafeInteger(manifest.totalBytes) ? Number(manifest.totalBytes) : 0,
  };
}

/**
 * Throw unless `entries` is exactly what the manifest describes, byte for byte.
 *
 * `entries` must already exclude archive-manifest.json itself: the manifest is written after the
 * file list is closed, so it never lists itself, and passing it in would read as an unlisted file.
 *
 * Every message starts with "not a valid case archive" so routes/encryptedImport.ts classifies it
 * as a 400 alongside the path and container failures, not a 500.
 */
export function verifyArchiveManifest(manifest: CaseArchiveManifest, entries: ArchiveEntry[]): void {
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  const listed = new Set<string>();
  for (const file of manifest.files) {
    // Duplicate rows are refused BEFORE anything is hashed, and the check is what bounds this loop
    // to one SHA-256 per archive entry. Rows are cheap to write and the entry a row points at can
    // be 512 MB, so a manifest repeating one path thousands of times used to buy that many hashes
    // of the same large buffer — synchronously, on the event loop, from any authenticated caller
    // holding a password they chose themselves. That is the resource the import route's rate
    // limiting exists to protect. A real export never writes a duplicate row, so nothing is lost.
    if (listed.has(file.path)) {
      throw new Error(`not a valid case archive: manifest lists "${file.path}" twice`);
    }
    listed.add(file.path);
    const entry = byPath.get(file.path);
    if (!entry) {
      throw new Error(
        `not a valid case archive: manifest lists a file the archive does not contain "${file.path}"`,
      );
    }
    const actual = createHash("sha256").update(entry.data).digest("hex");
    if (actual !== file.sha256) {
      throw new Error(`not a valid case archive: manifest checksum mismatch for "${file.path}"`);
    }
  }
  // The other direction matters just as much: a package that carries a file its manifest never
  // accounted for is not the package the exporter attested to, whatever the listed files hash to.
  for (const entry of entries) {
    if (!listed.has(entry.path)) {
      throw new Error(
        `not a valid case archive: archive contains a file the manifest does not list "${entry.path}"`,
      );
    }
  }
}

export function provenanceOf(manifest: CaseArchiveManifest): CaseArchiveProvenance {
  return {
    sourceCaseId: manifest.caseId,
    exportedAt: manifest.exportedAt,
    generatedBy: manifest.generatedBy,
    totalFiles: manifest.totalFiles,
    totalBytes: manifest.totalBytes,
  };
}
