/**
 * Filename portability — rewriting a name so the strictest filesystem a recipient uses can create
 * it, which is Windows.
 *
 * This lives in storage/ rather than beside either archive writer because both need it and neither
 * may import the other: a case archive and the ZIP writer sit in different analysis tiers. The
 * rules here are about filesystems, not about ZIP, so storage/ is where they belong.
 *
 * A case directory routinely holds names Windows refuses. The drop folder keeps a dropped file's
 * original name forever under drop/_processed/, and analysts drop files straight out of Windows
 * collections. Writing such a name into an archive means extraction on Windows either fails
 * outright or, for a colon, silently writes an NTFS alternate data stream — the file disappears
 * from the extracted tree with no error at all.
 *
 * Only a name being WRITTEN somewhere new is rewritten. The path bytes are read from must keep the
 * real on-disk spelling, or the read finds nothing.
 */

// Characters Windows refuses in a filename, plus the control range no platform wants. The forward
// slash is in the set too: inside a single segment it is content, not a separator.
const UNPORTABLE_SEGMENT_CHARS = /[<>:"/\\|?*\x00-\x1f]/g;

// Reserved device names. With or without an extension, CON, NUL, LPT1 and friends do not resolve to
// a file on Windows at all, so a name matching one cannot be created.
const WINDOWS_RESERVED_SEGMENT = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

/**
 * Rewrite one path segment so Windows can create a file with that name.
 *
 * Each substitution keeps the segment's length, so two names that differ before sanitizing usually
 * still differ after. Where they do not, the caller must refuse to write rather than let one file
 * overwrite the other. An ordinary name comes back unchanged, non-ASCII included — Windows accepts
 * those.
 */
export function portableZipSegment(segment: string): string {
  if (!segment) return "_";
  let out = segment.replace(UNPORTABLE_SEGMENT_CHARS, "_");
  // Windows strips trailing dots and spaces, so "notes." and "notes" resolve to one file. Padding
  // with "_" instead of trimming keeps the two names distinct, which the caller's collision check
  // needs in order to see two entries rather than one.
  out = out.replace(/[.\s]+$/, (run) => "_".repeat(run.length));
  if (WINDOWS_RESERVED_SEGMENT.test(out)) out = `_${out}`;
  return out;
}

/**
 * Rewrite a whole archive entry path, segment by segment. Empty segments are dropped so a doubled
 * slash does not invent a directory.
 *
 * A backslash is NOT treated as a separator. Every caller walks the case directory joining with
 * "/" on every platform, so a backslash arriving here is part of a FILENAME — a file may legally be
 * called "back\slash.bin" on Linux — and folding it would split one file into a directory and a
 * child that the case never had. It is content, so portableZipSegment substitutes it like any other
 * character Windows refuses, which also keeps this function's one-substitution-per-character
 * promise (#675).
 */
export function portableZipEntryPath(path: string): string {
  return path
    .split("/")
    .filter((seg) => seg !== "")
    .map(portableZipSegment)
    .join("/");
}

/**
 * The key two entry paths collide on, under the most collision-prone rules any supported platform
 * applies — which is Windows, where the filesystem is case-insensitive. Compared on EVERY platform,
 * not only Windows: an archive whose entries collide is malformed wherever it is opened, and an
 * import that quietly succeeds on Linux and loses a file on Windows is the harder bug to find.
 *
 * Upper-cased because that is the direction Windows' own comparison folds. JS case mapping is
 * locale-independent here (toUpperCase, not toLocaleUpperCase), so this does not shift under a
 * Turkish locale.
 */
export function destinationKey(path: string): string {
  return path.toUpperCase();
}

/**
 * Map each case-relative path to the path it will carry inside an archive, refusing any set of
 * names that cannot survive extraction intact (#675, #426, #742).
 *
 * A case directory is written under the host's naming rules, and on Linux those admit names that
 * Windows — and this tool's own importer — both refuse: a colon, a backslash, a trailing dot, a
 * reserved device name. Analysts produce them routinely by copying a Windows collection into the
 * drop folder, where the imported file keeps its original name under `drop/_processed/`. Packed
 * verbatim, such a name makes an archive DFIR Companion cannot restore: `isSafeZipEntryPath`
 * rejects the entry and the whole import fails. The write still reports success, so the failure
 * surfaces at restore time, when the case it came from may be long gone.
 *
 * Renaming is the lesser evil, but only while it stays visible and lossless. Every changed entry
 * keeps its original path in the manifest, and two files whose portable names collide abort by
 * name: sanitizing is what CREATES that collision — `a:b.bin` and `a_b.bin` are one file
 * afterwards — and letting the second entry overwrite the first is silent evidence loss, which
 * neither writer may produce. Resolved before a single file is read, so a case that cannot be
 * packaged says so immediately instead of after hashing every byte.
 *
 * A collision is not only two entries landing on one name. The import creates each entry's parent
 * folders with mkdir and then writes the file, so a name claimed as a FILE by one entry and as a
 * FOLDER on the way to another is equally fatal — whichever lands first, the second fails with
 * EEXIST, EISDIR or ENOTDIR. Sanitizing creates that shape too: a file `drop/notes` beside a
 * folder `drop/notes.` coexist on disk and become one name afterwards. Both directions are
 * checked, so entry order cannot decide whether the writer notices.
 *
 * `reserved` holds the paths of entries the archive GENERATES rather than reads from the case (the
 * custody manifest, archive-manifest.json). They are in the collision namespace too, so neither a
 * rename nor a case file's own name can land on top of one — the ZIP writer accepts duplicate
 * entry names without complaint, so a generated entry would silently shadow the case's own file.
 *
 * `action` is the verb the error messages tell the analyst to retry ("export", "archive"), so the
 * advice names the operation they actually ran.
 *
 * Shared by both archive writers rather than duplicated: the plain-ZIP writer behind
 * delete-with-archive holds the case's ONLY copy, and the two writers disagreeing about which
 * names are safe is how #742 was filed.
 */
export function portableArchivePaths(
  relPaths: string[],
  reserved: string[],
  action: string,
): Map<string, string> {
  const byRel = new Map<string, string>();
  // What each destination has to BE, and which case file needs it that way.
  const fileAt = new Map<string, string>();
  const folderAt = new Map<string, string>();
  // The generated entries, kept apart from fileAt only so their collision message can say the
  // archive writes that name itself rather than naming the same path on both sides.
  const reservedAt = new Map<string, string>();

  const claim = (source: string, archivePath: string, isReserved: boolean): void => {
    const key = destinationKey(archivePath);
    if (!isReserved) {
      const generated = reservedAt.get(key);
      if (generated !== undefined) {
        throw new Error(
          `"${source}" would be named "${archivePath}" inside the archive, but the ${action} ` +
            `writes its own "${generated}" there — rename the case file and ${action} again.`,
        );
      }
    }
    const twin = fileAt.get(key);
    if (twin !== undefined) {
      throw new Error(
        `"${source}" and "${twin}" would both be named "${archivePath}" inside the archive — ` +
          `rename one of them in the case directory and ${action} again.`,
      );
    }
    const asFolder = folderAt.get(key);
    if (asFolder !== undefined) {
      throw new Error(
        `"${source}" would be the file "${archivePath}" inside the archive, but "${asFolder}" ` +
          `needs that same name to be a folder — rename one of them in the case directory and ` +
          `${action} again.`,
      );
    }
    const segments = archivePath.split("/");
    for (let i = 1; i < segments.length; i++) {
      const ancestor = segments.slice(0, i).join("/");
      const ancestorKey = destinationKey(ancestor);
      const blocking = fileAt.get(ancestorKey);
      if (blocking !== undefined) {
        throw new Error(
          `"${source}" needs "${ancestor}" to be a folder inside the archive, but "${blocking}" ` +
            `is a file of that name — rename one of them in the case directory and ${action} again.`,
        );
      }
      if (!folderAt.has(ancestorKey)) folderAt.set(ancestorKey, source);
    }
    fileAt.set(key, source);
    if (isReserved) reservedAt.set(key, source);
  };

  for (const path of reserved) claim(path, path, true);
  for (const rel of relPaths) {
    const archivePath = portableZipEntryPath(rel);
    claim(rel, archivePath, false);
    byRel.set(rel, archivePath);
  }
  return byRel;
}
