// What a PATH says about the DETECTION STACK — the collector's own tree, the rule content it ships,
// and the volatile containers a full-volume scan walks.
//
// Extracted from veloDetectionNoise so a DETECTOR can reach it. These four predicates are pure
// string tests with no dependencies, while the rest of veloDetectionNoise reads Velociraptor ROW
// shapes and therefore sits in the ingest tier — a tier the detect layer may not import. Splitting
// on that line lets ransomwareDetect ask "is this the collector's own signature file?" without the
// ingest layer, and keeps ONE answer to that question across every ingest path (see #720).
//
// veloDetectionNoise re-exports all four, so existing callers are unchanged and its module comment
// remains the place the reasoning is written down.

// `.yms` is Velociraptor's own compiled-Sigma format. Nothing else on a Windows host carries it, so
// the extension alone identifies the file — an attacker who renamed a payload to `.yms` would be
// choosing an extension that exists nowhere but inside Velociraptor's unpacked tool directory.
const VELOCIRAPTOR_SIGNATURE_EXT = /\.yms$/i;

// These extensions are NOT self-identifying. `.yml` is the most common configuration format there
// is, and `.evtx` is a live Windows log; an attacker's `C:\Users\Public\payload.yml` ends the same
// way a Sigma rule does. So the extension only narrows the field — the path has to place the file
// inside detection tooling before anything is demoted.
const SHARED_CONTENT_EXT = /\.(?:ya?ml|evtx|etl)$/i;

// Where detection content actually lives, in the two forms a filesystem sweep reports it.
//
//   the directory   Velociraptor unpacks a signature tree into
//                   `\Program Files\Velociraptor\Tools\tmp*\signatures\sigma\…` for the duration of
//                   a hunt; Hayabusa, Chainsaw and Sigma trees have their own equivalents.
//   the ABSENCE of  …and Velociraptor deletes that tree when the hunt ends, so the MFT keeps the
//   a directory     entries with no resolvable parent and reports them as `<Err>\<Parent N-M need K>`.
//                   That placeholder is written by the MFT parser, not by anything on disk, so it
//                   cannot be forged by naming a file — and on a real collection it was where every
//                   single one of these rows landed.
const DETECTION_CONTENT_LOCATION =
  /<Err>|<Parent |\\Velociraptor\\Tools\\|\\signatures\\|\\sigma\\|\\rules\\|\\hayabusa\\|\\chainsaw\\|EVTX-ATTACK/i;

/**
 * A file whose CONTENT is detection logic or detection test data, matched by a rule pack that only
 * looked at the filename.
 *
 * On a real collection this covered 47 of the 48 High findings the MFT rule pack produced. The 48th
 * was a ransomware binary in ProgramData — which is the point: an analyst reading 48 High findings
 * does not see it, and reading one does.
 *
 * Scoped deliberately to the keyword-detection path in velociraptorImport. It is a statement about
 * what a FILENAME MATCH proves, not a claim that these extensions are harmless — a `.yml` carrying
 * an attacker's configuration is still ingested, still timelined, and still graded by everything
 * that reads content rather than names.
 */
export function isDetectionContentPath(value: string): boolean {
  const path = value.trim();
  if (VELOCIRAPTOR_SIGNATURE_EXT.test(path)) return true;
  return SHARED_CONTENT_EXT.test(path) && DETECTION_CONTENT_LOCATION.test(path);
}

// A file or process that lives inside the DETECTION TOOLING itself, matched regardless of extension.
// isDetectionContentPath is deliberately narrow — it only demotes rule-CONTENT files (.yml/.evtx …)
// so a real payload dropped in an odd place is never lost. This one is broader on purpose, for a
// different caller: a YARA/THOR SCAN that walks the collector's own working tree, its unpacked
// sample corpus, the collector binary itself, or a cached copy of a simulation repo, and reports
// them as host findings. The markers are NOT equally trustworthy, so they do not carry equal weight:
// only the collector's install tree is a location an intruder cannot supply, and only that one lets
// a caller drop an IOC. A corpus directory name is a name anyone can create, so it drops the hit to
// Info and stops there — see isCollectorOwnedLocation, and #720 for what the flat list cost.
//
//   [/\]Velociraptor[/\]  the collector's own install / unpacked-tool tree
//                          (`C:\Program Files\Velociraptor\…`, incl. `\Tools\tmp*\chainsaw\…`)
//   EVTX-ATTACK-SAMPLES    the Sigma test corpus bundled with those tools
//   Digital-Forensic-      the eval / training simulation corpus, downloaded to the host as a repo
//     Artifacts               (its cached copy is not the intrusion under investigation)
//
// CAUTION (why this is narrow): every marker must be a signal the ATTACKER CANNOT CHOOSE. A bare
// `velociraptor.exe`, or a lone `\sigma\` / `\chainsaw\` / `\signatures\` / `\Tools\tmp` directory
// component, is attacker-controllable — a real payload dropped in `C:\Users\x\sigma\evil.dll` would
// be hidden from the forensic view. So we require the collector ROOT context (`\Velociraptor\`,
// which the real THOR row carries as `image_file: C:\Program Files\Velociraptor\Velociraptor.exe`),
// or the published corpus name as a WHOLE path component — never a substring that can appear
// anywhere. Anchoring is not proof: a corpus name IS choosable, which is why it may not delete.

// The collector's own tree. This is the one marker here the attacker cannot supply, so it is also
// the only one that lets a caller DROP an indicator rather than merely lower a grade.
const COLLECTOR_INSTALL_ROOT = /[/\\]Velociraptor[/\\]/i;

// The two published corpus names, each as a WHOLE path component. They were bare substrings until
// #720, which let `EVTX-ATTACK` match `C:\Users\public\EVTX-ATTACKER-kit\evil.exe` — a path any
// intruder can create, and one that suppressed the finding. The trailing class admits the forms a
// real download takes (a directory, the GitHub zip's `-master` suffix, an archive extension)
// without admitting a longer word. Anchoring narrows the accident; it cannot stop a deliberately
// named folder, which is why a corpus match now grades DOWN without deleting evidence — see
// isCollectorOwnedLocation and mapYara.
const SAMPLE_CORPUS_DIR = /[/\\](?:EVTX-ATTACK-SAMPLES|Digital-Forensic-Artifacts)(?:[-_./\\]|$)/i;

const DETECTION_TOOL_LOCATION = new RegExp(
  `${COLLECTOR_INSTALL_ROOT.source}|${SAMPLE_CORPUS_DIR.source}`,
  "i",
);

export function isDetectionToolLocation(value: string): boolean {
  const v = (value || "").trim();
  if (!v) return false;
  return DETECTION_TOOL_LOCATION.test(v);
}

/**
 * The subset of isDetectionToolLocation that is NOT a name an intruder can pick: the collector's own
 * install tree. A hit here is not host evidence at all, so the caller may drop its IOCs. A hit in a
 * sample-corpus directory only LOOKS like tooling — the directory name is attacker-choosable — so it
 * leaves the timeline (Info) but keeps its indicators. See mapYara (#720).
 */
export function isCollectorOwnedLocation(value: string): boolean {
  const v = (value || "").trim();
  if (!v) return false;
  return COLLECTOR_INSTALL_ROOT.test(v);
}

// A volatile memory-backed container: the page/hibernation/swap files, a crash or process memory
// dump, or the NTFS metadata streams a full-volume YARA scan walks. A rule string found HERE proves
// only that the bytes existed in memory or metadata once — not that a named file executed. Kept
// (Low, and aggregated by the caller) rather than dropped, because a family's strings in the page
// file can still corroborate a finding built on stronger evidence.
const VOLATILE_CONTAINER =
  /\\pagefile\.sys$|\\hiberfil\.sys$|\\swapfile\.sys$|MEMORY\.DMP$|\.dmp$|\\\$(?:MFT|MFTMirr|LogFile|UsnJrnl|Extend|Secure|BadClus)\b|\bunallocated\b/i;

export function isVolatileContainer(value: string): boolean {
  const v = (value || "").trim();
  if (!v) return false;
  return VOLATILE_CONTAINER.test(v);
}
