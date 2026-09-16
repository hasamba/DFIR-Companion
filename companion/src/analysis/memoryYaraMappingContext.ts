// What a MemProcFS YARA match's own MemoryType/MemoryTag actually establish about address-space
// mapping validity (#933 item 13's string/match half; see #1148). Mirrors malfindContext.ts's own
// shape: a pure function reading a row's own fields into an honest, hedged assessment. Severity
// and MITRE derivation are explicitly NOT this module's business — see memoryImport.ts's own
// wiring, which derives both from the matched RULE's own content (severityFromMeta/mitreFromYara,
// reused from yaraImport.ts), never from where the match was found.
//
// ─────────────────────────── VERIFIED AGAINST MemProcFS'S OWN REAL SOURCE ───────────────────────
//
// `vmm/vmmyarautil.c` (github.com/ufrisk/MemProcFS, fetched 2026-09-16) emits exactly FOUR
// MemoryType values, in this priority order:
//
//   1. "Object Memory"           — peMatch->vaObject is set (checked FIRST, before pObProcess is
//                                   even consulted). Typically a FILE object (the only object-
//                                   reading call this branch makes is VmmWinObjFile_Read...).
//                                   PID/ProcessName are NOT populated on this branch.
//   2. "Virtual Memory (PTE)"    — pObProcess is set AND `!pObProcess->fUserOnly &&
//                                   VMM_KADDR(f32, vaBase)`: a kernel-mode address reached through
//                                   a NON-user-only process context. Chosen unconditionally by this
//                                   address/process-type test — NOT because a VAD/PTE lookup
//                                   failed.
//   3. "Virtual Memory (VAD)"    — pObProcess is set and the PTE condition above is false (an
//                                   ordinary user-mode address). Same "chosen unconditionally, tag
//                                   lookup is separately conditional" shape as PTE.
//   4. "Physical Memory"         — no process context at all. MemoryTag, MemoryBaseAddress AND
//                                   ObjectAddress are all the literal empty string on this branch
//                                   (confirmed: `",\"Physical Memory\",\"\",\"\",\"\""`).
//
// A non-empty MemoryTag on a VAD/PTE row means MemProcFS's own VmmMap_Get*Entry lookup succeeded
// in naming the containing region — an EMPTY tag on those same two types means the address is
// still in that address-space category, just without a recovered descriptor. Never phrase an
// empty tag as "unmapped" — that is not what MemProcFS's own branch selection means.
//
// There is no distinct pagefile category (grepped the whole file — zero hits). This module never
// claims a pagefile-only match WOULD surface as "Physical Memory"; it states only that this export
// format cannot identify pagefile provenance at all.

export type MappingClass =
  | "process-user-mode" // "Virtual Memory (VAD)"
  | "process-kernel-mode" // "Virtual Memory (PTE)"
  | "object" // "Object Memory" — typically a file object, no per-process ownership signal
  | "no-process-context" // "Physical Memory"
  | "unrecognized"; // a MemoryType MemProcFS has not been observed to emit — never the strongest case

export type TagBacking = "file-backed-likely" | "private-allocation-likely" | "unclassified" | "absent";

export interface YaraMappingContext {
  mappingClass: MappingClass;
  /** Only ever non-"absent" for process-user-mode/process-kernel-mode with a non-empty tag. */
  tagBacking: TagBacking;
  /** Hedged, length-bounded. The qualifying clause always precedes any interpolated tag text. */
  note: string;
}

// The longest real branch (PTE with a maximally bounded tag) measures 323 chars; 350 leaves
// margin without ever truncating a complete sentence mid-word (Codex code-review finding).
const NOTE_MAX = 350;
const FIELD_MAX = 60; // an interpolated pid/tag is bounded before insertion, never the note's own text

// A narrow PE/image-extension or path-separator match — NOT memoryFields.ts's own IMAGE_EXT, which
// is tuned for command-line tokens and also matches scripts/installers (.bat/.cmd/.ps1/.vbs/.msi)
// that say nothing about memory-mapping backing.
const FILE_BACKED_RE = /[\\/]|\.(?:dll|exe|sys|ocx|drv)(?:$|[^a-z0-9])/i;
// This codebase's own real observed private-allocation tag shape (tests/analysis/memoryImport.test.ts's
// own YARA_CSV fixture: "HEAP-00 [SegSegment]").
const PRIVATE_ALLOC_RE = /^(?:HEAP|STACK)-/i;

function bounded(value: string): string {
  const v = (value ?? "").trim();
  return v.length > FIELD_MAX ? `${v.slice(0, FIELD_MAX)}…` : v;
}

function tagBackingOf(tag: string): TagBacking {
  const t = tag.trim();
  if (!t) return "absent";
  if (FILE_BACKED_RE.test(t)) return "file-backed-likely";
  if (PRIVATE_ALLOC_RE.test(t)) return "private-allocation-likely";
  return "unclassified";
}

const PAGEFILE_LIMITATION =
  "This export cannot identify pagefile-only provenance, so a pagefile-backed string, if one exists, is not distinguishable from this.";

export function yaraMappingContext(memoryType: string, memoryTag: string): YaraMappingContext {
  const tag = bounded(memoryTag);

  if (memoryType === "Virtual Memory (VAD)") {
    const tagBacking = tagBackingOf(tag);
    let note: string;
    switch (tagBacking) {
      case "file-backed-likely":
        note = `This row does not establish exclusive process ownership — the region's own label appears file-backed, and such mappings are commonly shared across processes: "${tag}".`;
        break;
      case "private-allocation-likely":
        note = `This address is in this process's own user-mode memory, labeled "${tag}", which appears to be a private allocation.`;
        break;
      case "unclassified":
        note = `This address is in this process's own user-mode memory, labeled "${tag}" — this label does not establish whether the mapping is private or shared.`;
        break;
      default:
        note =
          "This address is in this process's own user-mode memory; no region label was recovered, so whether it is private or shared cannot be determined from this row.";
    }
    return { mappingClass: "process-user-mode", tagBacking, note: note.slice(0, NOTE_MAX) };
  }

  if (memoryType === "Virtual Memory (PTE)") {
    const tagBacking = tagBackingOf(tag);
    const base =
      "MemProcFS classified this as a kernel-mode address reached through this process's own context (not an ordinary user-only process). This row does not establish exclusive process ownership or identify which other contexts reach the same address.";
    // The disclaimer is always the LEAD; the recovered tag, if any, is appended after it — never
    // the reverse (Codex round-2 design finding on truncation order applies here too).
    const note = tag ? `${base} Recovered label: "${tag}".` : base;
    return { mappingClass: "process-kernel-mode", tagBacking, note: note.slice(0, NOTE_MAX) };
  }

  if (memoryType === "Object Memory") {
    const note = tag
      ? `This match was reported against an object (typically a file object) rather than a process's own memory, labeled "${tag}" — no process ownership can be established from this row.`
      : "This match was reported against an object (typically a file object) rather than a process's own memory — no process ownership can be established from this row.";
    return { mappingClass: "object", tagBacking: "absent", note: note.slice(0, NOTE_MAX) };
  }

  if (memoryType === "Physical Memory") {
    const note = `No process or address-space context exists for this match — this could be a freed page, a driver/kernel structure, or a stale remnant recovered from physical memory alone. ${PAGEFILE_LIMITATION}`;
    return { mappingClass: "no-process-context", tagBacking: "absent", note: note.slice(0, NOTE_MAX) };
  }

  const note = `MemProcFS reported an address-space category ("${bounded(memoryType)}") this importer does not yet recognize; treated the same as an unattributed physical-memory match. ${PAGEFILE_LIMITATION}`;
  return { mappingClass: "unrecognized", tagBacking: "absent", note: note.slice(0, NOTE_MAX) };
}
