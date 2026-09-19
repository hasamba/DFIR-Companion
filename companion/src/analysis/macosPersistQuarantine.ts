// The persistence target as a quarantine attribute observation (#1037 link 2, import half).
//
// A launchd plist's `# quarantine:` header is the program's own `com.apple.quarantine` value —
// the same fact a collected attribute record carries (quarantineAttribute.ts): a path and a mark.
// macosPersistRules.ts already decodes it into the finding's words; this puts it in the finding's
// envelope as a `quarantineAttribute` block with `role: "persistence-target"`, so the merge-time
// join (quarantinePersistenceLink.ts) reads the event identifier as data. A persistence collection
// names no host and its upload holds no database record, and the block says both.
//
// Nothing here joins: the database record lives in a different upload, and the words the finding
// already has are left exactly as the grader wrote them.

import { createCanonicalEvent } from "./canonicalEvent.js";
import type { LinuxPersistEvent } from "./linuxPersistImport.js";
import type { LinuxSignal } from "./linuxSignal.js";

const LABEL_MAX = 200;

/** The event with its envelope attached, when the signal carries a decodable mark that names an event. */
export function withQuarantineEnvelope(event: LinuxPersistEvent, signal: LinuxSignal): LinuxPersistEvent {
  const q = signal.quarantine;
  if (!q?.mark.eventId) return event;
  const label = q.label?.slice(0, LABEL_MAX);
  const locator = `${signal.artifact}:${signal.line}`;
  return {
    ...event,
    canonical: createCanonicalEvent({
      event: { category: "file", type: "persistence-quarantine-target" },
      quarantineAttribute: {
        role: "persistence-target",
        persistence: { artifact: signal.artifact, ...(label ? { label } : {}) },
        path: q.program,
        mark: {
          flags: q.mark.flags.raw,
          named: q.mark.flags.named,
          ...(q.mark.flags.unnamed ? { unnamed: q.mark.flags.unnamed } : {}),
          time: q.mark.time.iso,
          encoding: "unix-hex-seconds",
          agent: q.mark.agent,
          eventId: q.mark.eventId,
        },
        host: { state: "not named" },
        join: { state: "no database record in this upload" },
      },
      time: { observed: event.timestamp, normalized: event.timestamp },
      evidence: { rawRecords: [{ source: "macos-persistence", locator }] },
      producer: { importer: "macospersist", parserVersion: "1", mappingVersion: "persistence-quarantine-v1" },
      rawFieldMap: {
        "quarantineAttribute.path": ["ProgramArguments"],
        "quarantineAttribute.mark": ["# quarantine:"],
      },
    }),
  };
}
