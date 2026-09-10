// Reading a macOS persistence collection into the case (#908 item 6).
//
// The shape is the Linux one — one upload, either a single artifact or many files under per-file
// headers — because that is what a triage collection is on both platforms, and because macOS cron
// and shell profiles ARE the Linux ones. What this adds is launchd, and the two facts a Mac
// collection can carry that a Linux one cannot: whether the program is signed, and whether macOS
// recorded that it was downloaded.
//
// Those two facts arrive as header annotations on the plist that runs the program:
//
//   ==> /Library/LaunchDaemons/com.apple.softwareupdated.plist <==
//   # mtime: 2026-01-02T09:00:00Z
//   # codesign: unsigned
//   # quarantine: https://evil.test/update.zip
//
// Neither can produce a finding by itself. An unsigned binary is ordinary on a Mac and a quarantine
// record only proves a download happened. They raise and explain a job that is already suspicious
// for a reason of its own.

import { splitCollection, singleArtifact, type CollectedFile } from "./linuxPersistence.js";
import { analyzeLinuxCollection, type LinuxSignal } from "./linuxPersistRules.js";
import { classifyMacArtifact, isBinaryPlist, isXmlPlist } from "./macosPersistence.js";
import { gradeLaunchd, type MacContext } from "./macosPersistRules.js";
import {
  collectionNote,
  iocsFromSignals,
  signalsToEvents,
  type LinuxPersistEvent,
} from "./linuxPersistImport.js";

export interface MacPersistParse {
  files: CollectedFile[];
  signals: LinuxSignal[];
  events: LinuxPersistEvent[];
  iocs: { type: "file"; value: string }[];
  note: string;
}

/** Read an upload as a macOS collection, or — when it carries no headers — as one named artifact. */
export function readMacCollection(filename: string, text: string): CollectedFile[] {
  const members = splitCollection(text, classifyMacArtifact);
  if (members.some((m) => m.kind !== "unknown")) return members;
  const base = (filename ?? "").split(/[\\/]/).pop() ?? "";
  const named = singleArtifact(base.replace(/\.(?:txt|log|out)$/i, ""), text, classifyMacArtifact);
  if (named.length) return named;

  // A property list is self-identifying, so a plist saved under any other name is still a plist.
  // Requiring a .plist filename meant detection claimed the file — the CONTENT sniff routes it
  // here — and then this returned nothing, so the import was empty and the whole upload dropped.
  if (isXmlPlist(text) || isBinaryPlist(text)) {
    return [{ path: filename || "collected.plist", kind: "launchd", content: text }];
  }
  return [];
}

export function analyzeMacCollection(files: readonly CollectedFile[], ctx: MacContext = {}): LinuxSignal[] {
  // Everything that is not launchd is the same artifact it is on Linux, graded by the same rules.
  //
  // EXCEPT the SUID listing. macOS ships a different setuid set — /usr/libexec/authopen,
  // /usr/sbin/traceroute6, /usr/bin/quota and the rest — and none of it is in the Linux baseline,
  // so every one would have been reported on a healthy Mac. macOS setuid analysis is not part of
  // this item, and grading it against the wrong distribution's list is worse than not grading it.
  const gradable = files.filter((f) => f.kind !== "suid");
  const shared = analyzeLinuxCollection(gradable, ctx);
  const launchd = files.filter((f) => f.kind === "launchd").flatMap((f) => gradeLaunchd(f, ctx));
  return [...launchd, ...shared];
}

export function parseMacPersist(
  filename: string,
  text: string,
  ctx: MacContext = {},
  fallbackTime = new Date().toISOString(),
): MacPersistParse {
  const files = readMacCollection(filename, text);
  const signals = analyzeMacCollection(files, ctx);
  return {
    files,
    signals,
    events: signalsToEvents(
      signals,
      files,
      fallbackTime,
      "macOS persistence",
      "macOS persistence",
      "macospersist",
    ),
    iocs: iocsFromSignals(signals),
    note: collectionNote(files, signals, "macOS persistence"),
  };
}
