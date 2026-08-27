import type { ForensicEvent } from "./stateTypes.js";
import type { HypothesisSeed } from "./hypothesis.js";

// The refutation gate — you cannot disprove what you never looked for.
//
// Synthesis is allowed to mark a hypothesis `refuted`. Sometimes it should: the timeline shows the
// opposite of the claim, or a dedicated collection came back clean. But a refutation is an assertion
// of ABSENCE, and absence has a precondition the model does not check — that the collection contains
// a source capable of showing the thing had it happened. Without that, "no evidence of X" is a fact
// about the collection, not about the host, and recording it as `refuted` converts a coverage gap
// into a confident negative that closes the investigative thread.
//
// This is not hypothetical. In a real case the companion marked "ransomware encryption was executed"
// as refuted with the reasoning "no T1486 evidence anywhere in the timeline" — while no Prefetch,
// ShimCache or file listing of the encryption target had been collected at all. The encryption had
// in fact happened. The evidence that would have shown it was never gathered.
//
// So: classify what evidence CLASS a claim needs, check whether the collection has any source of
// that class, and when it does not, downgrade `refuted` to `unknown` and say which class is missing.
// The gate only ever WEAKENS a claim — it never promotes one, and never touches a positive finding.
// A `supported` hypothesis rests on evidence that IS present; missing coverage elsewhere says
// nothing about it.
//
// Pure and deterministic, NO AI call.

// The evidence classes a claim can depend on. Deliberately coarse — the question is only "could this
// collection have seen it at all", not "which exact artifact".
export type EvidenceClass = "execution" | "file-activity" | "network" | "persistence";

export const EVIDENCE_CLASSES: readonly EvidenceClass[] = [
  "execution",
  "file-activity",
  "network",
  "persistence",
];

// Source-name fragments (lowercased, substring match) that indicate a collection covers each class.
// Matched against ForensicEvent.sources — the importer/artifact names, e.g.
// "Windows.Forensics.Prefetch", "DetectRaptor.Windows.Detection.MFT", "Generic.Scanner.ThorZIP".
//
// The execution list is HISTORICAL execution evidence only. A live process list (Pstree) or socket
// table (netstat) shows what is running at collection time; neither can show that a binary ran last
// week, so neither belongs here — that distinction is the whole point of the gate.
export const EVIDENCE_CLASS_SOURCES: Record<EvidenceClass, readonly string[]> = {
  // GENERAL program-execution evidence only. PowerShell command history (PSReadline, transcripts)
  // records what one interpreter was asked to do and is silent about every other binary on the box,
  // and ShellBags record folder navigation, not execution at all — neither can vouch that a dropped
  // executable did or did not run, so neither belongs here.
  execution: [
    "prefetch",
    "amcache",
    "shimcache",
    "appcompat",
    "srum",
    "sysmon",
    "4688",
    "processcreation",
    "process_creation",
    "userassist",
    "bam",
    "executionhistory",
  ],
  // Full file-system enumerations only. A signature scanner (THOR, YARA) reports the files that
  // matched a rule — see DETECTION_FEED_RE — and its silence about everything else is the ruleset's
  // silence, not the file system's.
  "file-activity": [
    "mft",
    "usn",
    "journal",
    "ntfs",
    "filescan",
    "filefinder",
    "glob",
    "recyclebin",
    "filesystem",
  ],
  // Historical network records only. A live socket table (netstat) is excluded by
  // SNAPSHOT_SOURCE_RE for the same reason a live process list is: it describes collection time.
  // Suricata alerts are a hit feed, so they are excluded by DETECTION_FEED_RE.
  network: [
    "pcap",
    "packetcapture",
    "zeek",
    "netflow",
    "firewall",
    "dns",
    "proxy",
    "flow",
    "connection",
    "http",
  ],
  persistence: [
    "persistence",
    "service",
    "taskscheduler",
    "scheduledtask",
    "autorun",
    "startup",
    "runkey",
    "wmievent",
    "cron",
  ],
};

// Keyword fragments (lowercased) that mark a claim as depending on each evidence class. A claim can
// need more than one — "files were encrypted by a binary that ran" needs both execution and
// file-activity, and the gate requires ALL of them, because a refutation is only sound when every
// avenue that could have shown the event was actually covered.
const CLASS_KEYWORDS: Record<EvidenceClass, readonly string[]> = {
  execution: [
    "execut",
    " ran ",
    " run ",
    "launch",
    "process",
    "binary",
    "payload",
    "malware ran",
    "detonat",
    "invoked",
  ],
  "file-activity": [
    "encrypt",
    "file",
    "deleted",
    "dropp",
    "wrote",
    "written",
    "staged",
    "archive",
    "wiped",
    "ransom",
  ],
  network: [
    "exfiltrat",
    "c2",
    "command and control",
    "beacon",
    "outbound",
    "connect",
    "network",
    "upload",
    "download",
    "lateral",
    "remote",
  ],
  persistence: ["persist", "service", "scheduled task", "autorun", "startup", "run key", "backdoor"],
};

// Source names that mark a RULE-HIT feed rather than a full artifact collection. Matched against the
// normalized (lowercased, separator-stripped) source name, so "DetectRaptor.Windows.Detection.MFT",
// "Windows.Sigma.Base" and "Generic.Scanner.ThorZIP" are all caught. A hit feed proves presence; it
// can never prove absence, because its silence is the ruleset's silence rather than the artifact's.
const DETECTION_FEED_RE = /detection|detectraptor|sigma|chainsaw|hayabusa|thor|yara|suricata/;

// Source names that describe the host AT COLLECTION TIME rather than over the incident window: a
// live process list, the open-socket table, currently-open handles. They are excellent evidence of
// what is running now and no evidence at all about last Tuesday, so they cannot settle a claim about
// something that did or did not happen during the window.
const SNAPSHOT_SOURCE_RE = /pstree|netstat|processlist|runningprocess|openfiles|currentsession/;

// One downgraded refutation, for reporting back to the caller (counts, logging, an analyst note).
export interface GatedRefutation {
  sourceKey: string;
  title: string;
  missing: EvidenceClass[]; // the classes with no collected source
}

export interface GateRefutedResult {
  seeds: HypothesisSeed[];
  downgraded: GatedRefutation[];
}

// Which evidence classes a claim would need before it can be soundly refuted. Empty when the claim
// is not about an observable technical event at all (e.g. "the operator was authorized") — the gate
// has no opinion on those and leaves them alone.
export function requiredEvidenceClasses(text: string): EvidenceClass[] {
  const hay = ` ${(text || "").toLowerCase()} `;
  return EVIDENCE_CLASSES.filter((c) => CLASS_KEYWORDS[c].some((k) => hay.includes(k)));
}

// Which evidence classes the collection actually covers, derived from the named sources on the
// timeline. Events with no named source (manual entry, screenshot extraction) contribute nothing —
// they cannot vouch for a class of coverage.
//
// BOTH source fields are read, and `artifactName` is the one that matters. `sources` is the coarse
// importer label: every row from a Velociraptor collection carries the single string "Velociraptor",
// whatever artifact produced it, so matching on `sources` alone sees no classes at all and the gate
// then downgrades EVERY refutation — including the ones the collection genuinely supports. The
// artifact identity ("Windows.Forensics.Prefetch", "Windows.Network.NetstatEnriched") lives in
// `artifactName`. See ForensicEvent in stateTypes.ts.
export function collectedEvidenceClasses(events: readonly ForensicEvent[]): Set<EvidenceClass> {
  const found = new Set<EvidenceClass>();
  const norm = (s: string) => s.toLowerCase().replace(/[\s_-]+/g, "");
  for (const e of events) {
    for (const raw of [...(e.sources ?? []), e.artifactName ?? ""]) {
      if (!raw) continue;
      const s = norm(raw);
      // Neither a DETECTION feed nor a point-in-time SNAPSHOT is coverage.
      // "DetectRaptor.Windows.Detection.Amcache" returns only the Amcache rows that matched a rule —
      // three hits, not the hive; "Windows.Network.NetstatEnriched" returns the sockets open right
      // now. Only a full historical collection of the underlying artifact can vouch for an absence,
      // which is the only thing this function is asked about.
      if (DETECTION_FEED_RE.test(s) || SNAPSHOT_SOURCE_RE.test(s)) continue;
      for (const c of EVIDENCE_CLASSES) {
        if (found.has(c)) continue;
        if (EVIDENCE_CLASS_SOURCES[c].some((p) => s.includes(norm(p)))) found.add(c);
      }
    }
    if (found.size === EVIDENCE_CLASSES.length) break; // nothing left to learn
  }
  return found;
}

// Apply the gate. A `refuted` seed whose claim needs an evidence class the collection does not cover
// becomes `unknown`, with the missing class named in its description so the analyst knows exactly
// what to collect to settle it. Everything else passes through untouched.
export function gateRefutedSeeds(
  seeds: readonly HypothesisSeed[],
  collected: ReadonlySet<EvidenceClass>,
): GateRefutedResult {
  const downgraded: GatedRefutation[] = [];
  const out = seeds.map((seed) => {
    if (seed.status !== "refuted") return seed;
    const required = requiredEvidenceClasses(`${seed.title} ${seed.description}`);
    const missing = required.filter((c) => !collected.has(c));
    if (missing.length === 0) return seed;
    downgraded.push({ sourceKey: seed.sourceKey, title: seed.title, missing });
    const list = missing.join(" and ");
    const note =
      `Refutation withheld: settling this claim needs ${list} evidence, and no source of that kind was ` +
      `collected — so the absence of supporting artifacts is a fact about the collection, not about the ` +
      `host. Collect ${list} coverage for the relevant window, then re-assess.`;
    return {
      ...seed,
      status: "unknown" as const,
      description: seed.description ? `${seed.description} ${note}` : note,
    };
  });
  return { seeds: out, downgraded };
}
