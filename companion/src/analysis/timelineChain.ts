import type { ForensicEvent, IOC } from "./stateTypes.js";
import { clampOutlierYears } from "./timeYearClamp.js";
import { linkEmailDelivery } from "./initialAccess.js";
import { linkArchiveToExfil } from "./exfilCorrelate.js";
import { linkTransferToolStaging } from "./transferToolStaging.js";
import { linkToolStoreFolders } from "./toolStoreFolder.js";
import { markProcessLifetimeSignals } from "./processLifetime.js";
import { corroborateTimestompsOnTimeline } from "./timestompCorroborate.js";
import { corroborateDownloadExecution } from "./downloadExecution.js";
import { linkQuarantinePersistence } from "./quarantinePersistenceLink.js";
import { linkQuarantineVisitOrigin } from "./quarantineVisitOrigin.js";
import { linkQuarantineExecution } from "./quarantineExecutionLink.js";
import { corroborateSmbExecution } from "./smbExecution.js";
import { corroborateDefenderEpisodes } from "./defenderEpisodes.js";
import { corroborateRunKeyExecution } from "./runKeyExecution.js";
import { markInfectionWindow } from "./mobileInfectionWindow.js";
import { markAppCorroboration } from "./mobileBackgroundActivity.js";
import { corroborateInjectionSequences } from "./injectionSequence.js";
import { markRansomwarePrecursors } from "./ransomwarePrecursor.js";
import { raiseCasePrecursors } from "./cloudPrecursorMerge.js";
import { raiseCaseBecPairs } from "./m365BecMerge.js";
import { explainCertutilTransfers } from "./certutilTransfer.js";
import {
  explainMetadataAccess,
  instanceCredentialUseAway,
  metadataCoverageEvent,
} from "./cloudMetadataAccess.js";
import { summarizeBulkReads } from "./cloudBulkRead.js";
import { correlateStorageKeyToRead } from "./azureStorageKeyToRead.js";
import { correlateAwsFlowResourceAttribution } from "./awsFlowResourceAttribution.js";
import { correlateAwsFlowIdentityExecution } from "./awsFlowIdentityExecutionJoin.js";
import { correlateAwsFlowSensitiveData } from "./awsFlowSensitiveDataJoin.js";
import { attributionCoverageEvent, markServiceAccountBrowsing } from "./serviceAccountBrowsing.js";
import { markContainerEscape } from "./containerEscape.js";
import { markJndiInjection } from "./jndiInjection.js";

/**
 * The deterministic correlation chain, in order, over the whole timeline: the year clamp, then every
 * cross-import linker. `clamp` defaults to clampOutlierYears; the incremental merge passes the same
 * clamp with the case-wide dominant year, since its input is not the whole timeline.
 */
export function runTimelineChain(
  forensicTimeline: readonly ForensicEvent[],
  iocs: readonly IOC[],
  at: string,
  clamp: (events: readonly ForensicEvent[]) => ForensicEvent[] = clampOutlierYears,
  // The coverage row is judged over the whole timeline; a caller holding only part of it (the
  // incremental merge, which has checked the case-wide condition itself) turns it off.
  metadataCoverage = true,
): ForensicEvent[] {
  const passes = timelinePasses(iocs, at, clamp, metadataCoverage);
  return passes.reduce((events, pass) => pass(events), forensicTimeline as ForensicEvent[]);
}

/** One step of the chain: the whole timeline in, the whole timeline out. */
export type TimelinePass = (events: ForensicEvent[]) => ForensicEvent[];

/** The timeline with `row` replacing the row of its id, appended last; unchanged when `row` is null. */
const replacedLast = (events: ForensicEvent[], row: ForensicEvent | null): ForensicEvent[] =>
  row ? [...events.filter((e) => e.id !== row.id), row] : events;

/** runTimelineChain's passes in order: one list for it and the yielding merge (#2716, mergeYielding.ts). */
export function timelinePasses(
  iocs: readonly IOC[],
  at: string,
  clamp: (events: readonly ForensicEvent[]) => ForensicEvent[],
  metadataCoverage: boolean,
): TimelinePass[] {
  return [
    // Re-anchor mis-dated stray events (a year-less syslog/CSV line the AI import guessed into the wrong
    // year) onto the timeline's dominant year BEFORE correlation, so they sort/correlate in the right
    // place instead of corrupting the chronology. Conservative + idempotent (no-op unless one year clearly
    // dominates), and it only ever moves an event whose importer marked the year as a GUESS — a recorded
    // year is evidence (#739). See timeYearClamp.ts.
    clamp,
    // Stitch a phishing email to the host activity it caused: when a host later contacts a domain a
    // phishing email linked to, tag the contact as initial access (T1566.002 → T1204.002). Runs
    // before correlation so the tagged event still dedups normally. Conservative + idempotent (#201).
    linkEmailDelivery,
    // Stitch archive STAGING (T1560.001) to a subsequent UPLOAD (T1041) on the same host: the
    // SEQUENCE is the exfil signal (a lone upload to routine SaaS/cloud infra is not), so a matched
    // upload is raised to High and tagged — a deterministic, destination-agnostic "Data Exfiltration"
    // signal instead of relying on the synthesis model to notice the pairing. Conservative + idempotent.
    linkArchiveToExfil,
    linkTransferToolStaging, // + staged kits (#1955, #1970)
    linkToolStoreFolders,
    // Raise a process whose parent is not the one that ordinarily starts it, and an argument-free
    // host that something else already makes odd (#909 item 6). Runs here,
    // beside the other deterministic correlations, because parentage is only judgeable once the
    // events from every importer sit in one timeline. Only ever RAISES: parentage cannot make other
    // evidence about a process less true. A process with NO recorded parent is left alone — a
    // snapshot taken after the parent exited looks exactly like an orphan.
    markProcessLifetimeSignals,
    // Collapse duplicates / cross-source matches immediately (so re-importing the same report, or two
    // tools flagging one artifact, never doubles the timeline) — not only during synthesis. Idempotent.
    // Weigh each MFT timestomp signal against what an INDEPENDENT artifact recorded for the same file
    // (#909 item 8). Runs here because the MFT and ShimCache arrive as separate imports, so this is
    // the first point at which both are in hand. Only ever raises.
    corroborateTimestompsOnTimeline,
    // A download mark against the records that say the same file ran, and a hidden stream against
    // the command line that referenced it (#932 item 3, second half). Here for the same reason: the
    // MFT and the Prefetch / Sysmon rows arrive as separate imports. Only ever raises; its notes are
    // recomputed from the current evidence on every merge.
    corroborateDownloadExecution,
    // A macOS quarantine-database record against the launchd job whose program carries the same
    // event identifier (#1037 link 2). Here because the database dump and the persistence collection
    // are never one upload. Only ever raises (the database row, to Medium); its notes are recomputed
    // from the current evidence on every merge.
    linkQuarantinePersistence,
    // The same record against the browser visits that precede its origin page / download URL, and
    // the marked file against the rows that say it ran or was used (#1037 links 3 and 2). Here for
    // the same reason; only ever raise; notes recomputed on every merge.
    linkQuarantineVisitOrigin,
    linkQuarantineExecution,
    // A share write of an executable-shaped file, then the evidence it ran; a service-control or
    // task-scheduling pipe call, then the service/task it may have created — host+time joins across
    // separate imports (#933 item 4, correlation half — #1092). Only ever raises.
    corroborateSmbExecution,
    // A Defender action, then a later start of the same file on the same host (#930 item 1 part B).
    // Here because the Defender record and the process start arrive from different imports. Only
    // ever raises; notes recomputed on every merge. Then a start that runs a stored Run value (#2082).
    corroborateDefenderEpisodes,
    corroborateRunKeyExecution,
    // A mobile extraction's infection window (#932 item 18): rows of a subject device before or
    // after its earliest malicious app-inventory sign. Here because the verdict that makes a sign
    // arrives with enrichment, after the import; recomputed on every merge, notes only.
    (events) => markInfectionWindow(events, iocs, at),
    // An iOS app named by two or more independent artifacts — usage, power, permission, network,
    // notification (#932 item 16). Here for the same reason as the infection window: rows arrive from
    // separate LEAPP imports. Presence only, never a magnitude; recomputed on every merge, notes only.
    markAppCorroboration,
    // A write-capable handle, then a remote thread from the same source into the same target; a
    // process created, its image replaced, then reached into — joined by process GUID (#932 item 9,
    // second half). Here because the records may arrive in separate imports. Only ever raises;
    // recomputed on every merge.
    corroborateInjectionSequences,
    // Several distinct pre-encryption behaviours on one host inside one window (#908 item 3): the steps
    // come from different importers and only the combination is the finding. Only ever raises, never on
    // one behaviour alone. Then S3 checks (#2563) and M365 BEC pairs (#2570) whose halves came apart.
    markRansomwarePrecursors,
    raiseCasePrecursors,
    raiseCaseBecPairs,
    // Say what a certutil transfer actually did — where it connected, what it wrote — by stitching
    // the command to the network and file records of the same process (#908 item 4). Here, because
    // those three legs arrive from different importers.
    explainCertutilTransfers,
    // Instance-metadata credential access (#908 item 7). Here rather than in an importer because the
    // request and the process that made it routinely arrive from different sources — a web access log
    // and an EDR process event — and because the second half of the finding, an instance role used
    // from an address the instance does not have, lives in the cloud audit log instead. Only raises.
    explainMetadataAccess,
    instanceCredentialUseAway,
    // The metadata service leaves no audit-log record at all, so a case with only cloud logs can say
    // nothing about it either way. That gap is put ON the timeline rather than left as silence —
    // "nothing found" is the wrong answer when nothing could have been found. Replaced, not appended.
    (events) => (metadataCoverage ? replacedLast(events, metadataCoverageEvent(events)) : events),
    // One bounded summary per bulk object-read session (#908 item 8). It ADDS a summary event and
    // touches none of the reads themselves: promoting forty thousand GetObject rows would destroy the
    // timeline and put the whole export in front of the AI, which is what the forensic/super-timeline
    // boundary exists to prevent. A re-merge replaces a group's summary rather than adding a second.
    summarizeBulkReads,
    // A storage-account key listing joined to a later account-key-authenticated read on the same
    // account (#931 item 4). Here because the listing (Activity Log) and the read (Storage
    // diagnostic log) arrive from two separate uploads. Only ever adds a bounded join row; never
    // claims the same actor did both — SAS/key use leaves no reliable attribution trail.
    correlateStorageKeyToRead,
    // An AWS VPC flow's private-IP endpoint attributed to the EC2 instance that held it at the
    // flow's own timestamp (#931 item 13). Here because the flow log (Storage/S3 export) and the
    // CloudTrail-derived compute-lifecycle summary (#931 item 8) arrive from two separate uploads.
    // No termination time is required or assumed — a later launch on the same (account, IP) simply
    // supersedes an earlier one. Only ever adds a note; never guesses through NAT/load-balancer
    // hops or an ambiguous tie.
    correlateAwsFlowResourceAttribution,
    // The attributed instance's own launch identity and windowed remote-access requests, disclosed
    // beside the attribution note (#1151, a narrower slice of #931 item 13's own identity/execution
    // ask). Reads only the attribution pass's own note text — never re-derives the attribution.
    // States facts, never causation, and never claims a remote-access request ran anything.
    correlateAwsFlowIdentityExecution,
    // The bulk-read summaries (emitted above) signed with credentials CloudTrail records as delivered
    // to the attributed instance, disclosed beside the attribution note within ±24h (#1295, the
    // sensitive-data half of #931 item 13). Reads only the attribution note text and the raw read
    // rows' own envelopes; never claims the flow carried the objects or that the instance did the
    // reading — stolen IMDS credentials read from anywhere.
    correlateAwsFlowSensitiveData,
    // Browsing by an account that cannot be interactive (#908 item 10). Here because the shellbag,
    // the logon that made a desktop session possible, and any archiving beside it arrive from three
    // different importers. Only raises, and only for an account something SAYS is noninteractive.
    markServiceAccountBrowsing,
    // Browsing evidence that carries no account cannot be judged, and "no service-account browsing
    // found" would report a collection gap as a result. The gap goes ON the timeline, replaceable.
    (events) => replacedLast(events, attributionCoverageEvent(events)),
    // Container escape (#908 item 11). Here because the container's own command line, the host's
    // process telemetry and the host's persistence artifacts arrive from different importers — and
    // because a container-originated change to host persistence only reads as one event when both
    // halves are in the same timeline. Only raises. Then the JNDI-injection (Log4Shell) join, #2099.
    markContainerEscape,
    markJndiInjection,
  ];
}
