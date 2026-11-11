// Where the negative-answer coverage backstop (negativeAnswerCoverage.ts, #1588) sends the analyst
// to settle an unproven "no", by the case's MAIN EVIDENCE SOURCE (#2559).
//
// The backstop's default remedy is a Velociraptor collection (CLASS_COLLECTION in
// collectionInventory.ts). On a case whose evidence comes from an EDR or SIEM the analyst already
// has, the useful step is to SEARCH that tool for the missing class of evidence, so for CrowdStrike,
// Defender, Elastic and Splunk the step names the tool and the events/tables/fields to search.
// Velociraptor, host tools with no query language, cloud logs and an unknown source keep the
// Velociraptor collection, word for word — a cloud log cannot show host execution.
//
// Deterministic text only: this rewrites the backstop's own step, never the synthesis prompt, and
// CLASS_COLLECTION — which the synthesis prompt renders — is left as it is. It names event types and
// tables, never an evidence value, so no query-language quoting is needed.

import { familyOfEvents, type MainSourceResult, type SourceFamily } from "./caseMainSource.js";
import type { EvidenceClass } from "./refutationGate.js";
import type { InvestigationQuestion, InvestigationState } from "./stateTypes.js";

export interface SearchRemedy {
  /** The tool the analyst searches, as the step names it. */
  tool: string;
  /** What to search in it for the missing class. */
  what: string;
}

type SearchFamily = "crowdstrike" | "defender" | "elastic" | "splunk";

const SEARCH_REMEDIES: Readonly<Record<SearchFamily, { tool: string; what: Record<EvidenceClass, string> }>> =
  {
    crowdstrike: {
      tool: "CrowdStrike Falcon",
      what: {
        execution: "#event_simpleName=ProcessRollup2 process executions",
        "file-activity": "#event_simpleName file-write events such as PeFileWritten and NewExecutableWritten",
        network: "#event_simpleName=NetworkConnectIP4 and DnsRequest",
        persistence: "#event_simpleName=AsepValueUpdate, ServiceStarted and ScheduledTaskRegistered",
      },
    },
    defender: {
      tool: "Microsoft Defender XDR advanced hunting",
      what: {
        execution: "DeviceProcessEvents",
        "file-activity": "DeviceFileEvents",
        network: "DeviceNetworkEvents",
        persistence: "DeviceRegistryEvents and DeviceEvents (ServiceInstalled, ScheduledTaskCreated)",
      },
    },
    elastic: {
      tool: "Elastic",
      what: {
        execution: "event.category:process (process.name, process.command_line)",
        "file-activity": "event.category:file (file.path, event.action)",
        network: "event.category:network and dns (destination.ip, dns.question.name)",
        persistence: "registry.path and service / scheduled-task events",
      },
    },
    splunk: {
      tool: "Splunk",
      what: {
        execution: "Sysmon EventCode=1 or Security EventCode=4688 (process_name, CommandLine)",
        "file-activity": "Sysmon EventCode=11 and 23 (file_path)",
        network: "Sysmon EventCode=3 and 22, or firewall/proxy logs (dest_ip, query)",
        persistence: "Sysmon EventCode=12/13, System EventCode=7045 and Security EventCode=4698",
      },
    },
  };

const isSearchFamily = (f: SourceFamily | null): f is SearchFamily => !!f && f in SEARCH_REMEDIES;

/** The family whose tool settles this question: the main source, or on a mixed case the question's own evidence. */
export function questionFamily(
  q: InvestigationQuestion,
  state: InvestigationState,
  mainSource: Pick<MainSourceResult, "effective"> | undefined,
): SourceFamily | null {
  if (!mainSource || !mainSource.effective) return null;
  if (mainSource.effective !== "mixed") return mainSource.effective;
  const findingIds = new Set(q.relatedFindingIds ?? []);
  if (!findingIds.size) return null;
  const eventIds = new Set(
    state.findings.filter((f) => findingIds.has(f.id)).flatMap((f) => f.relatedEventIds ?? []),
  );
  return familyOfEvents(state.forensicTimeline.filter((e) => eventIds.has(e.id)));
}

/** The search remedy for a missing class, or undefined to keep the Velociraptor collection. */
export function searchRemedy(family: SourceFamily | null, missing: EvidenceClass): SearchRemedy | undefined {
  if (!isSearchFamily(family)) return undefined;
  const r = SEARCH_REMEDIES[family];
  return { tool: r.tool, what: r.what[missing] };
}
