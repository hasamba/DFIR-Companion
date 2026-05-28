export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export type FindingStatus = "open" | "confirmed" | "dismissed";
export type ThreadStatus = "open" | "closed";

export interface IOC {
  id: string;
  type: "ip" | "domain" | "hash" | "file" | "process" | "url" | "other";
  value: string;
  firstSeen: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  relatedIocs: string[];        // IOC ids
  sourceScreenshots: string[];  // screenshot filenames
  mitreTechniques: string[];    // technique ids, e.g. "T1059"
  firstSeen: string;
  lastUpdated: string;
  status: FindingStatus;
}

export interface Thread {
  id: string;
  description: string;
  status: ThreadStatus;
  openedAt: string;
  closedAt: string | null;
}

export interface TimelineEntry {
  timestamp: string;
  windowSequence: number;
  description: string;
  sourceScreenshots: string[];
}

export interface Technique {
  id: string;            // e.g. "T1059.001"
  name: string;
  findingIds: string[];
}

export interface InvestigationState {
  caseId: string;
  findings: Finding[];
  iocs: IOC[];
  openThreads: Thread[];
  timeline: TimelineEntry[];
  mitreTechniques: Technique[];
  lastSummary: string;
  updatedAt: string;
}

export function emptyState(caseId: string): InvestigationState {
  return {
    caseId,
    findings: [],
    iocs: [],
    openThreads: [],
    timeline: [],
    mitreTechniques: [],
    lastSummary: "",
    updatedAt: new Date(0).toISOString(),
  };
}
