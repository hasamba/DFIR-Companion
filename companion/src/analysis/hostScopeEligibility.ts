import type { IrisTactic } from "./mitreTactics.js";
import { COLLECTION_STEPS } from "./collectionPlan.js";
import { SEVERITY_RANK } from "./severityFloor.js";
import type { HostEvidence } from "./hostScopeAggregate.js";

// Clearance eligibility for one host. This decides whether the tool is allowed to OFFER clearance —
// the analyst still makes the assertion. Every criterion reports WHAT IS MISSING, so "not eligible"
// reads as a collection instruction rather than a dead end.
//
// Criterion 3 asks whether the host holds evidence CAPABLE of showing the tactics this case has
// actually confirmed: a box with only firewall logs cannot be cleared of credential dumping. An
// earlier draft asked instead whether fleet hunts came back empty for the host — unimplementable and
// unsafe, because HuntOutcome stores no host and HuntTarget selects by label/OS, so "no rows" cannot
// be told apart from "never targeted". Silence is not cleanliness. Hunts are shown as supporting
// context in the panel, never as a criterion here.
//
// The tactic→evidence table composes two vocabularies the codebase already pins by test (IrisTactic
// and COLLECTION_STEPS ids) rather than inventing a third. Pure — no I/O.

export const TACTIC_CLEARANCE_EVIDENCE: Partial<Record<IrisTactic, readonly string[]>> = {
  "Initial Access": ["edr", "windows-event-logs", "endpoint-triage", "web-logs", "m365", "identity"],
  Execution: ["edr", "windows-event-logs", "endpoint-triage"],
  Persistence: ["edr", "windows-event-logs", "endpoint-triage"],
  "Privilege Escalation": ["edr", "windows-event-logs", "endpoint-triage"],
  "Defense Evasion": ["edr", "windows-event-logs", "endpoint-triage"],
  "Credential Access": ["edr", "windows-event-logs", "memory"],
  Discovery: ["edr", "windows-event-logs", "endpoint-triage"],
  "Lateral Movement": ["edr", "windows-event-logs", "identity", "network"],
  Collection: ["edr", "endpoint-triage", "m365"],
  "Command and Control": ["edr", "network", "siem"],
  Exfiltration: ["network", "siem", "web-logs", "m365"],
  Impact: ["edr", "windows-event-logs", "endpoint-triage"],
};

// Host-level evidence classes. A host cannot be cleared on network-only telemetry, so network, siem
// and web-log classes are deliberately absent here — they still satisfy technique coverage for
// tactics genuinely visible from the wire, but they are not evidence ABOUT the box.
const HOST_LEVEL_STEPS = new Set(["edr", "windows-event-logs", "endpoint-triage", "memory"]);

const SOURCE_TO_STEP = new Map<string, string>(
  COLLECTION_STEPS.flatMap((step) =>
    step.satisfiedBy.map((label) => [label.toLowerCase(), step.id] as [string, string]),
  ),
);

// Minute precision, because the window-coverage detail prints FOUR stamps in one sentence and the
// panel renders that sentence verbatim. At full ISO the line runs past 110 characters of which 32
// are `:00.000Z` — seconds nothing in this comparison is decided by.
function stamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  const minutes = iso.slice(0, 16).replace("T", " ");
  return minutes.length === 16 ? `${minutes}Z` : iso;
}

export function sourceClassesFor(sources: Iterable<string>): Set<string> {
  const out = new Set<string>();
  for (const source of sources) {
    const step = SOURCE_TO_STEP.get(source.trim().toLowerCase());
    if (step) out.add(step);
  }
  return out;
}

export interface EligibilityCriterion {
  id: "source-breadth" | "window-coverage" | "technique-coverage" | "no-open-signal";
  met: boolean;
  detail: string;
}

export interface Eligibility {
  eligible: boolean;
  criteria: EligibilityCriterion[];
}

export function evaluateEligibility(input: {
  evidence: HostEvidence;
  window: { start: string | null; end: string | null };
  caseTactics: readonly IrisTactic[];
}): Eligibility {
  const { evidence, window, caseTactics } = input;
  const classes = sourceClassesFor(evidence.sources);

  const hostLevel = [...classes].filter((c) => HOST_LEVEL_STEPS.has(c));
  const sourceBreadth: EligibilityCriterion = {
    id: "source-breadth",
    met: hostLevel.length > 0,
    detail: hostLevel.length
      ? `host-level evidence: ${hostLevel.join(", ")}`
      : "no host-level evidence (EDR, event logs, triage or memory) was collected from this host",
  };

  const startOk = !window.start || (!!evidence.firstSeen && evidence.firstSeen <= window.start);
  const endOk = !window.end || (!!evidence.lastSeen && evidence.lastSeen >= window.end);
  const windowMet = Boolean(evidence.collected && startOk && endOk);
  const windowCoverage: EligibilityCriterion = {
    id: "window-coverage",
    met: windowMet,
    detail: windowMet
      ? "telemetry spans the incident window"
      : `telemetry covers ${stamp(evidence.firstSeen)} → ${stamp(evidence.lastSeen)}; ` +
        `incident window is ${stamp(window.start)} → ${stamp(window.end)}`,
  };

  const uncovered = caseTactics.filter((tactic) => {
    const capable = TACTIC_CLEARANCE_EVIDENCE[tactic];
    if (!capable || capable.length === 0) return false; // nothing claims to show it — do not block
    return !capable.some((step) => classes.has(step));
  });
  const techniqueCoverage: EligibilityCriterion = {
    id: "technique-coverage",
    met: uncovered.length === 0,
    detail: uncovered.length
      ? `no evidence capable of showing: ${uncovered.join(", ")}`
      : "evidence can show every confirmed tactic in this case",
  };

  const hasHighSeverity = SEVERITY_RANK[evidence.maxSeverity] <= SEVERITY_RANK.High;
  const noOpenSignal: EligibilityCriterion = {
    id: "no-open-signal",
    met: evidence.findingIds.size === 0 && !hasHighSeverity,
    detail:
      evidence.findingIds.size > 0
        ? `${evidence.findingIds.size} finding(s) reference this host`
        : hasHighSeverity
          ? `a ${evidence.maxSeverity} event is recorded on this host`
          : "no finding and no High/Critical event on this host",
  };

  const criteria = [sourceBreadth, windowCoverage, techniqueCoverage, noOpenSignal];
  return { eligible: criteria.every((c) => c.met), criteria };
}
