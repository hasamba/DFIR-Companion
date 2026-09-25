import type { FindingSimulation } from "./findingSimulation.js";
import type { HostAliasIndex } from "./hostAlias.js";
import { canonicalHostName, resolveHost } from "./hostAlias.js";
import {
  SEVERITY_RANK,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
  type Severity,
} from "./stateTypes.js";

// The simulation verdict (#1595). The synthesis can conclude that a case is an authorized attack
// simulation — a script named Invoke-…Simulation.ps1, an answer-key file, a lab-built VM — and still
// leave every attack finding at the severity of a live intrusion, with its own "this is a
// simulation" finding at Info. The verdict and the severities then contradict each other.
//
// The prompt constants are frozen by the eval change gate (#378/#1579), so this is a DETERMINISTIC
// step over the synthesis output, run after grading:
//   1. the verdict finding rises to the highest live-intrusion severity among the findings it explains;
//   2. those findings are tagged "simulated — pending owner confirmation" and capped at Medium, with
//      the live-intrusion severity kept beside the capped one;
//   3. persistence that stays on the host (the IFEO backdoor) keeps its severity — it is a real
//      exposure whatever the attribution.
// The analyst can overrule it with one click ("treat as real intrusion"), stored per case.
//
// Pure and idempotent: applying it twice equals applying it once. A case whose findings reach no
// verdict is returned unchanged.

export const SIMULATION_VERDICT_MIN_CONFIDENCE = 80;
export const SIMULATION_SEVERITY_CAP: Severity = "Medium";
export const SIMULATED_LABEL = "simulated — pending owner confirmation";

// What the exercise is called. A title needs one of these AND a verdict marker below: a title that
// merely NAMES simulation tooling ("Simulated ransomware execution") is a scenario finding, not a
// conclusion about the case.
const EXERCISE_NOUN =
  /\b(simulations?|exercises?|emulation|(red|purple)[- ]team(ing)?|penetration[- ]test(ing)?|pen[- ]?test(ing)?)\b/i;
// The affirmative conclusion: the finding says the activity IS the exercise. No bare "indicators":
// "indicators of penetration-test tooling" names tooling, it concludes nothing.
const VERDICT_MARKER =
  /\b(authori[sz]ed|sanctioned|planned|scripted|controlled|rather than|not an? (real|genuine|actual|uncontrolled)|likely|consistent with|appears to be|assessed as)\b/i;
// A title that says the tooling was turned against the case is the opposite verdict.
const HOSTILE_MARKER =
  /\b(unauthori[sz]ed|abused|abuse of|misused|misuse of|weaponi[sz]ed|attacker[- ](operated|controlled|used)|by (an? |the )?(attacker|threat actor|adversary)|malicious use)\b/i;
const NEGATION = /\b(no|not|non|unlikely|ruled out|rules out|without|isn't|is not)\b/i;
// A denial of authorization anywhere in the title, before or after the exercise noun: "red-team
// exercise was not authorized", "authorized exercise ruled out".
const DENIAL =
  /\b((was|is|were|are|been|being)?\s*(not|never|no longer)\s+(an?\s+)?(authori[sz]ed|sanctioned|approved|planned|scripted|a simulation|an exercise|part of)|ruled out|rules out|unlikely|disproved|disproven)\b/i;

// Persistence ATT&CK techniques: a mechanism that stays on the host after the exercise ends.
const PERSISTENCE_TECHNIQUES = [
  "T1546", // event-triggered execution (IFEO, accessibility features)
  "T1547", // boot / logon autostart
  "T1543", // create or modify system process (services)
  "T1053", // scheduled task / job
  "T1136", // create account
  "T1098", // account manipulation
  "T1505", // server software component (web shell)
  "T1037", // logon scripts
  "T1574", // hijack execution flow
  "T1197", // BITS jobs
  "T1137", // Office application startup
  "T1542", // pre-OS boot
  "T1556", // modify authentication process
  "T1176", // browser extensions
  "T1525", // implant internal image
  "T1554", // compromise host software binary
];
const PERSISTENCE_TITLE =
  /\b(backdoor|persistence|persistent|ifeo|image file execution options|sticky[- ]keys|web ?shell)\b/i;

/** Whether a finding's title states the case is a simulation (not merely that it saw simulation tooling). */
export function isSimulationVerdictTitle(title: string): boolean {
  const noun = EXERCISE_NOUN.exec(title);
  if (!noun) return false;
  if (!VERDICT_MARKER.test(title) || HOSTILE_MARKER.test(title) || DENIAL.test(title)) return false;
  // "No indication this was an authorized exercise": a negation BEFORE the noun flips the claim.
  return !NEGATION.test(title.slice(0, noun.index));
}

/**
 * The verdict finding: an undismissed simulation conclusion whose confidence reaches the threshold.
 * `confidenceOf` lets synthesis judge the model's OWN confidence: grading caps any single-tool,
 * single-host finding at 65, and the evidence of an exercise (a script, an answer-key file, a lab
 * build) usually comes from one file listing — the cap is about corroborating an attack claim.
 */
export function findSimulationVerdict(
  findings: readonly Finding[],
  confidenceOf: (f: Finding) => number = (f) => f.confidence ?? 0,
): Finding | undefined {
  let best: Finding | undefined;
  let bestConf = -1;
  for (const f of findings) {
    if (f.status === "dismissed" || f.ungrounded || f.contentMismatch) continue;
    if (!isSimulationVerdictTitle(f.title)) continue;
    const conf = confidenceOf(f);
    if (conf < SIMULATION_VERDICT_MIN_CONFIDENCE || conf <= bestConf) continue;
    best = f;
    bestConf = conf;
  }
  return best;
}

function isPersistence(f: Finding): boolean {
  const byTechnique = f.mitreTechniques.some((t) => {
    const id = t.trim().toUpperCase();
    return PERSISTENCE_TECHNIQUES.some((p) => id === p || id.startsWith(`${p}.`));
  });
  return byTechnique || PERSISTENCE_TITLE.test(f.title);
}

export interface SimulationVerdictOptions {
  /** The analyst said "treat as real intrusion": no caps, the verdict is only marked overridden. */
  treatAsReal?: boolean;
  aliasIndex?: HostAliasIndex;
  /** The model's confidence per finding id, before grading capped it (synthesis only). */
  modelConfidence?: ReadonlyMap<string, number>;
}

/** Strip a previous run's annotation. The stored original returns only if nothing rewrote the severity since. */
function normalize(f: Finding): Finding {
  if (!f.simulation) return f;
  const { simulation, ...rest } = f;
  return f.severity === simulation.appliedSeverity
    ? { ...rest, severity: simulation.originalSeverity }
    : rest;
}

/**
 * Apply the simulation verdict to a finding set. Returns the same array when nothing changes, so a
 * case with no simulation indicators is untouched.
 */
export function applySimulationVerdict(
  findings: readonly Finding[],
  events: readonly ForensicEvent[],
  opts: SimulationVerdictOptions = {},
): Finding[] {
  const hadAnnotation = findings.some((f) => f.simulation);
  // A verdict this step already accepted stays accepted while its finding stands: the override route
  // and an accepted second opinion re-apply the step without the model's pre-grading confidence.
  const accepted = new Set(findings.filter((f) => f.simulation?.role === "verdict").map((f) => f.id));
  const base = hadAnnotation ? findings.map(normalize) : [...findings];
  const verdict = findSimulationVerdict(base, (f) =>
    accepted.has(f.id)
      ? Number.MAX_SAFE_INTEGER
      : Math.max(f.confidence ?? 0, opts.modelConfidence?.get(f.id) ?? 0),
  );
  if (!verdict) return hadAnnotation ? base : (findings as Finding[]);

  if (opts.treatAsReal) {
    return base.map((f) =>
      f.id === verdict.id
        ? { ...f, simulation: annotation("verdict", f.severity, f.severity, { overridden: true }) }
        : f,
    );
  }

  const hosts = hostResolver(events, opts.aliasIndex);
  const verdictHosts = hosts.of(verdict);
  const explained = base.filter(
    (f) =>
      f.id !== verdict.id &&
      f.status !== "dismissed" &&
      SEVERITY_RANK[f.severity] <= SEVERITY_RANK[SIMULATION_SEVERITY_CAP] &&
      !isSimulationVerdictTitle(f.title) &&
      hosts.compatible(verdictHosts, hosts.of(f)),
  );
  if (!explained.length) return hadAnnotation ? base : (findings as Finding[]);

  const explainedIds = new Set(explained.map((f) => f.id));
  const top = explained.reduce<Severity>(
    (max, f) => (SEVERITY_RANK[f.severity] < SEVERITY_RANK[max] ? f.severity : max),
    verdict.severity,
  );
  return base.map((f) => {
    if (f.id === verdict.id)
      return { ...f, severity: top, simulation: annotation("verdict", f.severity, top) };
    if (!explainedIds.has(f.id)) return f;
    if (isPersistence(f)) {
      return {
        ...f,
        simulation: annotation("live-exposure", f.severity, f.severity, { verdictId: verdict.id }),
      };
    }
    const capped =
      SEVERITY_RANK[f.severity] < SEVERITY_RANK[SIMULATION_SEVERITY_CAP]
        ? SIMULATION_SEVERITY_CAP
        : f.severity;
    return {
      ...f,
      severity: capped,
      simulation: annotation("simulated", f.severity, capped, { verdictId: verdict.id }),
    };
  });
}

/** The step over a whole case state. Returns the same object when no finding changes. */
export function reconcileSimulationVerdict(
  state: InvestigationState,
  opts: SimulationVerdictOptions = {},
): InvestigationState {
  const findings = applySimulationVerdict(state.findings, state.forensicTimeline, opts);
  return findings === state.findings ? state : { ...state, findings };
}

function annotation(
  role: FindingSimulation["role"],
  originalSeverity: Severity,
  appliedSeverity: Severity,
  extra: Pick<FindingSimulation, "verdictId" | "overridden"> = {},
): FindingSimulation {
  return { role, originalSeverity, appliedSeverity, ...extra };
}

interface HostResolver {
  of(f: Finding): Set<string>;
  compatible(a: Set<string>, b: Set<string>): boolean;
}

// Which hosts a finding is about: the assets of the events it cites, forward and reverse. A short
// name and an FQDN with the same first label count as one machine here — this decides only whether
// the verdict explains a finding, never an identity merge. A finding with no resolvable host is
// case-wide only when the whole timeline has at most one host; otherwise it explains nothing, so a
// real intrusion elsewhere in the case is never capped by accident.
function hostResolver(
  events: readonly ForensicEvent[],
  aliasIndex: HostAliasIndex | undefined,
): HostResolver {
  const norm = (raw: string): string => {
    const name = aliasIndex ? resolveHost(aliasIndex, raw) : canonicalHostName(raw);
    return name.split(".")[0] ?? name;
  };
  const byId = new Map(events.map((e) => [e.id, e] as const));
  const reverse = new Map<string, Set<string>>();
  const caseHosts = new Set<string>();
  for (const e of events) {
    if (!e.asset) continue;
    const h = norm(e.asset);
    if (!h) continue;
    caseHosts.add(h);
    for (const fid of e.relatedFindingIds) {
      const set = reverse.get(fid) ?? new Set<string>();
      set.add(h);
      reverse.set(fid, set);
    }
  }
  const singleHost = caseHosts.size <= 1;
  return {
    of(f) {
      const out = new Set(reverse.get(f.id) ?? []);
      for (const id of f.relatedEventIds ?? []) {
        const asset = byId.get(id)?.asset;
        const h = asset ? norm(asset) : "";
        if (h) out.add(h);
      }
      return out;
    },
    compatible(a, b) {
      if (!a.size || !b.size) return singleHost;
      for (const h of b) if (a.has(h)) return true;
      return false;
    },
  };
}

/** The label a report or a ticket puts beside a finding's severity, or "" when the step did not touch it. */
export function simulationSeverityLabel(f: Pick<Finding, "severity" | "simulation">): string {
  const s = f.simulation;
  if (!s) return "";
  if (s.role === "verdict") {
    if (s.overridden) return "[treated as real intrusion (analyst)]";
    return s.originalSeverity !== f.severity
      ? `[simulation verdict; raised from ${s.originalSeverity}]`
      : "[simulation verdict]";
  }
  if (s.role === "live-exposure")
    return "[simulated case — live exposure, remediate regardless of attribution]";
  return s.originalSeverity !== f.severity
    ? `[${SIMULATED_LABEL}; live-intrusion severity: ${s.originalSeverity}]`
    : `[${SIMULATED_LABEL}]`;
}
