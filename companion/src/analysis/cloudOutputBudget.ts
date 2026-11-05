// The bounded output of a streaming cloud import (#2303). Every mapped and graded row is routed
// here, one at a time, and the output stays bounded however many rows the export has:
//
//   Critical / High → always an individual forensic event.
//   Medium          → individual up to MEDIUM_INDIVIDUAL_PER_RULE_ACTOR per (rule, actor) and
//                     MEDIUM_INDIVIDUAL_MAX per import; past either, aggregated — per (rule, actor)
//                     when that pair used its budget, per (rule, source address) when the import did.
//   Low             → aggregated in the forensic timeline, and written individually to the
//                     super-timeline while its per-import room lasts.
//   Info            → written individually to the super-timeline while its room lasts; past it,
//                     aggregated (and the aggregate, being Info, ends in the super-timeline too).
//
// Aggregation keeps a count, first/last time and the source-record relation (#2301, through the
// aggregator's provenance hook). Detailed groups (the importer's own aggregation key, or rule and
// actor) are capped at AGGREGATE_GROUPS_MAX; past that rows fold into coarser groups by rule (and
// source address for Medium), capped at COARSE_GROUPS_MAX; past that, one group per severity.
// Every one of those steps is counted in the disclosure, which the import note and the Cloud
// Coverage panel print. Pure: no I/O; the caller writes what this decides.

import { SEVERITY_RANK, type Severity } from "./stateTypes.js";
import type { MappedEvent, SiemEvent } from "./siemImport.js";
import { createEventAggregator, type AggregateProvenance, type EventAggregator } from "./eventAggregate.js";
import {
  AGGREGATE_GROUPS_MAX,
  COARSE_GROUPS_MAX,
  MEDIUM_INDIVIDUAL_MAX,
  MEDIUM_INDIVIDUAL_PER_RULE_ACTOR,
} from "./cloudStreamLimits.js";

export interface OutputBudgets {
  mediumPerRuleActor: number;
  mediumMax: number;
  aggregateGroupsMax: number;
  coarseGroupsMax: number;
  /** Rows this import may write to the super-timeline individually. */
  superRows: number;
}

export function defaultBudgets(superRows: number): OutputBudgets {
  return {
    mediumPerRuleActor: MEDIUM_INDIVIDUAL_PER_RULE_ACTOR,
    mediumMax: MEDIUM_INDIVIDUAL_MAX,
    aggregateGroupsMax: AGGREGATE_GROUPS_MAX,
    coarseGroupsMax: COARSE_GROUPS_MAX,
    superRows,
  };
}

/** What a row is about, read from its source record by the provider adapter. */
export interface RowFacts {
  rule: string; // the operation / API action
  actor: string; // the principal
  ip: string; // the source address, or ""
}

export type RouteDecision = "forensic" | "super" | "aggregate" | "super+aggregate" | "below-floor";

/** Every count the import discloses about what it kept, aggregated, capped or skipped. */
export interface OutputDisclosure {
  rowsRouted: number;
  belowFloor: number;
  individual: { critical: number; high: number; medium: number };
  superIndividual: number;
  aggregatedRows: { medium: number; low: number; info: number };
  mediumOverflow: { ruleActorBudget: number; importBudget: number };
  groups: { detailed: number; coarse: number; catchAll: number };
  /** Low/Info rows that found no room in the super-timeline and are only in aggregates. */
  superBudgetExceeded: number;
  budgets: OutputBudgets;
}

export interface OutputBudget {
  route(row: MappedEvent, facts: RowFacts): RouteDecision;
  /** The forensic-bound events: individual rows, then aggregates (descriptions say they are). */
  finish(): { individual: SiemEvent[]; aggregates: SiemEvent[]; disclosure: OutputDisclosure };
}

type Tier = "detailed" | "coarse" | "catchAll";

const RULE_MAX = 160;
const clip = (s: string): string => (s.length > RULE_MAX ? s.slice(0, RULE_MAX) : s);

export function createOutputBudget(opts: {
  budgets: OutputBudgets;
  provenance?: AggregateProvenance;
  minSeverity?: Severity;
}): OutputBudget {
  const b = opts.budgets;
  const floorRank = opts.minSeverity ? SEVERITY_RANK[opts.minSeverity] : Infinity;
  const individualAgg = createEventAggregator({
    aggregate: false,
    maxEvents: Infinity,
    provenance: opts.provenance,
  });
  const aggregateAgg: EventAggregator = createEventAggregator({
    aggregate: true,
    maxEvents: Infinity,
    provenance: opts.provenance,
  });
  const perRuleActor = new Map<string, number>();
  const tierOf = new Map<string, { tier: Tier; reason: string; rule: string; ip: string }>();
  let detailed = 0;
  let coarse = 0;
  let catchAll = 0;
  let mediumKept = 0;
  let superUsed = 0;
  const d: OutputDisclosure = {
    rowsRouted: 0,
    belowFloor: 0,
    individual: { critical: 0, high: 0, medium: 0 },
    superIndividual: 0,
    aggregatedRows: { medium: 0, low: 0, info: 0 },
    mediumOverflow: { ruleActorBudget: 0, importBudget: 0 },
    groups: { detailed: 0, coarse: 0, catchAll: 0 },
    superBudgetExceeded: 0,
    budgets: b,
  };

  /** The group a row folds into: detailed while there is room, then coarse, then one per severity. */
  function groupKey(
    sev: Severity,
    detailedKey: string | null,
    coarseKey: string,
    f: RowFacts,
    reason: string,
  ) {
    const take = (key: string, tier: Tier): string => {
      if (!tierOf.has(key)) {
        tierOf.set(key, { tier, reason, rule: f.rule, ip: tier === "coarse" ? f.ip : "" });
        if (tier === "detailed") detailed++;
        else if (tier === "coarse") coarse++;
        else catchAll++;
      }
      return key;
    };
    if (detailedKey && (tierOf.has(detailedKey) || detailed < b.aggregateGroupsMax))
      return take(detailedKey, "detailed");
    if (tierOf.has(coarseKey) || coarse < b.coarseGroupsMax) return take(coarseKey, "coarse");
    return take(`budget|${sev}|*`, "catchAll");
  }

  function aggregate(
    row: MappedEvent,
    f: RowFacts,
    sev: Severity,
    detailedKey: string | null,
    reason: string,
  ) {
    const coarseKey = `budget|${sev}|${clip(f.rule)}${sev === "Medium" ? `|${f.ip}` : ""}`;
    const key = groupKey(sev, detailedKey, coarseKey, f, reason);
    aggregateAgg.add({ ...row, aggKey: key });
    if (sev === "Medium") d.aggregatedRows.medium++;
    else if (sev === "Low") d.aggregatedRows.low++;
    else d.aggregatedRows.info++;
  }

  function routeMedium(row: MappedEvent, f: RowFacts): RouteDecision {
    const pair = `${clip(f.rule)}|${clip(f.actor)}`;
    const used = perRuleActor.get(pair) ?? 0;
    if (mediumKept < b.mediumMax && used < b.mediumPerRuleActor) {
      perRuleActor.set(pair, used + 1);
      mediumKept++;
      d.individual.medium++;
      individualAgg.add(row);
      return "forensic";
    }
    const actorSpent = used >= b.mediumPerRuleActor;
    if (actorSpent) d.mediumOverflow.ruleActorBudget++;
    else d.mediumOverflow.importBudget++;
    const reason = actorSpent
      ? "Medium budget per rule and actor reached"
      : "Medium budget for this import reached";
    aggregate(row, f, "Medium", actorSpent ? `budget|Medium|${pair}` : null, reason);
    return "aggregate";
  }

  function routeLowInfo(row: MappedEvent, f: RowFacts, sev: Severity): RouteDecision {
    const hasRoom = superUsed < b.superRows;
    if (hasRoom) {
      superUsed++;
      d.superIndividual++;
    } else d.superBudgetExceeded++;
    if (sev === "Info" && hasRoom) return "super";
    const reason = sev === "Low" ? "Low rows are aggregated" : "super-timeline room for this import used";
    aggregate(row, f, sev, `budget|${sev}|${row.aggKey}`, reason);
    return hasRoom ? "super+aggregate" : "aggregate";
  }

  return {
    route(row, facts) {
      d.rowsRouted++;
      const sev = row.severity;
      if (SEVERITY_RANK[sev] > floorRank) {
        d.belowFloor++;
        return "below-floor";
      }
      if (sev === "Critical" || sev === "High") {
        if (sev === "Critical") d.individual.critical++;
        else d.individual.high++;
        individualAgg.add(row);
        return "forensic";
      }
      if (sev === "Medium") return routeMedium(row, facts);
      return routeLowInfo(row, facts, sev);
    },
    finish() {
      const individual = individualAgg.finish().events;
      const aggregates = aggregateAgg
        .finish()
        .events.map((e) => describeAggregate(e, tierOf.get(e.aggKey ?? "")));
      d.groups = { detailed, coarse, catchAll };
      return { individual, aggregates, disclosure: { ...d, budgets: { ...b } } };
    },
  };
}

/** An aggregate's description says what it stands for; a coarse group's one example row is labelled as such. */
function describeAggregate(
  e: SiemEvent,
  tier: { tier: Tier; reason: string; rule: string; ip: string } | undefined,
): SiemEvent {
  if (!tier) return e;
  const n = e.count ?? 1;
  const span = e.endTimestamp && e.endTimestamp !== e.timestamp ? `, ${e.timestamp} → ${e.endTimestamp}` : "";
  const note = `[aggregated: ${n} row(s)${span} — ${tier.reason}]`;
  if (tier.tier === "detailed") return { ...e, description: `${e.description} ${note}` };
  const scope =
    tier.tier === "coarse" ? `${tier.rule}${tier.ip ? ` from ${tier.ip}` : ""}` : "other operations";
  const { sourceRecordId: _drop, ...rest } = e;
  return {
    ...rest,
    description: `${scope}: ${n} ${e.severity} row(s) aggregated ${note}; example: ${e.description}`,
  };
}
