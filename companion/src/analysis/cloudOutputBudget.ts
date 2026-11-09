// The bounded output of a streaming cloud import (#2303). Every mapped and graded row is routed
// here, one at a time, and the output stays bounded however many rows the export has:
//
//   Critical / High → always an individual forensic event.
//   Medium          → kept in detail up to MEDIUM_INDIVIDUAL_PER_RULE_ACTOR distinct rows per
//                     (rule, actor) and MEDIUM_INDIVIDUAL_MAX per import; past either, aggregated —
//                     per (rule, actor) when that pair used its budget, per (rule, source address)
//                     when the import did. Rows sharing the importer's own aggKey merge into one
//                     detail row and spend the budget once, as a whole-file import merges them
//                     (#2502); a later matching row joins that row even after the budgets are spent.
//                     A failed read-only call (#2481) also spends a per-actor budget of
//                     MEDIUM_FAILED_READS_PER_ACTOR across all actions; past it — or past the import
//                     budget — it folds into one counted event per actor that lists the actions, and
//                     is sent to the super-timeline individually while the import's room lasts.
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
  MEDIUM_FAILED_READS_PER_ACTOR,
  MEDIUM_INDIVIDUAL_MAX,
  MEDIUM_INDIVIDUAL_PER_RULE_ACTOR,
} from "./cloudStreamLimits.js";

export interface OutputBudgets {
  mediumPerRuleActor: number;
  mediumMax: number;
  aggregateGroupsMax: number;
  coarseGroupsMax: number;
  /** Distinct failed read-only Medium rows kept in detail per actor (#2481). */
  failedReadsPerActor: number;
  /** Rows this import may write to the super-timeline individually. */
  superRows: number;
}

export function defaultBudgets(superRows: number): OutputBudgets {
  return {
    mediumPerRuleActor: MEDIUM_INDIVIDUAL_PER_RULE_ACTOR,
    mediumMax: MEDIUM_INDIVIDUAL_MAX,
    aggregateGroupsMax: AGGREGATE_GROUPS_MAX,
    coarseGroupsMax: COARSE_GROUPS_MAX,
    failedReadsPerActor: MEDIUM_FAILED_READS_PER_ACTOR,
    superRows,
  };
}

/** What a row is about, read from its source record by the provider adapter. */
export interface RowFacts {
  rule: string; // the operation / API action
  actor: string; // the principal
  ip: string; // the source address, or ""
  /** A read-only call that failed (CloudTrail: readOnly with an errorCode) — #2481. */
  failedRead?: boolean;
}

export type RouteDecision = "forensic" | "super" | "aggregate" | "super+aggregate" | "below-floor";

/** Every count the import discloses about what it kept, aggregated, capped or skipped. */
export interface OutputDisclosure {
  rowsRouted: number;
  belowFloor: number;
  individual: { critical: number; high: number; medium: number };
  superIndividual: number;
  aggregatedRows: { medium: number; low: number; info: number };
  /** Medium rows kept in detail by joining a matching detail row (same aggKey, #2502). */
  mediumMerged: number;
  /** Why Medium rows were not kept in detail; failedReadBudget = the per-actor failed-read cap (#2481). */
  mediumOverflow: { ruleActorBudget: number; importBudget: number; failedReadBudget: number };
  /** Failed read-only calls folded into their actor's group, and how many went to the super-timeline. */
  failedReads: { folded: number; toSuper: number };
  groups: { detailed: number; coarse: number; catchAll: number };
  /** Low/Info rows (and folded failed reads) that found no room in the super-timeline. */
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
/** An actor's identity key is bounded far above any real principal, so distinct ARNs never collide. */
const ACTOR_KEY_MAX = 2_048;
const FAILED_READ_REASON = "failed read-only calls folded per actor";

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
  // In-budget Medium rows merge by the importer's aggKey (#2502); Critical/High above stay one each.
  const mediumAgg = createEventAggregator({
    aggregate: true,
    maxEvents: Infinity,
    provenance: opts.provenance,
  });
  const mediumKeys = new Set<string>();
  const aggregateAgg: EventAggregator = createEventAggregator({
    aggregate: true,
    maxEvents: Infinity,
    provenance: opts.provenance,
  });
  const perRuleActor = new Map<string, number>();
  const failedReadsKept = new Map<string, number>();
  const failedReadGroups = new Map<string, FailedReadTally>();
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
    mediumMerged: 0,
    mediumOverflow: { ruleActorBudget: 0, importBudget: 0, failedReadBudget: 0 },
    failedReads: { folded: 0, toSuper: 0 },
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
    return key;
  }

  /** A failed read past its actor's (or the import's) budget: one group per actor, and the super-timeline. */
  function foldFailedRead(
    row: MappedEvent,
    f: RowFacts,
    actorKey: string,
    why: keyof OutputDisclosure["mediumOverflow"],
  ) {
    d.mediumOverflow[why]++;
    d.failedReads.folded++;
    const detailedKey = `budget|Medium|failedRead|${actorKey}`;
    if (aggregate(row, f, "Medium", detailedKey, FAILED_READ_REASON) === detailedKey) {
      const tally = failedReadGroups.get(detailedKey) ?? createFailedReadTally(clip(f.actor));
      failedReadGroups.set(detailedKey, tally);
      tally.add(clip(f.rule));
    }
    if (superUsed < b.superRows) {
      superUsed++;
      d.superIndividual++;
      d.failedReads.toSuper++;
      return "super+aggregate";
    }
    d.superBudgetExceeded++;
    return "aggregate";
  }

  function routeMedium(row: MappedEvent, f: RowFacts): RouteDecision {
    if (mediumKeys.has(row.aggKey)) {
      // Joins a detail row already kept: no new forensic row, so no budget is spent.
      d.individual.medium++;
      d.mediumMerged++;
      mediumAgg.add(row);
      return "forensic";
    }
    const pair = `${clip(f.rule)}|${clip(f.actor)}`;
    const used = perRuleActor.get(pair) ?? 0;
    // An empty actor never folds as a failed read: unknown principals keep the ordinary path.
    const failedActor = f.failedRead && f.actor ? f.actor.slice(0, ACTOR_KEY_MAX) : null;
    const failedUsed = failedActor === null ? 0 : (failedReadsKept.get(failedActor) ?? 0);
    const failedSpent = failedActor !== null && failedUsed >= b.failedReadsPerActor;
    if (!failedSpent && mediumKept < b.mediumMax && used < b.mediumPerRuleActor) {
      perRuleActor.set(pair, used + 1);
      if (failedActor !== null) failedReadsKept.set(failedActor, failedUsed + 1);
      mediumKept++;
      d.individual.medium++;
      mediumKeys.add(row.aggKey);
      mediumAgg.add(row);
      return "forensic";
    }
    const actorSpent = used >= b.mediumPerRuleActor;
    if (failedActor !== null)
      return foldFailedRead(
        row,
        f,
        failedActor,
        failedSpent ? "failedReadBudget" : actorSpent ? "ruleActorBudget" : "importBudget",
      );
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
      // Each aggregator sorts most-severe first; mediumAgg holds only Medium, so this is one order.
      const individual = [...individualAgg.finish().events, ...mediumAgg.finish().events];
      const aggregates = aggregateAgg.finish().events.map((e) => {
        const failed = failedReadGroups.get(e.aggKey ?? "");
        return failed
          ? describeFailedReads(e, failed, FAILED_READ_REASON)
          : describeAggregate(e, tierOf.get(e.aggKey ?? ""));
      });
      d.groups = { detailed, coarse, catchAll };
      return {
        individual,
        aggregates,
        disclosure: {
          ...d,
          mediumOverflow: { ...d.mediumOverflow },
          failedReads: { ...d.failedReads },
          budgets: { ...b },
        },
      };
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
  // A one-row detailed group folded nothing in: it IS the original row, so no note (#2475).
  if (tier.tier === "detailed" && n <= 1) return e;
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

/** How many distinct actions one actor's failed-read group tracks by name; past it, calls are counted. */
const FAILED_READ_ACTIONS_TRACKED = 200;
/** How many of those actions the group's description names. */
const FAILED_READ_ACTIONS_LISTED = 20;

interface FailedReadTally {
  actor: string;
  /** Calls per action, in first-seen order. */
  actions: Map<string, number>;
  /** Calls to actions past FAILED_READ_ACTIONS_TRACKED (their names are not kept). */
  untracked: number;
  add(action: string): void;
}

function createFailedReadTally(actor: string): FailedReadTally {
  const t: FailedReadTally = {
    actor,
    actions: new Map(),
    untracked: 0,
    add(action) {
      const n = t.actions.get(action);
      if (n !== undefined) t.actions.set(action, n + 1);
      else if (t.actions.size < FAILED_READ_ACTIONS_TRACKED) t.actions.set(action, 1);
      else t.untracked++;
    },
  };
  return t;
}

/**
 * A principal's folded failed reads (#2481): who, how many, across which actions, when — the actions
 * named with their counts, most-called first. Actor and action names are clipped like every rule name.
 */
function describeFailedReads(e: SiemEvent, t: FailedReadTally, reason: string): SiemEvent {
  const n = e.count ?? 1;
  const span = e.endTimestamp && e.endTimestamp !== e.timestamp ? `, ${e.timestamp} → ${e.endTimestamp}` : "";
  const ranked = [...t.actions].sort((a, b) => b[1] - a[1]);
  const listed = ranked
    .slice(0, FAILED_READ_ACTIONS_LISTED)
    .map(([action, k]) => `${action} ×${k}`)
    .join(", ");
  const moreActions = ranked.length - Math.min(ranked.length, FAILED_READ_ACTIONS_LISTED);
  const more = [
    moreActions ? `+${moreActions} more action(s)` : "",
    t.untracked ? `${t.untracked} call(s) to further actions not named` : "",
  ]
    .filter(Boolean)
    .join("; ");
  const actions = `${t.untracked ? "at least " : ""}${t.actions.size} action(s)`;
  return {
    ...e,
    description:
      `${t.actor}: ${n} failed read-only call(s) across ${actions}${span} — ${listed}` +
      `${more ? ` (${more})` : ""} [aggregated: ${n} row(s) — ${reason}]`,
  };
}
