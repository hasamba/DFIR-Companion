export type HuntDataset = "forensic" | "super";
export type HuntFieldType = "keyword" | "string" | "number" | "boolean" | "timestamp";

export type HuntParameterValue = string | number | boolean | null;
export type HuntParameters = Readonly<Record<string, HuntParameterValue>>;

export interface HuntParameter {
  kind: "parameter";
  name: string;
}

export type HuntValue = HuntParameterValue | HuntParameter;

export type HuntPredicateOperator =
  "=" | "!=" | ">" | ">=" | "<" | "<=" | "contains" | "matches" | "exists" | "between" | "during";

export interface HuntPredicate {
  kind: "predicate";
  field: string;
  operator: HuntPredicateOperator;
  value?: HuntValue;
  upper?: HuntValue;
  regexFlags?: string;
}

export interface HuntBooleanExpression {
  kind: "boolean";
  operator: "and" | "or";
  left: HuntExpression;
  right: HuntExpression;
}

export interface HuntNotExpression {
  kind: "not";
  operand: HuntExpression;
}

export type HuntExpression = HuntPredicate | HuntBooleanExpression | HuntNotExpression;

export interface HuntGroupStage {
  kind: "group";
  field: string;
}

export interface HuntCountStage {
  kind: "count";
}

export type HuntStatisticFunction = "count" | "min" | "max" | "sum" | "avg";

export interface HuntStatistic {
  fn: HuntStatisticFunction;
  field?: string;
  alias: string;
}

export interface HuntStatsStage {
  kind: "stats";
  statistics: HuntStatistic[];
  by?: string;
}

export interface HuntRareStage {
  kind: "rare";
  field: string;
  limit: number;
}

/**
 * `prevalence <field> [limit N]` (#2670): per value, on how many DISTINCT HOSTS it appears, out of the
 * distinct hosts in the matched rows — "seen on 3 of 287 hosts". Rarest first. `rare` keeps its
 * meaning (events per value); this counts hosts.
 */
export interface HuntPrevalenceStage {
  kind: "prevalence";
  field: string;
  limit: number;
}

export interface HuntSortStage {
  kind: "sort";
  field: string;
  direction: "asc" | "desc";
}

export interface HuntLimitStage {
  kind: "limit";
  limit: number;
}

export type HuntPipelineStage =
  | HuntGroupStage
  | HuntCountStage
  | HuntStatsStage
  | HuntRareStage
  | HuntPrevalenceStage
  | HuntSortStage
  | HuntLimitStage;

export interface ParsedHuntQuery {
  text: string;
  filter: HuntExpression;
  pipeline: HuntPipelineStage[];
  parameters: string[];
}

export interface HuntFieldCatalogueEntry {
  name: string;
  type: HuntFieldType;
  description: string;
  indexed: boolean;
  aliases?: string[];
}

export interface HuntQueryErrorShape {
  code: string;
  message: string;
  line: number;
  column: number;
  length: number;
  expected?: string[];
  suggestions?: string[];
}
