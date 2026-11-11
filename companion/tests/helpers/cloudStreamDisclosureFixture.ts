import type { CloudStreamDisclosure } from "../../src/analysis/cloudStreamDisclosure.js";

/** One streamed page's disclosure with nothing capped or skipped; override what a test needs. */
export function streamDisclosure(over: Partial<CloudStreamDisclosure> = {}): CloudStreamDisclosure {
  return {
    kind: "aws",
    format: "cloudtrail-json",
    gzip: false,
    bytesRead: 1000,
    bytesDecoded: 1000,
    records: 50,
    duplicates: 0,
    conflicts: 0,
    unmapped: 0,
    parseErrors: 0,
    oversizeSkipped: 0,
    bomStripped: 0,
    documentsJoined: 0,
    belowFloor: 0,
    preGradeRaised: 0,
    individual: { critical: 0, high: 1, medium: 4 },
    aggregatedRows: { medium: 0, low: 10, info: 30 },
    mediumMerged: 0,
    mediumOverflow: { ruleActorBudget: 0, importBudget: 0, failedReadBudget: 0 },
    failedReads: { folded: 0, toSuper: 0 },
    groups: { detailed: 3, coarse: 0, catchAll: 0 },
    superWritten: 40,
    superBudgetExceeded: 0,
    superEvicted: 0,
    iocsDropped: 0,
    iocsMax: 5000,
    summaryWindow: { max: 100000, records: 50, truncated: false },
    sprayHistoryTruncated: false,
    budgets: {
      mediumPerRuleActor: 20,
      mediumMax: 500,
      aggregateGroupsMax: 2000,
      coarseGroupsMax: 200,
      failedReadsPerActor: 5,
      superRows: 100000,
    },
    ...over,
  };
}
