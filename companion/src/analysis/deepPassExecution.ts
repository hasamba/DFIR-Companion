import type { ForensicEvent, Severity } from "./stateTypes.js";
import {
  MAX_CONDENSE_ROUNDS,
  OBSERVATION_CAP_PER_BATCH,
  planCondenseRounds,
  renderObservationDigest,
  sanitizeObservations,
  type DeepPassCheckpoint,
  type Observation,
} from "./deepPass.js";
import { PresidioApprovalRequired } from "./presidio.js";

interface DeepPassExecutionInput {
  batches: readonly ForensicEvent[][];
  floor: Severity;
  selectionHash: string;
  validEventIds: ReadonlySet<string>;
  digestBudget: number;
  resumeFrom?: DeepPassCheckpoint;
  signal?: AbortSignal;
  onProgress?: (done: number, total: number, detail: string) => void;
  onCheckpoint?: (checkpoint: DeepPassCheckpoint) => Promise<void>;
  renderBatch: (batch: readonly ForensicEvent[]) => string;
  observe: (userPrompt: string) => Promise<unknown>;
  onFailure: (message: string) => void;
}

export interface DeepPassExecutionResult {
  observations: Observation[];
  batchesFailed: number;
  aborted: boolean;
}

function validateCheckpoint(input: DeepPassExecutionInput): void {
  const checkpoint = input.resumeFrom;
  if (
    checkpoint &&
    (checkpoint.floor !== input.floor ||
      checkpoint.totalBatches !== input.batches.length ||
      checkpoint.selectionHash !== input.selectionHash ||
      checkpoint.nextBatch < 0 ||
      checkpoint.nextBatch > input.batches.length)
  ) {
    throw new Error("deep-pass checkpoint no longer matches this case selection; start a new run");
  }
}

async function saveCheckpoint(
  input: DeepPassExecutionInput,
  nextBatch: number,
  observations: readonly Observation[],
  batchesFailed: number,
): Promise<void> {
  await input.onCheckpoint?.({
    nextBatch,
    totalBatches: input.batches.length,
    floor: input.floor,
    selectionHash: input.selectionHash,
    observations: [...observations],
    batchesFailed,
  });
}

export async function executeDeepPassBatches(
  input: DeepPassExecutionInput,
): Promise<DeepPassExecutionResult> {
  validateCheckpoint(input);
  let observations = input.resumeFrom ? [...input.resumeFrom.observations] : [];
  let batchesFailed = input.resumeFrom?.batchesFailed ?? 0;
  let aborted = false;
  const firstBatch = input.resumeFrom?.nextBatch ?? 0;

  for (let index = firstBatch; index < input.batches.length; index++) {
    if (input.signal?.aborted) {
      aborted = true;
      break;
    }
    input.onProgress?.(index, input.batches.length, `reading batch ${index + 1} of ${input.batches.length}`);
    try {
      const raw = await input.observe(input.renderBatch(input.batches[index]));
      observations.push(...sanitizeObservations(raw, input.validEventIds));
    } catch (error) {
      if (error instanceof PresidioApprovalRequired) throw error;
      if (input.signal?.aborted) {
        aborted = true;
        break;
      }
      batchesFailed++;
      input.onFailure(
        `batch ${index + 1}/${input.batches.length} produced no usable observations — ${(error as Error).message}`,
      );
    }
    await saveCheckpoint(input, index + 1, observations, batchesFailed);
    if (input.signal?.aborted) {
      aborted = true;
      break;
    }
  }

  for (let round = 0; !aborted && round < MAX_CONDENSE_ROUNDS; round++) {
    const plan = planCondenseRounds(observations, input.digestBudget, OBSERVATION_CAP_PER_BATCH * 2);
    if (!plan.length) break;
    input.onProgress?.(
      input.batches.length,
      input.batches.length,
      `condensing ${observations.length} observations (round ${round + 1})`,
    );
    const condensed: Observation[] = [];
    for (const group of plan) {
      if (input.signal?.aborted) {
        aborted = true;
        break;
      }
      try {
        const raw = await input.observe(renderObservationDigest(group));
        condensed.push(...sanitizeObservations(raw, input.validEventIds));
      } catch (error) {
        if (error instanceof PresidioApprovalRequired) throw error;
        if (input.signal?.aborted) {
          aborted = true;
          break;
        }
        condensed.push(...group);
        batchesFailed++;
        input.onFailure(`a condense group failed, keeping it uncondensed — ${(error as Error).message}`);
      }
    }
    if (!aborted) {
      observations = condensed;
      await saveCheckpoint(input, input.batches.length, observations, batchesFailed);
    }
  }

  return { observations, batchesFailed, aborted };
}
