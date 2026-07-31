import type { JobManager, RegisteredJob } from "../analysis/jobManager.js";

export const IMPORT_JOB_PENDING_DETAIL = "evidence committed; waiting for processing";

export function createImportJobTracking(
  manager: JobManager | undefined,
  job: RegisteredJob | undefined,
  kind: string,
  reportStatus: (done: number, total: number) => void,
) {
  return {
    start: async (): Promise<void> => {
      await job?.ready;
      if (job) {
        await manager?.checkpoint(job.jobId, {
          done: 0,
          total: 1,
          detail: `${kind} import — evidence committed; processing`,
        });
      }
    },
    onProgress: async (done: number, total: number): Promise<void> => {
      reportStatus(done, total);
      if (job) {
        await manager?.checkpoint(job.jobId, {
          done,
          total,
          detail: `${kind} import — committed batch ${done}/${total}`,
        });
      }
    },
    onParseProgress: (done: number, total: number, detail = "reading Windows events"): void => {
      if (job) manager?.progress(job.jobId, done, total, detail);
    },
  };
}
