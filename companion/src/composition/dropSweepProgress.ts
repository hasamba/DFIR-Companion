import { basename } from "node:path";
import type { ProgressStep } from "../analysis/jobRegistry.js";

/**
 * The Jobs-row count for one drop sweep (#2742). Every dropped file is one unit, except a Velociraptor
 * hunt zip: once its handler knows the plan, it counts as its result files to import, so the row reads
 * "3/40" with a speed and ETA instead of "1 file" at 0/1 until the whole zip ends.
 *
 * - A hunt zip's count is owned by its handler. The sweep's end-of-file tick never completes it, so a
 *   zip left in drop/ to resume (its progress could not be recorded) stays partial on the row.
 * - Files already handled in an earlier run (a resumed zip) count as done and as the step baseline, so
 *   the speed and ETA measure only this sweep's work. The step start is constant for the sweep, so the
 *   registry's never-count-backwards guard still holds; the total only grows.
 */

export interface HuntProgress {
  /** Result files handled (imported or failed), including those an earlier run recorded. */
  done: number;
  /** Result files this zip imports. Never 0: a zip with nothing to import never reports. */
  total: number;
  /** The result file about to import, when this update announces it. */
  current?: string;
}

export interface SweepProgressDeps {
  relpaths: readonly string[];
  startedAt: string;
  /** `step.label` is set when a hunt zip changes what the sweep holds; the row is renamed to it. */
  report: (done: number, total: number, detail: string | undefined, step: ProgressStep) => void;
}

export interface SweepProgress {
  hunt(relpath: string, p: HuntProgress): void;
  fileDone(relpath: string): void;
}

interface Unit {
  weight: number;
  done: number;
  hunt: boolean;
}

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

function sweepLabel(units: Iterable<Unit>): string {
  let hunts = 0;
  let results = 0;
  let others = 0;
  for (const u of units) {
    if (u.hunt) {
      hunts += 1;
      results += u.weight;
    } else others += 1;
  }
  if (!hunts) return `drop import (${plural(others, "file")})`;
  const what = hunts === 1 ? "hunt export" : `${hunts} hunt exports`;
  const rest = others ? ` + ${plural(others, "other file")}` : "";
  return `drop import (${what}, ${plural(results, "result file")}${rest})`;
}

export function createSweepProgress(d: SweepProgressDeps): SweepProgress {
  const units = new Map<string, Unit>(d.relpaths.map((r) => [r, { weight: 1, done: 0, hunt: false }]));
  let baseline = 0;

  const emit = (detail: string | undefined, label?: string): void => {
    let done = 0;
    let total = 0;
    for (const u of units.values()) {
      done += u.done;
      total += u.weight;
    }
    d.report(done, total, detail, {
      stepStartedAt: d.startedAt,
      stepBaseline: baseline,
      ...(label ? { label } : {}),
    });
  };

  return {
    hunt(relpath, p) {
      if (!(p.total > 0)) return;
      const before = units.get(relpath);
      const done = Math.max(0, Math.min(p.total, Math.floor(p.done)));
      let label: string | undefined;
      if (!before?.hunt) {
        units.set(relpath, { weight: p.total, done, hunt: true });
        baseline += done;
        label = sweepLabel(units.values());
      } else if (done > before.done) {
        units.set(relpath, { ...before, done });
      }
      const at = units.get(relpath)!;
      const name = basename(relpath);
      const detail = p.current
        ? `${name} — hunt file ${Math.min(at.done + 1, at.weight)} of ${at.weight}: ${p.current}`
        : `${name} — ${at.done} of ${at.weight} hunt files handled`;
      emit(detail, label);
    },
    fileDone(relpath) {
      const u = units.get(relpath);
      if (u?.hunt) return; // the hunt handler owns its count (a deferred zip stays partial)
      units.set(relpath, { weight: 1, done: 1, hunt: false });
      emit(basename(relpath));
    },
  };
}
