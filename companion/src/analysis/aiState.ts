import type { CustomEntity } from "./anonymize.js";
import type { NearDuplicate } from "./hostAlias.js";
import type { Job } from "./jobRegistry.js";

/**
 * What a case's AI is ACTUALLY doing, derived from state the server already holds.
 *
 * WHY THIS EXISTS. `ai_status` is pushed from 155 call sites over a websocket and the dashboard's
 * header pill is its only consumer, so the pill's state lived exclusively in that event stream.
 * Nothing ever reconciled it with the case. Every other surface — the Now cockpit, the gate chips —
 * derives from the server and self-corrects on load; the pill could not, and three separate bugs
 * came out of that one gap:
 *
 *   1. it announced "synthesizing" for a run the merge gate would refuse   (#577, wrong event)
 *   2. it stayed "on hold" after the last Presidio approval cleared        (#579, absent event)
 *   3. it said "ready (waiting for activity)" after a reload on a held case
 *
 * The third is the plainest statement of the problem: the pill's initial state came from `/health`,
 * which is server-wide and cannot know anything about a case. Pressing F5 on a held case produced a
 * pill reading "ready" beside a cockpit reading "on hold".
 *
 * So this is the correction, not a replacement. Pushed events remain the fast path for live progress
 * (they carry per-file import counts this derivation cannot know); the derived read is what the
 * client falls back to whenever it needs the truth rather than the latest rumour.
 *
 * PURE, like deriveCockpit: the caller supplies the facts. The route composes the stores.
 */

export type AiStateKind = "off" | "idle" | "analyzing" | "blocked" | "error";

/** A gate holding synthesis. `count` is how many decisions are outstanding. */
export interface AiHold {
  kind: "host-duplicates" | "presidio";
  count: number;
  detail: string;
}

export interface AiState {
  state: AiStateKind;
  detail: string;
  /**
   * Gates holding synthesis — reported ALONGSIDE `state`, not instead of it.
   *
   * A job can be genuinely running while a gate is pending: an import proceeds even though
   * synthesis is held. Collapsing that to "blocked" would hide real work, which is bug #1 in
   * reverse. So `state` says what is happening and `holds` says what cannot happen, and the pill
   * can render "importing… (analysis on hold)" from the two together.
   */
  holds: AiHold[];
  /** Work in flight right now, so the pill can name it rather than guess. */
  running: { kind: string; label: string }[];
  /**
   * Is the per-case live-analysis toggle off?
   *
   * A REPORTED FACT, NOT A STATE, and the distinction is load-bearing. `AiControl.enabled` gates the
   * LIVE screenshot loop only — manual re-synthesis, second opinion, deep pass and imports all run
   * with it off (see analysis/aiControl.ts, and the note in composition/captureAnalysis.ts about
   * routes that must set their own phase because of exactly this). It also defaults to false, so
   * folding it into "off" would report every fresh case as switched off, and would report a case
   * genuinely held at a gate as merely paused — hiding the decision the analyst has to make.
   */
  livePaused: boolean;
}

export interface AiStateInput {
  /** Is any model configured at all (server-wide). */
  aiConfigured: boolean;
  /** The per-case LIVE-analysis toggle. See `AiState.livePaused` — this is not "AI is off". */
  enabled: boolean;
  hostDuplicates?: readonly NearDuplicate[];
  presidioPending?: readonly CustomEntity[];
  jobs?: readonly Job[];
}

const ACTIVE: readonly Job["status"][] = ["running", "queued"];
const BROKEN: readonly Job["status"][] = ["failed", "interrupted"];

function holdsOf(input: AiStateInput): AiHold[] {
  const holds: AiHold[] = [];
  const dupes = input.hostDuplicates ?? [];
  if (dupes.length > 0) {
    holds.push({
      kind: "host-duplicates",
      count: dupes.length,
      // Same wording as HostMergeDecisionRequired's message, so the pill, the cockpit card and the
      // route's 409 all say the same thing about the same hold.
      detail: `${dupes.length} possible duplicate host${dupes.length === 1 ? "" : "s"} awaiting a merge decision`,
    });
  }
  const presidio = input.presidioPending ?? [];
  if (presidio.length > 0) {
    holds.push({
      kind: "presidio",
      count: presidio.length,
      detail: `${presidio.length} Presidio finding${presidio.length === 1 ? "" : "s"} awaiting approval`,
    });
  }
  return holds;
}

/**
 * The most recently ENDED job, or undefined when none has ended.
 *
 * Used to decide whether the resting state is an error. Deliberately the latest one rather than
 * "any failure present": a synthesis that failed an hour ago, followed by a successful import,
 * must not leave the pill red forever — the cockpit's activity cards are where run history belongs.
 */
function lastEnded(jobs: readonly Job[]): Job | undefined {
  return jobs
    .filter((job) => job.endedAt)
    .sort((a, b) => String(a.endedAt).localeCompare(String(b.endedAt)))
    .pop();
}

export function deriveAiState(input: AiStateInput): AiState {
  const holds = holdsOf(input);
  const jobs = input.jobs ?? [];
  const active = jobs.filter((job) => ACTIVE.includes(job.status));
  const running = active.map((job) => ({ kind: job.kind, label: job.label ?? job.kind }));

  const livePaused = !input.enabled;
  const common = { holds, running, livePaused };

  // "Off" means nothing can run AT ALL, which is only true with no model configured. The per-case
  // toggle is deliberately NOT here — see AiState.livePaused.
  if (!input.aiConfigured) {
    return { state: "off", detail: "no AI model configured", ...common };
  }

  // Real work in flight beats a hold: see the note on `holds`. The hold still rides along.
  if (active.length > 0) {
    const first = active[0];
    return { state: "analyzing", detail: first.label ?? `${first.kind} ${first.status}`, ...common };
  }

  // Above the failure check on purpose: a gate is a live obligation on the analyst, while the last
  // job's error is history. A case that is both held and carrying an old failure needs the decision
  // surfaced, not the post-mortem.
  if (holds.length > 0) {
    return { state: "blocked", detail: holds.map((hold) => hold.detail).join("; "), ...common };
  }

  const last = lastEnded(jobs);
  if (last && BROKEN.includes(last.status)) {
    return {
      state: "error",
      detail: last.error || last.detail || `${last.kind} ${last.status}`,
      ...common,
    };
  }

  return {
    state: "idle",
    detail: livePaused ? "up to date — live analysis paused" : "up to date",
    ...common,
  };
}
