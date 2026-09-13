// What the two collection facts on a launchd plist SAY, and whether they raise (#933 item 8).
// Reading is in macosLaunchTarget.ts; the finding that carries these words is built in
// macosPersistRules.ts.
//
// Both facts are the collector's assertions about the host at collection time, and the words say
// so. Neither can create a finding: they raise or explain a job that is already reportable.
//
//   • # target: a file fact bound to the job's resolved absolute target. Owned by a non-root
//     account, or writable by every account, on a job configured for root → High: an
//     unprivileged write path to what root runs. Group-write is shown and not raised — who is in
//     the group was not recorded. A missing target is an observation, not a story.
//   • # launchctl: the queried domain's view. A PID is execution at collection time. A non-zero
//     last status means it ran at least once. Status 0 with no PID is ALSO the value of a job that
//     has never run, and says nothing. The domain must be one that loads this plist's scope.

import type { LaunchJob, LaunchScope } from "./macosPersistence.js";
import {
  domainFitsScope,
  readLaunchctl,
  readTargetFacts,
  shown,
  type LaunchContext,
  type ResolvedTarget,
} from "./macosLaunchTarget.js";

export interface FactWords {
  words: string;
  /** The fact is evidence that raises an already-reportable job to High. */
  raise: boolean;
}

const NONE: FactWords = { words: "", raise: false };

function insideWindow(iso: string, incident?: { start: string; end: string }): boolean {
  if (!incident) return false;
  const t = Date.parse(iso);
  const a = Date.parse(incident.start);
  const b = Date.parse(incident.end);
  return (
    Number.isFinite(t) &&
    Number.isFinite(a) &&
    Number.isFinite(b) &&
    t >= Math.min(a, b) &&
    t <= Math.max(a, b)
  );
}

/** The `# target:` header's words for this job. */
export function targetFactWords(
  value: string | undefined,
  resolved: ResolvedTarget,
  ctx: LaunchContext,
  incident?: { start: string; end: string },
): FactWords {
  if (!value) return NONE;
  const facts = readTargetFacts(value);
  if (!facts) {
    return { words: ` A target fact (${shown(value)}) names no path; not applied.`, raise: false };
  }
  if (!resolved.target) {
    return {
      words: ` A target fact was recorded for ${shown(facts.path)}, but this job names no absolute path to bind it to; not applied.`,
      raise: false,
    };
  }
  if (facts.path !== resolved.target) {
    return {
      words: ` A target fact was recorded for ${shown(facts.path)}, not this job's target; not applied.`,
      raise: false,
    };
  }
  if (facts.missing) {
    return {
      words: ` The collector found no object at ${shown(facts.path)} at collection time. As configured the job cannot launch that path; nothing here shows it ever ran.`,
      raise: false,
    };
  }

  const parts: string[] = [];
  let raise = false;
  if (facts.owner) parts.push(`owned by ${shown(facts.owner)}`);
  if (facts.mode !== undefined) {
    parts.push(`mode ${facts.mode.toString(8).padStart(4, "0")}`);
  }
  let words = ` The collector reported the program ${parts.join(", ")}.`;
  if (ctx.root && facts.owner && facts.owner !== "root") {
    words += ` It is owned by ${shown(facts.owner)}, and a file's owner can change it, so that account can change what root runs.`;
    raise = true;
  }
  if (facts.mode !== undefined) {
    if (facts.mode & 0o002) {
      words += ctx.root
        ? " It is writable by every account on the host, so any of them can change what root runs."
        : " It is writable by every account on the host.";
      raise = raise || ctx.root;
    } else if (facts.mode & 0o020) {
      words += ` It is writable by its group (${facts.group ? shown(facts.group) : "group not recorded"}); who is in that group was not recorded.`;
    }
  }
  words += " ACLs, file flags and the permissions of the parent directories were not read.";
  if (facts.mtime && insideWindow(facts.mtime, incident)) {
    words += ` The reported modification time of the program falls inside the incident window (${facts.mtime}).`;
    raise = true;
  }
  if (facts.unreadable.length) {
    words += ` Part of the target fact was not readable: ${facts.unreadable.map(shown).join(", ")}.`;
  }
  return { words, raise };
}

/** The `# launchctl:` header's words for this job. */
export function launchctlWords(value: string | undefined, job: LaunchJob, scope: LaunchScope): FactWords {
  if (!value) return NONE;
  const fact = readLaunchctl(value);
  if (!fact) {
    return {
      words: ` A launchctl fact (${shown(value)}) is not decodable as a launchctl list line; not applied.`,
      raise: false,
    };
  }
  if (!domainFitsScope(fact.domain, scope)) {
    return {
      words: ` The launchctl line queried ${shown(fact.domain)}, which does not load this plist; not applied.`,
      raise: false,
    };
  }
  if (!fact.loaded) {
    return {
      words: ` The job was not loaded in ${shown(fact.domain)} at collection time; says nothing about earlier boots or about any other domain.`,
      raise: false,
    };
  }
  if (fact.label !== job.label) {
    return {
      words: ` The launchctl line names ${shown(fact.label ?? "")}, not this job; not applied.`,
      raise: false,
    };
  }
  const agent = scope !== "system-daemon" && scope !== "apple-daemon" && scope !== "elsewhere";
  const others = agent ? " It may be loaded in other users' domains this line does not speak for." : "";
  if (fact.pid !== undefined) {
    return {
      words: ` The job was loaded and running at collection time (pid ${fact.pid}, domain ${shown(fact.domain)}).${others}`,
      raise: true,
    };
  }
  const status = fact.status ?? 0;
  if (status === 0) {
    return {
      words: ` The job was loaded at collection time (domain ${shown(fact.domain)}) and not running; launchctl reported last status 0 — also the value of a job that has not run yet, so this does not show a run.${others}`,
      raise: false,
    };
  }
  const ended =
    status < 0
      ? `it last ended on signal ${-status}`
      : `it has run at least once and last exited with status ${status}`;
  return {
    words: ` The job was loaded at collection time (domain ${shown(fact.domain)}) and not running; ${ended}.${others}`,
    raise: true,
  };
}
