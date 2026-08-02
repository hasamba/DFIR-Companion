/**
 * Case-state waits, built on `pollFor` (issue #408).
 *
 * `poll.ts` stays domain-free — it knows only about budgets and probes. These are the DFIR-specific
 * waits the server and pipeline tests share, and they live here so the wording of a failure is
 * written once rather than copied per file.
 *
 * Every one of them replaced a hand-rolled `for (let i = 0; i < N; i++) { read(); await sleep(25) }`
 * loop. That spelled a private sub-2s deadline, and on expiry it did not say so — it fell through to
 * the caller's assertion, so a starved CI box reported `expected 0 to be 1` and read like a pipeline
 * that produced nothing rather than a wait that ran out. An iteration count was not even a coherent
 * budget: most of each iteration was the state read, not the sleep, so the wait got SHORTER exactly
 * when the machine was slowest. The description closures below name what never happened and report
 * the counts actually observed.
 */
import type { StateStore } from "../../src/analysis/stateStore.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";
import { pollFor } from "./poll.js";

/**
 * Wait until `ready` accepts the case state, then return that state.
 *
 * Costs ONE poll budget — keep the calling test's timeout above the sum of its waits.
 */
export async function pollState(
  stateStore: StateStore,
  caseId: string,
  what: string,
  ready: (s: InvestigationState) => boolean,
): Promise<InvestigationState> {
  let last: InvestigationState | undefined;
  return pollFor(
    () =>
      `${what} — last saw ${last?.forensicTimeline.length ?? 0} event(s), ` +
      `${last?.findings.length ?? 0} finding(s), ${last?.iocs.length ?? 0} IOC(s)`,
    async () => {
      last = await stateStore.load(caseId);
      return ready(last) ? last : undefined;
    },
  );
}

/** Wait for the background analysis (extraction → synthesis) to produce a finding. */
export function pollForFinding(stateStore: StateStore, caseId: string): Promise<InvestigationState> {
  return pollState(
    stateStore,
    caseId,
    "the background analysis to produce a finding",
    (s) => s.findings.length > 0,
  );
}

/**
 * Wait for a background import to land at least `atLeast` forensic events.
 *
 * Pass the count the test actually asserts on. Polling for "any event" and then asserting a count
 * reintroduces the bug this helper exists to remove: the second event merely landing late reports
 * as `expected 1 to be 2`.
 */
export function pollForForensicEvents(
  stateStore: StateStore,
  caseId: string,
  atLeast = 1,
): Promise<InvestigationState> {
  return pollState(
    stateStore,
    caseId,
    `the background import to land ${atLeast} forensic event(s)`,
    (s) => s.forensicTimeline.length >= atLeast,
  );
}

/** As `pollForForensicEvents`, but returns the event count for tests that assert on it directly. */
export async function waitForEvents(stateStore: StateStore, caseId: string, atLeast = 1): Promise<number> {
  return (await pollForForensicEvents(stateStore, caseId, atLeast)).forensicTimeline.length;
}

/** Wait for background enrichment to annotate the case's first IOC. */
export function pollForFirstIocEnrichment(
  stateStore: StateStore,
  caseId: string,
): Promise<InvestigationState> {
  return pollState(stateStore, caseId, "the background enrichment to annotate the first IOC", (s) =>
    Boolean(s.iocs[0]?.enrichments),
  );
}
