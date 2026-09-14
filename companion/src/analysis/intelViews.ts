// The three views of an IOC's intel assertions (#933 item 19, second half — #1024), and the
// label every surface prints beside one that is not live:
//   - latest:     the newest state of each assertion from a successful check;
//   - actionable: the latest, and LIVE at the moment of use — `at` is the moment (an export, a
//                 grounding run), so a validity that ended since the last check counts as ended;
//   - lastKnown:  the newest state of each assertion whatever its status, each labelled.
// Blocklists, STIX bundles and grounding read `actionable`; reports and CSV read `lastKnown` and
// print the label. A hit stored before assertion tracking is `legacy-unverified`: last-known,
// labelled, never actionable until re-checked.

import type { IOC, IocEnrichment, IntelAssertionStatus } from "./stateTypes.js";

const lower = (s: string): string => s.trim().toLowerCase();

/** A stored hit with no tracking reads as legacy; the identity is (owner, source, record id | value). */
function identified(
  e: IocEnrichment,
  iocValue: string,
): IocEnrichment & { assertionId: string; status: IntelAssertionStatus } {
  const owner = e.provider ?? e.source;
  const record = e.providerRecordId?.trim() || `value:${lower(iocValue)}`;
  return {
    ...e,
    assertionId: e.assertionId ?? `legacy:${lower(owner)}|${lower(e.source)}|${record}`,
    status: e.status ?? "legacy-unverified",
  };
}

/** The status of an assertion at `at`: a validity that has ended since the check ends it now. */
export function statusAt(e: IocEnrichment, at: string): IntelAssertionStatus {
  const stored = e.status ?? "legacy-unverified";
  if (stored !== "live") return stored;
  const until = e.validity?.until;
  if (until && Number.isFinite(Date.parse(until)) && Date.parse(until) <= Date.parse(at)) return "expired";
  return "live";
}

/** The newest state per assertion id, whatever its status. */
export function lastKnownAssertions(
  ioc: IOC,
): Array<IocEnrichment & { assertionId: string; status: IntelAssertionStatus }> {
  const byId = new Map<string, IocEnrichment & { assertionId: string; status: IntelAssertionStatus }>();
  for (const e of (ioc.enrichments ?? []).map((x) => identified(x, ioc.value))) {
    const cur = byId.get(e.assertionId);
    if (!cur || e.fetchedAt > cur.fetchedAt) byId.set(e.assertionId, e);
  }
  return [...byId.values()];
}

/** The newest state per assertion from a successful check (not errored, not legacy). */
export function latestAssertions(
  ioc: IOC,
): Array<IocEnrichment & { assertionId: string; status: IntelAssertionStatus }> {
  return lastKnownAssertions(ioc).filter(
    (e) => e.status !== "errored-last-known" && e.status !== "legacy-unverified",
  );
}

/** The assertions a consumer may ACT on at `at`: live now — not expired, revoked, not-returned, errored or legacy. */
export function actionableAssertions(
  ioc: IOC,
  at: string = new Date().toISOString(),
): Array<IocEnrichment & { assertionId: string; status: IntelAssertionStatus }> {
  return lastKnownAssertions(ioc).filter((e) => statusAt(e, at) === "live");
}

/** The label a report prints beside a non-live assertion; "" for a live one. */
export function assertionLabel(e: IocEnrichment, at: string = new Date().toISOString()): string {
  const status = statusAt(e, at);
  switch (status) {
    case "live":
      return "";
    case "expired":
      return `validity ended ${(e.validity?.until ?? "").slice(0, 10)}${caseTimeWords(e.validity?.until, at)}; kept as history`;
    case "revoked":
      return "revoked by the provider; kept as history";
    case "not-returned":
      return `not returned on the check at ${(e.lastMissAt ?? "").slice(0, 19)}; kept as history — a miss is not a withdrawal`;
    case "errored-last-known":
      return "last known; the provider errored on the last check";
    case "legacy-unverified":
      return "recorded before assertion tracking; re-check to make it actionable";
    case "superseded":
      return "superseded";
  }
}

function caseTimeWords(until: string | undefined, at: string): string {
  if (!until || !Number.isFinite(Date.parse(until)) || !Number.isFinite(Date.parse(at))) return "";
  return Date.parse(until) <= Date.parse(at) ? " (before now)" : " (after now)";
}

/** True when the IOC carries at least one actionable assertion with a malicious or suspicious verdict. */
export function hasActionableIntel(ioc: IOC, at?: string): boolean {
  return actionableAssertions(ioc, at).some((e) => e.verdict === "malicious" || e.verdict === "suspicious");
}
