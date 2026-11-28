// The demo case's PsExec movement, as the TARGETS recorded it (#3085). Each target logged a network
// logon (Security 4624, logon type 3) from WKSTN-JSMITH at 10.10.10.45 right before PsExec created
// its PSEXESVC service there. Without these rows the demo's forensic timeline named the source only
// in prose (e012/e017/e018), so Evidence Chain → "Lateral movement paths" had no direction evidence
// and chained the targets onto each other (DC01 → FS01 → WEB01) through the shared PSEXESVC.exe hash.
// With them the panel shows the real fan-out: WKSTN-JSMITH → DC01, → FS01 and → WEB01.
//
// The descriptions use the exact mapWindows 4624 wording that the canonical upgrader and
// parseLoginEvent read (same shape as the super-timeline's logon rows). The account on FS01 and
// WEB01 is the domain admin the attacker took from DC01, so those two hosts also show up as
// "sharing an account" — a link, not a hop.
//
// Split out of seedDemoCase.ts, which is held at its length by scripts/file-size-ledger.json — the
// same reason, and the same `satisfies` / literal-timestamp conventions, as seedDemoBackfillFixtures.ts.
import type { ForensicEvent } from "./stateTypes.js";

const logon = (id: string, timestamp: string, host: string, account: string) =>
  ({
    id,
    timestamp,
    severity: "Low",
    mitreTechniques: ["T1021.002"],
    relatedFindingIds: ["f004"],
    sourceScreenshots: [],
    asset: host,
    sources: ["Chainsaw"],
    description: `Windows Security Successful logon (EID 4624) - ${account} - LogonType=3 - IpAddress=10.10.10.45 - WorkstationName=WKSTN-JSMITH @ ${host} [Network]`,
  }) satisfies ForensicEvent;

export const demoLateralLogons = [
  logon("e062", "2026-05-16T08:22:00.000Z", "DC01", "GLOBALTECH\\jsmith"), // ts(16, 8, 22), with e012/e013
  logon("e063", "2026-05-16T10:00:00.000Z", "FS01", "GLOBALTECH\\svc-admin"), // ts(16, 10, 0), with e017
  logon("e064", "2026-05-16T10:05:00.000Z", "WEB01", "GLOBALTECH\\svc-admin"), // ts(16, 10, 5), with e018
];
