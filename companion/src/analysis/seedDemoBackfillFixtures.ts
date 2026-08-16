// The one uncovered event and the two deterministic backfill findings that let the demo case
// demonstrate the Findings panel's origin lenses ("Hide auto-flagged" / "Hide coverage-gap") — see
// seedDemoCase.ts, which appends demoBackfillEvent to forensicTimeline and demoBackfillFindings to
// findings via .concat() (not a spread inside the array literal — prettier always re-expands a
// spread onto its own line, and this file's own length is exactly why that line doesn't fit).
//
// Split into its own module rather than growing seedDemoCase.ts: that file is frozen at its
// current length by scripts/file-size-ledger.json (scripts/check-file-size.mjs), and the gate's
// own guidance for exactly this situation — new content that would push a ledgered file over its
// cap — is to move it into its own module rather than raise the ledger.
//
// `satisfies`, not `:` — an explicit `ForensicEvent`/`Finding[]` annotation here would WIDEN this
// value's own type to the interface (e.g. Finding.confidence turns optional), and .concat() then
// rejects it against seedDemoCase.ts's own array literals, whose element type TypeScript infers
// narrowly from ~50 untyped object literals it was never worth annotating. `satisfies` checks
// against the interface without widening, keeping this value structurally compatible with that
// inferred type. (demoBackfillEvent also omits `path`, present on some sibling events, for the same
// reason: forensicTimeline's inferred type is a union of ~23 field-combinations from those literals,
// and only some include `path`+`sha256` together — the description states the path in prose instead.)
//
// Timestamps are written as literal ISO strings rather than importing seedDemoCase.ts's local
// ts(day, h, m, s) helper, so this file has no dependency on seedDemoCase.ts (a dependency the
// other direction — seedDemoCase.ts importing from here — already exists, and a cycle between the
// two would be exactly what scripts/check-imports.mjs exists to catch). Each literal is annotated
// with the equivalent ts(...) call for readability against seedDemoCase.ts's own convention.
import type { ForensicEvent, Finding } from "./stateTypes.js";

// e044: deliberately UNCOVERED — every event in seedDemoCase.ts's forensicTimeline already carries
// a relatedFindingIds tie, so there was nothing for highSeverityFindings.ts's deterministic
// backfill to promote. A signature-based AV hit that never made it into the AI's synthesis
// narrative is a realistic way for that to happen (the tool logs it; nobody links it). Timed
// minutes before the closing THOR sweep (e031, ts(22, 8, 0) in seedDemoCase.ts) rather than inside
// an existing quiet stretch, so it doesn't manufacture a second timeline gap alongside the one
// e043→e019 already bounds, and stays before synthesis's anchor time (e031's timestamp, which
// every finding's lastUpdated matches) so firstSeen never lands after a finding's own lastUpdated.
// Gives the backfill a genuine Critical/High orphan to turn into f-auto-e044 below, instead of the
// seed cheating by inventing an unlinked finding outright.
export const demoBackfillEvent = {
  id: "e044",
  timestamp: "2026-05-22T07:45:00.000Z", // ts(22, 7, 45)
  severity: "High",
  mitreTechniques: ["T1505.003"],
  relatedFindingIds: ["f-auto-e044"],
  sourceScreenshots: [],
  asset: "WEB01",
  sources: ["Microsoft Defender for Endpoint"],
  description:
    "Microsoft Defender flagged a leftover web shell on WEB01 during a scheduled scan. The file (C:\\Tomcat9\\webapps\\ROOT\\shell.aspx, ASPXSpy variant, detection name Trojan:MSIL/ASPXSpy.A) predates the Log4Shell callback and was never submitted to CrowdStrike or Suricata for cross-tool correlation.",
} satisfies ForensicEvent;

// f-auto-e044 and f-gap-e043-e019 are the two deterministic BACKFILL findings (issue: the demo
// case had none, so the Findings panel's origin-lens checkboxes — "Hide auto-flagged" / "Hide
// coverage-gap" — had nothing to hide and the e2e suite could only prove the controls exist,
// never that a row actually disappears). Every finding in seedDemoCase.ts's own findings array
// came from AI synthesis; these two did not. They are written to match exactly what their real
// generators would emit for the event(s) above — highSeverityFindings.ts's
// backfillHighSeverityFindings for e044 (id derivation, confidence 100, the single-source
// confidenceReason wording, the shortTitle-derived title, the " (auto-flagged from a …"
// description suffix) and gapDetect.ts's backfillSilenceGapFindings for the silent stretch
// between e043 and e019 (id derivation, confidence 50, the "Timeline coverage gap: …" title, the
// GAP_CAVEAT wording, and T1070). The relatedFindingIds back-links this produces — e044 above, and
// e043/e019 in seedDemoCase.ts — are load-bearing: without them the dashboard's client-side scope
// projection can never prove a backfill finding out of scope, so it would survive every scope
// change until the next AI re-synthesis no matter how far outside the analyst's chosen window it
// falls.
export const demoBackfillFindings = [
  {
    id: "f-auto-e044",
    severity: "High",
    confidence: 100,
    confidenceReason:
      "Deterministic backfill of an uncovered High event — a graded artifact row is treated as a confirmed finding.",
    title: "Microsoft Defender flagged a leftover web shell on WEB01 during a scheduled scan.",
    description:
      "Microsoft Defender flagged a leftover web shell on WEB01 during a scheduled scan. The file (C:\\Tomcat9\\webapps\\ROOT\\shell.aspx, ASPXSpy variant, detection name Trojan:MSIL/ASPXSpy.A) predates the Log4Shell callback and was never submitted to CrowdStrike or Suricata for cross-tool correlation. (auto-flagged from a High-severity artifact row that had no finding).",
    relatedIocs: [],
    mitreTechniques: ["T1505.003"],
    sourceScreenshots: [],
    firstSeen: "2026-05-22T07:45:00.000Z", // ts(22, 7, 45)
    lastUpdated: "2026-05-22T08:00:00.000Z", // ts(22, 8, 0)
    status: "open",
  },
  {
    id: "f-gap-e043-e019",
    severity: "High",
    confidence: 50,
    title: "Timeline coverage gap: 16h 2m of complete silence from 2026-05-16T10:13:00.000Z",
    description:
      "No forensic activity was recorded from 2026-05-16T10:13:00.000Z to 2026-05-17T02:15:00.000Z (16h 2m) — every source went silent (Chainsaw, CrowdStrike Falcon, Microsoft Defender for Endpoint, SIEM, Suricata, THOR, Velociraptor). A complete coverage gap is a classic indicator of log tampering (cleared Windows Event Logs, a stopped collector/auditd, or deleted log files) or a collection blindspot. A coverage gap is a lead, not proof of tampering — an analyst may have collected logs for a limited window, or activity genuinely paused. A gap where EVERY source went silent is the classic signature of cleared logs or a stopped collector; confirm against the collection scope and host clocks before concluding.",
    relatedIocs: [],
    mitreTechniques: ["T1070"],
    sourceScreenshots: [],
    firstSeen: "2026-05-16T10:13:00.000Z", // ts(16, 10, 13)
    lastUpdated: "2026-05-22T08:00:00.000Z", // ts(22, 8, 0)
    status: "open",
  },
] satisfies Finding[];
