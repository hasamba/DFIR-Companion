import type { Logger } from "../../logging/logger.js";
import type { AnonControlStore } from "../anonControl.js";
import type { CustomEntitiesStore } from "../anonEntities.js";
import type { DiscoveredEntitiesStore } from "../anonDiscovered.js";
import type { AiCostStore } from "../aiCost.js";
import type { OcrRunner } from "../ocrRedact.js";
import type { OperationalMetricsStore } from "../operationalMetrics.js";
import type { PresidioClient } from "../presidio.js";
import type { PresidioPendingStore } from "../presidioPending.js";
import type { AiAuthoredTextStore } from "../aiAuthoredText.js";
import type { SafetyStopCapture } from "./safetyStopCapture.js";

/**
 * Names the case anonymizer cannot derive from state, masked on every AI call on the case: the raw-only
 * hosts and accounts Watson's super-timeline searches showed (watson/rosterNames.ts, final review H3).
 */
export interface RawNamesSource {
  load(caseId: string): Promise<{ readonly hosts: readonly string[]; readonly usernames: readonly string[] }>;
}

/** What the gate needs. Deliberately no state store, no providers list, no synthesis knobs. */
export interface ProviderCallContext {
  readonly log: Logger;
  readonly opts: {
    anonStore?: AnonControlStore;
    customEntitiesStore?: CustomEntitiesStore;
    discoveredStore?: DiscoveredEntitiesStore;
    /** Watson's masking roster (H3). Absent → only state-derived, custom and discovered entities. */
    rawNamesStore?: RawNamesSource;
    ocrRunner?: OcrRunner;
    presidio?: { client: PresidioClient; url: string; minScore: number };
    presidioPendingStore?: PresidioPendingStore;
    /** Text the synthesis model wrote, which the gate skips. Absent → the gate skips nothing. */
    aiAuthoredStore?: AiAuthoredTextStore;
    presidioScanCapsOverride?: { chunkChars: number; maxChars: number };
    aiCostStore?: AiCostStore;
    operationalMetrics?: OperationalMetricsStore;
    /** DFIR_AI_CAPTURE_SAFETY_STOPS (#2083): absent → a safety-stopped prompt is never saved. */
    safetyStopCapture?: SafetyStopCapture;
  };
}
