import type { ForensicEvent, TimelineEntry } from "./stateTypes.js";

/** Continue the stable `<import-prefix>eN` sequence after batches committed before a restart. */
export function lastImportEventSequence(events: readonly ForensicEvent[], idPrefix: string): number {
  const prefix = `${idPrefix}e`;
  let highest = 0;
  for (const event of events) {
    if (!event.id.startsWith(prefix)) continue;
    const sequence = Number(event.id.slice(prefix.length));
    if (Number.isInteger(sequence) && sequence > highest) highest = sequence;
  }
  return highest;
}

/** Recover a batch committed just before a crash even if its ledger checkpoint did not flush. */
export function lastCommittedImportBatch(timeline: readonly TimelineEntry[], label: string): number {
  let highest = 0;
  for (const entry of timeline) {
    if (!entry.sourceScreenshots.includes(label) || entry.windowSequence >= 0) continue;
    highest = Math.max(highest, -entry.windowSequence);
  }
  return highest;
}
