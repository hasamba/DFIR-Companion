import type { Finding, ForensicEvent, NextStep } from "../../stateTypes.js";
import { WATSON_FINDING_ID_PREFIX } from "../../responseSchema.js";
import type {
  WatsonFindingDraft,
  WatsonStepDraft,
  WatsonStepUpdateDraft,
  WatsonWrites,
} from "./writesSchema.js";
import { pasteLineKey, type WatsonWriteInputs } from "./roundWrites.js";
import type { WatsonFindingProposal, WatsonProposal } from "./types.js";
import { pasteLineEvent } from "./writers/pasteLineEvents.js";
import { sameStep } from "./writers/nextStepUpdateWriter.js";

// A reply's sanitized writes as PENDING proposals. Pure: everything read from disk arrives in
// `inputs`. A finding's paste-line events are built now, so the analyst sees the exact rows that will
// land; a finding left with no citation once the lines are read is not proposed. Watson's ids are
// fixed here: findings `f-watson-<8 hex>`, next steps `ns-watson-<8 hex>`. Report text is model text
// that report.md renders raw, so it is neutralised here (the injected blockMd: no heading, fence or
// raw-HTML block can open), and the card, the stored text and undo's comparison all see that string.

type NewId = (prefix: string) => string;

/** D9b: an item's rawEvidenceIds by its position in the reply (rawReferences.ts `refKey`). */
export type WatsonRawEvidenceMap = ReadonlyMap<string, readonly string[]>;

/** `{ rawEvidenceIds }` for the item at `kind:index`, or nothing when it rests on no promoted row. */
export function evidenceFor(
  evidence: WatsonRawEvidenceMap | undefined,
  kind: string,
  index: number,
): { rawEvidenceIds?: string[] } {
  const ids = evidence?.get(`${kind}:${index}`);
  return ids?.length ? { rawEvidenceIds: [...ids] } : {};
}

function findingProposal(
  d: WatsonFindingDraft,
  inputs: WatsonWriteInputs,
  turnId: string,
  newId: NewId,
  now: string,
): WatsonFindingProposal | null {
  const before = d.updateId ? inputs.findings.get(d.updateId) : undefined;
  // The Watson finding the update names is gone by now: drop the draft, never mint a new finding.
  if (d.updateId && !before) return null;
  // newId adds the "-": the prefix comes from the finding-id register (responseSchema.ts).
  const id = before?.id ?? newId(WATSON_FINDING_ID_PREFIX.slice(0, -1));
  const pasteEvents: ForensicEvent[] = [];
  const citedPasteLines = d.pasteLines.filter(({ pasteId, line }) => {
    const paste = inputs.pastes.get(pasteId);
    const text = inputs.lines.get(pasteLineKey(pasteId, line));
    if (!paste || text === undefined) return false;
    pasteEvents.push(pasteLineEvent(paste, line, text, d.severity, id, now));
    return true;
  });
  if (!d.eventIds.length && !pasteEvents.length) return null;
  const drafted = {
    severity: d.severity,
    title: d.title,
    description: d.description,
    mitreTechniques: d.mitreTechniques,
    relatedEventIds: [...d.eventIds, ...pasteEvents.map((e) => e.id)],
    lastUpdated: now,
    author: "watson" as const,
  };
  const { citedPasteLines: _old, ...base } = before ?? {
    id,
    relatedIocs: [],
    sourceScreenshots: [],
    firstSeen: now,
    status: "open" as const,
  };
  const after: Finding = {
    ...base,
    ...drafted,
    id,
    ...(citedPasteLines.length ? { citedPasteLines } : {}),
  };
  return {
    id: newId("wp"),
    turnId,
    kind: before ? "finding_update" : "finding_new",
    targetId: id,
    ...(before ? { before } : {}),
    after,
    pasteLineEvents: pasteEvents,
    status: "pending",
  };
}

function stepProposal(s: WatsonStepDraft, turnId: string, newId: NewId): WatsonProposal {
  const id = newId("ns-watson");
  const after: NextStep = { id, ...s, author: "watson" };
  return { id: newId("wp"), turnId, kind: "next_step_new", targetId: id, after, status: "pending" };
}

/** A step change for a step in the case now; none when it changes nothing. `before` is the step as read. */
function stepUpdateProposal(
  u: WatsonStepUpdateDraft,
  inputs: WatsonWriteInputs,
  turnId: string,
  newId: NewId,
): WatsonProposal | null {
  const found = inputs.steps?.get(u.stepId);
  if (!found) return null;
  const { step, index } = found;
  // Someone edited the step while Watson thought: its decision was about the old step (Codex review).
  if (u.seen && !sameStep(step, u.seen)) return null;
  if (!u.done && (!u.priority || u.priority === step.priority)) return null;
  const after = u.done ? null : { ...step, priority: u.priority! };
  return {
    id: newId("wp"),
    turnId,
    kind: "next_step_update",
    targetId: step.id,
    before: step,
    after,
    why: u.why,
    index,
    status: "pending",
  };
}

/** One proposal per report field whose neutralised text differs from the report's text now. */
function reportProposals(
  writes: WatsonWrites,
  inputs: WatsonWriteInputs,
  turnId: string,
  newId: NewId,
  evidence: WatsonRawEvidenceMap | undefined,
): WatsonProposal[] {
  const { report: current, reportBlockText: safe } = inputs;
  if (!current || !safe) return [];
  return writes.report.flatMap((r, index): WatsonProposal[] => {
    const after = safe(r.text);
    if (after === current[r.field]) return [];
    const before = current[r.field];
    return [
      {
        id: newId("wp"),
        turnId,
        kind: "report_text",
        targetId: r.field,
        field: r.field,
        before,
        after,
        status: "pending",
        ...evidenceFor(evidence, "report", index),
      },
    ];
  });
}

/** `p` with the rawEvidenceIds of the reply item it was built from (D9b), by the item's own index. */
const stamped = <P extends WatsonProposal>(
  p: P,
  ev: WatsonRawEvidenceMap | undefined,
  kind: string,
  i: number,
): P => ({
  ...p,
  ...evidenceFor(ev, kind, i),
});

export function buildWriteProposals(
  writes: WatsonWrites,
  inputs: WatsonWriteInputs | undefined,
  turnId: string,
  newId: NewId,
  evidence?: WatsonRawEvidenceMap,
): WatsonProposal[] {
  if (!inputs) return [];
  const now = new Date().toISOString();
  const findings = writes.findings.flatMap((d, i) => {
    const p = findingProposal(d, inputs, turnId, newId, now);
    return p ? [stamped(p, evidence, "finding", i)] : [];
  });
  const steps = writes.nextSteps.map((s, i) =>
    stamped(stepProposal(s, turnId, newId), evidence, "nextStep", i),
  );
  const updates = (writes.stepUpdates ?? []).flatMap((u, i) => {
    const p = stepUpdateProposal(u, inputs, turnId, newId);
    return p ? [stamped(p, evidence, "stepUpdate", i)] : [];
  });
  return [...findings, ...steps, ...updates, ...reportProposals(writes, inputs, turnId, newId, evidence)];
}
