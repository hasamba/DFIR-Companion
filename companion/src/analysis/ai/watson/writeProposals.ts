import type { Finding, ForensicEvent, NextStep } from "../../stateTypes.js";
import type { WatsonFindingDraft, WatsonStepDraft, WatsonWrites } from "./writesSchema.js";
import { pasteLineKey, type WatsonWriteInputs } from "./roundWrites.js";
import type { WatsonFindingProposal, WatsonProposal } from "./types.js";
import { pasteLineEvent } from "./writers/pasteLineEvents.js";

// A reply's sanitized writes as PENDING proposals. Pure: everything read from disk arrives in
// `inputs`. A finding's paste-line events are built now, so the analyst sees the exact rows that will
// land; a finding left with no citation once the lines are read is not proposed. Watson's ids are
// fixed here: findings `f-watson-<8 hex>`, next steps `ns-watson-<8 hex>`. Report text is model text
// that report.md renders raw, so it is neutralised here (the injected blockMd: no heading, fence or
// raw-HTML block can open), and the card, the stored text and undo's comparison all see that string.

type NewId = (prefix: string) => string;

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
  const id = before?.id ?? newId("f-watson");
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

/** One proposal per report field whose neutralised text differs from the report's text now. */
function reportProposals(
  writes: WatsonWrites,
  inputs: WatsonWriteInputs,
  turnId: string,
  newId: NewId,
): WatsonProposal[] {
  const { report: current, reportBlockText: safe } = inputs;
  if (!current || !safe) return [];
  return writes.report.flatMap((r): WatsonProposal[] => {
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
      },
    ];
  });
}

export function buildWriteProposals(
  writes: WatsonWrites,
  inputs: WatsonWriteInputs | undefined,
  turnId: string,
  newId: NewId,
): WatsonProposal[] {
  if (!inputs) return [];
  const now = new Date().toISOString();
  const findings = writes.findings.flatMap((d) => findingProposal(d, inputs, turnId, newId, now) ?? []);
  const steps = writes.nextSteps.map((s) => stepProposal(s, turnId, newId));
  return [...findings, ...steps, ...reportProposals(writes, inputs, turnId, newId)];
}
