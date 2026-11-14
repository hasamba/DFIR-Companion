import { WatsonProposalConflict } from "../proposalErrors.js";
import type { WatsonReportTextProposal } from "../types.js";
import type { WatsonReportFields, WatsonReportText, WatsonWriter, WriterDeps } from "./writerTypes.js";

// Report text Watson proposed ("Conclusions" or "Investigation limitations", never the executive
// summary — D3), applied by the analyst. The check and the write run inside the report store's one
// serialized update(), so an analyst save can never land between them. Apply writes only while the
// field still holds the text Watson saw; undo restores it only while the field holds Watson's text.
// It touches no case state, so it takes no state lock (self-locking).

const LABEL: Record<WatsonReportTextProposal["field"], string> = {
  conclusions: "Conclusions",
  investigationLimitations: "Investigation limitations",
};

function store(deps: WriterDeps): WatsonReportText {
  if (!deps.reportText) throw new WatsonProposalConflict("Report details are not available on this server");
  return deps.reportText;
}

const changed = (p: WatsonReportTextProposal): WatsonProposalConflict =>
  new WatsonProposalConflict(`${LABEL[p.field]} changed since this proposal; nothing was written`);

function withoutMark(m: WatsonReportFields, p: WatsonReportTextProposal): WatsonReportFields["watsonFields"] {
  const { [p.field]: mark, ...rest } = m.watsonFields ?? {};
  return mark && mark.proposalId !== p.id ? m.watsonFields : rest;
}

async function apply(deps: WriterDeps, caseId: string, p: WatsonReportTextProposal) {
  const at = new Date().toISOString();
  await store(deps).update(caseId, (m) => {
    if (m[p.field] !== p.before) throw changed(p);
    return {
      ...m,
      [p.field]: p.after,
      watsonFields: { ...m.watsonFields, [p.field]: { proposalId: p.id, at } },
    };
  });
  return {};
}

async function undo(deps: WriterDeps, caseId: string, p: WatsonReportTextProposal) {
  await store(deps).update(caseId, (m) => {
    if (m[p.field] !== p.after) throw changed(p);
    return { ...m, [p.field]: p.before, watsonFields: withoutMark(m, p) };
  });
  return {};
}

export const reportTextWriter: WatsonWriter<WatsonReportTextProposal> = { selfLocking: true, apply, undo };
