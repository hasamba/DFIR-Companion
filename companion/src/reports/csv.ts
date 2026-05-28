import type { InvestigationState } from "../analysis/stateTypes.js";

function cell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}
function row(values: string[]): string {
  return values.map(cell).join(",");
}

export function findingsCsv(state: InvestigationState): string {
  const header = "id,severity,title,description,relatedIocs,mitreTechniques,sourceScreenshots,firstSeen,lastUpdated,status";
  const rows = state.findings.map((f) => row([
    f.id, f.severity, f.title, f.description,
    f.relatedIocs.join("|"), f.mitreTechniques.join("|"), f.sourceScreenshots.join("|"),
    f.firstSeen, f.lastUpdated, f.status,
  ]));
  return [header, ...rows].join("\n") + "\n";
}

export function iocsCsv(state: InvestigationState): string {
  const header = "id,type,value,firstSeen";
  const rows = state.iocs.map((i) => row([i.id, i.type, i.value, i.firstSeen]));
  return [header, ...rows].join("\n") + "\n";
}

export function timelineCsv(state: InvestigationState): string {
  const header = "timestamp,windowSequence,description,sourceScreenshots";
  const rows = state.timeline.map((t) => row([
    t.timestamp, String(t.windowSequence), t.description, t.sourceScreenshots.join("|"),
  ]));
  return [header, ...rows].join("\n") + "\n";
}
