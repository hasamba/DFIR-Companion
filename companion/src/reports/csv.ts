import type { InvestigationState } from "../analysis/stateTypes.js";
import { byEventTime } from "../analysis/forensicSort.js";
import { deriveIocSources } from "../analysis/iocCorroboration.js";
import { scoreIocsFromState } from "../analysis/iocRiskScore.js";
import type { GeoMapData } from "../analysis/geoMap.js";

function cell(value: string): string {
  const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${guarded.replace(/"/g, '""')}"`;
}
function row(values: string[]): string {
  return values.map(cell).join(",");
}

export function findingsCsv(state: InvestigationState): string {
  const header = "id,severity,confidence,title,description,relatedIocs,mitreTechniques,sourceScreenshots,firstSeen,lastUpdated,status";
  const rows = state.findings.map((f) => row([
    f.id, f.severity, f.confidence !== undefined ? String(f.confidence) : "",
    f.title, f.description,
    f.relatedIocs.join("|"), f.mitreTechniques.join("|"), f.sourceScreenshots.join("|"),
    f.firstSeen, f.lastUpdated, f.status,
  ]));
  return [header, ...rows].join("\n") + "\n";
}

export function iocsCsv(state: InvestigationState): string {
  const header = "id,type,value,firstSeen,sources,sourceCount,enrichment,riskScore,riskFactors";
  const iocSrc = deriveIocSources(state.iocs, state.forensicTimeline);
  const risk = scoreIocsFromState(state);   // #63 composite risk (verdict + severity + corroboration)
  const rows = state.iocs.map((i) => {
    const intel = (i.enrichments ?? [])
      .map((e) => `${e.source}:${e.verdict}${e.score ? ` (${e.score})` : ""}`)
      .join(" | ");
    const src = iocSrc[i.id] ?? [];
    const r = risk[i.id];
    return row([i.id, i.type, i.value, i.firstSeen, src.join("|"), String(src.length), intel, r?.score ?? "", (r?.factors ?? []).join(" | ")]);
  });
  return [header, ...rows].join("\n") + "\n";
}

export function timelineCsv(state: InvestigationState): string {
  const header = "timestamp,windowSequence,description,sourceScreenshots";
  const rows = state.timeline.map((t) => row([
    t.timestamp, String(t.windowSequence), t.description, t.sourceScreenshots.join("|"),
  ]));
  return [header, ...rows].join("\n") + "\n";
}

// Forensic timeline: real incident events sorted by their true time — the
// chronological attack story, suitable for a master-timeline export.
export function forensicTimelineCsv(state: InvestigationState): string {
  const header = "timestamp,endTimestamp,count,severity,description,mitreTechniques,sources,relatedFindingIds,sourceScreenshots";
  const rows = [...state.forensicTimeline].sort(byEventTime).map((e) => row([
    e.timestamp, e.endTimestamp ?? "", String(e.count ?? 1), e.severity, e.description,
    e.mitreTechniques.join("|"), (e.sources ?? []).join("|"), e.relatedFindingIds.join("|"), e.sourceScreenshots.join("|"),
  ]));
  return [header, ...rows].join("\n") + "\n";
}

// IP + geolocation export for the Geographic map panel (#133) — for external OSINT tooling.
export function geoMapCsv(data: GeoMapData): string {
  const header = "ip,country,city,lat,lon,asn,severity,verdict,internal,eventCount,approximate";
  const rows = data.markers.map((m) =>
    row([
      m.ip, m.country ?? "", m.city ?? "", String(m.lat), String(m.lon), m.asn ?? "",
      m.severity, m.verdict ?? "", m.internal ? "yes" : "no", String(m.eventCount),
      m.approximate ? "yes" : "no",
    ]),
  );
  return [header, ...rows].join("\n") + "\n";
}
