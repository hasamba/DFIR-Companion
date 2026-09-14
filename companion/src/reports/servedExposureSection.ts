import type { InvestigationState } from "../analysis/stateTypes.js";
import { servedExposure } from "../analysis/servedExposure.js";
import { cellMd } from "./mdText.js";

/**
 * "Served exposure" section (#930 item 4): per declared served location, each resource under its
 * root with the stage the case establishes — suspected exposure (a file under the root),
 * retrieval requested (an access-log request mapped to it while a version covered it), response
 * size recorded (what the server logged: a size, never a transfer), corroborated disclosure (a
 * logged size while the resource was confirmed sensitive or was the sensitive document by
 * digest). Reasons name what was read and what was not. Requests to paths with no file evidence
 * are leads. A public location's unconfirmed resources are negative controls.
 */
export function servedExposureSection(state: InvestigationState, lines: string[]): void {
  lines.push("## Served exposure", "");
  const locations = state.servedLocations ?? [];
  if (!locations.length) {
    lines.push(
      "No served location has been declared for this case — a request path is not a file path without one.",
      "",
    );
    return;
  }
  const exposure = servedExposure(state, locations);
  lines.push(
    "A file under a served root is a suspected exposure; a mapped request is a retrieval request; a logged response size is what the server said, not a transfer; disclosure is corroborated only for a resource the analyst confirmed sensitive or whose covering version is the sensitive document by digest.",
    "",
  );
  for (const e of exposure.locations) {
    const l = e.location;
    lines.push(
      `### ${cellMd(l.host)}${l.vhost ? ` (${cellMd(l.vhost)})` : ""}: ${cellMd(l.urlPrefix || "/")} ← ${cellMd(l.localRoot)}${l.public ? " — declared public" : ""}`,
      "",
    );
    if (e.gaps.length) lines.push(...e.gaps.map((g) => `- Gap: ${cellMd(g)}`));
    lines.push(
      `- Read: ${e.read.fileRows} file row(s), ${e.read.webRows} web row(s)${e.read.fileRowsUnread + e.read.webRowsUnread ? `; ${e.read.fileRowsUnread + e.read.webRowsUnread} unread` : ""}${e.read.undated ? `; ${e.read.undated} undated` : ""}; ${e.unmapped.count} request(s) not mapped${
        e.unmapped.count
          ? ` (${Object.entries(e.unmapped.reasons)
              .map(([k, v]) => `${cellMd(k)}: ${v}`)
              .join(", ")})`
          : ""
      }; coverage: ${e.coverage.map(cellMd).join(", ") || "none"}`,
    );
    if (e.resources.length) {
      lines.push(
        "",
        "| Resource | Stage | Sensitivity | Versions / observations | Requests | Reason |",
        "|---|---|---|---|---|---|",
      );
      for (const r of e.resources) {
        const versions = `${r.versions.length} version(s), ${r.observations.length} observation(s)${r.historicalLeads.length ? `, ${r.historicalLeads.length} historical lead(s)` : ""}`;
        const requests =
          r.requests
            .slice(0, 5)
            .map(
              (q) =>
                `${cellMd(q.at)} ${cellMd(q.method)} → ${q.status ?? "?"}${q.size !== undefined ? ` (${q.size})` : ""} [${cellMd(q.placement)}]`,
            )
            .join("; ") + (r.requestsTotal > 5 ? ` … ${r.requestsTotal} total` : "");
        const sens = `${cellMd(r.sensitivity)}${r.negativeControl ? " — negative control (public)" : ""}${r.conflict ? ` — CONFLICT: ${cellMd(r.conflict)}` : ""}`;
        lines.push(
          `| ${cellMd(r.url)} | ${cellMd(r.stage)} | ${sens} | ${versions} | ${requests || "none"} | ${cellMd(r.stageReason)} |`,
        );
      }
      if (e.resourcesNotShown) lines.push(`| … | | | | | +${e.resourcesNotShown} resource(s) not shown |`);
    }
    if (e.unevidencedRequests.length) {
      lines.push("", "Requests to paths with no file evidence (leads, no exposure claim):");
      for (const u of e.unevidencedRequests.slice(0, 20))
        lines.push(`- ${cellMd(u.path)}: ${u.count} request(s), status ${u.statuses.join("/")}`);
    }
    lines.push("");
  }
}
