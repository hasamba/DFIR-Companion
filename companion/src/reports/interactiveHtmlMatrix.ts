import type { InvestigationState, Severity } from "../analysis/stateTypes.js";
import { loadAttackMatrix, type AttackMatrixData } from "../analysis/attackMatrixData.js";
import {
  buildAttackMatrix,
  MATRIX_PLATFORMS,
  type MatrixCell,
  type MatrixHit,
  type MatrixModel,
  type MatrixPlatform,
} from "../analysis/attackMatrix.js";
import { buildMatrixHits, presentSeverities } from "./attackMatrixHits.js";
import { caseDomains, defangIndicators } from "./defang.js";

// The interactive HTML report's ATT&CK Matrix section (#1764): the data it embeds, the markup it
// places, and its styles. The renderer that draws it lives in interactiveHtmlMatrixScript.ts.
//
// ONE SOURCE OF LAYOUT TRUTH. The report never lays anything out. The server builds the model with
// buildAttackMatrix() — the same function the dashboard's client mirror is pinned to — once for
// every platform × Hits-only combination (10 models), so the dropdown and the toggle work offline
// without a JavaScript port of the layout. The client only swaps between models and draws them.
//
// COMPACT, NOT DIFFERENT. Ten full models repeat every technique name and every hit's event list
// ten times (~370 KB on a small case). So each model is stored as bare cell ids, and the names and
// the hits sit once beside them. The renderer's expandModel() puts them back; a test pins
// expandModel() to deep-equal buildAttackMatrix() for every combination, so the compaction is
// lossless by proof, not by care.
//
// WHAT IT EMBEDS (see the confidentiality note in interactiveHtml.ts): public ATT&CK catalogue data
// (tactic and technique ids and names), plus per technique the case hits: worst severity, finding
// ids, forensic-event ids and the analyst-accepted flag. The finding titles and event rows the
// popover shows are the ones the report already embeds. No other case field enters the file.

/** One cell as stored: `h` = has a hit (look it up in `hits`), `x` = expanded, `k` = children. */
export interface CompactCell {
  id: string;
  h?: 1;
  x?: 1;
  k?: CompactCell[];
}
export interface CompactColumn {
  t: string; // tactic id
  n: number; // hitCount
  c: CompactCell[];
}
export interface CompactModel {
  columns: CompactColumn[];
  unmapped: string[]; // hit ids
}
export interface MatrixEmbed {
  attackVersion: string;
  catalogueAvailable: boolean;
  tactics: Array<{ id: string; shortname: string; name: string }>;
  /** Technique id → name: the catalogue, plus the case's own name for a hit the catalogue lacks. */
  names: Record<string, string>;
  hits: Record<string, MatrixHit>;
  severities: Severity[];
  /** Keyed `${platform}|${hitsOnly ? 1 : 0}`. */
  models: Record<string, CompactModel>;
}

export const modelKey = (platform: MatrixPlatform, hitsOnly: boolean): string =>
  `${platform}|${hitsOnly ? 1 : 0}`;

function compactCell(cell: MatrixCell, hits: Record<string, MatrixHit>): CompactCell {
  if (cell.hit) hits[cell.id] = cell.hit;
  return {
    id: cell.id,
    ...(cell.hit ? { h: 1 as const } : {}),
    ...(cell.expanded ? { x: 1 as const } : {}),
    ...(cell.children.length ? { k: cell.children.map((c) => compactCell(c, hits)) } : {}),
  };
}

function compactModel(model: MatrixModel, hits: Record<string, MatrixHit>): CompactModel {
  for (const h of model.unmapped) hits[h.id] = h;
  return {
    columns: model.columns.map((col) => ({
      t: col.tactic.id,
      n: col.hitCount,
      c: col.cells.map((cell) => compactCell(cell, hits)),
    })),
    unmapped: model.unmapped.map((h) => h.id),
  };
}

/**
 * Build the matrix blob for the interactive report from the FILTERED state (the same state
 * reportWriter.attackLayer() hands buildAttackLayer()). `catalogue` is injectable for tests.
 */
export function buildMatrixEmbed(
  state: InvestigationState,
  catalogue: AttackMatrixData = loadAttackMatrix(),
): MatrixEmbed {
  const caseHits = buildMatrixHits(state);
  const hits: Record<string, MatrixHit> = {};
  const models: Record<string, CompactModel> = {};
  for (const platform of MATRIX_PLATFORMS) {
    for (const hitsOnly of [false, true]) {
      const model = buildAttackMatrix(catalogue, caseHits, { platform, hitsOnly });
      models[modelKey(platform, hitsOnly)] = compactModel(model, hits);
    }
  }
  const names: Record<string, string> = {};
  for (const t of catalogue.techniques) names[t.id] = t.name;
  // A hit the catalogue cannot name keeps the case table's name. That name can be model prose, so
  // it is defanged like every other prose field in this report (#892).
  const domains = caseDomains(state);
  for (const h of caseHits) {
    const id = h.id.trim().toUpperCase();
    if (!(id in names)) names[id] = defangIndicators(h.name, domains);
  }
  return {
    attackVersion: catalogue.attackVersion,
    catalogueAvailable: catalogue.techniques.length > 0,
    tactics: catalogue.tactics.map((t) => ({ id: t.id, shortname: t.shortname, name: t.name })),
    names,
    hits,
    severities: presentSeverities(Object.values(hits)),
    models,
  };
}

/** The section markup; the renderer fills #atm-grid, #atm-legend and #atm-pop. */
export const MATRIX_SECTION_HTML = [
  `<h2 id="attack-matrix">ATT&amp;CK Matrix</h2>`,
  `<div class="controls">`,
  `<label>Platform <select id="atm-platform">`,
  `<option value="windows">Windows</option><option value="linux">Linux</option>`,
  `<option value="macos">macOS</option><option value="cloud">Cloud</option><option value="all">All</option>`,
  `</select></label>`,
  `<label><input id="atm-hits" type="checkbox"> Hits only</label>`,
  `<button type="button" id="atm-expand">Expand all</button>`,
  `<button type="button" id="atm-collapse">Collapse all</button>`,
  `</div>`,
  `<p id="atm-note" class="empty" hidden></p>`,
  `<div id="atm-grid" class="atm-grid"></div>`,
  `<div id="atm-legend" class="atm-legend"></div>`,
  `<div id="atm-pop" class="atm-pop" role="dialog" aria-modal="false" hidden></div>`,
].join("\n");

export const MATRIX_STYLES = `
  .atm-grid { display: flex; gap: 6px; overflow-x: auto; padding: 4px 0 10px; align-items: flex-start; }
  .atm-col { flex: 0 0 132px; min-width: 132px; }
  .atm-col h3 { font-size: 12px; margin: 0 0 6px; padding: 4px 6px; background: #16213a; color: #fff;
    border-radius: 4px; line-height: 1.3; }
  .atm-col h3 .atm-n { display: block; font-weight: 400; font-size: 11px; opacity: .85; }
  .atm-item { margin: 0 0 3px; }
  .atm-row { display: flex; align-items: stretch; gap: 2px; }
  .atm-cell { flex: 1; text-align: left; font: inherit; font-size: 11.5px; line-height: 1.25; padding: 4px 5px;
    border: 1px solid #d7dbe0; border-radius: 3px; background: #f3f4f6; color: #1b1f24; cursor: pointer; }
  .atm-cell:focus-visible { outline: 2px solid #24314f; outline-offset: 1px; }
  .atm-cell .atm-badge { float: right; margin-left: 4px; font-size: 10.5px; font-weight: 700; }
  .atm-cell.sev-Critical, .atm-cell.sev-High, .atm-cell.sev-Medium, .atm-cell.sev-Low, .atm-cell.sev-Info
    { font-weight: 400; padding: 4px 5px; border-radius: 3px; }
  .atm-toggle { flex: 0 0 26px; font: inherit; font-size: 11px; border: 1px solid #d7dbe0; border-radius: 3px;
    background: #fff; cursor: pointer; padding: 0; }
  .atm-kids { margin: 2px 0 0 10px; border-left: 2px solid #d7dbe0; padding-left: 4px; }
  .atm-legend { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; font-size: 12.5px; color: #5a6675; }
  .atm-pop { position: absolute; z-index: 10; max-width: 420px; max-height: 60vh; overflow: auto; background: #fff;
    border: 1px solid #c7ccd4; border-radius: 6px; box-shadow: 0 4px 16px rgba(0,0,0,.18); padding: 10px 14px; font-size: 13px; }
  .atm-pop[hidden] { display: none; }
  .atm-pop h4 { margin: 0 0 4px; font-size: 14px; }
  .atm-pop ul { margin: 4px 0 8px; padding-left: 18px; }
  .atm-pop .atm-close { float: right; font: inherit; border: 0; background: none; cursor: pointer; font-size: 16px; }
  .atm-flash { outline: 3px solid #f1c40f; outline-offset: 2px; }
`;
