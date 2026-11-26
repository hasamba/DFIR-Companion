import { escapeBidiControls } from "../../analysis/bidiControl.js";
import { escapeRegExp } from "../../analysis/regexEscape.js";
import type { WatsonProposal, WatsonRequest, WatsonTurn } from "../../analysis/ai/watson/types.js";
import { proposalPreview } from "./watsonMirrorActions.js";

// #2647: the Telegram mirror's formatter. Pure, no I/O.
//
// Order is the contract: workstation roots out → (the service masks) → escape → split. The text is
// chunked RAW and each chunk escaped on its own, so an HTML entity is never cut in two; a chunk's
// budget is measured on its ESCAPED length, so a run of "<" (four characters each once escaped) still
// fits. The only tag the mirror ever writes is the footer link, which is always present.

/** Escaped characters per message body. The footer (and a blank line) fit in Telegram's 4,096. */
export const MIRROR_CHUNK_MAX = 3800;

/** Escape for Telegram's HTML parse mode: tags, both quote kinds (link attribute), bidi controls. */
export function escapeMirrorHtml(s: string): string {
  return escapeBidiControls(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ── Workstation roots ─────────────────────────────────────────────────────────────────

export interface WorkstationRoot {
  /** The root, with no trailing separator. */
  readonly path: string;
  readonly placeholder: "<case>" | "<companion>";
}

/** A filesystem root ("/", "C:\") or an empty value: never a workstation root, it would eat evidence. */
const isFilesystemRoot = (p: string): boolean => /^([a-z]:)?[\\/]*$/i.test(p);

const trimSeparators = (p: string): string => p.replace(/[\\/]+$/, "");

/**
 * The roots replaced in every outgoing message: the cases root becomes `<case>`, the data directory
 * and the install directories `<companion>`. Longest first, so the cases root (inside the data dir)
 * wins. Evidence paths from artifacts are never touched: no generic path pattern is used.
 */
export function workstationRoots(input: {
  casesRoot: string;
  dataDir: string;
  installDirs: readonly string[];
}): WorkstationRoot[] {
  const raw: WorkstationRoot[] = [
    { path: input.casesRoot, placeholder: "<case>" },
    { path: input.dataDir, placeholder: "<companion>" },
    ...input.installDirs.map((p) => ({ path: p, placeholder: "<companion>" as const })),
  ];
  const seen = new Set<string>();
  const out: WorkstationRoot[] = [];
  for (const r of raw) {
    const path = trimSeparators((r.path ?? "").trim());
    if (isFilesystemRoot(path) || seen.has(path.toLowerCase())) continue;
    seen.add(path.toLowerCase());
    out.push({ path, placeholder: r.placeholder });
  }
  return out.sort((a, b) => b.path.length - a.path.length);
}

/** Either slash direction, any case: a Windows path is written both ways and is case-insensitive. */
function rootPattern(path: string): RegExp {
  const body = path
    .split(/[\\/]+/)
    .map(escapeRegExp)
    .join(String.raw`[\\/]`);
  return new RegExp(`${body}(?=[\\\\/]|$|[^\\w.-])`, "gi");
}

export function replaceWorkstationRoots(text: string, roots: readonly WorkstationRoot[]): string {
  return roots.reduce((acc, r) => acc.replace(rootPattern(r.path), r.placeholder), text);
}

// ── One turn as text ──────────────────────────────────────────────────────────────────

const roleLine = (t: WatsonTurn): string =>
  t.role === "analyst"
    ? `Analyst${t.actor ? ` (${t.actor})` : ""}:`
    : t.role === "watson"
      ? "Watson:"
      : `Note${t.actor ? ` (${t.actor})` : ""}:`;

function requestLine(r: WatsonRequest): string {
  switch (r.kind) {
    case "query":
      return `Watson asks you to run a ${r.language} query (see the dashboard).`;
    case "import":
      return `Watson asks you to import: ${r.what}`;
    case "velociraptor":
      return `Watson asks for a Velociraptor ${r.mode === "hunt" ? "hunt" : "collection"}: ${r.title}`;
    case "crowdstrike_search":
      return `Watson asks for a CrowdStrike search: ${r.title}`;
  }
}

const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** One line per proposal kind. Fields are read defensively: a stored proposal may be partial. */
function proposalLabel(p: WatsonProposal): string {
  switch (p.kind) {
    case "question_new":
      return `new key question: ${str(p.after?.question)}`;
    case "question_update":
      return `key question update: ${str(p.after?.question)}`;
    case "finding_new":
      return `new finding: ${str(p.after?.title)}`;
    case "finding_update":
      return `finding update: ${str(p.after?.title)}`;
    case "next_step_new":
      return `new next step: ${str(p.after?.action)}`;
    case "next_step_update":
      return p.after === null
        ? `mark next step done: ${str(p.before?.action)}`
        : `next step change: ${str(p.before?.action)}`;
    case "finding_review":
      return `${p.action === "dismiss" ? "dismiss" : "lower the severity of"} finding: ${str(p.before?.title)}`;
    case "report_text":
      return `report text for ${p.field === "conclusions" ? "Conclusions" : "Investigation limitations"}`;
    case "event_promote":
      return `add ${Array.isArray(p.events) ? p.events.length : 0} event(s) to the forensic timeline`;
    case "velo_launch":
      return `Velociraptor ${p.mode === "hunt" ? "hunt" : "collection"}: ${str(p.title)}`;
    case "cs_search":
      return `CrowdStrike search: ${str(p.title)}`;
  }
}

const UNKNOWN_PROPOSAL = "a change (open the dashboard to see it)";

/**
 * What the dashboard shows for the turn, as plain text: the role, the text, the answer's status line,
 * answer and `Next:` pointer, what Watson learned, the request and one line per proposal. Cards and
 * result tables are one line each; the footer link leads to the rest.
 *
 * #2712: a proposal in `numbers` carries Apply / Reject buttons: its line reads "Watson proposes [n]:"
 * and is followed by the change itself, so the analyst sees what the button approves.
 */
export function turnPlainText(
  turn: WatsonTurn,
  proposals: readonly WatsonProposal[],
  numbers: ReadonlyMap<string, number> = new Map(),
): string {
  const byId = new Map(proposals.map((p) => [p.id, p]));
  const lines = [roleLine(turn)];
  if (turn.text) lines.push(turn.text);
  if (turn.answer?.answer) lines.push(`[${turn.answer.status}] ${turn.answer.answer}`);
  if (turn.answer?.pointer) lines.push(`Next: ${turn.answer.pointer}`);
  if (turn.learned) lines.push(`Learned: ${turn.learned}`);
  if (turn.request) lines.push(requestLine(turn.request));
  for (const id of turn.proposalIds ?? []) {
    const p = byId.get(id);
    const n = numbers.get(id);
    if (!p || n === undefined) {
      lines.push(`Watson proposes: ${p ? proposalLabel(p) : UNKNOWN_PROPOSAL}`);
      continue;
    }
    lines.push(`Watson proposes [${n}]: ${proposalLabel(p)}`);
    const preview = proposalPreview(p);
    if (preview) lines.push(`  ${preview}`);
  }
  return lines.join("\n");
}

// ── Footer and split ──────────────────────────────────────────────────────────────────

/**
 * Always present. A link only when a public dashboard URL is set: the loopback guess is useless on a
 * phone, so without one the footer names the case instead.
 */
export function mirrorFooter(caseId: string, publicUrl: string | undefined): string {
  const label = escapeMirrorHtml(`Open case ${caseId} in the dashboard`);
  const base = (publicUrl ?? "").trim().replace(/\/+$/, "");
  if (!base) return label;
  const href = escapeMirrorHtml(`${base}/dashboard?caseId=${encodeURIComponent(caseId)}`);
  return `<a href="${href}">${label}</a>`;
}

/** Cut one raw line into pieces whose escaped form fits `max`, by code point. */
function hardSplit(line: string, max: number): string[] {
  const out: string[] = [];
  let piece = "";
  let size = 0;
  for (const ch of Array.from(line)) {
    const n = escapeMirrorHtml(ch).length;
    if (size + n > max && piece) {
      out.push(piece);
      piece = "";
      size = 0;
    }
    piece += ch;
    size += n;
  }
  if (piece) out.push(piece);
  return out;
}

/** The raw text cut on line boundaries into chunks whose escaped form fits `max`. */
function chunkRaw(raw: string, max: number): string[] {
  const chunks: string[] = [];
  let cur: string[] = [];
  let size = 0;
  const flush = (): void => {
    if (cur.length) chunks.push(cur.join("\n"));
    cur = [];
    size = 0;
  };
  for (const line of raw.split("\n")) {
    const pieces = escapeMirrorHtml(line).length > max ? hardSplit(line, max) : [line];
    for (const piece of pieces) {
      const n = escapeMirrorHtml(piece).length + (cur.length ? 1 : 0);
      if (size + n > max) flush();
      size += escapeMirrorHtml(piece).length + (cur.length ? 1 : 0);
      cur.push(piece);
    }
  }
  flush();
  return chunks;
}

/** Raw text → escaped Telegram messages in order, each ending with the (already escaped) footer. */
export function buildMirrorMessages(raw: string, footer: string, max: number = MIRROR_CHUNK_MAX): string[] {
  const chunks = chunkRaw(raw, max).filter((c) => c.trim() !== "");
  const bodies = chunks.length ? chunks : [""];
  return bodies.map((c) => `${escapeMirrorHtml(c)}\n\n${footer}`.replace(/^\n\n/, ""));
}
