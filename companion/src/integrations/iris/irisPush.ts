// Orchestrates a full Companion → DFIR-IRIS push. Find-or-create the case by name, then
// push: assets→assets, IOCs→IOCs, forensic timeline→timeline, executive summary→case summary,
// and every other section→notes. Idempotent: re-pushing an existing case adds only what's
// missing (assets by name, IOCs by value, events by title+time) and cleanly replaces the
// Companion notes + summary — so the spec's "if exists update, else create" holds end to end.
//
// The IRIS client is injected as a structural interface so this is unit-testable with a mock
// (no network), matching the enrichment-service pattern.

import type { InvestigationState, ForensicEvent } from "../../analysis/stateTypes.js";
import { buildAssetGraph, type AssetGraph } from "../../analysis/assetGraph.js";
import type { ReportMeta } from "../../reports/reportMeta.js";
import { emptyReportMeta } from "../../reports/reportMeta.js";
import {
  mapAsset, mapIoc, mapEvent, mapNextStepTask, buildNotes, executiveSummaryMarkdown,
} from "./irisMap.js";
import type {
  IrisCaseCreate, IrisCaseRef, IrisAssetRef, IrisIocRef, IrisEventRef, IrisDirRef, IrisTaskRef,
  IrisAssetBody, IrisIocBody, IrisEventBody, IrisTaskBody,
} from "./irisClient.js";

// Structural subset of IrisClient used here — lets tests pass a lightweight mock.
export interface IrisClientLike {
  ping(): Promise<void>;
  findCaseByName(name: string): Promise<IrisCaseRef | null>;
  createCase(body: IrisCaseCreate): Promise<IrisCaseRef>;
  setSummary(caseId: number, markdown: string): Promise<void>;
  iocTypeMap(): Promise<Map<string, number>>;
  assetTypeMap(): Promise<Map<string, number>>;
  eventCategoryMap(): Promise<Map<string, number>>;
  taskStatusMap(): Promise<Map<string, number>>;
  listAssets(cid: number): Promise<IrisAssetRef[]>;
  addAsset(cid: number, body: IrisAssetBody): Promise<number>;
  listIocs(cid: number): Promise<IrisIocRef[]>;
  addIoc(cid: number, body: IrisIocBody): Promise<number>;
  listEvents(cid: number): Promise<IrisEventRef[]>;
  addEvent(cid: number, body: IrisEventBody): Promise<number>;
  listTasks(cid: number): Promise<IrisTaskRef[]>;
  addTask(cid: number, body: IrisTaskBody): Promise<number>;
  listDirectories(cid: number): Promise<IrisDirRef[]>;
  addDirectory(cid: number, name: string): Promise<number>;
  deleteDirectory(cid: number, directoryId: number): Promise<void>;
  addNote(cid: number, directoryId: number, title: string, content: string): Promise<number>;
}

export interface IrisPushInput {
  caseName: string;                    // = the Companion case id (used as the IRIS case name)
  state: InvestigationState;
  meta?: ReportMeta;
  assetGraph?: AssetGraph;             // defaults to buildAssetGraph(state)
}

export interface IrisPushOptions {
  customerId?: number;                 // IRIS customer id (default 1 — seeded IrisInitialClient)
  classificationId?: number;           // IRIS case classification id (default 1)
  baseUrl?: string;                    // to build a clickable case URL in the result
  notesDirectory?: string;             // managed notes directory name (default "DFIR Companion")
}

interface SectionCount { added: number; existing: number; skipped: number }

export interface IrisPushResult {
  caseId: number;
  caseName: string;
  created: boolean;                    // true = the case was newly created
  assets: SectionCount;
  iocs: SectionCount;
  timeline: SectionCount;
  tasks: SectionCount;
  notes: number;
  summaryUpdated: boolean;
  caseUrl?: string;
  warnings: string[];
}

const NOTES_DIR = "DFIR Companion";

export async function pushCaseToIris(
  client: IrisClientLike,
  input: IrisPushInput,
  options: IrisPushOptions = {},
): Promise<IrisPushResult> {
  const meta = input.meta ?? emptyReportMeta();
  const graph = input.assetGraph ?? buildAssetGraph(input.state);
  const warnings: string[] = [];
  const assets: SectionCount = { added: 0, existing: 0, skipped: 0 };
  const iocs: SectionCount = { added: 0, existing: 0, skipped: 0 };
  const timeline: SectionCount = { added: 0, existing: 0, skipped: 0 };
  const tasks: SectionCount = { added: 0, existing: 0, skipped: 0 };

  // 1. Connectivity / auth (fatal).
  await client.ping();

  // 2. Find-or-create the case by name (fatal — we need a case id to write into).
  const found = await client.findCaseByName(input.caseName);
  let ref: IrisCaseRef;
  let created = false;
  if (found) {
    ref = found;
  } else {
    ref = await client.createCase({
      case_name: input.caseName,
      case_description: "Imported from DFIR Companion.",
      case_customer: options.customerId ?? 1,
      classification_id: options.classificationId ?? 1,
      case_soc_id: "",
    });
    created = true;
  }
  const cid = ref.caseId;

  // 3. Executive summary → collaborative case summary (non-fatal).
  let summaryUpdated = false;
  try {
    await client.setSummary(cid, executiveSummaryMarkdown(input.state, meta));
    summaryUpdated = true;
  } catch (err) {
    warnings.push(`summary: ${(err as Error).message}`);
  }

  // 4. Resolve type-id maps once.
  const [iocTypes, assetTypes] = await Promise.all([client.iocTypeMap(), client.assetTypeMap()]);

  // 5. Assets (dedupe by name) — build name→IRIS-id map for event linking.
  const assetByName = new Map<string, number>();
  for (const a of await client.listAssets(cid)) assetByName.set(a.name.trim().toLowerCase(), a.id);
  for (const asset of graph.assets) {
    const key = asset.name.trim().toLowerCase();
    if (assetByName.has(key)) { assets.existing += 1; continue; }
    const body = mapAsset(asset, assetTypes);
    if (!body) { assets.skipped += 1; warnings.push(`asset skipped (no IRIS type for "${asset.type}"): ${asset.name}`); continue; }
    try {
      assetByName.set(key, await client.addAsset(cid, body));
      assets.added += 1;
    } catch (err) {
      assets.skipped += 1;
      warnings.push(`asset "${asset.name}": ${(err as Error).message}`);
    }
  }

  // 6. IOCs (dedupe by value) — build value→IRIS-id map for event linking.
  const iocByValue = new Map<string, number>();
  for (const i of await client.listIocs(cid)) iocByValue.set(i.value.trim().toLowerCase(), i.id);
  for (const ioc of input.state.iocs) {
    const key = ioc.value.trim().toLowerCase();
    if (iocByValue.has(key)) { iocs.existing += 1; continue; }
    const body = mapIoc(ioc, iocTypes);
    if (!body) { iocs.skipped += 1; warnings.push(`ioc skipped (no IRIS type for "${ioc.type}"): ${ioc.value}`); continue; }
    try {
      iocByValue.set(key, await client.addIoc(cid, body));
      iocs.added += 1;
    } catch (err) {
      iocs.skipped += 1;
      warnings.push(`ioc "${ioc.value}": ${(err as Error).message}`);
    }
  }

  // 7. Timeline (dedupe by title+date; best-effort listing). Events are auto-categorized by
  // MITRE tactic (categoryByName) and linked to the IOCs referenced via their findings.
  const seenEvents = new Set<string>();
  try {
    for (const e of await client.listEvents(cid)) seenEvents.add(`${e.title}|${e.date}`);
  } catch {
    warnings.push("timeline: could not list existing events — re-push may duplicate events");
  }
  let categoryByName = new Map<string, number>();
  try { categoryByName = await client.eventCategoryMap(); } catch (err) { warnings.push(`event categories: ${(err as Error).message}`); }
  const findingById = new Map(input.state.findings.map((f) => [f.id, f]));
  const iocById = new Map(input.state.iocs.map((i) => [i.id, i]));
  const findingIocValues = (e: ForensicEvent): string[] => {
    const out: string[] = [];
    for (const fid of e.relatedFindingIds) {
      const f = findingById.get(fid);
      if (f) for (const iid of f.relatedIocs) { const i = iocById.get(iid); if (i) out.push(i.value); }
    }
    return out;
  };
  const ctx = { assetByName, iocByValue, categoryByName, findingIocValues };
  for (const event of input.state.forensicTimeline) {
    const body = mapEvent(event, ctx);
    if (!body) { timeline.skipped += 1; continue; }     // unparseable timestamp
    const dedupeKey = `${body.event_title}|${body.event_date}`;
    if (seenEvents.has(dedupeKey)) { timeline.existing += 1; continue; }
    try {
      await client.addEvent(cid, body);
      seenEvents.add(dedupeKey);
      timeline.added += 1;
    } catch (err) {
      timeline.skipped += 1;
      warnings.push(`event "${body.event_title as string}": ${(err as Error).message}`);
    }
  }

  // 8. Recommended Next Steps → IRIS tasks (dedupe by title; status "To do").
  if (input.state.nextSteps.length) {
    let statusId = 1;
    try {
      const statuses = await client.taskStatusMap();
      statusId = statuses.get("to do") ?? statuses.get("open") ?? [...statuses.values()][0] ?? 1;
    } catch (err) { warnings.push(`task status: ${(err as Error).message}`); }
    const seenTasks = new Set<string>();
    try { for (const t of await client.listTasks(cid)) seenTasks.add(t.title); }
    catch { warnings.push("tasks: could not list existing tasks — re-push may duplicate"); }
    for (const step of input.state.nextSteps) {
      const body = mapNextStepTask(step);
      const title = String(body.task_title);
      if (seenTasks.has(title)) { tasks.existing += 1; continue; }
      try {
        await client.addTask(cid, { ...body, task_status_id: statusId, task_assignees_id: [] });
        seenTasks.add(title);
        tasks.added += 1;
      } catch (err) {
        tasks.skipped += 1;
        warnings.push(`task "${title}": ${(err as Error).message}`);
      }
    }
  }

  // 9. Notes — clean-replace the managed directory so notes reflect current state.
  let notes = 0;
  const dirName = options.notesDirectory ?? NOTES_DIR;
  try {
    const existingDir = (await client.listDirectories(cid)).find((d) => d.name === dirName);
    if (existingDir) await client.deleteDirectory(cid, existingDir.id);
    const dirId = await client.addDirectory(cid, dirName);
    for (const note of buildNotes(input.state, meta)) {
      try { await client.addNote(cid, dirId, note.title, note.content); notes += 1; }
      catch (err) { warnings.push(`note "${note.title}": ${(err as Error).message}`); }
    }
  } catch (err) {
    warnings.push(`notes: ${(err as Error).message}`);
  }

  return {
    caseId: cid,
    caseName: ref.caseName,
    created,
    assets,
    iocs,
    timeline,
    tasks,
    notes,
    summaryUpdated,
    caseUrl: options.baseUrl ? `${options.baseUrl.replace(/\/+$/, "")}/case?cid=${cid}` : undefined,
    warnings,
  };
}
