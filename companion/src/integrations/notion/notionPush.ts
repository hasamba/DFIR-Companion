// Orchestrates a Companion → Notion export. The Companion owns a SINGLE managed toggle block on
// the target page; ALL its content lives inside that toggle. On re-export it archives the
// toggle's children and re-appends freshly-rendered blocks — so anything the investigators
// wrote OUTSIDE the toggle (their notes, pasted finding screenshots) is never read or touched.
//
//   • "new" page    → create a page (a row in a database, or a child of a parent page), then
//                     create the managed container on it.
//   • "existing" page → reuse the remembered container (or adopt one by title / create a fresh
//                     one), then refresh its children.
//
// Notion has no find-by-name, so we remember the target page + container id in a per-case store
// (NotionExportStore). The client is injected as a structural interface so this is unit-testable
// with a mock (no network), matching the IRIS/Timesketch push pattern.

import type { InvestigationState } from "../../analysis/stateTypes.js";
import type { ReportMeta } from "../../reports/reportMeta.js";
import { emptyReportMeta } from "../../reports/reportMeta.js";
import {
  buildCompanionBlocks,
  batchBlocks,
  toggle,
  DEFAULT_CONTAINER_TITLE,
  type NotionBlock,
} from "./notionBlocks.js";
import {
  NotionApiError,
  type NotionParent,
  type NotionPageRef,
  type NotionBlockRef,
  type NotionBotUser,
} from "./notionClient.js";
import type { NotionExport } from "./notionExportStore.js";
import { StateLock } from "../../analysis/stateLock.js";

// Structural subset of NotionClient used here — lets tests pass a lightweight mock.
export interface NotionClientLike {
  me(): Promise<NotionBotUser>;
  retrievePage(pageId: string): Promise<NotionPageRef>;
  retrieveBlock(blockId: string): Promise<NotionBlockRef | null>;
  listChildren(blockId: string): Promise<NotionBlockRef[]>;
  appendChildren(blockId: string, children: NotionBlock[]): Promise<NotionBlockRef[]>;
  archiveBlock(blockId: string): Promise<void>;
  createPage(parent: NotionParent, title: string): Promise<NotionPageRef>;
}

// Structural subset of NotionExportStore — lets tests pass an in-memory fake (no file I/O).
export interface NotionExportStoreLike {
  load(caseId: string): Promise<NotionExport>;
  record(caseId: string, patch: Partial<NotionExport>): Promise<NotionExport>;
}

export interface NotionPushInput {
  caseName: string; // = the Companion case id (used as the page title)
  state: InvestigationState;
  meta?: ReportMeta;
}

// Where to export — chosen by the analyst in the dashboard modal / CLI.
export interface NotionPushTarget {
  mode: "new" | "existing";
  pageId?: string; // existing: the page to write into (already parsed to a dashed UUID)
  parentPageId?: string; // new: create the page under this parent page
  databaseId?: string; // new: create the page as a row in this database (preferred)
}

export interface NotionPushOptions {
  baseUrl?: string; // notion.so base, for a fallback page link
  parentPageId?: string; // default parent page for "new" exports (DFIR_NOTION_PARENT_PAGE_ID)
  databaseId?: string; // default database for "new" exports (DFIR_NOTION_DATABASE_ID)
  containerTitle?: string; // managed container title (default DEFAULT_CONTAINER_TITLE)
  maxTimelineRows?: number; // cap timeline rows written to Notion
  exportedAt?: string; // ISO stamp (injectable for deterministic tests)
  sleep?: (ms: number) => Promise<void>; // inter-batch pacing (injectable; tests pass a no-op)
}

export interface NotionPushResult {
  created: boolean; // true = a new page was created
  pageId: string;
  pageUrl?: string;
  containerBlockId: string;
  containerRecreated: boolean; // true = the remembered container was gone and we made a new one
  blocksAppended: number;
  blocksArchived: number;
  batches: number;
  warnings: string[];
}

const INTER_BATCH_MS = 350; // ~3 req/s — Notion's documented average rate limit

/**
 * The export stopped part-way (#2414). The page exists (and is remembered), so the analyst can
 * re-export INTO it instead of creating another page. Carries the page so the route and dashboard
 * can offer exactly that.
 */
export class NotionExportIncompleteError extends Error {
  constructor(
    message: string,
    readonly pageId: string,
    readonly pageUrl: string | undefined,
  ) {
    super(message);
    this.name = "NotionExportIncompleteError";
  }
}

// One export per case at a time (#2414): two overlapping exports could each create a page, overwrite
// each other's remembered pointer, or interleave archiving and appending in the same container.
const notionPushLock = new StateLock();

export function pushCaseToNotion(
  client: NotionClientLike,
  input: NotionPushInput,
  target: NotionPushTarget,
  options: NotionPushOptions = {},
  store: NotionExportStoreLike,
): Promise<NotionPushResult> {
  return notionPushLock.runExclusive(input.caseName, () =>
    pushCaseToNotionNow(client, input, target, options, store),
  );
}

async function pushCaseToNotionNow(
  client: NotionClientLike,
  input: NotionPushInput,
  target: NotionPushTarget,
  options: NotionPushOptions,
  store: NotionExportStoreLike,
): Promise<NotionPushResult> {
  const meta = input.meta ?? emptyReportMeta();
  const warnings: string[] = [];
  const containerTitle = options.containerTitle ?? DEFAULT_CONTAINER_TITLE;
  const exportedAt = options.exportedAt ?? new Date().toISOString();
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));

  // 1. Auth (fatal — surfaces a bad token as a clean message).
  await client.me();

  // 2. Render the managed content once (pure, no I/O).
  const blocks = buildCompanionBlocks(input.state, meta, {
    caseId: input.caseName,
    exportedAt,
    maxTimelineRows: options.maxTimelineRows,
  });

  // 3. Resolve the target page + managed container.
  const remembered = await store.load(input.caseName);
  const hadRemembered = remembered.pageId !== "" && remembered.containerBlockId !== "";

  let pageId: string;
  let pageUrl: string | undefined;
  let created = false;
  let parentPageId = "";
  let databaseId = "";
  let containerBlockId = "";

  if (target.mode === "existing") {
    if (!target.pageId) throw new Error("existing-page export requires a page id");
    pageId = target.pageId;
    const page = await client.retrievePage(pageId); // fatal when the integration lacks access
    pageUrl = page.url ?? (remembered.pageUrl || undefined);

    // Reuse the remembered container when it still exists on THIS page and isn't archived.
    if (remembered.pageId === pageId && remembered.containerBlockId) {
      const existing = await client.retrieveBlock(remembered.containerBlockId);
      if (existing && !existing.archived) containerBlockId = existing.id;
    }
    // When the remembered container is gone (store lost/deleted, or a different page), do NOT
    // adopt a same-titled toggle by name — that could be an analyst's own toggle with their own
    // notes, and the export would archive its children and repurpose it as the Companion container
    // (analyst content destruction). Instead, leave containerBlockId empty so a fresh toggle is
    // created below, same as the first-export path. The remembered id is the only ownership marker
    // the Companion has; title alone is not a strong enough signal.
  } else {
    const db = target.databaseId ?? options.databaseId;
    const parent = target.parentPageId ?? options.parentPageId;
    const title = pageTitle(input.caseName);
    let page: NotionPageRef;
    if (db) {
      try {
        page = await client.createPage({ database_id: db }, title);
        databaseId = db;
      } catch (err) {
        // The dashboard sends one "new target" field as BOTH database and parent, so the id may
        // actually be a page, not a database. Fall back to creating under it as a parent page.
        const kind = err instanceof NotionApiError ? err.kind : "";
        if (parent && (kind === "validation" || kind === "notfound")) {
          page = await client.createPage({ page_id: parent }, title);
          parentPageId = parent;
        } else {
          throw err;
        }
      }
    } else if (parent) {
      page = await client.createPage({ page_id: parent }, title);
      parentPageId = parent;
    } else {
      throw new Error(
        "no parent for the new page — set DFIR_NOTION_DATABASE_ID or DFIR_NOTION_PARENT_PAGE_ID, or pass a parent/database",
      );
    }
    pageId = page.id;
    pageUrl = page.url;
    created = true;
    // #2414: remembered the moment it exists, so a failure below never leaves an untracked page.
    await store.record(input.caseName, {
      pageId,
      pageUrl: pageUrl ?? "",
      containerBlockId: "",
      parentPageId,
      databaseId,
      lastMode: target.mode,
    });
  }
  const pointer = { pageId, pageUrl: pageUrl ?? "", parentPageId, databaseId, lastMode: target.mode };
  const incomplete = (message: string) => new NotionExportIncompleteError(message, pageId, pageUrl);

  // 4. Create the managed container when we don't have one yet; otherwise clean its children.
  let containerRecreated = false;
  let blocksArchived = 0;
  if (!containerBlockId) {
    const appended = await client.appendChildren(pageId, [toggle(containerTitle)]); // fatal if this fails
    containerBlockId = appended[0]?.id ?? "";
    if (!containerBlockId) throw new Error("Notion did not return the created container block id");
    containerRecreated = hadRemembered && remembered.pageId === pageId;
    await store.record(input.caseName, { ...pointer, containerBlockId }); // #2414
  } else {
    // Children-replace: archive only OUR container's children — never the page's other blocks.
    const failed: string[] = [];
    for (const child of await client.listChildren(containerBlockId)) {
      try {
        await client.archiveBlock(child.id);
        blocksArchived += 1;
      } catch (err) {
        failed.push(`${child.id}: ${(err as Error).message}`);
      }
    }
    // #2414: appending now would leave the old content beside the new — a page that contradicts
    // itself. Stop before writing anything new.
    if (failed.length)
      throw incomplete(
        `Notion export stopped: ${failed.length} block(s) of the previous export could not be removed ` +
          `(${failed[0]}). Nothing new was written; export to this page again to retry.`,
      );
  }

  // 5. Append the fresh content in ≤100-block batches, paced for the rate limit.
  const batches = batchBlocks(blocks);
  let blocksAppended = 0;
  for (let i = 0; i < batches.length; i++) {
    if (i > 0) await sleep(INTER_BATCH_MS);
    try {
      await client.appendChildren(containerBlockId, batches[i]);
      blocksAppended += batches[i].length;
    } catch (err) {
      // #2414: a failed batch would leave a hole mid-page. Stop — no later batch is appended after
      // a gap — and fail the export loudly. Re-exporting replaces the container's children.
      throw incomplete(
        `Notion export incomplete: batch ${i + 1} of ${batches.length} failed (${(err as Error).message}). ` +
          `${blocksAppended} of ${blocks.length} block(s) were written; export to this page again to replace them.`,
      );
    }
  }

  // 6. Persist the pointer so the next export refreshes this same container.
  await store.record(input.caseName, {
    ...pointer,
    containerBlockId,
    lastExportedAt: exportedAt,
    lastBlocksAppended: blocksAppended,
  });

  return {
    created,
    pageId,
    pageUrl,
    containerBlockId,
    containerRecreated,
    blocksAppended,
    blocksArchived,
    batches: batches.length,
    warnings,
  };
}

function pageTitle(caseName: string): string {
  return `DFIR Companion — ${caseName}`;
}
