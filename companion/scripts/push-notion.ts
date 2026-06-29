// Export a case to Notion from the command line. The Companion writes ALL its content inside ONE
// managed toggle block on the target page; a re-export refreshes that block and never touches the
// investigators' own notes/screenshots. Shares the same per-case pointer (state/notion-export.json)
// as the dashboard, so the CLI and the dashboard refresh the SAME container. Reads DFIR_NOTION_*
// from .env. The content matches the report (scope + legitimate filters).
//
//   npm run notion:push -- <caseId> --page <urlOrId>          # export into an existing page
//   npm run notion:push -- <caseId> --new [--database <id>]   # create a new page (database row)
//   npm run notion:push -- <caseId> --new [--parent <id>]     # create a new page under a parent
import { config as loadDotenv } from "dotenv";
loadDotenv({ quiet: true });

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { ScopeStore } from "../src/analysis/scope.js";
import { LegitimateStore } from "../src/analysis/legitimate.js";
import { ReportMetaStore } from "../src/reports/reportMeta.js";
import { ReportWriter } from "../src/reports/reportWriter.js";
import { parseNotionPageId } from "../src/integrations/notion/notionClient.js";
import { pushCaseToNotion, type NotionPushTarget } from "../src/integrations/notion/notionPush.js";
import { NotionExportStore } from "../src/integrations/notion/notionExportStore.js";
import { buildNotionClient, notionPushOptions } from "../src/server.js";

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : undefined;
  if (!caseId) {
    console.error("usage: npm run notion:push -- <caseId> --page <urlOrId> | --new [--database <id>] [--parent <id>]");
    process.exit(2);
  }

  const client = buildNotionClient();
  if (!client) {
    console.error("Notion not configured. Set DFIR_NOTION_TOKEN in companion/.env.");
    process.exit(1);
  }

  // Resolve the target from flags. --page → existing page; otherwise create a new page.
  const pageArg = flag("--page");
  const target: NotionPushTarget = pageArg ? { mode: "existing" } : { mode: "new" };
  if (pageArg) {
    const pageId = parseNotionPageId(pageArg);
    if (!pageId) { console.error(`could not read a Notion page id from "${pageArg}"`); process.exit(2); }
    target.pageId = pageId;
  } else {
    const db = flag("--database");
    const parent = flag("--parent");
    if (db) target.databaseId = parseNotionPageId(db) ?? db;
    if (parent) target.parentPageId = parseNotionPageId(parent) ?? parent;
  }

  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  // Build a ReportWriter so the exported content matches the report (same scope/legitimate filters).
  const reportWriter = new ReportWriter(store, stateStore, new ScopeStore(store), new LegitimateStore(store), new ReportMetaStore(store));
  const state = await reportWriter.filteredState(caseId);
  const meta = await new ReportMetaStore(store).load(caseId);
  const exportStore = new NotionExportStore(store);

  console.log(`Exporting "${caseId}" to Notion (${target.mode} page) …`);
  const res = await pushCaseToNotion(client, { caseName: caseId, state, meta }, target, notionPushOptions(), exportStore);

  console.log(`\nNotion page ${res.pageId} ${res.created ? "CREATED" : "UPDATED"}`);
  console.log(`  blocks:   +${res.blocksAppended} appended in ${res.batches} batch(es); ${res.blocksArchived} archived${res.containerRecreated ? "; container recreated" : ""}`);
  if (res.pageUrl) console.log(`  open:     ${res.pageUrl}`);
  if (res.warnings.length) {
    console.log(`\n  ${res.warnings.length} warning(s):`);
    for (const w of res.warnings.slice(0, 20)) console.log(`   - ${w}`);
    if (res.warnings.length > 20) console.log(`   … and ${res.warnings.length - 20} more`);
  }
}

main().catch((e) => { console.error("notion push error:", (e as Error).message); process.exit(1); });
