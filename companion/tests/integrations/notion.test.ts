import { describe, it, expect } from "vitest";
import { parseNotionPageId, NotionApiError, type NotionParent, type NotionPageRef, type NotionBlockRef, type NotionBotUser } from "../../src/integrations/notion/notionClient.js";
import {
  buildCompanionBlocks, batchBlocks, tables, paragraph, richText, callout, type NotionBlock,
} from "../../src/integrations/notion/notionBlocks.js";
import {
  pushCaseToNotion, type NotionClientLike, type NotionExportStoreLike,
} from "../../src/integrations/notion/notionPush.js";
import { notionExportSchema, type NotionExport } from "../../src/integrations/notion/notionExportStore.js";
import { emptyState, type InvestigationState, type Finding } from "../../src/analysis/stateTypes.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";

const AT = "2026-01-01T00:00:00.000Z";
const noop = async (): Promise<void> => {};

// Plain text of a built block (reads block[type].rich_text), for assertions / the mock.
function plainTextOf(b: NotionBlock): string | undefined {
  const body = (b as Record<string, unknown>)[b.type] as { rich_text?: Array<{ text?: { content?: string } }> } | undefined;
  const rt = body?.rich_text;
  if (!Array.isArray(rt)) return undefined;
  return rt.map((r) => r.text?.content ?? "").join("");
}

// ---- parseNotionPageId -----------------------------------------------------

describe("parseNotionPageId", () => {
  const ID32 = "1a2b3c4d5e6f78901a2b3c4d5e6f7890";
  const DASHED = "1a2b3c4d-5e6f-7890-1a2b-3c4d5e6f7890";
  it("reads a bare 32-hex id, a dashed UUID, and notion.so URLs; rejects junk", () => {
    expect(parseNotionPageId(ID32)).toBe(DASHED);
    expect(parseNotionPageId(DASHED)).toBe(DASHED);
    expect(parseNotionPageId(`https://www.notion.so/My-Investigation-${ID32}`)).toBe(DASHED);
    expect(parseNotionPageId(`https://www.notion.so/ws/My-Page-${ID32}?pvs=4`)).toBe(DASHED);
    expect(parseNotionPageId(`https://notion.so/ws/Page?p=${ID32}`)).toBe(DASHED);
    expect(parseNotionPageId("not a page")).toBeNull();
    expect(parseNotionPageId("")).toBeNull();
  });
});

// ---- block rendering -------------------------------------------------------

describe("notionBlocks", () => {
  it("chunks rich text at 2000 chars per run", () => {
    const runs = richText("a".repeat(2500));
    expect(runs).toHaveLength(2);
    expect(runs[0].text.content).toHaveLength(2000);
    expect(runs[1].text.content).toHaveLength(500);
  });

  it("builds a table with a header row and caps rows per table block", () => {
    const one = tables(["A", "B"], [["1", "2"], ["3", "4"]]);
    expect(one).toHaveLength(1);
    const t = one[0].table as { table_width: number; has_column_header: boolean; children: unknown[] };
    expect(t.table_width).toBe(2);
    expect(t.has_column_header).toBe(true);
    expect(t.children).toHaveLength(3); // header + 2 data rows

    const big = tables(["A"], Array.from({ length: 200 }, (_, i) => [String(i)]));
    expect(big).toHaveLength(3); // 200 rows split into 90/90/20
  });

  it("colors a Critical finding header red and includes the section headings", () => {
    const blocks = buildCompanionBlocks(sampleState(), emptyReportMeta(), { caseId: "c1", exportedAt: AT });
    expect(blocks[0].type).toBe("callout"); // managed banner first
    expect(blocks.some((b) => b.type === "heading_2" && plainTextOf(b) === "Findings")).toBe(true);
    expect(blocks.some((b) => b.type === "heading_2" && plainTextOf(b) === "Incident Timeline")).toBe(true);
    const crit = blocks.find((b) => b.type === "callout" && plainTextOf(b)?.startsWith("[Critical]"));
    expect((crit?.callout as { color: string }).color).toBe("red_background");
  });

  it("packs blocks into ≤100-weight batches; a 90-row table is one batch", () => {
    const batched = batchBlocks(Array.from({ length: 150 }, () => paragraph("x")));
    expect(batched).toHaveLength(2);
    expect(batched[0]).toHaveLength(100);
    const tableBlock = tables(["A"], Array.from({ length: 90 }, () => ["x"]))[0];
    expect(batchBlocks([tableBlock])).toHaveLength(1); // weight 91 ≤ 100
  });
});

// ---- orchestrator with a recording in-memory mock --------------------------

interface MockBlock { id: string; type: string; archived: boolean; plainText?: string; parentId: string; children: string[] }

class MockNotion implements NotionClientLike {
  private seq = 0;
  pages = new Map<string, { id: string; url: string; children: string[] }>();
  blocks = new Map<string, MockBlock>();
  createPageCalls: { parent: NotionParent; title: string }[] = [];
  appendCalls: { blockId: string; count: number }[] = [];
  meCalled = false;
  failArchive = false;
  failDatabaseCreate = false; // simulate "this id is a page, not a database" (Notion 400)

  private newId(prefix: string): string { return `${prefix}-${++this.seq}`; }
  private childrenOf(parentId: string): string[] {
    const p = this.pages.get(parentId);
    if (p) return p.children;
    const b = this.blocks.get(parentId);
    if (b) return b.children;
    throw new Error(`unknown parent ${parentId}`);
  }

  seedPage(id: string): void { this.pages.set(id, { id, url: `https://notion.so/${id}`, children: [] }); }
  seedBlock(parentId: string, type: string, plainText?: string): string {
    const id = this.newId("blk");
    this.blocks.set(id, { id, type, archived: false, plainText, parentId, children: [] });
    this.childrenOf(parentId).push(id);
    return id;
  }

  async me(): Promise<NotionBotUser> { this.meCalled = true; return { id: "bot", name: "test" }; }

  async retrievePage(pageId: string): Promise<NotionPageRef> {
    const p = this.pages.get(pageId);
    if (!p) throw new NotionApiError("not found", 404, "notfound");
    return { id: p.id, url: p.url };
  }

  async retrieveBlock(blockId: string): Promise<NotionBlockRef | null> {
    const b = this.blocks.get(blockId);
    if (!b || b.archived) return null;
    return { id: b.id, type: b.type, archived: b.archived, plainText: b.plainText };
  }

  async listChildren(blockId: string): Promise<NotionBlockRef[]> {
    return this.childrenOf(blockId)
      .map((id) => this.blocks.get(id))
      .filter((b): b is MockBlock => !!b && !b.archived)
      .map((b) => ({ id: b.id, type: b.type, archived: b.archived, plainText: b.plainText }));
  }

  async appendChildren(blockId: string, children: NotionBlock[]): Promise<NotionBlockRef[]> {
    this.appendCalls.push({ blockId, count: children.length });
    const refs: NotionBlockRef[] = [];
    for (const c of children) {
      const id = this.newId("blk");
      this.blocks.set(id, { id, type: c.type, archived: false, plainText: plainTextOf(c), parentId: blockId, children: [] });
      this.childrenOf(blockId).push(id);
      refs.push({ id, type: c.type });
    }
    return refs;
  }

  async archiveBlock(blockId: string): Promise<void> {
    if (this.failArchive) throw new Error("archive failed");
    const b = this.blocks.get(blockId);
    if (b) b.archived = true;
  }

  async createPage(parent: NotionParent, title: string): Promise<NotionPageRef> {
    this.createPageCalls.push({ parent, title });
    if (this.failDatabaseCreate && "database_id" in parent) throw new NotionApiError("not a database", 400, "validation");
    const id = this.newId("page");
    this.pages.set(id, { id, url: `https://notion.so/${id}`, children: [] });
    return { id, url: `https://notion.so/${id}` };
  }
}

class MemStore implements NotionExportStoreLike {
  data = new Map<string, NotionExport>();
  async load(caseId: string): Promise<NotionExport> { return this.data.get(caseId) ?? notionExportSchema.parse({}); }
  async record(caseId: string, patch: Partial<NotionExport>): Promise<NotionExport> {
    const next: NotionExport = { ...(this.data.get(caseId) ?? notionExportSchema.parse({})), ...patch };
    this.data.set(caseId, next);
    return next;
  }
}

function finding(i: number, severity: Finding["severity"] = "High"): Finding {
  return {
    id: `f${i}`, severity, title: `Finding ${i}`, description: `desc ${i}`,
    relatedIocs: [], sourceScreenshots: [`cap-${i}.png`], mitreTechniques: ["T1059"],
    firstSeen: AT, lastUpdated: AT, status: "open",
  };
}

function sampleState(): InvestigationState {
  return {
    ...emptyState("Case Alpha"),
    findings: [finding(1, "Critical"), finding(2, "High")],
    iocs: [{ id: "i1", type: "ip", value: "8.8.8.8", firstSeen: AT }],
    forensicTimeline: [
      { id: "e1", timestamp: "2026-06-04T10:00:00Z", description: "logon to DC01", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "DC01" },
    ],
  };
}

describe("pushCaseToNotion", () => {
  it("creates a new page as a database row, builds the container, and records the pointer", async () => {
    const m = new MockNotion();
    const store = new MemStore();
    const res = await pushCaseToNotion(
      m, { caseName: "Case Alpha", state: sampleState() },
      { mode: "new", databaseId: "db-123" }, { exportedAt: AT, sleep: noop }, store,
    );
    expect(m.meCalled).toBe(true);
    expect(res.created).toBe(true);
    expect(m.createPageCalls).toHaveLength(1);
    expect(m.createPageCalls[0].parent).toEqual({ database_id: "db-123" });
    expect(m.createPageCalls[0].title).toContain("Case Alpha");
    expect(res.containerBlockId).toBeTruthy();
    expect(res.blocksAppended).toBeGreaterThan(0);
    const saved = await store.load("Case Alpha");
    expect(saved.pageId).toBe(res.pageId);
    expect(saved.containerBlockId).toBe(res.containerBlockId);
    expect(saved.databaseId).toBe("db-123");
  });

  it("exports into an existing page (empty store) without creating a page", async () => {
    const m = new MockNotion();
    m.seedPage("page-1");
    const store = new MemStore();
    const res = await pushCaseToNotion(
      m, { caseName: "c1", state: sampleState() },
      { mode: "existing", pageId: "page-1" }, { exportedAt: AT, sleep: noop }, store,
    );
    expect(m.createPageCalls).toHaveLength(0);
    expect(res.created).toBe(false);
    const pageChildren = await m.listChildren("page-1");
    expect(pageChildren.some((b) => b.type === "toggle")).toBe(true);
    expect((await store.load("c1")).pageId).toBe("page-1");
  });

  it("re-export refreshes the managed container and never archives the user's own blocks", async () => {
    const m = new MockNotion();
    m.seedPage("page-1");
    const userNote = m.seedBlock("page-1", "paragraph", "my investigator note"); // OUTSIDE the container
    const store = new MemStore();
    await pushCaseToNotion(m, { caseName: "c1", state: sampleState() }, { mode: "existing", pageId: "page-1" }, { exportedAt: AT, sleep: noop }, store);
    const container = (await store.load("c1")).containerBlockId;

    const res2 = await pushCaseToNotion(m, { caseName: "c1", state: sampleState() }, { mode: "existing", pageId: "page-1" }, { exportedAt: AT, sleep: noop }, store);
    expect(res2.containerRecreated).toBe(false);
    expect(res2.containerBlockId).toBe(container);      // same container reused
    expect(res2.blocksArchived).toBeGreaterThan(0);     // old container children archived
    expect(m.blocks.get(userNote)!.archived).toBe(false); // user note survived
    expect((await m.listChildren("page-1")).some((b) => b.id === userNote)).toBe(true);
  });

  it("recreates the container when the user deleted it", async () => {
    const m = new MockNotion();
    m.seedPage("page-1");
    const store = new MemStore();
    await pushCaseToNotion(m, { caseName: "c1", state: sampleState() }, { mode: "existing", pageId: "page-1" }, { exportedAt: AT, sleep: noop }, store);
    const container = (await store.load("c1")).containerBlockId;
    await m.archiveBlock(container); // user trashed the managed block

    const res = await pushCaseToNotion(m, { caseName: "c1", state: sampleState() }, { mode: "existing", pageId: "page-1" }, { exportedAt: AT, sleep: noop }, store);
    expect(res.containerRecreated).toBe(true);
    expect(res.containerBlockId).not.toBe(container);
  });

  it("batches content into ≤100-block appends", async () => {
    const m = new MockNotion();
    const store = new MemStore();
    const big: InvestigationState = { ...emptyState("big"), findings: Array.from({ length: 40 }, (_, i) => finding(i)) };
    const res = await pushCaseToNotion(m, { caseName: "big", state: big }, { mode: "new", databaseId: "db" }, { exportedAt: AT, sleep: noop }, store);
    const contentAppends = m.appendCalls.filter((a) => a.blockId === res.containerBlockId);
    expect(contentAppends.length).toBeGreaterThan(1);
    for (const a of contentAppends) expect(a.count).toBeLessThanOrEqual(100);
  });

  it("falls back to a parent page when the supplied 'new target' id is a page, not a database", async () => {
    const m = new MockNotion();
    m.failDatabaseCreate = true; // the id isn't a database
    const store = new MemStore();
    // The dashboard sends the same id as both database and parent.
    const res = await pushCaseToNotion(
      m, { caseName: "c1", state: sampleState() },
      { mode: "new", databaseId: "x", parentPageId: "x" }, { exportedAt: AT, sleep: noop }, store,
    );
    expect(res.created).toBe(true);
    // First create attempt was as a database (failed), then a successful parent-page create.
    expect(m.createPageCalls[0].parent).toEqual({ database_id: "x" });
    expect(m.createPageCalls[1].parent).toEqual({ page_id: "x" });
    expect((await store.load("c1")).databaseId).toBe(""); // recorded as a page parent, not a DB
  });

  it("treats a failed archive as a non-fatal warning and still appends", async () => {
    const m = new MockNotion();
    m.seedPage("page-1");
    const store = new MemStore();
    await pushCaseToNotion(m, { caseName: "c1", state: sampleState() }, { mode: "existing", pageId: "page-1" }, { exportedAt: AT, sleep: noop }, store);
    m.failArchive = true;
    const res = await pushCaseToNotion(m, { caseName: "c1", state: sampleState() }, { mode: "existing", pageId: "page-1" }, { exportedAt: AT, sleep: noop }, store);
    expect(res.warnings.length).toBeGreaterThan(0);
    expect(res.blocksAppended).toBeGreaterThan(0);
  });
});
