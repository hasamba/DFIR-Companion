import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { notionPushOptions } from "../../src/server.js";

describe("notionPushOptions", () => {
  const savedEnv = { ...process.env };
  afterEach(() => {
    process.env = { ...savedEnv };
  });

  it("passes through a bare id unchanged", () => {
    process.env.DFIR_NOTION_DATABASE_ID = "11111111aaaa2222bbbb333333333333";
    process.env.DFIR_NOTION_PARENT_PAGE_ID = "";
    const opts = notionPushOptions();
    expect(opts.databaseId).toBe("11111111-aaaa-2222-bbbb-333333333333");
  });

  it("extracts the id from a full Notion URL, matching the request-body parsing path", () => {
    process.env.DFIR_NOTION_DATABASE_ID = "https://notion.com/p/acme-workspace/11111111aaaa2222bbbb333333333333";
    const opts = notionPushOptions();
    expect(opts.databaseId).toBe("11111111-aaaa-2222-bbbb-333333333333");
  });

  it("is undefined when unset, not an empty/unparsed string", () => {
    delete process.env.DFIR_NOTION_DATABASE_ID;
    delete process.env.DFIR_NOTION_PARENT_PAGE_ID;
    const opts = notionPushOptions();
    expect(opts.databaseId).toBeUndefined();
    expect(opts.parentPageId).toBeUndefined();
  });
});
