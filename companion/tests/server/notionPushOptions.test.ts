import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { notionPushOptions } from "../../src/server.js";

describe("notionPushOptions", () => {
  const savedEnv = { ...process.env };
  afterEach(() => {
    process.env = { ...savedEnv };
  });

  it("passes through a bare id unchanged", () => {
    process.env.DFIR_NOTION_DATABASE_ID = "c65caad5aaaa4444bbbb888888888888";
    process.env.DFIR_NOTION_PARENT_PAGE_ID = "";
    const opts = notionPushOptions();
    expect(opts.databaseId).toBe("c65caad5-aaaa-4444-bbbb-888888888888");
  });

  it("extracts the id from a full Notion URL, matching the request-body parsing path", () => {
    process.env.DFIR_NOTION_DATABASE_ID = "https://notion.com/p/tenroot/c65caad5aaaa4444bbbb888888888888";
    const opts = notionPushOptions();
    expect(opts.databaseId).toBe("c65caad5-aaaa-4444-bbbb-888888888888");
  });

  it("is undefined when unset, not an empty/unparsed string", () => {
    delete process.env.DFIR_NOTION_DATABASE_ID;
    delete process.env.DFIR_NOTION_PARENT_PAGE_ID;
    const opts = notionPushOptions();
    expect(opts.databaseId).toBeUndefined();
    expect(opts.parentPageId).toBeUndefined();
  });
});
