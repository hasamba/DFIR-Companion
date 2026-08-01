import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildClickUpClient,
  buildIrisClient,
  buildJiraClient,
  buildMispPushClient,
  buildNotionClient,
  buildServiceNowClient,
  buildTimesketchClient,
  irisPushOptions,
  mispPushOptions,
  notionPushOptions,
} from "../../src/composition/integrationClients.js";

// The contract every builder in src/composition/integrationClients.ts shares, asserted once per
// integration rather than described once in a comment (#384).
//
// It is a small contract and that is the point: read env, return a client, or return undefined when
// the integration is not configured. `undefined` is not an error path — it is how an optional
// integration stays switched off, and it is what hides the corresponding dashboard button. Getting
// that backwards for one integration (throwing, or returning a half-built client that fails on
// first use) would surface as a broken dashboard for operators who never configured it, which is
// the population least able to diagnose it.
//
// These tests were added when the builders moved out of server.ts. They pass identically before and
// after the move — which is the useful property, since a behaviour-preserving extraction should be
// provable rather than asserted.

interface Case {
  name: string;
  build: () => unknown;
  /** The complete configuration. Every key is required for the builder to return a client. */
  env: Record<string, string>;
}

const CASES: Case[] = [
  {
    name: "IRIS",
    build: buildIrisClient,
    env: { DFIR_IRIS_URL: "https://iris.example", DFIR_IRIS_KEY: "k" },
  },
  {
    name: "Timesketch",
    build: buildTimesketchClient,
    env: {
      DFIR_TIMESKETCH_URL: "https://ts.example",
      DFIR_TIMESKETCH_USER: "u",
      DFIR_TIMESKETCH_PASSWORD: "p",
    },
  },
  {
    name: "MISP",
    build: buildMispPushClient,
    env: { DFIR_MISP_URL: "https://misp.example", DFIR_MISP_KEY: "k" },
  },
  { name: "Notion", build: buildNotionClient, env: { DFIR_NOTION_TOKEN: "t" } },
  { name: "ClickUp", build: buildClickUpClient, env: { DFIR_CLICKUP_TOKEN: "t" } },
  {
    name: "Jira",
    build: buildJiraClient,
    env: {
      DFIR_JIRA_URL: "https://jira.example",
      DFIR_JIRA_USER: "u",
      DFIR_JIRA_TOKEN: "t",
    },
  },
  {
    name: "ServiceNow",
    build: buildServiceNowClient,
    env: {
      DFIR_SERVICENOW_URL: "https://snow.example",
      DFIR_SERVICENOW_USER: "u",
      DFIR_SERVICENOW_PASSWORD: "p",
    },
  },
];

/** Every DFIR_ var any case touches, cleared between tests so one case cannot configure another. */
const ALL_KEYS = [...new Set(CASES.flatMap((c) => Object.keys(c.env)))];

let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = Object.fromEntries(ALL_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ALL_KEYS) delete process.env[k];
});

afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  vi.unstubAllGlobals();
});

describe.each(CASES)("$name client construction", ({ build, env }) => {
  it("returns undefined when nothing is configured", () => {
    expect(build()).toBeUndefined();
  });

  it("returns a client when every variable is set", () => {
    Object.assign(process.env, env);
    expect(build()).toBeDefined();
  });

  it.each(Object.keys(env))("returns undefined when %s alone is missing", (missing) => {
    Object.assign(process.env, env);
    delete process.env[missing];
    // Every field in these builders is required; a partially configured integration must stay off
    // rather than construct a client that fails on first use, somewhere far from the cause.
    expect(build()).toBeUndefined();
  });

  it("treats a blank value as unset", () => {
    Object.assign(process.env, env);
    const [first] = Object.keys(env);
    process.env[first] = "";
    expect(build()).toBeUndefined();
  });

  it("makes no network call while constructing", () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    Object.assign(process.env, env);
    expect(build()).toBeDefined();
    // Construction reads env and stores it. Reaching the network here would turn server startup
    // into something that can hang or fail on an unreachable integration host.
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("numeric option parsing", () => {
  it("drops a non-numeric IRIS customer id rather than passing NaN", () => {
    process.env.DFIR_IRIS_CUSTOMER_ID = "not-a-number";
    expect(irisPushOptions().customerId).toBeUndefined();
  });

  it("drops a zero IRIS customer id, which is not a real id", () => {
    process.env.DFIR_IRIS_CUSTOMER_ID = "0";
    expect(irisPushOptions().customerId).toBeUndefined();
    delete process.env.DFIR_IRIS_CUSTOMER_ID;
  });

  it.each(["", "0", "-5", "3.5", "abc"])(
    "ignores %o as a MISP timeline limit and falls back to the default",
    (raw) => {
      process.env.DFIR_MISP_TIMELINE_LIMIT = raw;
      // positiveIntEnv exists because `Number(x) || undefined` accepted "0" here, and a cap of zero
      // means the push silently sends no timeline at all rather than using the documented default.
      expect(mispPushOptions().timelineLimit).toBeUndefined();
      delete process.env.DFIR_MISP_TIMELINE_LIMIT;
    },
  );

  it("keeps a valid MISP timeline limit", () => {
    process.env.DFIR_MISP_TIMELINE_LIMIT = "2500";
    expect(mispPushOptions().timelineLimit).toBe(2500);
    delete process.env.DFIR_MISP_TIMELINE_LIMIT;
  });

  it("normalizes a full Notion URL into the dashed page id the API expects", () => {
    process.env.DFIR_NOTION_PARENT_PAGE_ID =
      "https://www.notion.so/Some-Page-1234567890abcdef1234567890abcdef";
    // Operators paste the URL from the browser; the API rejects it unparsed. Note the output is the
    // DASHED uuid form, not the bare hex that appears in the URL — that is the shape Notion wants,
    // and it is the reason this normalization exists rather than a plain substring.
    expect(notionPushOptions().parentPageId).toBe("12345678-90ab-cdef-1234-567890abcdef");
    delete process.env.DFIR_NOTION_PARENT_PAGE_ID;
  });
});
