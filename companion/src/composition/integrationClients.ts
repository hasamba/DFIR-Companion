import { ClickUpClient } from "../integrations/clickup/clickupClient.js";
import { IrisClient } from "../integrations/iris/irisClient.js";
import { type IrisPushOptions } from "../integrations/iris/irisPush.js";
import { JiraClient } from "../integrations/jira/jiraClient.js";
import { MispPushClient } from "../integrations/misp/mispPushClient.js";
import { type MispPushOptions } from "../integrations/misp/mispPush.js";
import { NotionClient, parseNotionPageId } from "../integrations/notion/notionClient.js";
import { type NotionPushOptions } from "../integrations/notion/notionPush.js";
import { ServiceNowClient } from "../integrations/servicenow/servicenowClient.js";
import { TimesketchClient } from "../integrations/timesketch/timesketchClient.js";
import { type TimesketchPushOptions } from "../integrations/timesketch/timesketchPush.js";
import { positiveIntEnv } from "./env.js";
import { tlsFetchFor } from "./tlsFetch.js";

/**
 * Outbound integration clients, built from environment variables (#384, moved from server.ts).
 *
 * Every builder here follows the same contract, and it is the contract that makes the group
 * cohesive enough to be one module: **read env, return a client, or return undefined when the
 * integration is not configured.** `undefined` is not an error path — it is how an optional
 * integration stays switched off, and it is what hides the corresponding dashboard button. None of
 * these functions validate credentials or make a network call; a wrong key surfaces later, from the
 * client, as that integration's own error.
 *
 * They are re-exported from server.ts, because the five push scripts and the wiring tests import
 * them from there.
 */

// Build the DFIR-IRIS push client from env (DFIR_IRIS_URL + DFIR_IRIS_KEY). Returns
// undefined when not configured, which hides the dashboard's "Push to IRIS" button.
// TLS trust for a self-hosted IRIS honors DFIR_IRIS_CA / DFIR_IRIS_INSECURE.
export function buildIrisClient(): IrisClient | undefined {
  const baseUrl = process.env.DFIR_IRIS_URL;
  const apiKey = process.env.DFIR_IRIS_KEY;
  if (!baseUrl || !apiKey) return undefined;
  return new IrisClient({ baseUrl, apiKey, fetchFn: tlsFetchFor("IRIS") });
}

export function irisPushOptions(): IrisPushOptions {
  return {
    baseUrl: process.env.DFIR_IRIS_URL,
    customerId: Number(process.env.DFIR_IRIS_CUSTOMER_ID) || undefined,
    classificationId: Number(process.env.DFIR_IRIS_CLASSIFICATION_ID) || undefined,
  };
}

// Build the Timesketch push client from env (DFIR_TIMESKETCH_URL + USER + PASSWORD). Returns
// undefined when not configured, which hides the dashboard's "Push to Timesketch" button. TLS
// trust for a self-hosted Timesketch honors DFIR_TIMESKETCH_CA / DFIR_TIMESKETCH_INSECURE.
export function buildTimesketchClient(): TimesketchClient | undefined {
  const baseUrl = process.env.DFIR_TIMESKETCH_URL;
  const username = process.env.DFIR_TIMESKETCH_USER;
  const password = process.env.DFIR_TIMESKETCH_PASSWORD;
  if (!baseUrl || !username || !password) return undefined;
  return new TimesketchClient({ baseUrl, username, password, fetchFn: tlsFetchFor("TIMESKETCH") });
}

export function timesketchPushOptions(): TimesketchPushOptions {
  return {
    baseUrl: process.env.DFIR_TIMESKETCH_URL,
    timelineName: process.env.DFIR_TIMESKETCH_TIMELINE || undefined,
  };
}

// Build the MISP push client from env (DFIR_MISP_URL + DFIR_MISP_KEY). Returns undefined
// when not configured, which hides the dashboard's "Push to MISP" button. TLS trust for a
// self-hosted MISP honors DFIR_MISP_CA / DFIR_MISP_INSECURE (same env vars as enrichment).
export function buildMispPushClient(): MispPushClient | undefined {
  const baseUrl = process.env.DFIR_MISP_URL;
  const apiKey = process.env.DFIR_MISP_KEY;
  if (!baseUrl || !apiKey) return undefined;
  return new MispPushClient({ baseUrl, apiKey, fetchFn: tlsFetchFor("MISP") });
}

export function mispPushOptions(): MispPushOptions {
  return {
    baseUrl: process.env.DFIR_MISP_URL,
    distribution: process.env.DFIR_MISP_DISTRIBUTION || undefined,
    analysis: process.env.DFIR_MISP_ANALYSIS || undefined,
    // Cap on forensic-timeline events per push. The push costs one sequential round-trip per
    // event, so an unbounded timeline can block the export route for hours; past the cap the
    // most severe events are kept (Info noise is cut first) and truncation is warned about.
    // Exposed here because the cap is a property of the operator's MISP instance and case sizes,
    // not of the code — the warning text tells the analyst to raise it, so it must be raisable.
    timelineLimit: positiveIntEnv(process.env.DFIR_MISP_TIMELINE_LIMIT),
  };
}

// Build the Notion export client from env (DFIR_NOTION_TOKEN). Returns undefined when not
// configured, which hides the dashboard's "Export to Notion" option. Notion is public SaaS, so
// tlsFetchFor("NOTION") is a no-op unless DFIR_NOTION_CA / DFIR_NOTION_INSECURE are set.
export function buildNotionClient(): NotionClient | undefined {
  const token = process.env.DFIR_NOTION_TOKEN;
  if (!token) return undefined;
  return new NotionClient({ token, fetchFn: tlsFetchFor("NOTION") });
}

export function notionPushOptions(): NotionPushOptions {
  return {
    baseUrl: "https://www.notion.so",
    // Same normalization the request-body page/parent/database fields go through
    // (routes/caseLifecycle.ts parseNotionPageId calls) — an operator's .env value is commonly a
    // full Notion URL, not a bare id, and the client-facing API rejects the unparsed URL.
    parentPageId: parseNotionPageId(process.env.DFIR_NOTION_PARENT_PAGE_ID ?? "") ?? undefined,
    databaseId: parseNotionPageId(process.env.DFIR_NOTION_DATABASE_ID ?? "") ?? undefined,
    containerTitle: process.env.DFIR_NOTION_CONTAINER_TITLE || undefined,
    maxTimelineRows: Number(process.env.DFIR_NOTION_MAX_TIMELINE) || undefined,
  };
}

// Build the ClickUp client from env (DFIR_CLICKUP_TOKEN). Returns undefined when not configured,
// which hides the dashboard's "Push to ClickUp" option. An optional DFIR_CLICKUP_LIST_ID is the
// default target list (the analyst can still override it per push).
export function buildClickUpClient(): ClickUpClient | undefined {
  const token = process.env.DFIR_CLICKUP_TOKEN;
  if (!token) return undefined;
  return new ClickUpClient({ token, fetchFn: tlsFetchFor("CLICKUP") });
}

export function clickupOptions(): { defaultListId?: string } {
  return { defaultListId: process.env.DFIR_CLICKUP_LIST_ID || undefined };
}

// Build the Jira export client from env (DFIR_JIRA_URL + DFIR_JIRA_USER + DFIR_JIRA_TOKEN + optional
// DFIR_JIRA_PROJECT_KEY). Returns undefined when not configured, hiding the dashboard button.
export function buildJiraClient(): JiraClient | undefined {
  const baseUrl = process.env.DFIR_JIRA_URL;
  const user = process.env.DFIR_JIRA_USER;
  const token = process.env.DFIR_JIRA_TOKEN;
  if (!baseUrl || !user || !token) return undefined;
  return new JiraClient({
    baseUrl,
    user,
    token,
    projectKey: process.env.DFIR_JIRA_PROJECT_KEY || "",
    fetchFn: tlsFetchFor("JIRA"),
  });
}

export function jiraOptions(): { projectKey?: string; issueType?: string } {
  return {
    projectKey: process.env.DFIR_JIRA_PROJECT_KEY || undefined,
    issueType: process.env.DFIR_JIRA_ISSUE_TYPE || undefined,
  };
}

// Build the ServiceNow export client from env (DFIR_SERVICENOW_URL + DFIR_SERVICENOW_USER +
// DFIR_SERVICENOW_PASSWORD). Returns undefined when not configured, hiding the dashboard button.
export function buildServiceNowClient(): ServiceNowClient | undefined {
  const baseUrl = process.env.DFIR_SERVICENOW_URL;
  const user = process.env.DFIR_SERVICENOW_USER;
  const password = process.env.DFIR_SERVICENOW_PASSWORD;
  if (!baseUrl || !user || !password) return undefined;
  return new ServiceNowClient({ baseUrl, user, password, fetchFn: tlsFetchFor("SERVICENOW") });
}

export function servicenowOptions(): { caller?: string; category?: string; subcategory?: string } {
  return {
    caller: process.env.DFIR_SERVICENOW_CALLER || undefined,
    category: process.env.DFIR_SERVICENOW_CATEGORY || undefined,
    subcategory: process.env.DFIR_SERVICENOW_SUBCATEGORY || undefined,
  };
}
