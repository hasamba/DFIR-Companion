// Server sets: named bundles of IRIS / Timesketch / Velociraptor connection settings. A case
// links to one set. Secrets are sealed on disk and masked in every API response.

import type { IrisClient } from "../iris/irisClient.js";
import type { IrisPushOptions } from "../iris/irisPush.js";
import type { TimesketchClient } from "../timesketch/timesketchClient.js";
import type { TimesketchPushOptions } from "../timesketch/timesketchPush.js";
import type { VelociraptorClient } from "../velociraptor/velociraptorApi.js";

export const MASKED_SECRET = "••••••";

export interface IrisSettings {
  url: string;
  apiKey: string;
  ca?: string;
  insecure?: boolean;
  customerId?: string;
  classificationId?: string;
}

export interface TimesketchSettings {
  url: string;
  user: string;
  password: string;
  ca?: string;
  insecure?: boolean;
  timeline?: string;
}

export interface VelociraptorSettings {
  apiConfigPath: string;
  org?: string;
  guiUrl?: string;
}

export interface ServerSet {
  id: string;
  name: string;
  revision: number;
  iris?: IrisSettings;
  timesketch?: TimesketchSettings;
  velociraptor?: VelociraptorSettings;
}

export type ServerSetInput = Omit<ServerSet, "id" | "revision">;
export type ToolName = "iris" | "timesketch" | "velociraptor";
export const TOOL_NAMES: readonly ToolName[] = ["iris", "timesketch", "velociraptor"];
export const TOOL_LABEL: Record<ToolName, string> = {
  iris: "IRIS",
  timesketch: "Timesketch",
  velociraptor: "Velociraptor",
};

const has = (v: unknown): boolean => typeof v === "string" && v.trim() !== "";

// Required fields per tool. A tool with some fields set but a required one empty is incomplete.
// A tool that is absent or fully empty means "the case does not use this tool".
export function incompleteTools(set: ServerSetInput): ToolName[] {
  const out: ToolName[] = [];
  const i = set.iris;
  if (
    i &&
    [i.url, i.apiKey, i.ca, i.customerId, i.classificationId].some(has) &&
    !(has(i.url) && has(i.apiKey))
  ) {
    out.push("iris");
  }
  const t = set.timesketch;
  if (
    t &&
    [t.url, t.user, t.password, t.ca, t.timeline].some(has) &&
    !(has(t.url) && has(t.user) && has(t.password))
  ) {
    out.push("timesketch");
  }
  const v = set.velociraptor;
  if (v && [v.apiConfigPath, v.org, v.guiUrl].some(has) && !has(v.apiConfigPath)) out.push("velociraptor");
  return out;
}

export function maskServerSet(set: ServerSet): ServerSet {
  const out: ServerSet = { ...set };
  if (set.iris) out.iris = { ...set.iris, apiKey: set.iris.apiKey ? MASKED_SECRET : "" };
  if (set.timesketch)
    out.timesketch = { ...set.timesketch, password: set.timesketch.password ? MASKED_SECRET : "" };
  return out;
}

/** True when the input still holds the mask in place of a secret. */
export function hasMaskedSecret(input: ServerSetInput): boolean {
  return input.iris?.apiKey === MASKED_SECRET || input.timesketch?.password === MASKED_SECRET;
}

/** The input with each masked secret replaced by the stored one from `prev` ("" when none). */
export function withStoredSecrets(input: ServerSetInput, prev: ServerSetInput): ServerSetInput {
  const out: ServerSetInput = { ...input };
  if (input.iris) {
    const apiKey = input.iris.apiKey === MASKED_SECRET ? (prev.iris?.apiKey ?? "") : input.iris.apiKey;
    out.iris = { ...input.iris, apiKey };
  }
  if (input.timesketch) {
    const keep = input.timesketch.password === MASKED_SECRET;
    out.timesketch = {
      ...input.timesketch,
      password: keep ? (prev.timesketch?.password ?? "") : input.timesketch.password,
    };
  }
  return out;
}

// The clients one set yields. A tool the set does not use is undefined.
export interface CaseServers {
  setId: string;
  setName: string;
  iris?: IrisClient;
  irisPush?: IrisPushOptions;
  timesketch?: TimesketchClient;
  timesketchPush?: TimesketchPushOptions;
  velociraptor?: VelociraptorClient;
}

/** A case's set gave no usable client. `status` is what a route answers: 409 unresolved, 501 tool absent. */
export class ServerSetUnavailableError extends Error {
  constructor(
    message: string,
    readonly status: 409 | 501,
  ) {
    super(message);
    this.name = "ServerSetUnavailableError";
  }
}

export type ResolveResult = { ok: true; servers: CaseServers } | { ok: false; status: 409; error: string };

/** Clients built from typed values, and why a tool got none (incomplete, or its build failed). */
export interface InputServers {
  servers: CaseServers;
  errors: Partial<Record<ToolName, string>>;
}

export interface ServerClients {
  forCase(caseId: string): ResolveResult;
  forDefault(): ResolveResult;
  forSet(setId: string): ResolveResult;
  /** Builds clients from `set` as given: no cache, no store. For the editor's connection tests. */
  forInput(set: ServerSet): InputServers;
  invalidate(setId?: string): void;
}
