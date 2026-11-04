// Boundary checks for the /server-sets routes: the request body becomes a ServerSetInput that holds
// only the known fields, and a connection-test error becomes a short message that can name no
// secret and echo no remote response.
import {
  TOOL_NAMES,
  type IrisSettings,
  type ServerSetInput,
  type TimesketchSettings,
  type ToolName,
  type VelociraptorSettings,
} from "../integrations/serverSets/types.js";

type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

const MAX_FIELD = 2048;
const MAX_ERROR = 200;

function str(obj: Record<string, unknown>, tool: string, key: string): string | undefined {
  const v = obj[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "string") throw new Error(`${tool}.${key} must be a string`);
  if (v.length > MAX_FIELD) throw new Error(`${tool}.${key} is too long`);
  return v.trim();
}

function bool(obj: Record<string, unknown>, tool: string, key: string): boolean | undefined {
  const v = obj[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "boolean") throw new Error(`${tool}.${key} must be true or false`);
  return v;
}

function section(body: Record<string, unknown>, tool: string): Record<string, unknown> | undefined {
  const v = body[tool];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "object" || Array.isArray(v)) throw new Error(`${tool} must be an object`);
  return v as Record<string, unknown>;
}

// Drops keys whose value is undefined, so a stored set carries no empty placeholders.
function compact<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}

// A tool whose every text field is empty is "not used" and is left out of the set.
const anyText = (o: object): boolean => Object.values(o).some((v) => typeof v === "string" && v !== "");

function iris(body: Record<string, unknown>): IrisSettings | undefined {
  const s = section(body, "iris");
  if (!s) return undefined;
  const out = compact<IrisSettings>({
    url: str(s, "iris", "url") ?? "",
    apiKey: str(s, "iris", "apiKey") ?? "",
    ca: str(s, "iris", "ca"),
    insecure: bool(s, "iris", "insecure"),
    customerId: str(s, "iris", "customerId"),
    classificationId: str(s, "iris", "classificationId"),
  });
  return anyText(out) ? out : undefined;
}

function timesketch(body: Record<string, unknown>): TimesketchSettings | undefined {
  const s = section(body, "timesketch");
  if (!s) return undefined;
  const out = compact<TimesketchSettings>({
    url: str(s, "timesketch", "url") ?? "",
    user: str(s, "timesketch", "user") ?? "",
    password: str(s, "timesketch", "password") ?? "",
    ca: str(s, "timesketch", "ca"),
    insecure: bool(s, "timesketch", "insecure"),
    timeline: str(s, "timesketch", "timeline"),
  });
  return anyText(out) ? out : undefined;
}

function velociraptor(body: Record<string, unknown>): VelociraptorSettings | undefined {
  const s = section(body, "velociraptor");
  if (!s) return undefined;
  const out = compact<VelociraptorSettings>({
    apiConfigPath: str(s, "velociraptor", "apiConfigPath") ?? "",
    org: str(s, "velociraptor", "org"),
    guiUrl: str(s, "velociraptor", "guiUrl"),
  });
  return anyText(out) ? out : undefined;
}

/** The body as a ServerSetInput with only the known fields, or the reason it is refused. */
export function parseServerSetInput(raw: unknown): Parsed<ServerSetInput> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, error: "body must be an object" };
  }
  const body = raw as Record<string, unknown>;
  try {
    if (typeof body.name !== "string") throw new Error("name required");
    return {
      ok: true,
      value: compact<ServerSetInput>({
        name: body.name,
        iris: iris(body),
        timesketch: timesketch(body),
        velociraptor: velociraptor(body),
      }),
    };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

/** The optional `tools` list of a connection test: every tool when absent, else the named ones. */
export function parseTestTools(raw: unknown): Parsed<ToolName[]> {
  const tools = (raw as { tools?: unknown } | undefined)?.tools;
  if (tools === undefined || tools === null) return { ok: true, value: [...TOOL_NAMES] };
  if (!Array.isArray(tools) || !tools.every((t) => TOOL_NAMES.includes(t as ToolName))) {
    return { ok: false, error: `tools must be a list of: ${TOOL_NAMES.join(", ")}` };
  }
  return { ok: true, value: TOOL_NAMES.filter((t) => tools.includes(t)) };
}

/**
 * A connection-test failure as a short message: the first line only, URL credentials removed, and
 * an IRIS API error cut before the text the remote server sent back.
 */
export function probeError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  const line = (raw.split(/\r?\n/)[0] ?? "")
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/gi, "$1")
    .replace(/^(IRIS error on \S+?):.*$/, "$1");
  return line.length > MAX_ERROR ? `${line.slice(0, MAX_ERROR)}…` : line || "connection test failed";
}
