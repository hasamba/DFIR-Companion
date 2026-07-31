import type { ForensicEvent } from "./stateTypes.js";
import type { HuntFieldCatalogueEntry, HuntFieldType } from "./huntQueryTypes.js";

type FieldValue = string | number | boolean | null | undefined | string[];

interface HuntFieldDefinition extends HuntFieldCatalogueEntry {
  read(event: ForensicEvent): FieldValue;
}

function canonicalPath(event: ForensicEvent, path: string): unknown {
  let value: unknown = event.canonical;
  for (const part of path.split(".")) {
    if (value == null || typeof value !== "object") return undefined;
    value = (value as Record<string, unknown>)[part];
  }
  return value;
}

function canonical(
  name: string,
  type: HuntFieldType,
  path: string,
  description: string,
  options: {
    indexed?: boolean;
    aliases?: string[];
    fallback?: (event: ForensicEvent) => FieldValue;
  } = {},
): HuntFieldDefinition {
  return {
    name,
    type,
    description,
    indexed: options.indexed ?? false,
    ...(options.aliases ? { aliases: options.aliases } : {}),
    read: (event) => {
      const value = canonicalPath(event, path);
      return value == null ? options.fallback?.(event) : (value as FieldValue);
    },
  };
}

function legacy(
  entry: HuntFieldCatalogueEntry,
  read: (event: ForensicEvent) => FieldValue,
): HuntFieldDefinition {
  return { ...entry, read };
}

function entityField(
  prefix: "actor" | "subject" | "object" | "target",
  leaf: "kind" | "id" | "name" | "domain" | "address" | "port",
  type: HuntFieldType = "keyword",
): HuntFieldDefinition {
  return canonical(
    `${prefix}.${leaf}`,
    type,
    `${prefix}.${leaf}`,
    `${leaf} of the canonical ${prefix} entity`,
  );
}

const definitions: HuntFieldDefinition[] = [
  legacy(
    {
      name: "id",
      type: "keyword",
      description: "Stable forensic event identifier",
      indexed: true,
      aliases: ["event.id"],
    },
    (event) => event.id,
  ),
  legacy(
    {
      name: "timestamp",
      type: "timestamp",
      description: "Normalized event time",
      indexed: true,
      aliases: ["@timestamp"],
    },
    (event) => event.timestamp,
  ),
  legacy(
    {
      name: "original_timestamp",
      type: "timestamp",
      description: "Original recorded time before clock-skew projection",
      indexed: false,
    },
    (event) => event.originalTimestamp,
  ),
  legacy(
    {
      name: "description",
      type: "string",
      description: "Analyst-facing event summary",
      indexed: false,
    },
    (event) => event.description,
  ),
  legacy(
    {
      name: "message",
      type: "string",
      description: "Full source message when retained",
      indexed: false,
    },
    (event) => event.message,
  ),
  legacy(
    {
      name: "severity",
      type: "keyword",
      description: "DFIR Companion event severity",
      indexed: true,
    },
    (event) => event.severity,
  ),
  legacy(
    {
      name: "host.name",
      type: "keyword",
      description: "Affected host or asset",
      indexed: true,
      aliases: ["asset"],
    },
    (event) =>
      event.asset ??
      (canonicalPath(event, "target.kind") === "host"
        ? (canonicalPath(event, "target.name") as string | undefined)
        : undefined),
  ),
  legacy(
    {
      name: "event.source",
      type: "keyword",
      description: "Producing artifact or collection source",
      indexed: true,
      aliases: ["source", "artifact"],
    },
    (event) =>
      [event.artifactName, ...(event.sources ?? [])].filter((value): value is string => Boolean(value)),
  ),
  canonical(
    "event.category",
    "keyword",
    "event.category",
    "Normalized event family such as authentication, process or network",
  ),
  canonical("event.type", "keyword", "event.type", "Normalized event type"),
  canonical("event.action", "keyword", "event.action", "Normalized action", {
    fallback: (event) => event.action,
  }),
  canonical("event.outcome", "keyword", "event.outcome", "Normalized success or failure outcome", {
    aliases: ["outcome"],
  }),
  canonical("user.name", "keyword", "account.name", "Normalized account name", {
    aliases: ["account.name"],
    fallback: (event) =>
      canonicalPath(event, "actor.kind") === "account"
        ? (canonicalPath(event, "actor.name") as string | undefined)
        : undefined,
  }),
  canonical("user.id", "keyword", "account.id", "Normalized account identifier", { aliases: ["account.id"] }),
  canonical("user.domain", "keyword", "account.domain", "Normalized account domain", {
    aliases: ["account.domain"],
  }),
  canonical("source.ip", "keyword", "network.source.address", "Source network address", {
    indexed: true,
    fallback: (event) => event.srcIp,
  }),
  canonical("source.port", "number", "network.source.port", "Source network port"),
  canonical("source.hostname", "keyword", "network.source.hostname", "Source hostname"),
  canonical("destination.ip", "keyword", "network.destination.address", "Destination network address", {
    indexed: true,
    fallback: (event) => event.dstIp,
  }),
  canonical("destination.port", "number", "network.destination.port", "Destination network port", {
    fallback: (event) => event.port,
  }),
  canonical("destination.hostname", "keyword", "network.destination.hostname", "Destination hostname"),
  canonical("network.protocol", "keyword", "network.protocol", "Normalized network protocol"),
  canonical("process.name", "keyword", "process.name", "Subject process name", {
    fallback: (event) => event.processName,
  }),
  canonical("process.pid", "number", "process.pid", "Subject process identifier", {
    fallback: (event) => event.pid,
  }),
  canonical("process.executable", "string", "process.executable", "Subject process executable path", {
    fallback: (event) => event.path,
  }),
  canonical("process.command_line", "string", "process.commandLine", "Subject process command line", {
    aliases: ["process.commandline"],
    fallback: (event) => event.commandLine,
  }),
  canonical("process.parent.name", "keyword", "process.parent.name", "Parent process name", {
    fallback: (event) => event.parentName,
  }),
  canonical("process.parent.pid", "number", "process.parent.pid", "Parent process identifier"),
  canonical(
    "process.parent.executable",
    "string",
    "process.parent.executable",
    "Parent process executable path",
  ),
  canonical("file.path", "string", "file.path", "Normalized file path", {
    indexed: true,
    aliases: ["path"],
    fallback: (event) => event.path,
  }),
  canonical("file.name", "keyword", "file.name", "Normalized file name"),
  canonical("file.sha256", "keyword", "file.sha256", "SHA-256 file hash", {
    indexed: true,
    aliases: ["sha256"],
    fallback: (event) => event.sha256,
  }),
  canonical("file.md5", "keyword", "file.md5", "MD5 file hash", {
    indexed: true,
    aliases: ["md5"],
    fallback: (event) => event.md5,
  }),
  canonical("registry.key", "string", "registry.key", "Registry key path"),
  canonical("registry.value_name", "keyword", "registry.valueName", "Registry value name"),
  canonical("registry.value_data", "string", "registry.valueData", "Registry value data"),
  canonical("service.name", "keyword", "service.name", "Service name"),
  canonical("service.display_name", "string", "service.displayName", "Service display name"),
  canonical("service.executable", "string", "service.executable", "Service executable"),
  canonical("task.name", "keyword", "task.name", "Scheduled task name"),
  canonical("task.command", "string", "task.command", "Scheduled task command"),
  canonical(
    "authentication.session_id",
    "keyword",
    "authentication.sessionId",
    "Authentication session identifier",
  ),
  canonical("authentication.logon_type", "number", "authentication.logonType", "Windows logon type"),
  canonical("authentication.protocol", "keyword", "authentication.protocol", "Authentication protocol"),
  canonical("session.id", "keyword", "session.id", "Normalized session identifier"),
  canonical("session.interactive", "boolean", "session.interactive", "Whether the session is interactive"),
  canonical("cloud.provider", "keyword", "cloud.provider", "Cloud provider"),
  canonical("cloud.principal_id", "keyword", "cloud.principalId", "Cloud principal identifier"),
  canonical("cloud.tenant", "keyword", "cloud.tenant", "Cloud tenant"),
  canonical("cloud.region", "keyword", "cloud.region", "Cloud region"),
  canonical("cloud.resource", "string", "cloud.resource", "Cloud resource"),
  canonical("mailbox.sender", "keyword", "mailbox.sender", "Message sender"),
  canonical("mailbox.recipient", "keyword", "mailbox.recipients", "Message recipient"),
  canonical("mailbox.subject", "string", "mailbox.subject", "Message subject"),
  ...(["actor", "subject", "object", "target"] as const).flatMap((prefix) => [
    entityField(prefix, "kind"),
    entityField(prefix, "id"),
    entityField(prefix, "name"),
    entityField(prefix, "domain"),
    entityField(prefix, "address"),
    entityField(prefix, "port", "number"),
  ]),
  legacy(
    {
      name: "mitre.technique",
      type: "keyword",
      description: "MITRE ATT&CK technique identifier",
      indexed: true,
      aliases: ["mitre"],
    },
    (event) => event.mitreTechniques,
  ),
  legacy(
    {
      name: "related.finding_id",
      type: "keyword",
      description: "Finding identifier citing or cited by the event",
      indexed: false,
    },
    (event) => event.relatedFindingIds,
  ),
  legacy(
    {
      name: "evidence.screenshot",
      type: "string",
      description: "Source screenshot path",
      indexed: false,
    },
    (event) => event.sourceScreenshots,
  ),
  legacy(
    {
      name: "count",
      type: "number",
      description: "Number of collapsed occurrences",
      indexed: false,
    },
    (event) => event.count ?? 1,
  ),
  legacy(
    {
      name: "ioc",
      type: "keyword",
      description: "Any indexed indicator value carried by the event",
      indexed: true,
    },
    (event) =>
      [
        event.srcIp,
        event.dstIp,
        event.sha256,
        event.md5,
        event.path,
        canonicalPath(event, "network.source.address"),
        canonicalPath(event, "network.destination.address"),
        canonicalPath(event, "file.sha256"),
        canonicalPath(event, "file.md5"),
        canonicalPath(event, "file.path"),
      ].filter((value): value is string => typeof value === "string" && value.length > 0),
  ),
];

const byName = new Map<string, HuntFieldDefinition>();
for (const definition of definitions) {
  byName.set(definition.name.toLowerCase(), definition);
  for (const alias of definition.aliases ?? []) {
    byName.set(alias.toLowerCase(), definition);
  }
}

export const HUNT_FIELD_CATALOGUE: readonly HuntFieldCatalogueEntry[] = definitions.map(
  ({ read: _read, ...entry }) => entry,
);

export function resolveHuntField(name: string): HuntFieldCatalogueEntry | undefined {
  const definition = byName.get(name.toLowerCase());
  if (!definition) return undefined;
  const { read: _read, ...entry } = definition;
  return entry;
}

export function canonicalHuntFieldName(name: string): string | undefined {
  return byName.get(name.toLowerCase())?.name;
}

export function readHuntField(event: ForensicEvent, name: string): FieldValue {
  return byName.get(name.toLowerCase())?.read(event);
}

function editDistance(left: string, right: string): number {
  const prior = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let row = 1; row <= left.length; row++) {
    let diagonal = prior[0];
    prior[0] = row;
    for (let column = 1; column <= right.length; column++) {
      const above = prior[column];
      prior[column] = Math.min(
        prior[column] + 1,
        prior[column - 1] + 1,
        diagonal + (left[row - 1] === right[column - 1] ? 0 : 1),
      );
      diagonal = above;
    }
  }
  return prior[right.length];
}

export function suggestHuntFields(name: string, limit = 3): string[] {
  const lower = name.toLowerCase();
  return definitions
    .map((definition) => ({
      name: definition.name,
      distance: editDistance(lower, definition.name.toLowerCase()),
    }))
    .sort((left, right) => left.distance - right.distance || left.name.localeCompare(right.name))
    .slice(0, limit)
    .map((item) => item.name);
}
