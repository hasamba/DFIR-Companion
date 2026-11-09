// The Hunt Workbench's field list and the Grammar reference text (#2461). Split from
// hunt-workbench.js so that file stays under the size limit.

// The client-side fallback field list, used for autocomplete until the server catalogue loads.
export const STATIC_FIELDS = [
  "id",
  "timestamp",
  "description",
  "message",
  "severity",
  "host.name",
  "event.source",
  "event.category",
  "event.type",
  "event.action",
  "event.outcome",
  "user.name",
  "user.domain",
  "source.ip",
  "source.port",
  "destination.ip",
  "destination.port",
  "network.protocol",
  "process.name",
  "process.pid",
  "process.executable",
  "process.command_line",
  "process.parent.name",
  "file.path",
  "file.name",
  "file.sha256",
  "file.md5",
  "registry.key",
  "service.name",
  "task.name",
  "mitre.technique",
  "related.finding_id",
  "ioc",
];

// The grammar reference panel: the grammar, then one "name  type" line per catalogue field.
// The result goes into textContent, never innerHTML.
export function renderCatalog(catalog) {
  const fields = Array.isArray(catalog?.fields) ? catalog.fields : [];
  const width = Math.max(0, ...fields.map((field) => String(field.name).length));
  const fieldLines = fields.map(
    (field) => `  ${String(field.name).padEnd(width)}  ${field.type ?? ""}`,
  );
  const grammar = typeof catalog?.grammar === "string" ? catalog.grammar : "";
  return fieldLines.length
    ? `${grammar}\n\nFields:\n${fieldLines.join("\n")}`
    : grammar;
}
