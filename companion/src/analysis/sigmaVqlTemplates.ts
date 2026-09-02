// One fixed VQL template per Sigma logsource category (#797). The category picks the client-side
// plugin and a fixed field map; a Sigma field outside the map is a refusal, never a warning. Add a
// category only with a fixture proven against a real Velociraptor, not from memory.
//
// Each template materialises ONE stage (`LET <Stage> <= SELECT … FROM <plugin>`) whose columns
// carry the Sigma field names, so the WHERE clause the compiler writes reads like the rule. The
// hunt launcher splits statements on blank lines, so a template never emits one.

export type ColumnKind = "string" | "number" | "ip" | "hashes" | "hash";

export interface TemplateColumn {
  kind: ColumnKind;
  /** VQL expression the WHERE clause uses; defaults to the Sigma field name. */
  expr?: string;
  /** An extra stage or column this field needs; added to the template only when the field is used. */
  needs?: "parent" | "hash" | "procLookup";
  /** The field whose values derive the glob() roots (file and registry templates). */
  globSource?: boolean;
  /** A per-field reason shown instead of the generic "no column" refusal. */
  hint?: string;
}

export interface VqlTemplate {
  categories: readonly string[];
  stage: string;
  /** The plugin call, for the header and the FROM clause. */
  source: string;
  /** Base columns, always selected. */
  baseColumns: readonly string[];
  /** Columns added when a field with the matching `needs` is used, in this order. */
  extraColumns: Readonly<Partial<Record<NonNullable<TemplateColumn["needs"]>, string>>>;
  /** LET stages that precede the main stage, keyed by need. */
  extraStages: Readonly<Partial<Record<NonNullable<TemplateColumn["needs"]>, string>>>;
  /** Canonical Sigma field name → column. Lookup is case-insensitive; refusals list these names. */
  fields: Readonly<Record<string, TemplateColumn>>;
  /** Header sentence: what the plugin covers. `roots` is set for glob templates. */
  coverage: (roots: readonly string[]) => string;
  /** Glob templates: how the FROM clause is built from the derived roots. */
  globFrom?: (roots: readonly string[]) => string;
  registry?: boolean;
  /**
   * True when the plugin reads live state (the process list, open connections, the disk or the
   * registry as they are NOW) rather than an event history. The hunt loop must never record such a
   * query's empty result as a miss (#803). Every v1 template is a snapshot; an event-backed
   * template (Sysmon EID 1 from the endpoint's EVTX, #802) would be the first to say false.
   */
  snapshot: boolean;
}

const BY_PID_PARENT = 'LET ByPid <= memoize(query={ SELECT Pid, Exe, CommandLine FROM pslist() }, key="Pid")';
const BY_PID_IMAGE = 'LET ByPid <= memoize(query={ SELECT Pid, Exe FROM pslist() }, key="Pid")';

export const PROCESS_CREATION: VqlTemplate = {
  categories: ["process_creation"],
  stage: "Procs",
  source: "pslist()",
  baseColumns: ["Pid", "Ppid", "Name", "Exe AS Image", "CommandLine", "Username AS User"],
  extraColumns: {
    hash: "hash(path=Exe) AS Hashes",
    parent:
      "get(item=ByPid, field=str(str=Ppid)).Exe AS ParentImage, get(item=ByPid, field=str(str=Ppid)).CommandLine AS ParentCommandLine",
  },
  extraStages: { parent: BY_PID_PARENT },
  fields: {
    Image: { kind: "string" },
    CommandLine: { kind: "string" },
    ProcessId: { kind: "number", expr: "Pid" },
    ParentProcessId: { kind: "number", expr: "Ppid" },
    User: { kind: "string" },
    ParentImage: { kind: "string", needs: "parent" },
    ParentCommandLine: { kind: "string", needs: "parent" },
    Hashes: { kind: "hashes", needs: "hash" },
    sha256: { kind: "hash", expr: "Hashes.SHA256", needs: "hash" },
    md5: { kind: "hash", expr: "Hashes.MD5", needs: "hash" },
    sha1: { kind: "hash", expr: "Hashes.SHA1", needs: "hash" },
  },
  coverage: () => "pslist(): running processes only, not process history",
  snapshot: true,
};

export const NETWORK_CONNECTION: VqlTemplate = {
  categories: ["network_connection"],
  stage: "Conns",
  source: "netstat()",
  baseColumns: [
    "Pid",
    "Status",
    "Laddr.IP AS SourceIp",
    "Laddr.Port AS SourcePort",
    "Raddr.IP AS DestinationIp",
    "Raddr.Port AS DestinationPort",
  ],
  extraColumns: { procLookup: "get(item=ByPid, field=str(str=Pid)).Exe AS Image" },
  extraStages: { procLookup: BY_PID_IMAGE },
  fields: {
    DestinationIp: { kind: "ip" },
    DestinationPort: { kind: "number" },
    SourceIp: { kind: "ip" },
    SourcePort: { kind: "number" },
    Image: { kind: "string", needs: "procLookup" },
    DestinationHostname: {
      kind: "string",
      hint: "netstat() has no hostname column, so DestinationHostname cannot be matched; use DestinationIp",
    },
  },
  coverage: () => "netstat(): open connections only, not connection history",
  snapshot: true,
};

export const FILE_EVENT: VqlTemplate = {
  categories: ["file_event"],
  stage: "Files",
  source: "glob()",
  baseColumns: ["OSPath AS TargetFilename", "Size", "Mtime"],
  extraColumns: {},
  extraStages: {},
  fields: { TargetFilename: { kind: "string", globSource: true } },
  coverage: (roots) =>
    `glob(): files on disk now under ${roots.join(", ")}` +
    (roots.some((r) => r.startsWith("C:/**")) ? ", which walks the whole disk" : ""),
  globFrom: (roots) => `glob(globs=${listLiteral(roots)})`,
  snapshot: true,
};

export const REGISTRY: VqlTemplate = {
  categories: ["registry_set", "registry_event", "registry_add", "registry_delete"],
  stage: "Keys",
  source: 'glob(accessor="registry")',
  baseColumns: ["OSPath AS TargetObject", "Data.value AS Details", "Mtime"],
  extraColumns: {},
  extraStages: {},
  fields: { TargetObject: { kind: "string", globSource: true }, Details: { kind: "string" } },
  coverage: (roots) =>
    `glob(accessor="registry"): registry keys and values as they are now under ${roots.join(", ")}`,
  globFrom: (roots) => `glob(globs=${listLiteral(roots)}, accessor="registry")`,
  registry: true,
  snapshot: true,
};

export const VQL_TEMPLATES: readonly VqlTemplate[] = [
  PROCESS_CREATION,
  NETWORK_CONNECTION,
  FILE_EVENT,
  REGISTRY,
];

/** Every Sigma logsource category with a template, in display order. */
export const SIGMA_VQL_CATEGORIES: readonly string[] = VQL_TEMPLATES.flatMap((t) => t.categories);

export function templateFor(category: string | undefined): VqlTemplate | undefined {
  if (!category) return undefined;
  const key = category.trim().toLowerCase();
  return VQL_TEMPLATES.find((t) => t.categories.includes(key));
}

/** Case-insensitive field lookup; returns the canonical name with the column. */
export function templateField(
  template: VqlTemplate,
  field: string,
): { name: string; column: TemplateColumn } | undefined {
  const key = field.toLowerCase();
  for (const [name, column] of Object.entries(template.fields)) {
    if (name.toLowerCase() === key) return { name, column };
  }
  return undefined;
}

/** The field names a template answers, for the refusal that names them. Hint-only fields are left out. */
export function templateFieldNames(template: VqlTemplate): string[] {
  return Object.entries(template.fields)
    .filter(([, c]) => !c.hint)
    .map(([name]) => name);
}

function listLiteral(values: readonly string[]): string {
  return `[${values.map((v) => `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`).join(", ")}]`;
}
