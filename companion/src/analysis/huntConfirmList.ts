import { itemVerdict } from "./huntApprovalMatch.js";
import { answeringHostCount, itemLabel, type HuntInventory, type InventoryItem } from "./huntInventory.js";
import { markInputSchema, type Baseline, type MarkInput } from "./clientProfile.js";

/**
 * The client's "please confirm" list (#2670). From THIS case's inventory: every item the reviewed
 * baseline does not settle (Unknown), rarest first, with its hosts, path and — where known — publisher
 * (unverified), hashes (SHA-256 and the usable Amcache SHA1) and verified signer. Exported as CSV (formula-injection guarded) and Markdown; the client's filled
 * CSV comes back in through parseClientCsv. PURE.
 */
export interface ConfirmCandidate {
  key: string;
  family: InventoryItem["family"];
  program: string;
  pathPattern: string;
  label: string;
  hostCount: number;
  hosts: string[];
  evidence: string[];
  publishers: string[];
  sha256: string[];
  /** Usable Amcache SHA1s (#2731): size recorded and within 30 MiB. */
  sha1: string[];
  /** Verified signers seen (#2731). */
  signers: string[];
  /** The one verified signer an approval can name: every host verified by it, nothing failed. */
  approvableSigner?: string;
  firstSeen: string;
  reason: string;
}

const HOSTS_LISTED = 20;

export function confirmCandidates(
  inv: HuntInventory,
  baseline: Baseline,
  answered: ReadonlySet<string>,
  now: string,
): ConfirmCandidate[] {
  const out: ConfirmCandidate[] = [];
  for (const item of Object.values(inv.items)) {
    const v = itemVerdict(baseline, { ...item, sha256: item.sha256 }, now);
    if (v.verdict !== "unknown") continue;
    const hosts = Object.values(item.hosts).map((h) => h.hostname);
    out.push({
      key: item.key,
      family: item.family,
      program: item.program,
      pathPattern: item.pathPattern,
      label: itemLabel(item),
      hostCount: answered.size ? answeringHostCount(item, answered) || hosts.length : hosts.length,
      hosts: hosts.sort().slice(0, HOSTS_LISTED),
      evidence: item.evidence,
      publishers: item.publishers,
      sha256: item.sha256,
      sha1: item.sha1 ?? [],
      signers: item.signers ?? [],
      ...signerOf(item),
      firstSeen: item.firstSeen,
      reason: v.reason,
    });
  }
  return out.sort((a, b) => a.hostCount - b.hostCount || a.label.localeCompare(b.label));
}

/** The signer an approval can name: one verified signer covering every host, nothing failed or capped. */
function signerOf(item: InventoryItem): { approvableSigner?: string } {
  const one = item.signers?.length === 1 ? item.signers[0] : undefined;
  const complete =
    item.unsignedHosts?.length === 0 &&
    item.signersCapped === false &&
    !item.signatureUnverified &&
    !item.hostOverflow;
  return one && complete ? { approvableSigner: one } : {};
}

/** One CSV cell: a leading =, +, -, @, tab or CR is neutralised so a spreadsheet never runs it. */
export function csvCell(v: string): string {
  const clean = v.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, " ");
  const guarded = /^[=+\-@\t\r]/.test(clean) ? `'${clean}` : clean;
  return `"${guarded.replace(/"/g, '""')}"`;
}

export const CONFIRM_COLUMNS = [
  "family",
  "program",
  "path_pattern",
  "host_count",
  "hosts",
  "evidence",
  "publisher_unverified",
  "sha256",
  "sha1",
  "signer_verified",
  "first_seen",
  "verdict",
  "note",
] as const;

export function confirmListCsv(list: readonly ConfirmCandidate[]): string {
  const lines = [CONFIRM_COLUMNS.join(",")];
  for (const c of list)
    lines.push(
      [
        c.family,
        c.program,
        c.pathPattern,
        String(c.hostCount),
        c.hosts.join(" "),
        c.evidence.join(" "),
        c.publishers.join(" | "),
        c.sha256.join(" "),
        c.sha1.join(" "),
        c.approvableSigner ?? "",
        c.firstSeen,
        "",
        "",
      ]
        .map(csvCell)
        .join(","),
    );
  return `${lines.join("\r\n")}\r\n`;
}

const mdCell = (v: string): string => v.replace(/[\r\n]+/g, " ").replace(/([\\|`*_[\]<>])/g, "\\$1");

export function confirmListMarkdown(list: readonly ConfirmCandidate[], clientName: string): string {
  const head = [
    `# Please confirm — ${mdCell(clientName)}`,
    "",
    "Mark each item **Approved**, **Not allowed** or **Unknown**. Seeing a program never approves it. Publisher text is as the endpoint reported it and is not verified.",
    "",
    "| Program | Path | Hosts | Evidence | Publisher (unverified) | Verdict |",
    "|---|---|---|---|---|---|",
  ];
  const rows = list.map(
    (c) =>
      `| ${mdCell(c.program)} | ${mdCell(c.pathPattern || "(any)")} | ${c.hostCount}: ${mdCell(c.hosts.join(", "))} | ${mdCell(c.evidence.join(", "))} | ${mdCell(c.publishers.join(" | "))} |  |`,
  );
  return [...head, ...rows, ""].join("\n");
}

/** Minimal RFC 4180 reader: quoted fields, doubled quotes, CRLF or LF. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(cell);
      cell = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else cell += ch;
  }
  if (cell || row.length) rows.push([...row, cell]);
  return rows.filter((r) => r.some((c) => c.trim()));
}

const VERDICTS: Record<string, MarkInput["verdict"]> = {
  approved: "approved",
  approve: "approved",
  yes: "approved",
  "not allowed": "not-allowed",
  "not-allowed": "not-allowed",
  notallowed: "not-allowed",
  blocked: "not-allowed",
  no: "not-allowed",
  unknown: "unknown",
};

const unguard = (v: string): string => (v.startsWith("'") && /^'[=+\-@\t\r]/.test(v) ? v.slice(1) : v).trim();

const listCell = (r: readonly string[], i: number): string[] =>
  i >= 0
    ? unguard(r[i] ?? "")
        .split(/\s+/)
        .filter(Boolean)
    : [];

export interface ClientCsvResult {
  marks: MarkInput[];
  skipped: { line: number; reason: string }[];
}

/** The client's filled confirm list → marks. Rows with no verdict are skipped (still pending). */
export function parseClientCsv(text: string, maxRows = 20_000): ClientCsvResult {
  const [header, ...rows] = parseCsv(text);
  const col = (name: string) => (header ?? []).map((h) => unguard(h).toLowerCase()).indexOf(name);
  const at = {
    family: col("family"),
    program: col("program"),
    path: col("path_pattern"),
    verdict: col("verdict"),
    note: col("note"),
    sha: col("sha256"),
    sha1: col("sha1"),
    signer: col("signer_verified"),
  };
  const out: ClientCsvResult = { marks: [], skipped: [] };
  if (at.program < 0 || at.verdict < 0 || at.family < 0) {
    out.skipped.push({ line: 1, reason: "header must name family, program and verdict" });
    return out;
  }
  rows.slice(0, maxRows).forEach((r, i) => {
    const raw = unguard(r[at.verdict] ?? "").toLowerCase();
    if (!raw) return;
    const verdict = VERDICTS[raw];
    const parsed = markInputSchema.safeParse({
      verdict,
      family: unguard(r[at.family] ?? ""),
      program: unguard(r[at.program] ?? ""),
      pathPattern: at.path >= 0 ? unguard(r[at.path] ?? "") : "",
      sha256:
        at.sha >= 0
          ? unguard(r[at.sha] ?? "")
              .split(/\s+/)
              .filter(Boolean)
          : [],
      sha1: listCell(r, at.sha1),
      ...(at.signer >= 0 && unguard(r[at.signer] ?? "") ? { signer: unguard(r[at.signer] ?? "") } : {}),
      note: at.note >= 0 ? unguard(r[at.note] ?? "") : "",
    });
    if (verdict && parsed.success) out.marks.push(parsed.data);
    else out.skipped.push({ line: i + 2, reason: verdict ? "invalid row" : `unknown verdict "${raw}"` });
  });
  return out;
}
