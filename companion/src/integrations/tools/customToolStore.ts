import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { atomicWrite } from "../../storage/atomicWrite.js";
import type { ToolConfig } from "./toolConfig.js";

// User-defined external tools (#211) — the extensible counterpart to the built-in Hayabusa/Velociraptor
// CLI/Suricata/Snort/YARA. The analyst adds their OWN tool (name, binary, run command, optional update
// command, and the file extensions it should run on); it then behaves like a built-in in the Import
// dialog + drop folder. GLOBAL + shared across cases (a variable-length list, so a JSON store rather
// than fixed .env keys — mirrors ImporterStore / ArtifactBundleStore). Its output is auto-detected
// (importKind "auto" → detectImportKind) since we don't know each custom tool's format ahead of time.
//
// Security parity with built-ins: the command runs with NO shell (argv-tokenized), from the binary's
// own directory, against a case-contained target path. The user runs their OWN trusted binaries.

export const customToolSchema = z.object({
  id: z.string(),
  name: z.string(),
  binary: z.string(),
  runArgs: z.string().catch(""),
  updateCommand: z.string().optional(),
  extensions: z.array(z.string()).catch([]),
  autoRun: z.boolean().catch(false),
  timeoutMs: z.number().catch(300_000),
  maxOutputBytes: z.number().catch(100 * 1024 * 1024),
});
export type CustomTool = z.infer<typeof customToolSchema>;

export interface CustomToolInput {
  name: string;
  binary: string;
  runArgs?: string;
  updateCommand?: string;
  extensions?: string[] | string;   // array or a comma/space-separated string
  autoRun?: boolean;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

// Normalize a file extension: lowercase, single leading dot, alnum only (drops junk / injection chars).
export function normalizeExt(raw: string): string {
  const e = String(raw ?? "").trim().toLowerCase().replace(/^\.+/, "").replace(/[^a-z0-9]/g, "");
  return e ? `.${e}` : "";
}

function normalizeExts(input: string[] | string | undefined): string[] {
  const parts = Array.isArray(input) ? input : String(input ?? "").split(/[,\s]+/);
  const out: string[] = [];
  for (const p of parts) { const e = normalizeExt(p); if (e && !out.includes(e)) out.push(e); }
  return out;
}

// Stable slug id from the tool name (so a re-add of the same name updates rather than duplicates).
export function slugifyToolName(name: string): string {
  const s = String(name ?? "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60);
  return s ? `custom-${s}` : `custom-${randomUUID().slice(0, 8)}`;
}

// A custom tool → the runtime ToolConfig the runner consumes. Output goes to auto-detect; the mode is
// derived from whether the run command writes to a file (`<output>` placeholder) or to stdout.
export function customToolToConfig(t: CustomTool): ToolConfig {
  const outputMode = t.runArgs.includes("<output>") ? "file" : "stdout";
  return {
    id: t.id,
    binary: t.binary,
    runArgs: t.runArgs,
    updateCommand: t.updateCommand && t.updateCommand.trim() ? t.updateCommand.trim() : undefined,
    importKind: "auto",
    outputMode,
    outputFile: outputMode === "file" ? "output.dat" : undefined,
    rulesPath: undefined,
    autoRun: t.autoRun,
    timeoutMs: t.timeoutMs,
    maxOutputBytes: t.maxOutputBytes,
  };
}

function fromInput(input: CustomToolInput, id: string): CustomTool {
  return {
    id,
    name: String(input.name ?? "").trim().slice(0, 120),
    binary: String(input.binary ?? "").trim(),
    runArgs: String(input.runArgs ?? "").trim() || "<target>",
    updateCommand: input.updateCommand && String(input.updateCommand).trim() ? String(input.updateCommand).trim() : undefined,
    extensions: normalizeExts(input.extensions),
    autoRun: input.autoRun === true,
    timeoutMs: Number(input.timeoutMs) > 0 ? Number(input.timeoutMs) : 300_000,
    maxOutputBytes: Number(input.maxOutputBytes) > 0 ? Number(input.maxOutputBytes) : 100 * 1024 * 1024,
  };
}

export class CustomToolStore {
  constructor(private readonly file: string) {}

  async load(): Promise<CustomTool[]> {
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as unknown;
      if (!Array.isArray(raw)) return [];
      // Re-validate on read so a hand-edited file can't inject a malformed tool into the runner.
      return raw
        .map((r) => { const p = customToolSchema.safeParse(r); return p.success ? p.data : null; })
        .filter((t): t is CustomTool => t !== null && !!t.id && !!t.name && !!t.binary);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async save(list: CustomTool[]): Promise<void> {
    const dir = dirname(this.file);
    if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true });
    await atomicWrite(this.file, JSON.stringify(list, null, 2));
  }

  // Add (or, when the name slugifies to an existing id, replace) a custom tool. Validates required
  // fields. Returns the stored tool.
  async add(input: CustomToolInput): Promise<CustomTool> {
    const name = String(input.name ?? "").trim();
    const binary = String(input.binary ?? "").trim();
    if (!name) throw new Error("a tool name is required");
    if (!binary) throw new Error("a binary path is required");
    const id = slugifyToolName(name);
    const tool = fromInput(input, id);
    const list = await this.load();
    const next = list.some((t) => t.id === id)
      ? list.map((t) => (t.id === id ? tool : t))
      : [...list, tool];
    await this.save(next);
    return tool;
  }

  async update(id: string, patch: Partial<CustomToolInput>): Promise<CustomTool | null> {
    const list = await this.load();
    const cur = list.find((t) => t.id === id);
    if (!cur) return null;
    const merged = fromInput({
      name: patch.name ?? cur.name,
      binary: patch.binary ?? cur.binary,
      runArgs: patch.runArgs ?? cur.runArgs,
      updateCommand: patch.updateCommand ?? cur.updateCommand,
      extensions: patch.extensions ?? cur.extensions,
      autoRun: patch.autoRun ?? cur.autoRun,
      timeoutMs: patch.timeoutMs ?? cur.timeoutMs,
      maxOutputBytes: patch.maxOutputBytes ?? cur.maxOutputBytes,
    }, id);   // keep the same id (name change does not re-slug an existing tool)
    await this.save(list.map((t) => (t.id === id ? merged : t)));
    return merged;
  }

  async remove(id: string): Promise<boolean> {
    const list = await this.load();
    const next = list.filter((t) => t.id !== id);
    if (next.length === list.length) return false;
    await this.save(next);
    return true;
  }
}
