import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { type DwellWindow, type DwellWindowInput, sanitizeDwellWindowInput } from "./dwellWindow.js";

// Per-case dwell-time-window store (state/dwell-windows.json). Mirrors HypothesisStore: a thin
// I/O wrapper (atomic-write, which retries the rename through transient Dropbox/OneDrive/AV locks)
// around the pure validation in dwellWindow.ts. Durable investigation data — NOT part of
// InvestigationState (so synthesis never wipes it), and IS in SNAPSHOT_STATE_FILES.

export class DwellWindowStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "dwell-windows.json");
  }

  async list(caseId: string): Promise<DwellWindow[]> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8"));
      return Array.isArray(parsed) ? (parsed as DwellWindow[]) : [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async get(caseId: string, id: string): Promise<DwellWindow | null> {
    return (await this.list(caseId)).find((w) => w.id === id) ?? null;
  }

  private async save(caseId: string, windows: DwellWindow[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(windows, null, 2));
  }

  // Create a window (server-assigned id + createdAt). Throws sanitizeDwellWindowInput's descriptive
  // error on invalid input.
  async add(caseId: string, input: DwellWindowInput): Promise<DwellWindow> {
    const clean = sanitizeDwellWindowInput(input);
    const window: DwellWindow = { id: randomUUID(), ...clean, createdAt: new Date().toISOString() };
    await this.save(caseId, [...(await this.list(caseId)), window]);
    return window;
  }

  // Update a window's fields (merged onto the existing record, then re-sanitized as a whole) —
  // preserves id + createdAt. A partial input (e.g. label only) merges onto the existing
  // start/end rather than failing sanitizeDwellWindowInput's "must be a valid date" check on the
  // missing fields. Returns the updated window, or null if no window with that id exists.
  async update(caseId: string, id: string, input: Partial<DwellWindowInput>): Promise<DwellWindow | null> {
    const windows = await this.list(caseId);
    const existing = windows.find((w) => w.id === id);
    if (!existing) return null;
    const clean = sanitizeDwellWindowInput({ ...existing, ...input });
    const updated: DwellWindow = { ...existing, ...clean };
    const next = windows.map((w) => (w.id === id ? updated : w));
    await this.save(caseId, next);
    return updated;
  }

  // Remove one window by id; returns true if it existed.
  async remove(caseId: string, id: string): Promise<boolean> {
    const windows = await this.list(caseId);
    const next = windows.filter((w) => w.id !== id);
    if (next.length === windows.length) return false;
    await this.save(caseId, next);
    return true;
  }
}
