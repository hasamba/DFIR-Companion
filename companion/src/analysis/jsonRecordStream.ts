// Incremental JSON record scanner for the streaming cloud import (#2303). Fed text chunks of any
// size, it hands each record to `onRecord` without ever holding the whole document:
//
//   [ {…}, {…} ]                      — a top-level array: each object element is a record;
//   { "Records": [ {…} ], … }         — a wrapper (CloudTrail S3 object, Graph `value`, …): the
//                                       elements of its record array are records, the rest ignored;
//   {…}\n{…}\n                        — JSON lines: after the first line, read line by line, so one
//                                       broken line costs one record, not the rest of the file;
//   [ … ][ … ]  /  {"Records":…}{"Records":…} — concatenated documents, joined and counted.
//
// The repairs are the tolerant whole-file reader's (tolerantJson.ts), counted the same way so the
// import note can disclose them: documents joined, unreadable stretches skipped. A record larger
// than `maxRecordChars` is skipped and counted, never buffered — the bound that keeps memory flat.
// Only the record's own text is ever held, and only while it is being read.

import { isObject } from "./siemFieldPick.js";

type Row = Record<string, unknown>;

/** The wrapper keys whose array holds the records (siemImport.ts RECORD_ARRAY_KEYS, plus `data`). */
const RECORD_KEYS = new Set([
  "events",
  "records",
  "results",
  "logs",
  "rows",
  "items",
  "alerts",
  "value",
  "data",
]);
const KEY_MAX = 64;

export interface JsonScanCounts {
  documentsJoined: number;
  garbageSkipped: number;
  oversizeSkipped: number;
  format: "array" | "wrapper" | "jsonl" | "object" | "empty";
}

const enum C {
  Quote = 34,
  Backslash = 92,
  OpenObj = 123,
  CloseObj = 125,
  OpenArr = 91,
  CloseArr = 93,
  Comma = 44,
  Colon = 58,
  Newline = 10,
}

const isWs = (c: number): boolean => c === 32 || c === 9 || c === 10 || c === 13;

export class JsonRecordScanner {
  private depth = 0;
  private inStr = false;
  private esc = false;
  /** Depth at which elements are records: 1 inside a top-level array, 2 inside a wrapper's array. */
  private recordDepth = -1;
  private topKind: "array" | "object" | null = null;
  private topWrapper = false;
  private docs = 0; // top-level arrays/wrappers completed
  private garbageRun = false;
  private lineMode = false;
  private sawNewlineAfterTop = false;
  private plainTopDone = false;
  // depth-1 key tracking inside a top-level object
  private keyPos = false;
  private keyBuf: string | null = null;
  private pendingKey: string | null = null;
  private expectValueFor: string | null = null;
  // capture of the current record (or top object) text
  private parts: string[] = [];
  private partStart = -1;
  private capLen = 0;
  private capturing = false;
  private capOversize = false;
  private capEndDepth = 0;
  private line = "";
  private lineOversize = false;
  readonly counts: JsonScanCounts = {
    documentsJoined: 0,
    garbageSkipped: 0,
    oversizeSkipped: 0,
    format: "empty",
  };

  constructor(
    private readonly onRecord: (row: Row) => void,
    private readonly maxRecordChars: number,
  ) {}

  push(chunk: string): void {
    if (this.lineMode) return this.pushLines(chunk);
    const n = chunk.length;
    for (let i = 0; i < n; i++) {
      const c = chunk.charCodeAt(i);
      if (this.inStr) {
        this.stringChar(c, chunk, i);
        continue;
      }
      if (this.depth === 0) {
        if (this.topLevelChar(c, chunk, i)) return this.pushLines(chunk.slice(i));
        continue;
      }
      this.structChar(c, chunk, i);
    }
    this.flushPart(chunk, n);
  }

  /** End of input: a value still open is a truncated tail — counted, never guessed at. */
  end(): JsonScanCounts {
    if (this.lineMode) this.finishLine();
    else if (this.depth > 0 || this.inStr) this.counts.garbageSkipped++;
    this.counts.documentsJoined = Math.max(0, this.docs - 1) + this.counts.documentsJoined;
    return { ...this.counts };
  }

  // ───────────── char handlers ─────────────

  private stringChar(c: number, chunk: string, i: number): void {
    if (this.esc) this.esc = false;
    else if (c === C.Backslash) this.esc = true;
    else if (c === C.Quote) {
      this.inStr = false;
      if (this.keyBuf !== null) {
        this.pendingKey = this.keyBuf;
        this.keyBuf = null;
      }
      return;
    }
    if (this.keyBuf !== null && this.keyBuf.length < KEY_MAX) this.keyBuf += chunk[i];
  }

  /** Returns true when the rest of the input must be read as JSON lines. */
  private topLevelChar(c: number, chunk: string, i: number): boolean {
    if (isWs(c)) {
      if (c === C.Newline && this.plainTopDone) this.sawNewlineAfterTop = true;
      return false;
    }
    if (c === C.OpenArr || c === C.OpenObj) {
      if (this.plainTopDone && this.sawNewlineAfterTop && c === C.OpenObj) {
        this.lineMode = true;
        this.counts.format = "jsonl";
        return true;
      }
      this.garbageRun = false;
      this.depth = 1;
      if (c === C.OpenArr) {
        this.topKind = "array";
        this.recordDepth = 1;
        if (this.counts.format === "empty") this.counts.format = "array";
      } else {
        this.topKind = "object";
        this.topWrapper = false;
        this.keyPos = true;
        this.startCapture(i, 0);
      }
      return false;
    }
    if (!this.garbageRun) {
      this.counts.garbageSkipped++;
      this.garbageRun = true;
    }
    return false;
  }

  private structChar(c: number, chunk: string, i: number): void {
    if (c === C.Quote) {
      this.inStr = true;
      if (this.depth === 1 && this.topKind === "object" && this.keyPos) {
        this.keyBuf = "";
        this.keyPos = false;
      }
      return;
    }
    if (this.expectValueFor !== null && !isWs(c)) {
      const key = this.expectValueFor;
      this.expectValueFor = null;
      if (c === C.OpenArr && RECORD_KEYS.has(key.toLowerCase()) && !this.topWrapper && this.recordDepth < 0) {
        this.becomeWrapper();
        this.depth++;
        return;
      }
    }
    if (c === C.OpenObj || c === C.OpenArr) {
      if (this.depth === this.recordDepth && !this.capturing) this.startCapture(i, this.depth);
      this.depth++;
      return;
    }
    if (c === C.CloseObj || c === C.CloseArr) {
      this.depth--;
      if (this.capturing && this.depth === this.capEndDepth) this.endCapture(chunk, i);
      if (this.depth === this.recordDepth - 1 && this.topWrapper && this.depth === 1) this.recordDepth = -1;
      if (this.depth === 0) this.topDone();
      return;
    }
    if (this.depth === 1 && this.topKind === "object") {
      if (c === C.Comma) this.keyPos = true;
      else if (c === C.Colon && this.pendingKey !== null) {
        this.expectValueFor = this.pendingKey;
        this.pendingKey = null;
      }
    }
  }

  private becomeWrapper(): void {
    this.topWrapper = true;
    this.recordDepth = 2;
    this.capturing = false; // the wrapper itself is never held
    this.parts = [];
    this.partStart = -1;
    if (this.counts.format === "empty" || this.counts.format === "object") this.counts.format = "wrapper";
  }

  private topDone(): void {
    if (this.topKind === "array" || this.topWrapper) {
      this.docs++;
      this.plainTopDone = false;
    } else {
      this.plainTopDone = true;
      this.sawNewlineAfterTop = false;
      if (this.counts.format === "empty") this.counts.format = "object";
    }
    this.recordDepth = -1;
    this.topKind = null;
    this.topWrapper = false;
    this.keyPos = false;
    this.pendingKey = null;
    this.expectValueFor = null;
  }

  // ───────────── capture ─────────────

  private startCapture(i: number, endDepth: number): void {
    this.capturing = true;
    this.capOversize = false;
    this.capLen = 0;
    this.parts = [];
    this.partStart = i;
    this.capEndDepth = endDepth;
  }

  private flushPart(chunk: string, end: number): void {
    if (!this.capturing || this.partStart < 0) return;
    this.appendPart(chunk.slice(this.partStart, end));
    this.partStart = 0;
  }

  private appendPart(s: string): void {
    if (this.capOversize) return;
    this.capLen += s.length;
    if (this.capLen > this.maxRecordChars) {
      this.capOversize = true;
      this.parts = [];
      return;
    }
    this.parts.push(s);
  }

  private endCapture(chunk: string, i: number): void {
    this.appendPart(chunk.slice(Math.max(0, this.partStart), i + 1));
    this.capturing = false;
    this.partStart = -1;
    if (this.capOversize) {
      this.counts.oversizeSkipped++;
      this.parts = [];
      return;
    }
    const text = this.parts.join("");
    this.parts = [];
    this.emitText(text);
  }

  private emitText(text: string): void {
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      this.counts.garbageSkipped++;
      return;
    }
    if (isObject(value)) this.onRecord(value);
  }

  // ───────────── JSON lines ─────────────

  private pushLines(chunk: string): void {
    let start = 0;
    for (;;) {
      const nl = chunk.indexOf("\n", start);
      const piece = nl < 0 ? chunk.slice(start) : chunk.slice(start, nl);
      if (!this.lineOversize) {
        if (this.line.length + piece.length > this.maxRecordChars) {
          this.lineOversize = true;
          this.line = "";
        } else this.line += piece;
      }
      if (nl < 0) return;
      this.finishLine();
      start = nl + 1;
    }
  }

  private finishLine(): void {
    const oversize = this.lineOversize;
    const text = this.line.trim();
    this.line = "";
    this.lineOversize = false;
    if (oversize) {
      this.counts.oversizeSkipped++;
      return;
    }
    if (!text) return;
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      this.counts.garbageSkipped++;
      return;
    }
    if (!isObject(value)) return;
    const wrapped = wrapperRecords(value);
    if (!wrapped) return this.onRecord(value);
    this.counts.documentsJoined++;
    for (const r of wrapped) this.onRecord(r);
  }
}

/** A one-line wrapper document's records (a single-line CloudTrail object), or null. */
function wrapperRecords(value: Row): Row[] | null {
  for (const [k, v] of Object.entries(value))
    if (RECORD_KEYS.has(k.toLowerCase()) && Array.isArray(v)) return v.filter(isObject);
  return null;
}
