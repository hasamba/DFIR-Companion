import { openNoFollow } from "../storage/noFollowRead.js";

/**
 * Whether a dropped Velociraptor result file holds several PCs' results (#2805): named `All <Artifact>`
 * (the hunt-wide copy), or two different client ids anywhere in it — a JSON/JSONL `"ClientId"` value or
 * a CSV `ClientId` column. Read in chunks, stopping at the second PC, since a file sorted by PC shows
 * only its first PC in the head. Only values shaped like a Velociraptor client id (`C.<hex>`) count, so
 * a CSV line split inside a quoted multi-line cell cannot invent a second PC. Only files over a size
 * limit are scanned.
 */

const SCAN_CHUNK = 1024 * 1024;
const CLIENT_ID_VALUE = /^C\.[0-9a-f]{4,}$/i;
const JSON_CLIENT_ID = /"ClientId"\s*:\s*"([^"]+)"/g;

/** One CSV line's cells, honouring double quotes ("" is a literal quote). */
export function csvCells(line: string): string[] {
  const cells: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') ((cur += '"'), i++);
      else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") (cells.push(cur), (cur = ""));
    else cur += ch;
  }
  cells.push(cur);
  return cells.map((c) => c.replace(/\r$/, "").trim());
}

/** Feeds text and answers once two different client ids were seen. */
function clientCounter(): { add(id: string | undefined): boolean } {
  let first = "";
  return {
    add(id) {
      if (!id || !CLIENT_ID_VALUE.test(id)) return false;
      if (!first) first = id;
      return id !== first;
    },
  };
}

export async function severalPcs(path: string, name: string): Promise<boolean> {
  if (/^All /i.test(name)) return true;
  const fh = await openNoFollow(path);
  try {
    const buf = Buffer.alloc(SCAN_CHUNK);
    const ids = clientCounter();
    let format: "json" | "csv" | undefined;
    let column = -1;
    let carry = "";
    for (let pos = 0; ;) {
      const { bytesRead } = await fh.read(buf, 0, SCAN_CHUNK, pos);
      if (!bytesRead) return format === "csv" && column >= 0 && ids.add(csvCells(carry)[column]);
      pos += bytesRead;
      const text = carry + buf.toString("utf8", 0, bytesRead);
      format ??= /^\s*[[{]/.test(text) ? "json" : "csv";
      if (format === "json") {
        for (const m of text.matchAll(JSON_CLIENT_ID)) if (ids.add(m[1])) return true;
        carry = text.slice(-256); // a ClientId split across two chunks
        continue;
      }
      const lines = text.split("\n");
      carry = lines.pop() ?? ""; // the last line may continue in the next chunk
      for (const line of lines) {
        if (column < 0) {
          column = csvCells(line.replace(/^\uFEFF/, "")).indexOf("ClientId");
          if (column < 0) return false; // no ClientId column: one PC's results
          continue;
        }
        if (ids.add(csvCells(line)[column])) return true;
      }
    }
  } finally {
    await fh.close();
  }
}
