import { createHash } from "node:crypto";
import type { HuntDataset, HuntParameters, ParsedHuntQuery } from "./huntQueryTypes.js";

export interface HuntCursorState {
  version: 1;
  fingerprint: string;
  sourceCursor: number | null;
  skip: number;
  anchorTime: string;
}

export class HuntCursorError extends Error {
  constructor() {
    super("cursor is invalid or belongs to a different query");
  }
}

function stableParameters(parameters: HuntParameters): string {
  return JSON.stringify(
    Object.fromEntries(Object.entries(parameters).sort(([left], [right]) => left.localeCompare(right))),
  );
}

export function huntCursorFingerprint(
  parsed: ParsedHuntQuery,
  dataset: HuntDataset,
  parameters: HuntParameters,
): string {
  return createHash("sha256")
    .update(`${dataset}\n${parsed.text}\n${stableParameters(parameters)}`)
    .digest("base64url")
    .slice(0, 22);
}

export function encodeHuntCursor(cursor: HuntCursorState): string {
  return Buffer.from(JSON.stringify(cursor)).toString("base64url");
}

export function decodeHuntCursor(raw: string, expectedFingerprint: string): HuntCursorState {
  try {
    const value = JSON.parse(Buffer.from(raw, "base64url").toString("utf8")) as Partial<HuntCursorState>;
    if (
      value.version !== 1 ||
      value.fingerprint !== expectedFingerprint ||
      (value.sourceCursor !== null && !Number.isSafeInteger(value.sourceCursor)) ||
      !Number.isSafeInteger(value.skip) ||
      (value.skip ?? -1) < 0 ||
      typeof value.anchorTime !== "string" ||
      !Number.isFinite(Date.parse(value.anchorTime))
    ) {
      throw new HuntCursorError();
    }
    return value as HuntCursorState;
  } catch {
    throw new HuntCursorError();
  }
}
