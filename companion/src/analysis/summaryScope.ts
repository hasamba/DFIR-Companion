// What a whole-export summary row rests on (#2482): the records of ONE upload (a file import — the
// default), or every page of ONE live cloud collection run, read in page order into one summary
// window. The summary builders take it only to say which, and (for a collection) to key their
// per-upload rows to the collection instead of to a file hash.

import { z } from "zod";

export type SummaryScope =
  | { kind: "upload" }
  | {
      kind: "collection";
      /** Pages whose records fed the summary window. */
      pages: number;
      /** Stands in for a file's hash wherever a summary keys a row to its upload. */
      uploadId: string;
    };

export const UPLOAD_SCOPE: SummaryScope = { kind: "upload" };

/**
 * The noun a summary row uses for what it was built over: the file form's own noun — "upload", or
 * "export" for the Microsoft / GCP builders that always said so (#2493) — or "collection".
 */
export function scopeNoun<F extends "upload" | "export" = "upload">(
  scope: SummaryScope,
  fileNoun?: F,
): F | "upload" | "collection" {
  return scope.kind === "collection" ? "collection" : (fileNoun ?? "upload");
}

// The file form's head: "upload" (#2482's AWS summaries) or "export" (#2493's Microsoft / GCP ones).
const UPLOAD_HEADS = ["records of this upload only; ", "records of this export only; "] as const;
const fileHead = (basis: string): string | undefined => UPLOAD_HEADS.find((h) => basis.startsWith(h));
const COLLECTION_HEAD =
  /^records of this collection only \(\d+ pages?; record:N counts the records of the pages in page order\); /;

/**
 * A summary block's `basis` sentence for `scope`. `uploadBasis` is the file form, which starts
 * "records of this upload only; " (or "… export only; "); a collection's form says so and what
 * its locators count.
 */
export function scopeBasis(scope: SummaryScope, uploadBasis: string): string {
  const head = fileHead(uploadBasis);
  if (scope.kind === "upload" || !head) return uploadBasis;
  const pages = `${scope.pages} page${scope.pages === 1 ? "" : "s"}`;
  return `records of this collection only (${pages}; record:N counts the records of the pages in page order); ${uploadBasis.slice(head.length)}`;
}

/** The schema of a `basis` sentence: the upload form exactly, or its collection form. */
export function scopeBasisSchema<T extends string>(uploadBasis: T): z.ZodType<string> {
  const tail = uploadBasis.slice(fileHead(uploadBasis)?.length ?? 0);
  return z.union([
    z.literal(uploadBasis),
    z.string().refine((s) => COLLECTION_HEAD.test(s) && s.replace(COLLECTION_HEAD, "") === tail),
  ]);
}
