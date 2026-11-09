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

/** The noun a summary row uses for what it was built over: "upload" or "collection". */
export function scopeNoun(scope: SummaryScope): "upload" | "collection" {
  return scope.kind;
}

const UPLOAD_HEAD = "records of this upload only; ";
const COLLECTION_HEAD =
  /^records of this collection only \(\d+ pages?; record:N counts the records of the pages in page order\); /;

/**
 * A summary block's `basis` sentence for `scope`. `uploadBasis` is the file form, which starts
 * "records of this upload only; "; a collection's form says so and what its locators count.
 */
export function scopeBasis(scope: SummaryScope, uploadBasis: string): string {
  if (scope.kind === "upload" || !uploadBasis.startsWith(UPLOAD_HEAD)) return uploadBasis;
  const pages = `${scope.pages} page${scope.pages === 1 ? "" : "s"}`;
  return `records of this collection only (${pages}; record:N counts the records of the pages in page order); ${uploadBasis.slice(UPLOAD_HEAD.length)}`;
}

/** The schema of a `basis` sentence: the upload form exactly, or its collection form. */
export function scopeBasisSchema<T extends string>(uploadBasis: T): z.ZodType<string> {
  const tail = uploadBasis.slice(UPLOAD_HEAD.length);
  return z.union([
    z.literal(uploadBasis),
    z.string().refine((s) => COLLECTION_HEAD.test(s) && s.replace(COLLECTION_HEAD, "") === tail),
  ]);
}
