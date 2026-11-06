import type { NextFunction, Request, RequestHandler, Response } from "express";

/**
 * The routes whose request body is the raw file, read by the route itself as a stream (#2336):
 * POST /cases/:id/import-upload. The generous JSON and text body parsers must never consume it,
 * whatever content type the client claims — a `.json` export sent with its own MIME type would
 * otherwise be buffered whole (up to DFIR_MAX_BODY_MB) before the route could spool it to disk.
 * Matched the way Express routes: case-insensitive, trailing slash optional.
 */
const RAW_UPLOAD_PATH = /^\/cases\/[^/]+\/import-upload\/?$/i;

export function isRawUploadRequest(req: Pick<Request, "method" | "path">): boolean {
  return req.method === "POST" && RAW_UPLOAD_PATH.test(req.path);
}

/** `parser`, skipped for a raw-upload request so its body stays unread for the route. */
export function skipRawUploads(parser: RequestHandler): RequestHandler {
  return function bodyParserUnlessRawUpload(req: Request, res: Response, next: NextFunction): void {
    if (isRawUploadRequest(req)) return next();
    parser(req, res, next);
  };
}
