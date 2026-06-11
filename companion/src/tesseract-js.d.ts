// Minimal ambient declarations for tesseract.js so tsc resolves the dynamic import
// in TesseractOcrRunner before the package is installed in node_modules.
// When tesseract.js IS installed its own bundled types take precedence via skipLibCheck.
declare module "tesseract.js" {
  interface BBox { x0: number; y0: number; x1: number; y1: number }
  interface Word { text: string; confidence: number; bbox: BBox }
  interface RecognizeResult { data: { words: Word[] } }
  export function recognize(
    image: Buffer | string | ArrayBuffer,
    langs?: string,
    options?: { logger?: (msg: unknown) => void; [k: string]: unknown },
  ): Promise<RecognizeResult>;
  const _default: { recognize: typeof recognize };
  export default _default;
}
