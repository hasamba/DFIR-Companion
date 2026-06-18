// Build a portable single-executable application (SEA) for the companion server.
//
// Pipeline:
//   1. esbuild bundles src/server.ts → build-sea/bundle.cjs (CJS, all deps inlined except sharp).
//   2. node --experimental-sea-config writes the SEA blob.
//   3. The matching node binary is copied to dist-sea/dfir-companion(.exe).
//   4. postject injects the blob into that binary.
//   5. An ICO is built from public/DFIR_Companion_favicon.png and embedded via rcedit (Windows).
//   6. dist-sea/ is staged with the EXE + public/ + node_modules/sharp (+ @img/* + all transitive
//      runtime deps: detect-libc, color, semver, …) + a sample .env.
//
// Run with:  npm run package:sea
//
// Notes:
//  - sharp is native — SEA cannot embed .node files, so it stays external and we ship the
//    pre-built node_modules/sharp + @img/sharp-* tree next to the EXE. The bundle calls
//    require("sharp") which createRequire(execPath) resolves to that adjacent folder.
//  - Node 20 SEA only supports CommonJS main scripts; esbuild handles the ESM→CJS transform.
//  - Targets the host platform (whatever node you launched this with); CI is responsible
//    for running this on the right OS (Windows for .exe).

import { build } from "esbuild";
import { mkdir, copyFile, rm, writeFile, readFile, chmod, cp, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { platform } from "node:os";
import { inject as postjectInject } from "postject";
import sharp from "sharp";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const COMPANION_DIR = resolve(SCRIPT_DIR, "..");
const REPO_DIR = resolve(COMPANION_DIR, "..");
const BUILD_DIR = join(COMPANION_DIR, "build-sea");
const DIST_DIR = join(COMPANION_DIR, "dist-sea");
const EXE_NAME = platform() === "win32" ? "dfir-companion.exe" : "dfir-companion";
const EXE_PATH = join(DIST_DIR, EXE_NAME);
const BUNDLE_PATH = join(BUILD_DIR, "bundle.cjs");
const SEA_CONFIG_PATH = join(BUILD_DIR, "sea-config.json");
const SEA_BLOB_PATH = join(BUILD_DIR, "sea-prep.blob");
// Sentinel chosen by Node for SEA fuses; postject needs it verbatim.
const SEA_FUSE = "fce680ab2cc467b6e072b8b5df1996b2";

// spawn wrapper. `useShell` is only set for `npx` (which on Windows is a .cmd shim and
// needs the shell). Direct EXEs are spawned without a shell so paths with spaces
// (e.g. C:\Program Files\nodejs\node.exe) don't get mangled by cmd.exe quoting rules.
function run(cmd, args, { useShell = false, ...opts } = {}) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(cmd, args, { stdio: "inherit", shell: useShell, ...opts });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolveRun(undefined);
      else reject(new Error(`${cmd} ${args.join(" ")} exited with ${code}`));
    });
  });
}

async function rmrf(path) {
  await rm(path, { recursive: true, force: true });
}

async function ensureDir(path) {
  await mkdir(path, { recursive: true });
}

async function copyTree(src, dest) {
  await cp(src, dest, { recursive: true, dereference: false, errorOnExist: false, force: true });
}

async function bundleServer() {
  const pkg = JSON.parse(await readFile(join(COMPANION_DIR, "package.json"), "utf8"));
  console.log("[sea] esbuild → bundle.cjs");
  await build({
    entryPoints: [join(COMPANION_DIR, "src", "server.ts")],
    outfile: BUNDLE_PATH,
    platform: "node",
    target: "node20",
    format: "cjs",
    bundle: true,
    minify: false,
    sourcemap: false,
    legalComments: "none",
    // sharp ships native .node bindings; cannot be embedded into a SEA blob. Two things
    // are needed: (a) the bundler must NOT pull sharp's JS into the SEA blob, AND
    // (b) the runtime require for sharp must use a disk-backed `createRequire`, because
    // SEA's embedded `require()` only resolves builtins. The `alias` reroutes the import
    // through `sea-sharp-shim.cjs`, which does both — and the bundle still treats the
    // shim's require call as external.
    external: ["sharp"],
    alias: {
      sharp: join(COMPANION_DIR, "scripts", "sea-sharp-shim.cjs"),
    },
    // Quiet warning about unused dynamic require usage in some deps; banner provides
    // a CommonJS-compatible `require`/`__filename`/`__dirname` even when nothing in
    // the bundle reaches for them, so external sharp `require()`s succeed at runtime.
    banner: {
      js: [
        "\"use strict\";",
        "var __sea_require = require;",
        "if (typeof require === \"undefined\") { var require = __sea_require; }",
      ].join("\n"),
    },
    define: {
      "process.env.NODE_ENV": JSON.stringify("production"),
      "process.env.DFIR_BUILD_VERSION": JSON.stringify(pkg.version),
    },
    // `import.meta.url` becomes empty in CJS — esbuild warns. The two call sites that
    // consult it (`detectSea` + the URL fallback in serverAssets.ts) are guarded by the
    // SEA check at runtime and never fire from inside the SEA blob, so the warning is
    // a false positive. Silence it.
    logOverride: {
      "empty-import-meta": "silent",
    },
  });
}

async function writeSeaConfig() {
  const config = {
    main: BUNDLE_PATH,
    output: SEA_BLOB_PATH,
    disableExperimentalSEAWarning: true,
    useSnapshot: false,
    useCodeCache: true,
  };
  await writeFile(SEA_CONFIG_PATH, JSON.stringify(config, null, 2));
}

async function generateBlob() {
  console.log("[sea] node --experimental-sea-config → sea-prep.blob");
  await run(process.execPath, ["--experimental-sea-config", SEA_CONFIG_PATH]);
}

async function stageExe() {
  console.log(`[sea] copy node binary → ${EXE_PATH}`);
  await ensureDir(DIST_DIR);
  await copyFile(process.execPath, EXE_PATH);
  if (process.platform !== "win32") {
    await chmod(EXE_PATH, 0o755);
  }
}

async function injectBlob() {
  console.log("[sea] postject inject blob");
  // Programmatic API — avoids npx + cmd.exe quoting headaches with paths containing
  // spaces (Program Files, Dropbox-synced folders, etc.).
  const blob = await readFile(SEA_BLOB_PATH);
  const options = { sentinelFuse: `NODE_SEA_FUSE_${SEA_FUSE}` };
  if (process.platform === "darwin") {
    options.machoSegmentName = "NODE_SEA";
  }
  await postjectInject(EXE_PATH, "NODE_SEA_BLOB", blob, options);
}

// All packages that sharp requires at runtime (direct deps + their transitive deps).
// These must be staged next to the EXE so Node can resolve them at startup.
const SHARP_RUNTIME_DEPS = [
  "detect-libc",   // sharp direct dep
  "color",         // sharp direct dep
  "semver",        // sharp direct dep
  "color-convert", // color dep
  "color-string",  // color dep
  "color-name",    // color-convert + color-string dep
  "simple-swizzle",// color-string dep
  "is-arrayish",   // simple-swizzle dep
];

async function findSharpRoots() {
  // Locate the sharp package + its @img/* prebuilt-binary siblings + all transitive runtime
  // deps. They might live in companion/node_modules or be hoisted to repo-root node_modules
  // — check both.
  const roots = [
    join(COMPANION_DIR, "node_modules"),
    join(REPO_DIR, "node_modules"),
  ];
  for (const root of roots) {
    const sharpPath = join(root, "sharp");
    if (!existsSync(sharpPath)) continue;

    const sources = [{ kind: "package", name: "sharp", from: sharpPath }];
    const imgRoot = join(root, "@img");
    if (existsSync(imgRoot)) {
      sources.push({ kind: "scope", name: "@img", from: imgRoot });
    }
    for (const dep of SHARP_RUNTIME_DEPS) {
      const depPath = join(root, dep);
      if (existsSync(depPath)) {
        sources.push({ kind: "package", name: dep, from: depPath });
      } else {
        console.warn(`[sea] warning: sharp transitive dep "${dep}" not found in ${root}`);
      }
    }
    return sources;
  }
  throw new Error("sharp not found in companion/ or repo-root node_modules; run `npm install` first.");
}

// Build a Windows ICO file from an array of {size, data: Buffer} PNG frames.
// Uses the PNG-in-ICO container format (no BMP conversion needed; supported by all
// modern Windows versions and browsers).
function buildIco(frames) {
  const count = frames.length;
  const dirSize = 6 + count * 16;
  const header = Buffer.alloc(dirSize);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // type = 1 (icon)
  header.writeUInt16LE(count, 4);
  let offset = dirSize;
  const parts = [header];
  for (let i = 0; i < count; i++) {
    const { size, data } = frames[i];
    const w = size >= 256 ? 0 : size; // 0 encodes as 256 in ICO spec
    const e = 6 + i * 16;
    header.writeUInt8(w, e);           // width
    header.writeUInt8(w, e + 1);       // height
    header.writeUInt8(0, e + 2);       // color count (0 = truecolor)
    header.writeUInt8(0, e + 3);       // reserved
    header.writeUInt16LE(0, e + 4);    // planes
    header.writeUInt16LE(32, e + 6);   // bits per pixel
    header.writeUInt32LE(data.length, e + 8);  // size in bytes
    header.writeUInt32LE(offset, e + 12);       // file offset
    parts.push(data);
    offset += data.length;
  }
  return Buffer.concat(parts);
}

async function createIco() {
  console.log("[sea] create app.ico from DFIR_Companion_favicon.png");
  const srcPng = join(REPO_DIR, "public", "DFIR_Companion_favicon.png");
  const icoPath = join(BUILD_DIR, "app.ico");

  // Replicate the same background-removal logic used in make-icons.ts so the icon
  // uses the clean transparent emblem rather than the raw source with its gray background.
  const { data, info } = await sharp(srcPng).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const { width: W, height: H } = info;
  const buf = Buffer.from(data);
  const isBg = (i) => buf[i] > 185 && buf[i + 1] > 185 && buf[i + 2] > 185;
  const visited = new Uint8Array(W * H);
  const stack = [];
  const seed = (x, y) => { if (x >= 0 && y >= 0 && x < W && y < H) stack.push(y * W + x); };
  for (let x = 0; x < W; x++) { seed(x, 0); seed(x, H - 1); }
  for (let y = 0; y < H; y++) { seed(0, y); seed(W - 1, y); }
  while (stack.length) {
    const p = stack.pop();
    if (visited[p]) continue;
    visited[p] = 1;
    if (!isBg(p * 4)) continue;
    buf[p * 4 + 3] = 0;
    const x = p % W, y = (p / W) | 0;
    seed(x + 1, y); seed(x - 1, y); seed(x, y + 1); seed(x, y - 1);
  }
  const emblem = sharp(buf, { raw: { width: W, height: H, channels: 4 } });

  const SIZES = [16, 32, 48, 256];
  const frames = await Promise.all(SIZES.map(async (size) => {
    const data = await emblem.clone()
      .trim({ threshold: 10 })
      .resize(size, size, { fit: "cover", kernel: "lanczos3" })
      .png({ compressionLevel: 9 })
      .toBuffer();
    return { size, data };
  }));

  await writeFile(icoPath, buildIco(frames));
  return icoPath;
}

async function embedIcon(icoPath) {
  if (process.platform !== "win32") {
    console.log("[sea] skip icon embed (not Windows — run on Windows CI to get the icon)");
    return;
  }
  console.log("[sea] embed icon with rcedit");
  try {
    const { default: rcedit } = await import("rcedit");
    await rcedit(EXE_PATH, { icon: icoPath });
  } catch (err) {
    // rcedit is optional; a missing icon is cosmetic, not a crash.
    console.warn(`[sea] icon embed skipped: ${err.message}`);
  }
}

async function stageRuntimeAssets(icoPath) {
  console.log("[sea] stage public/ + data/ + sharp + sample .env");
  await copyTree(join(REPO_DIR, "public"), join(DIST_DIR, "public"));
  // Bundled offline datasets (e.g. the MITRE ATT&CK Groups file behind Adversary Hints) ship
  // next to the EXE — adversaryGroupsData.ts resolves them via dirname(process.execPath)/data.
  await copyTree(join(COMPANION_DIR, "data"), join(DIST_DIR, "data"));
  if (icoPath && existsSync(icoPath)) {
    await copyFile(icoPath, join(DIST_DIR, "dfir-companion.ico"));
  }

  const sharpSources = await findSharpRoots();
  const nodeModulesDest = join(DIST_DIR, "node_modules");
  await ensureDir(nodeModulesDest);
  for (const src of sharpSources) {
    const dest = join(nodeModulesDest, src.name);
    await copyTree(src.from, dest);
  }

  const envExampleSrc = join(COMPANION_DIR, ".env.example");
  if (existsSync(envExampleSrc)) {
    await copyFile(envExampleSrc, join(DIST_DIR, ".env.example"));
  }

  // A README so the EXE folder is self-explanatory.
  const readmeBody = [
    "# DFIR Companion — portable Windows build",
    "",
    "Double-click `dfir-companion.exe` and open http://127.0.0.1:4773/dashboard.",
    "",
    "Configuration (optional):",
    "- Copy `.env.example` to `.env` next to the EXE and edit it (AI provider, threat-intel keys, …).",
    "- Cases are stored in `cases/` next to the EXE.",
    "- The dashboard is served from `public/dashboard.html` next to the EXE — leave it in place.",
    "",
    "To stop the server: close the console window, or",
    "  Get-NetTCPConnection -LocalPort 4773 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }",
    "",
  ].join("\n");
  await writeFile(join(DIST_DIR, "README.txt"), readmeBody);
}

async function reportSize() {
  const s = await stat(EXE_PATH);
  console.log(`[sea] ${EXE_NAME}: ${(s.size / (1024 * 1024)).toFixed(1)} MiB`);
}

async function main() {
  console.log(`[sea] node: ${process.version} on ${process.platform}-${process.arch}`);
  await rmrf(BUILD_DIR);
  await rmrf(DIST_DIR);
  await ensureDir(BUILD_DIR);
  await ensureDir(DIST_DIR);

  await bundleServer();
  await writeSeaConfig();
  await generateBlob();
  await stageExe();
  await injectBlob();
  // Icon embed skipped: rcedit hangs on the postject-modified binary because the
  // injected SEA blob invalidates the original PE signature, leaving the file in a
  // state rcedit can't lock for writing. createIco() still runs so the .ico is
  // available for manual embedding or a future signing step.
  const icoPath = await createIco();
  await stageRuntimeAssets(icoPath);
  await reportSize();

  console.log(`[sea] done → ${DIST_DIR}`);
}

main().catch((err) => {
  console.error("[sea] FAILED:", err.message ?? err);
  process.exit(1);
});
