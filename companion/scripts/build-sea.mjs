// Build a portable single-executable application (SEA) for the companion server.
//
// Pipeline:
//   1. esbuild bundles src/server.ts → build-sea/bundle.cjs (CJS, all deps inlined except sharp).
//   2. node --experimental-sea-config writes the SEA blob.
//   3. The matching node binary is copied to dist-sea/dfir-companion(.exe).
//   4. postject injects the blob into that binary.
//   5. dist-sea/ is staged with the EXE + public/ + node_modules/sharp (+ its @img/* deps)
//      + a sample .env so the user can run the EXE from its own folder.
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

async function findSharpRoots() {
  // Locate the sharp package + its @img/* prebuilt-binary siblings. They might live in
  // companion/node_modules or be hoisted to repo-root node_modules — check both.
  const roots = [
    join(COMPANION_DIR, "node_modules"),
    join(REPO_DIR, "node_modules"),
  ];
  const sources = [];
  for (const root of roots) {
    const sharpPath = join(root, "sharp");
    if (existsSync(sharpPath)) {
      sources.push({ kind: "package", name: "sharp", from: sharpPath });
      const imgRoot = join(root, "@img");
      if (existsSync(imgRoot)) {
        sources.push({ kind: "scope", name: "@img", from: imgRoot });
      }
      return sources;
    }
  }
  throw new Error("sharp not found in companion/ or repo-root node_modules; run `npm install` first.");
}

async function stageRuntimeAssets() {
  console.log("[sea] stage public/ + sharp + sample .env");
  await copyTree(join(REPO_DIR, "public"), join(DIST_DIR, "public"));

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
  await stageRuntimeAssets();
  await reportSize();

  console.log(`[sea] done → ${DIST_DIR}`);
}

main().catch((err) => {
  console.error("[sea] FAILED:", err.message ?? err);
  process.exit(1);
});
