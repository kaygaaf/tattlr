#!/usr/bin/env node
// Builds the npm packages from GoReleaser's dist/ folder. It does not publish.
//
//   goreleaser release --clean        (or --snapshot for a dry run)
//   node npm/scripts/build-packages.mjs
//
// Output goes to npm/out/: one folder per platform package plus the main
// tattlr package, all set to the version from dist/metadata.json. The script
// prints the npm publish commands at the end; run them yourself when ready.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const npmDir = path.resolve(here, "..");
const repo = path.resolve(npmDir, "..");
const dist = path.join(repo, "dist");
const out = path.join(npmDir, "out");

const meta = JSON.parse(fs.readFileSync(path.join(dist, "metadata.json"), "utf8"));
const version = meta.version;
const artifacts = JSON.parse(fs.readFileSync(path.join(dist, "artifacts.json"), "utf8"));

const NODE_OS = { darwin: "darwin", linux: "linux", windows: "win32" };
const NODE_CPU = { amd64: "x64", arm64: "arm64" };

// npm's spam filter won't take the name tattlr-win32-arm64, so there's no
// package for it. On Windows arm64 the launcher downloads the binary from the
// GitHub release on first run instead (checked against checksums.txt).
const NO_NPM_PACKAGE = new Set(["tattlr-win32-arm64"]);

fs.rmSync(out, { recursive: true, force: true });
const main = JSON.parse(fs.readFileSync(path.join(npmDir, "package.json"), "utf8"));
main.version = version;
main.optionalDependencies = {};
const order = [];

for (const a of artifacts) {
  if (a.type !== "Binary" || a.extra?.ID !== "tattlr") continue;
  const os = NODE_OS[a.goos];
  const cpu = NODE_CPU[a.goarch];
  if (!os || !cpu) continue;
  const name = `tattlr-${os}-${cpu}`;
  if (NO_NPM_PACKAGE.has(name)) continue;
  const dir = path.join(out, name);
  const exe = os === "win32" ? "tattlr.exe" : "tattlr";
  fs.mkdirSync(path.join(dir, "bin"), { recursive: true });
  fs.copyFileSync(path.join(repo, a.path), path.join(dir, "bin", exe));
  fs.chmodSync(path.join(dir, "bin", exe), 0o755);
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify(
      {
        name,
        version,
        description: `The tattlr binary for ${os} ${cpu}. Install tattlr instead of this.`,
        license: "MIT",
        repository: main.repository,
        homepage: main.homepage,
        os: [os],
        cpu: [cpu],
        files: ["bin"],
        preferUnplugged: true,
      },
      null,
      2,
    ) + "\n",
  );
  fs.writeFileSync(path.join(dir, "README.md"), `The ${os} ${cpu} binary for [tattlr](${main.homepage}). Use \`npm i -g tattlr\`.\n`);
  main.optionalDependencies[name] = version;
  order.push(name);
}

if (order.length === 0) throw new Error("no tattlr binaries in dist/artifacts.json");
main.optionalDependencies = Object.fromEntries(Object.entries(main.optionalDependencies).sort());

const mainDir = path.join(out, "tattlr");
fs.mkdirSync(mainDir, { recursive: true });
for (const d of ["bin", "lib"]) fs.cpSync(path.join(npmDir, d), path.join(mainDir, d), { recursive: true });
fs.copyFileSync(path.join(npmDir, "README.md"), path.join(mainDir, "README.md"));
delete main.scripts;
fs.writeFileSync(path.join(mainDir, "package.json"), JSON.stringify(main, null, 2) + "\n");

console.log(`Built ${order.length + 1} packages for ${version} in ${path.relative(repo, out)}/`);
console.log("Not published. To publish, platform packages go first:");
for (const n of order.sort()) console.log(`  npm publish --access public ${path.relative(repo, path.join(out, n))}`);
console.log(`  npm publish --access public ${path.relative(repo, mainDir)}`);
