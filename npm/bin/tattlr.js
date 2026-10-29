#!/usr/bin/env node
"use strict";

// npm launcher for the tattlr Go binary. No postinstall: the binary comes in
// a per-platform optional dependency, or gets downloaded on first run.
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { target } = require("../lib/platform");
const { version } = require("../package.json");

function fromPackage(t) {
  try {
    const dir = path.dirname(require.resolve(`${t.pkg}/package.json`));
    const p = path.join(dir, "bin", t.exe);
    return fs.existsSync(p) ? p : null;
  } catch {
    return null;
  }
}

async function resolveBinary() {
  if (process.env.TATTLR_BINARY) return process.env.TATTLR_BINARY;
  const t = target();
  if (!t) {
    throw new Error(
      `no prebuilt tattlr for ${process.platform}/${process.arch}. Try: go install github.com/kaygaaf/tattlr/cmd/tattlr@latest`,
    );
  }
  return fromPackage(t) || (await require("../lib/download").download(t, version));
}

async function main() {
  let bin;
  try {
    bin = await resolveBinary();
  } catch (err) {
    process.stderr.write(`tattlr: ${err.message}\n`);
    process.exit(1);
  }
  const res = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
  if (res.error) {
    process.stderr.write(`tattlr: could not run ${bin}: ${res.error.message}\n`);
    process.exit(1);
  }
  if (res.signal) process.kill(process.pid, res.signal);
  process.exit(res.status ?? 1);
}

main();
