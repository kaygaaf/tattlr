"use strict";

// First run fallback when the platform package is missing, for example after
// `npm i --omit=optional`. Downloads the release archive once, checks it
// against checksums.txt and caches the binary.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { fromTarGz, fromZip } = require("./extract");

const REPO = "kaygaaf/tattlr";

function cacheDir(version) {
  const root =
    process.env.TATTLR_CACHE_DIR ||
    (process.platform === "win32"
      ? path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"), "tattlr")
      : path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"), "tattlr"));
  return path.join(root, version);
}

async function get(url) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

function expectedSum(checksums, file) {
  for (const line of checksums.split("\n")) {
    const [sum, name] = line.trim().split(/\s+/);
    if (name === file || name === "*" + file) return sum;
  }
  return null;
}

async function download(t, version, log = (m) => process.stderr.write(m + "\n")) {
  const dir = cacheDir(version);
  const dest = path.join(dir, t.exe);
  if (fs.existsSync(dest)) return dest;

  const base = (process.env.TATTLR_BASE_URL || `https://github.com/${REPO}/releases/download`).replace(/\/$/, "");
  const file = t.archive(version);
  const tag = "v" + version;
  log(`tattlr: first run, downloading ${file}`);
  const [archive, sums] = await Promise.all([get(`${base}/${tag}/${file}`), get(`${base}/${tag}/checksums.txt`)]);

  const want = expectedSum(sums.toString("utf8"), file);
  if (!want) throw new Error(`${file} is not listed in checksums.txt`);
  const got = crypto.createHash("sha256").update(archive).digest("hex");
  if (got !== want) throw new Error(`checksum mismatch for ${file} (want ${want}, got ${got}). Not running it.`);

  const bin = file.endsWith(".zip") ? fromZip(archive, t.exe) : fromTarGz(archive, t.exe);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${dest}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, bin, { mode: 0o755 });
  fs.renameSync(tmp, dest);
  log(`tattlr: checksum ok, cached in ${dir}`);
  return dest;
}

module.exports = { download, expectedSum, cacheDir };
