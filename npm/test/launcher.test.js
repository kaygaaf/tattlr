"use strict";

const test = require("node:test");
const assert = require("node:assert");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");

const { target } = require("../lib/platform");
const { fromTarGz, fromZip } = require("../lib/extract");
const { download, expectedSum } = require("../lib/download");

const repo = path.resolve(__dirname, "..", "..");
const dist = path.join(repo, "dist");
const haveDist = fs.existsSync(path.join(dist, "metadata.json"));

test("platform names match GoReleaser archives", () => {
  assert.deepStrictEqual(
    [target("linux", "x64").pkg, target("linux", "x64").archive("0.1.0")],
    ["tattlr-linux-x64", "tattlr_0.1.0_linux_amd64.tar.gz"],
  );
  assert.strictEqual(target("darwin", "arm64").archive("0.1.0"), "tattlr_0.1.0_darwin_arm64.tar.gz");
  assert.strictEqual(target("win32", "x64").archive("0.1.0"), "tattlr_0.1.0_windows_amd64.zip");
  assert.strictEqual(target("win32", "arm64").exe, "tattlr.exe");
  assert.strictEqual(target("freebsd", "x64"), null);
  assert.strictEqual(target("linux", "ia32"), null);
});

test("expectedSum reads checksums.txt", () => {
  const sums = "aaa  tattlr_1_linux_amd64.tar.gz\nbbb *tattlr_1_windows_amd64.zip\n";
  assert.strictEqual(expectedSum(sums, "tattlr_1_linux_amd64.tar.gz"), "aaa");
  assert.strictEqual(expectedSum(sums, "tattlr_1_windows_amd64.zip"), "bbb");
  assert.strictEqual(expectedSum(sums, "nope"), null);
});

test("extracts from a tar.gz made by tar", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tattlr-npm-"));
  fs.writeFileSync(path.join(dir, "tattlr"), "#!/bin/sh\necho hi\n");
  fs.writeFileSync(path.join(dir, "README.md"), "x");
  execFileSync("tar", ["-czf", path.join(dir, "a.tar.gz"), "-C", dir, "README.md", "tattlr"]);
  const got = fromTarGz(fs.readFileSync(path.join(dir, "a.tar.gz")), "tattlr");
  assert.strictEqual(got.toString(), "#!/bin/sh\necho hi\n");
  assert.throws(() => fromTarGz(fs.readFileSync(path.join(dir, "a.tar.gz")), "nope"), /not found/);
});

test("extracts from the real GoReleaser archives", { skip: !haveDist && "no dist/, run goreleaser release --snapshot --clean" }, () => {
  const v = JSON.parse(fs.readFileSync(path.join(dist, "metadata.json"))).version;
  const tgz = fromTarGz(fs.readFileSync(path.join(dist, `tattlr_${v}_linux_amd64.tar.gz`)), "tattlr");
  assert.ok(tgz.length > 1e6);
  assert.strictEqual(tgz.subarray(1, 4).toString(), "ELF");
  const exe = fromZip(fs.readFileSync(path.join(dist, `tattlr_${v}_windows_amd64.zip`)), "tattlr.exe");
  assert.strictEqual(exe.subarray(0, 2).toString(), "MZ");
});

function serve(root) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const p = path.join(root, decodeURIComponent(req.url));
      if (!p.startsWith(root) || !fs.existsSync(p)) {
        res.writeHead(404).end();
        return;
      }
      res.end(fs.readFileSync(p));
    });
    srv.listen(0, "127.0.0.1", () => resolve(srv));
  });
}

test("first run download checks the sha256", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tattlr-rel-"));
  const t = target("linux", "x64");
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "tattlr-src-"));
  fs.writeFileSync(path.join(work, "tattlr"), "binary");
  for (const [v, good] of [["1.0.0", true], ["6.6.6", false]]) {
    const dir = path.join(root, "v" + v);
    fs.mkdirSync(dir);
    const file = t.archive(v);
    execFileSync("tar", ["-czf", path.join(dir, file), "-C", work, "tattlr"]);
    const sum = good ? crypto.createHash("sha256").update(fs.readFileSync(path.join(dir, file))).digest("hex") : "0".repeat(64);
    fs.writeFileSync(path.join(dir, "checksums.txt"), `${sum}  ${file}\n`);
  }
  const srv = await serve(root);
  process.env.TATTLR_BASE_URL = `http://127.0.0.1:${srv.address().port}`;
  process.env.TATTLR_CACHE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "tattlr-cache-"));
  const quiet = () => {};
  try {
    const p = await download(t, "1.0.0", quiet);
    assert.strictEqual(fs.readFileSync(p, "utf8"), "binary");
    assert.strictEqual(await download(t, "1.0.0", quiet), p, "second run uses the cache");
    await assert.rejects(download(t, "6.6.6", quiet), /checksum mismatch/);
    assert.ok(!fs.existsSync(path.join(process.env.TATTLR_CACHE_DIR, "6.6.6", "tattlr")));
    await assert.rejects(download(t, "2.0.0", quiet), /HTTP 404/);
  } finally {
    srv.close();
    delete process.env.TATTLR_BASE_URL;
    delete process.env.TATTLR_CACHE_DIR;
  }
});

test("launcher passes args and exit code through", { skip: process.platform === "win32" }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tattlr-fake-"));
  const fake = path.join(dir, "tattlr");
  fs.writeFileSync(fake, '#!/bin/sh\necho "args:$*"\nexit 3\n', { mode: 0o755 });
  const res = spawnSync(process.execPath, [path.join(__dirname, "..", "bin", "tattlr.js"), "scan", "--json"], {
    env: { ...process.env, TATTLR_BINARY: fake },
    encoding: "utf8",
  });
  assert.strictEqual(res.stdout.trim(), "args:scan --json");
  assert.strictEqual(res.status, 3);
});
