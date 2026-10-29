// Screenshots a page with headless Chrome over the DevTools protocol.
// Plain Node 20 (run with --experimental-websocket), no packages.
//   node --experimental-websocket scripts/shot.mjs <chrome> <url> <out.png> [width] [height] [url2 out2.png]
import { spawn } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [chrome, url, out, w = "1180", hgt = "1240", url2, out2] = process.argv.slice(2);
const port = 30000 + Math.floor(Math.random() * 20000);
const proc = spawn(chrome, ["--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
  `--user-data-dir=${mkdtempSync(join(tmpdir(), "shot-"))}`, `--remote-debugging-port=${port}`, "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const done = (code) => { proc.kill(); process.exit(code); };
setTimeout(() => { console.error("shot: timed out"); done(1); }, 30000);

let target;
for (let i = 0; i < 100 && !target; i++) {
  try {
    const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    target = list.find((t) => t.type === "page");
  } catch { await sleep(100); }
}
if (!target) { console.error("shot: chrome did not start"); done(1); }

const ws = new WebSocket(target.webSocketDebuggerUrl);
let id = 0;
const waiting = new Map();
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && waiting.has(msg.id)) { waiting.get(msg.id)(msg); waiting.delete(msg.id); }
};
const send = (method, params = {}) => new Promise((res) => { const n = ++id; waiting.set(n, res); ws.send(JSON.stringify({ id: n, method, params })); });
await new Promise((r) => (ws.onopen = r));
await send("Emulation.setDeviceMetricsOverride", { width: +w, height: +hgt, deviceScaleFactor: 2, mobile: false });
await send("Page.enable");
async function capture(u, file) {
  await send("Page.navigate", { url: u });
  await sleep(2500);
  const shot = await send("Page.captureScreenshot", { format: "png" });
  if (!shot.result) { console.error("shot:", JSON.stringify(shot.error)); done(1); }
  writeFileSync(file, Buffer.from(shot.result.data, "base64"));
}
await capture(url, out);
if (url2) await capture(url2, out2);
done(0);
