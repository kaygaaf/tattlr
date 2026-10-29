// The part of the plugin that talks to tattlr. Plain JS so it runs and
// tests without a TypeScript build.
import { spawn } from "node:child_process";

/**
 * @typedef {{ toolName: string, params?: Record<string, unknown>, derivedPaths?: string[], toolCallId?: string }} ToolCall
 * @typedef {{ sessionId?: string, agentId?: string, signal?: AbortSignal, cwd?: string }} CallContext
 * @typedef {{ bin?: string, failClosed?: boolean, timeoutMs?: number, spawnImpl?: typeof spawn }} Config
 * @typedef {{ action: "allow" | "ask" | "deny", reason?: string, title?: string, severity?: string }} Answer
 */

const DESCRIPTION_MAX = 512;
const TITLE_MAX = 80;

/**
 * Runs `tattlr hook openclaw` with the call on stdin and parses the answer.
 * @param {ToolCall} call
 * @param {CallContext} ctx
 * @param {Config} config
 * @returns {Promise<Answer>}
 */
export function askTattlr(call, ctx, config = {}) {
  const bin = config.bin || process.env.TATTLR_BIN || "tattlr";
  const timeoutMs = config.timeoutMs ?? 10_000;
  const run = config.spawnImpl ?? spawn;
  const payload = JSON.stringify({
    tool_name: call.toolName,
    params: call.params ?? {},
    derived_paths: call.derivedPaths ?? [],
    tool_call_id: call.toolCallId,
    session_id: ctx.sessionId ?? "",
    agent_id: ctx.agentId ?? "",
    cwd: ctx.cwd ?? process.cwd(),
  });
  return new Promise((resolve, reject) => {
    const child = run(bin, ["hook", "openclaw"], { stdio: ["pipe", "pipe", "pipe"], signal: ctx.signal });
    let out = "";
    let err = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`tattlr did not answer within ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`tattlr exited ${code}: ${err.trim()}`));
        return;
      }
      try {
        const answer = JSON.parse(out);
        if (!["allow", "ask", "deny"].includes(answer.action)) throw new Error(`unknown action ${answer.action}`);
        resolve(answer);
      } catch (e) {
        reject(new Error(`bad answer from tattlr: ${e.message}`));
      }
    });
    child.stdin.on("error", () => {});
    child.stdin.end(payload);
  });
}

/**
 * Maps tattlr's answer onto OpenClaw's before_tool_call result.
 * @param {Answer} answer
 */
export function toHookResult(answer) {
  const reason = answer.reason || "tattlr policy";
  if (answer.action === "deny") {
    return { block: true, blockReason: reason };
  }
  if (answer.action === "ask") {
    return {
      requireApproval: {
        title: clip(answer.title || "tattlr wants a human to OK this", TITLE_MAX),
        description: clip(reason, DESCRIPTION_MAX),
        severity: answer.severity === "critical" ? "critical" : "warning",
        // tattlr does not remember approvals, so "always" is not offered.
        allowedDecisions: ["allow-once", "deny"],
        timeoutMs: 120_000,
      },
    };
  }
  return undefined; // no decision, the call goes ahead
}

/**
 * The before_tool_call handler body.
 * @param {ToolCall} call
 * @param {CallContext} ctx
 * @param {Config} config
 */
export async function checkToolCall(call, ctx, config = {}) {
  try {
    return toHookResult(await askTattlr(call, ctx, config));
  } catch (e) {
    if (config.failClosed) {
      return { block: true, blockReason: `tattlr could not check this call (${e.message}), and failClosed is on.` };
    }
    console.warn(`[tattlr] could not check ${call.toolName}: ${e.message}; letting it run`);
    return undefined;
  }
}

/** @param {string} s @param {number} n */
function clip(s, n) {
  const chars = [...s];
  return chars.length <= n ? s : chars.slice(0, n - 1).join("") + "…";
}
