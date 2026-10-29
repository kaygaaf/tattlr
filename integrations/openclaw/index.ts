import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { checkToolCall } from "./src/tattlr.js";

export default definePluginEntry({
  id: "tattlr",
  name: "tattlr",
  description: "Checks every tool call against your local tattlr policy before it runs.",
  register(api) {
    // Plugin config is optional; every field has a default.
    const config = ((api as { pluginConfig?: Record<string, unknown> }).pluginConfig ?? {}) as {
      bin?: string;
      failClosed?: boolean;
      timeoutMs?: number;
    };
    api.on("before_tool_call", (event, ctx) =>
      checkToolCall(
        {
          toolName: event.toolName,
          params: event.params,
          derivedPaths: event.derivedPaths,
          toolCallId: event.toolCallId,
        },
        { sessionId: ctx.sessionId ?? ctx.sessionKey, agentId: ctx.agentId, signal: ctx.abortSignal },
        config,
      ),
    );
  },
});
