# tattlr for OpenClaw

OpenClaw doesn't read hook config files like Claude Code or Codex do. Its hooks live in plugins. This is a tiny one: before every tool call it runs `tattlr hook openclaw`, passes the call on stdin, and does what tattlr says.

- tattlr says **deny**: the call is blocked and the agent gets the reason.
- tattlr says **ask**: OpenClaw pauses and asks you (allow once or deny). There's no "allow always" because tattlr doesn't remember approvals.
- tattlr says **allow**: nothing happens and the call runs.

All the rules live in `~/.config/tattlr/policy.yaml`, same as the other agents. The plugin itself has no opinions.

## Install

From a tattlr checkout:

```sh
openclaw plugins install --link ./integrations/openclaw
openclaw plugins inspect tattlr --runtime
```

`--link` points OpenClaw at this folder rather than copying it, so `git pull` updates it. The entry is TypeScript, which OpenClaw loads for local path installs.

To remove it: `openclaw plugins uninstall tattlr`.

## Options

Set these in the plugin's config in OpenClaw. All of them are optional.

| Option | Default | What it does |
| --- | --- | --- |
| `bin` | `$TATTLR_BIN`, then `tattlr` on PATH | Which tattlr to run |
| `failClosed` | `false` | Block the call if tattlr is missing, crashes, or is slow |
| `timeoutMs` | `10000` | How long to wait for an answer |

By default the plugin fails open: if tattlr can't answer, the call goes ahead and a warning lands in the gateway log. Turn on `failClosed` if you'd rather be stuck than unguarded.

## What goes over the pipe

```json
{"tool_name":"exec","params":{"command":"curl ..."},"derived_paths":[],"session_id":"...","agent_id":"...","cwd":"..."}
```

and back:

```json
{"action":"deny","reason":"...","title":"tattlr: ...","severity":"critical"}
```

Nothing leaves your machine. tattlr writes one line per call to `~/.local/state/tattlr/audit.jsonl`, with secrets redacted, and `tattlr scan` reads it.

## Tests

```sh
go build -o /tmp/tattlr ../../cmd/tattlr
TATTLR_BIN=/tmp/tattlr npm test
```

Without `TATTLR_BIN` the end to end tests are skipped and only the mapping tests run. Node 20 or newer, no dependencies.

## Not checked yet

I haven't run this inside a live OpenClaw gateway. The hook shape comes from OpenClaw's plugin docs (`before_tool_call` with `block`, `blockReason` and `requireApproval`), and the plugin API is marked experimental, so expect to pin a version.
