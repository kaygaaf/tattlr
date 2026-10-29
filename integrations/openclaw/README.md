# tattlr for OpenClaw

OpenClaw doesn't read hook config files like Claude Code or Codex do. Its hooks live in plugins. This is a tiny one: before every tool call it runs `tattlr hook openclaw`, passes the call on stdin, and does what tattlr says.

- tattlr says **deny**: the call is blocked and the agent gets the reason.
- tattlr says **ask**: OpenClaw pauses and asks you (allow once or deny). There's no "allow always" because tattlr doesn't remember approvals.
- tattlr says **allow**: nothing happens and the call runs.

All the rules live in `~/.config/tattlr/policy.yaml`, same as the other agents. The plugin itself has no opinions.

## Install

From a tattlr checkout:

```sh
openclaw plugins install --link --force --accept-capabilities ./integrations/openclaw
openclaw plugins inspect tattlr --runtime
```

`--link` points OpenClaw at this folder rather than copying it, so `git pull` updates it. The entry is TypeScript, which OpenClaw loads for local path installs.

The other two flags are there because OpenClaw 2026.10 asks before it installs a local plugin, and again before it lets a plugin hook tool calls. In a terminal you can drop them and answer the prompts. In a script without a terminal, the install is cancelled without `--force` and refused without `--accept-capabilities`. Read the plugin first (it's two small files) and only pass them if you're fine with it.

`inspect` should say `Status: loaded` and list `before_tool_call` under typed hooks. It also prints two notes you can ignore: the plugin is "hook-only" (a supported shape, it just doesn't register any tools), and its manifest id `tattlr` differs from the npm package name `openclaw-tattlr`.

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

## What's been checked

Tested with OpenClaw 2026.10.8: installed as above into a throwaway home, then `openclaw agent --local` against a scripted model on 127.0.0.1. The model read a README with a prompt injection in it, ran `ls`, read a planted canary, then tried to curl it to a local listener. The plugin let the first three through, blocked the curl (the listener got nothing), and the agent got tattlr's reason back as the tool result. All four calls landed in the audit log, and `tattlr scan` read the session back out of OpenClaw's SQLite store.

That run used a fake model, not a real provider account, so it shows the plugin and the hook work, not how a real model reacts to a block.

Two known gaps:

- OpenClaw doesn't pass the working directory to `before_tool_call`, so the plugin reports the gateway's own directory as `cwd`. That's right for `openclaw agent --local` started in your project, and can be wrong for a long-running gateway.
- The plugin API is marked experimental, so expect to pin a version.
