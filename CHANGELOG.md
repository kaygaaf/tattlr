# Changelog

## v0.1.0 (unreleased)

First release.

### Scan
- `tattlr scan` reads local session logs from Claude Code, Codex CLI, Gemini CLI, OpenClaw and Cursor and prints a rap sheet: who did what, the worst moments, and a verdict per agent.
- Rules for secret reads, destructive commands, `curl | sh`, network exfil, privilege, tampering with shell or agent config, and canaries. `tattlr rules` lists them.
- Secrets in commands and outputs are masked everywhere.
- `--since`, `--agent`, `--project`, `--json`, `--fail-on`.
- `--card` makes a 1200x675 share image with no commands, paths or secrets on it.
- A short welcome screen on a machine with no agent logs yet.

### Traps
- `tattlr trap` plants fake AWS keys, a decoy `.env` and optionally a decoy SSH key. Reading one is always critical. `--remove` takes them back out.

### Protect
- `tattlr protect install` hooks into Claude Code, Codex, Cursor, Gemini CLI and OpenClaw (via a plugin) and checks every tool call before it runs. Shows a diff and asks first, backs up configs, and uninstalls cleanly.
- A policy file with observe, protect and strict modes, per rule and per severity actions, and an allowlist.
- Once a session reads a canary, anything it tries to send over the network is denied.
- Agents can't turn tattlr off: edits to its policy, audit log, binary or the agents' hook switches are always blocked.
- Audit log in `~/.local/state/tattlr/audit.jsonl`, desktop notifications, and `tattlr protect status` with a self-test.

### UI
- `tattlr ui` shows a live timeline and an approval inbox on 127.0.0.1, so Codex and Cursor calls that would be "ask" can wait for a click instead of being denied.

### Install
- Release archives for macOS, Linux and Windows with sha256 checksums, an `install.sh` that checks them, a Homebrew cask, an npm package and `go install`.
