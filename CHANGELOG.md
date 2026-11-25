# Changelog

## Unreleased

- README notes that Claude Code 2.1.329 no longer stops a Code Mode tool call when a PreToolUse hook errors, unless `onFailure` is `block`. The Claude command hook already sets that. The live run is still 2.1.312.

- `tattlr protect status` says skipped, not hooked up, when Gemini will not run the hook. That is `hooksConfig.enabled` set to false, or `tattlr` or the hook command listed in `hooksConfig.disabled`. A Gemini settings file that already has user and project BeforeTool hooks keeps those, and install adds tattlr once.
- `tattlr protect status` lists session-start hooks and local MCP commands in the home config for Claude Code, Codex, Cursor and Gemini CLI, including `~/.claude.json`. tattlr's own PreToolUse hook is skipped. A URL MCP server is left alone. A home with no extra session-start hooks says so. These run outside the PreToolUse hook.
- New rule `codex-remote` (high): `codex exec --remote`, `codex --remote`, `codex remote-control` (and `start` or `pair`), and `codex app-server --remote-control` or `daemon enable-remote-control`. A printed pairing code counts too (`Pairing code:`, `manualPairingCode`, or a `chatgpt.com/codex/pair` link). Plain `codex exec` and a local `codex app-server` call, which the trust check uses, stay quiet. Protect asks, and strict mode denies. The hook still only sees the machine it is installed on.
- New command `tattlr repo [path]`: reads a checkout and does not run anything in it. Flags a session-start or folder-open hook under `.claude/`, `.cursor/`, `.gemini/` or `.codex/` (tattlr's own hook is skipped), a `.vscode/tasks.json` task with `runOn: folderOpen`, an MCP server whose command is a local program or script, and an instruction file (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, copilot instructions, `.cursor/rules/`) that tells the agent not to read a file, to hide the output, or to run something without asking. A normal how-to-run-the-tests file stays quiet. Supports `--fail-on` and `--format text|json|sarif|markdown`. `tattlr protect status` names a SessionStart hook in the current folder that tattlr did not install.
- New rule `secret-then-egress` (critical): a session read a real secret (`secret-read`, `keychain` or `env-dump`) and a later call uploads a file, talks to a drop site, copies files to another host with `scp`/`rsync`/`sftp`, or sends a file the secret was copied into (`cat .env > /tmp/x`, `cp`, `tee`, `mv`, also copies of copies). The finding says when the secret was read and with what. `scan` links the calls per session, and `protect` keeps track across hook calls through the audit log (new `secret_copies` field). The default policy asks, even in policy files written before this rule existed. `npm install` and plain `curl` calls after reading `.env` don't count. Reads the hook blocked don't count either.
- The fixture logs in `testdata/home` now include a reverse shell, an `authorized_keys` append and a history wipe, and the README output, `docs/scan.svg` and `docs/card.png` are refreshed.
- New command `tattlr workflows [path]`: reads `.github/workflows` and flags agent steps (Claude Code, Codex and Gemini CLI actions, or `claude -p`, `codex exec`, `gemini -p` in a script) that run on issues, comments, `pull_request_target`, reviews or discussions and that outsiders can steer: their text in the prompt, `allow-users: "*"`, write permissions or extra secrets, and sandboxes turned off. A copy of the old Codex issue labeler comes out critical. Supports `--fail-on` and `--format text|json|sarif|markdown`, with line numbers in SARIF.
- New rule `publish` (high): `npm`/`pnpm`/`yarn`/`bun publish` and `npm unpublish`, `cargo publish`, `twine upload`, `uv`/`poetry`/`hatch publish`, `gem push`, `dotnet nuget push`, `mvn deploy`, `gh release create` and `goreleaser release`. `docker push` is medium. `--dry-run` and `goreleaser --snapshot` are left alone, and so is `npm run publish`. The default policy asks first.
- New rule `reverse-shell` (critical): `bash -i >& /dev/tcp/...`, `nc -e`, `ncat --exec`, `socat exec:... tcp:...`, the `mkfifo` plus `nc` trick, and the usual Python, Perl, PHP, Ruby, Node and PowerShell one liners that wire a socket to a shell. Denied by default. Port checks like `nc -z host 443` or `</dev/tcp/host/443` are fine.
- New rule `ssh-backdoor` (high): writing or appending to `~/.ssh/authorized_keys` (or `authorized_keys2`), from a shell redirect, `tee -a`, `cp` or a Write/Edit tool call. Reading the file is still fine. The default policy asks first.
- New rule `cover-tracks` (high): `history -c`, `unset HISTFILE`, `HISTFILE=/dev/null`, wiping `.bash_history` or `.zsh_history`, `iptables -F`, `ufw disable`, `csrutil disable`, `spctl --master-disable`, `setenforce 0`, stopping `auditd`, and turning off Defender real-time protection. The default policy asks first.

## v0.3.0 (2026-11-14)

- New rule `infra-destroy` (high): `terraform destroy`, `pulumi destroy`, `kubectl delete namespace`, `aws s3 rb --force`, `gcloud ... delete`, `az group delete` and similar. Single `kubectl delete pod` and `helm uninstall` count as medium. The default policy asks first.
- New rule `imds` (critical): flags requests to cloud instance metadata services such as `169.254.169.254`, `metadata.google.internal`, ECS/EKS metadata IPs and Alibaba's `100.100.100.200`. The default policy denies them. AWS time sync at `169.254.169.123` is left alone.
- New rule `container-escape` (high): `docker`/`podman`/`nerdctl` `run` or `create` with `--privileged`, the Docker or Podman socket mounted in, the host `/` or `/etc` mounted, `--pid=host` or `--cap-add SYS_ADMIN`, and `nsenter -t 1`. The default policy asks first. Normal `-v $PWD:/src` mounts are fine.

## v0.2.0 (2026-11-11)

- `tattlr scan --format sarif` writes SARIF 2.1.0, so findings can go into GitHub code scanning or any tool that reads SARIF. Files an agent touched inside your checkout get a path relative to it; everything else points at the session log.
- `tattlr scan --format markdown` writes a short summary for CI job summaries, issues and PR comments.
- `--json` still works and is the same as `--format json`.
- `--home` accepts relative paths properly.
- New: [tattlr-action](https://github.com/kaygaaf/tattlr-action) runs a scan in GitHub Actions after your agent step, with a job summary, `fail-on` and optional SARIF upload.

## v0.1.1 (2026-11-06)

- `go install` and `tattlr version` print the version without a leading `v`.
- `tattlr scan --card file.png` writes a PNG itself, so you don't need rsvg-convert, resvg or Chrome for that.
- The share card now shows the overall score next to the flagged-call count.
- On Windows arm64, `npm i -g tattlr` downloads the binary from the GitHub release. npm's filter blocks that platform package name.

## v0.1.0 (2026-10-29)

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
