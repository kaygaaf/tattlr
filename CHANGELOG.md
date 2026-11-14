# Changelog

## Unreleased

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
