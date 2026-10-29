# Contributing

Thanks for looking. tattlr is small on purpose, so a few ground rules:

- **No network calls.** tattlr never phones home, and a PR that adds telemetry, update checks or a CDN won't get merged. The npm launcher's first-run download is the one exception, and it only happens when the platform package is missing.
- **No real secrets in tests or issues.** Fixtures use obviously fake keys. If you paste a log snippet, redact it first.
- **Small PRs.** One rule, one parser fix, one bug. Easier to review, easier to revert.

## Running it

```sh
go test ./...
go vet ./...
gofmt -l .           # should print nothing
golangci-lint run
```

You need Go 1.22 or newer. Packaging has its own checks if you touch it:

```sh
goreleaser release --snapshot --clean   # builds dist/
sh scripts/test-install.sh              # install.sh against dist/, on 127.0.0.1
cd npm && npm test                      # the npm launcher
```

## Adding a rule

Rules live in `internal/rules`. Each one needs a test with a command that should match and a few that look close but shouldn't. False positives make people turn the thing off, so the "shouldn't" cases matter more.

## Adding or fixing a parser

Parsers live in `internal/parsers/<agent>`. Put a redacted real log in `testdata/` and test against it. Say which agent version it came from.

## Commit style

Short lowercase subject that says what changed, like `scan: count resumed sessions once`. No need for a body unless the why isn't obvious.

## Security bugs

Please don't open a public issue. See [SECURITY.md](SECURITY.md).
