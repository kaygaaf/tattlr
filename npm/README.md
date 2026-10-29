# tattlr on npm

```sh
npm i -g tattlr
tattlr
```

This package is a small launcher for the tattlr Go binary. There is no
postinstall script. The binary comes in a per platform package
(`tattlr-linux-x64`, `tattlr-darwin-arm64` and so on) that npm picks through
`optionalDependencies`, so only the one for your machine gets installed.
Windows on arm64 has no npm package (npm's spam filter blocked the name), so
there the launcher always takes the download route below.

If that package is missing, say you installed with `--omit=optional`, the
launcher downloads the matching archive from the GitHub release on first run,
checks it against `checksums.txt`, and caches it in `~/.cache/tattlr/<version>`
(`%LOCALAPPDATA%\tattlr` on Windows). Nothing else ever goes over the network.

Use a global install if you plan to run `tattlr protect install`. The hooks
remember the binary's path, and the npx cache gets cleaned up.

Environment:

- `TATTLR_BINARY` runs this binary instead of the bundled one.
- `TATTLR_BASE_URL` changes where the first run download comes from.
- `TATTLR_CACHE_DIR` changes where it gets cached.

Docs, source and issues: https://github.com/kaygaaf/tattlr

## Maintainers

`node npm/scripts/build-packages.mjs` turns GoReleaser's `dist/` into
publishable folders in `npm/out/` and prints the publish commands. It never
publishes by itself.
