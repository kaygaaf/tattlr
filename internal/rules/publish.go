package rules

// checkPublish flags commands that push a package or release out to the
// world: npm publish, cargo publish, twine upload, gh release create and
// friends. Once a version is on a registry other people can install it, and
// most registries won't let you take it back cleanly. Dry runs are fine.
func checkPublish(p string, args []string, add func(string, string, Severity)) {
	if hasLong(args, "--dry-run", "--dryrun", "--snapshot") || contains(args, "-n") && p == "cargo" {
		return
	}
	pos := positional(args[1:])
	sub := ""
	if len(pos) > 0 {
		sub = pos[0]
	}
	switch p {
	case "npm", "pnpm", "bun":
		// "npm run publish" runs a script, so leave that to whatever it does.
		if sub == "run" || sub == "run-script" || sub == "exec" || sub == "x" {
			return
		}
		if contains(pos, "unpublish") {
			add(RulePublish, p+" unpublish", 0)
		} else if contains(pos, "publish") {
			add(RulePublish, p+" publish", 0)
		}
	case "yarn":
		// yarn 1 has "yarn publish", berry has "yarn npm publish".
		if sub == "publish" || sub == "npm" && len(pos) > 1 && pos[1] == "publish" {
			add(RulePublish, "yarn publish", 0)
		}
	case "cargo":
		if sub == "publish" || sub == "yank" {
			add(RulePublish, "cargo "+sub, 0)
		}
	case "twine":
		if sub == "upload" {
			add(RulePublish, "twine upload", 0)
		}
	case "poetry", "uv", "hatch", "flit", "pdm":
		if sub == "publish" {
			add(RulePublish, p+" publish", 0)
		}
	case "gem":
		if sub == "push" || sub == "yank" {
			add(RulePublish, "gem "+sub, 0)
		}
	case "vsce", "ovsx":
		if sub == "publish" {
			add(RulePublish, p+" publish", 0)
		}
	case "dotnet":
		if len(pos) > 1 && pos[0] == "nuget" && pos[1] == "push" {
			add(RulePublish, "dotnet nuget push", 0)
		}
	case "mvn", "mvnw":
		if contains(pos, "deploy") {
			add(RulePublish, "mvn deploy", 0)
		}
	case "goreleaser":
		if sub == "release" || sub == "" {
			add(RulePublish, "goreleaser release", 0)
		}
	case "gh":
		if len(pos) > 1 && pos[0] == "release" && (pos[1] == "create" || pos[1] == "new") {
			add(RulePublish, "gh release create", 0)
		}
	case "docker", "podman", "nerdctl":
		// Pushing an image is a release too, but it happens a lot in normal
		// dev loops, so it only counts as medium.
		if sub == "push" || sub == "image" && len(pos) > 1 && pos[1] == "push" {
			add(RulePublish, p+" push "+pos[len(pos)-1], Medium)
		}
	}
}
