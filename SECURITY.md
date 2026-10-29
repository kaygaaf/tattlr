# Security

tattlr sits in the path of every tool call your agent makes, so bugs that let an agent get around it count as security bugs. That includes:

- a command that does something tattlr should block, but gets through `tattlr protect`
- a way for an agent to switch off, edit or uninstall tattlr without you noticing
- a secret that shows up unmasked in the terminal, the JSON, the audit log or the card
- anything that gets `tattlr ui` to approve a call without you clicking approve

## Reporting

Use GitHub's private reporting: the **Security** tab of [kaygaaf/tattlr](https://github.com/kaygaaf/tattlr/security), then **Report a vulnerability**. Please don't open a public issue or PR for these.

Include the agent and its version, your OS, the tool call or command (with any real secrets taken out) and what you expected to happen. A failing test is the best possible report.

I'll reply within a few days. This is a one person project, so a fix can take a bit longer, but I'll keep you posted and credit you in the changelog unless you'd rather I didn't.

## Supported versions

Only the latest release gets fixes.

## What isn't a bug

tattlr only sees what the agent's hooks and logs tell it. A tool that spawns its own processes, or an agent with no hook for some event, can do things tattlr never hears about. Those are listed under "Known gaps" in the README. If you find a new one, a regular issue is fine.
