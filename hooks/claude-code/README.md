# Claude Code hook

The Claude Code `PreToolUse` hook is the `veto hook claude-code`
subcommand built into the veto binary itself. It detects
package-manager install commands — even when wrapped (`timeout`,
`xargs`, `env`, `sudo`, …), invoked through `bash -c "..."`, or chained
with `&&`/`||`/`;`/`|` — and refuses the tool call if it isn't prefixed
with `veto`. The agent then reissues the command with the prefix,
routing the install through veto's malware scan.

## Wiring

```sh
veto install-claude-hook            # edits ~/.claude/settings.json
veto install-claude-hook --project  # edits ./.claude/settings.json
veto install-claude-hook --print    # preview the change without writing
```

Idempotent. Re-running upgrades the command path if veto was
reinstalled at a different location. Other hooks in the same
`PreToolUse[Bash]` chain are preserved.

To uninstall:

```sh
veto uninstall-claude-hook
```

## Coverage

All sixteen package managers `veto` supports:

`npm`, `npx`, `yarn`, `pnpm`, `pnpx`, `rush`, `rushx`, `bun`, `bunx`,
`pip`, `pip3`, `uv`, `uvx`, `poetry`, `pipx`, `pdm`.

## Bypass

Prepend `VETO_BYPASS=1 ` to the command. Use sparingly — the hook
exists specifically because shell-function-only protection fails open
in agent shells.
