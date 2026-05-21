# Claude Code hook

The Claude Code `PreToolUse` hook is the `bouncer hook claude-code`
subcommand built into the bouncer binary itself. It detects
package-manager install commands — even when wrapped (`timeout`,
`xargs`, `env`, `sudo`, …), invoked through `bash -c "..."`, or chained
with `&&`/`||`/`;`/`|` — and refuses the tool call if it isn't prefixed
with `bouncer`. The agent then reissues the command with the prefix,
routing the install through bouncer's malware scan.

## Wiring

```sh
bouncer install-claude-hook            # edits ~/.claude/settings.json
bouncer install-claude-hook --project  # edits ./.claude/settings.json
bouncer install-claude-hook --print    # preview the change without writing
```

Idempotent. Re-running upgrades the command path if bouncer was
reinstalled at a different location. Other hooks in the same
`PreToolUse[Bash]` chain are preserved.

To uninstall:

```sh
bouncer uninstall-claude-hook
```

## Why the hook lives in the bouncer binary

The previous design used a Python script via shebang
(`bouncer-hook.py`). That script had a documented fail-OPEN: if
`python3` was missing at hook-invocation time, Claude Code would let
the unguarded tool call through. Compiling the hook into the same
binary the agent's corrected command must already invoke removes that
failure mode entirely — if `bouncer` is on PATH, the hook is too.

The legacy `bouncer-hook.py` is kept in this directory for reference
during the transition. `install-claude-hook` recognises old shebang
wiring and migrates it to the Go subcommand in place.

## Coverage

All sixteen package managers `bouncer` supports:

`npm`, `npx`, `yarn`, `pnpm`, `pnpx`, `rush`, `rushx`, `bun`, `bunx`,
`pip`, `pip3`, `uv`, `uvx`, `poetry`, `pipx`, `pdm`.

## Bypass

Prepend `BOUNCER_BYPASS=1 ` to the command. Use sparingly — the hook
exists specifically because shell-function-only protection fails open
in agent shells.
