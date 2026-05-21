# Claude Code hook

`bouncer-hook.py` is a Claude Code `PreToolUse` hook for the `Bash` tool. It
detects package-manager install commands — even when wrapped (`timeout`,
`xargs`, `env`, `sudo`, …), invoked through `bash -c "..."`, or chained with
`&&`/`||`/`;`/`|` — and refuses the tool call if it isn't prefixed with
`bouncer`. The agent then reissues the command with the prefix, routing the
install through bouncer's malware scan.

## Wiring

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/package-bouncer/hooks/claude-code/bouncer-hook.py"
          }
        ]
      }
    ]
  }
}
```

If you already have a Bash `PreToolUse` chain, append this entry to the
existing `hooks` array; hooks run in order and any one of them can deny.

## Coverage

All sixteen package managers `bouncer` supports:

`npm`, `npx`, `yarn`, `pnpm`, `pnpx`, `rush`, `rushx`, `bun`, `bunx`,
`pip`, `pip3`, `uv`, `uvx`, `poetry`, `pipx`, `pdm`.

## Bypass

Prepend `BOUNCER_BYPASS=1 ` to the command. Use sparingly — the hook
exists specifically because shell-function-only protection fails open
in agent shells.
