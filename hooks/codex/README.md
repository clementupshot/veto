# Codex CLI integration

Codex CLI doesn't expose a per-tool hook protocol, so bouncer integrates
via PATH shims rather than a custom hook script.

## Setup

```sh
bouncer install-shims              # default: ~/.local/bin
export PATH=$HOME/.local/bin:$PATH # in front of the real npm/pip/... dirs
```

Codex inherits the shell's `PATH`, so any `npm install foo` it issues
resolves to the shim, which is `bouncer` invoked as `npm`. Bouncer
detects the shim invocation by `os.Args[0]` basename and dispatches
through the same gate the Claude Code hook uses.

To uninstall:

```sh
bouncer uninstall-shims
```

Both commands refuse to overwrite existing files that aren't already
bouncer-managed symlinks, unless `--force` is passed.
