# Codex CLI integration

Codex CLI does not expose a per-tool hook protocol (as of 0.130), so
veto integrates via PATH shims rather than a custom hook script.

## Setup

```sh
veto install-codex                # install-shims + codex-config scan
export PATH=$HOME/.local/bin:$PATH   # in front of the real npm/pip/... dirs
```

`veto install-codex` is `install-shims` plus an inspection of
`~/.codex/config.toml`. Specifically it checks
`[shell_environment_policy]` — if `inherit = "core"` is set, Codex
strips the user's PATH when launching the agent shell and the shims
won't be reached. The inspector flags this and tells you the one-line
fix.

Codex inherits the shell's `PATH`, so any `npm install foo` it issues
resolves to the shim, which is `veto` invoked as `npm`. Veto
detects the shim invocation by `os.Args[0]` basename and dispatches
through the same gate the Claude Code hook uses.

For direct child-process invocations that bypass PATH entirely
(`subprocess.run(["/full/path/to/npm", ...], shell=False)`), install
Layer 3 (`veto install-preload`) and Layer 4
(`veto install-wrappers`). Layer 3 hooks libc's execve in any
process that inherits the preload env; Layer 4 replaces the real
binary bytes at the absolute install path so even env-stripped
subprocess calls hit the gate. See
[`../../docs/onboarding.md`](../../docs/onboarding.md) for the full
per-layer walkthrough.

To uninstall:

```sh
veto uninstall-shims
```

Both `install-shims` and `uninstall-shims` refuse to overwrite existing
files that aren't already veto-managed symlinks unless `--force` is
passed.
