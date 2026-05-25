# Onboarding

Veto protects you from upstream supply-chain attacks by intercepting
package-manager invocations and refusing any that name a flagged package.
It is built for humans and agent shells alike: every layer below is
designed to fail closed when the gate can't reach a confident decision.

This doc walks a fresh install through the FOUR defense layers, what
each layer covers, and how to verify the gate is actually in front of
your installs. Skim the table, install all four (they compose), and
read the verification checklist before relying on veto in any agent
session.

## What gets caught at each layer

```
              ┌──────────────────────────────────────────────┐
              │ Layer 4:  real-binary wrappers               │
              │  catches  absolute-path execve even when     │
              │           env vars are stripped              │
              ├──────────────────────────────────────────────┤
              │ Layer 3:  native interposer (LD_PRELOAD /    │
              │           DYLD_INSERT_LIBRARIES)             │
              │  catches  full-path execve, subprocess.Popen │
              │           shell=False, syscall.Exec, ...     │
              ├──────────────────────────────────────────────┤
              │ Layer 2:  PATH shims (~/.local/bin/{npm,…})  │
              │  catches  bare-name PM in any shell that     │
              │           inherits PATH                      │
              ├──────────────────────────────────────────────┤
              │ Layer 1:  Claude Code PreToolUse hook        │
              │  catches  every Bash tool call Claude makes  │
              │           (incl. wrappers, bash -c "...")    │
              └──────────────────────────────────────────────┘
```

The layers compose. Layer 1 catches Claude's primary attack surface;
layer 2 catches Codex and any non-Claude shell; layer 3 closes the
direct-child-process gap when the calling process inherits the
preload env; layer 4 closes that gap unconditionally by wrapping the
real binaries at their absolute install paths.

| Threat                                            | Layer 1 | Layer 2 | Layer 3 | Layer 4 |
|---------------------------------------------------|:-------:|:-------:|:-------:|:-------:|
| `npm install evil` in Claude's Bash tool          |   ✓     |   ✓     |   ✓     |   ✓     |
| `timeout 30 npm install evil`                     |   ✓     |   ✓     |   ✓     |   ✓     |
| `bash -c "cd / && pip install evil"`              |   ✓     |   ✓     |   ✓     |   ✓     |
| Codex agent typing `pnpm add evil`                |   —     |   ✓     |   ✓     |   ✓     |
| Python `subprocess.run(["npm","install","evil"])` |   —     |   ✓     |   ✓     |   ✓     |
| Python `subprocess.run(["/full/path/npm","..."])` |   —     |   —     |   ✓     |   ✓     |
| Same as above but env stripped (no DYLD_INSERT)   |   —     |   —     |   —     |   ✓     |
| Lockfile transitive dep flagged                   |   —     |   ✓     |   ✓     |   ✓     |
| SIP-protected system binary (`/usr/bin/*`)        |   —     |   —     |   —     |   —     |

The last row is a documented limitation. macOS strips
`DYLD_INSERT_LIBRARIES` from SIP-protected binaries; no user-space
interposer can change that. Veto is a command-layer scanner, not a
kernel-level interposer.

---

## Install

### Prerequisites

- Go 1.26+ (the repo's `go.mod` is pinned to 1.26.2).
- A C compiler on PATH (any clang/gcc) — only needed if you want layer 3.
- ~50 MB cache space for intel feeds (Aikido + OpenSSF + OSV).

### One-shot install

```sh
git clone https://github.com/brynbellomy/veto.git
cd veto
make install              # builds veto, installs to ~/.local/bin
veto install-all --force  # shims, shell block, hook, interposer,
                         # wrappers, sync, doctor
```

`install-all` builds the native interposer with `make interposer` when
the shared library is not already present. Use `--skip-interposer` only
on hosts where compiling or loading the shared library is not possible.

Confirm veto is on PATH:

```sh
which veto             # → ~/.local/bin/veto (or wherever you installed)
veto status            # lists configured sources
```

If `which veto` shows nothing, fix your PATH before continuing — every
layer below assumes the binary is reachable.

---

## Layer 1 — Claude Code hook

Wires `veto hook claude-code` into Claude Code's `PreToolUse` chain
for the `Bash` tool. The hook denies any unguarded package-manager
invocation and tells the agent the exact `veto …` corrected command
to re-issue.

### Install

```sh
veto install-claude-hook            # edits ~/.claude/settings.json
# or
veto install-claude-hook --project  # edits ./.claude/settings.json
```

Idempotent. Re-running upgrades the command path if you reinstalled
veto to a different location. To preview the change without writing:

```sh
veto install-claude-hook --print
```

### How it works

Claude Code calls the hook before any Bash tool execution with a JSON
payload describing the command. The hook:

1. Parses the command — peels wrappers (`timeout`, `xargs`, `sudo`,
   `env`, `sudo`, `nice`, `nohup`, `time`, `watch`, `stdbuf`, `xargs`,
   `chronic`, `ts`), unpacks `bash -c "…"` nesting, splits on shell
   separators (`|`, `||`, `&&`, `;`, `&`), and reaches the leaf
   command.
2. If the leaf is a covered PM (`npm`, `pnpm`, `yarn`, `bun`, `pip`,
   `pip3`, `uv`, `poetry`, `pdm`, `pipx`, `npx`, `pnpx`, `bunx`, `uvx`,
   `rush`, `rushx`) with a dangerous verb (`install`, `add`, `update`,
   etc.), the hook denies the call and surfaces the corrected
   `veto <pm> <args>` invocation in the deny reason.
3. The agent re-issues the corrected command; veto's CLI does the
   actual malware lookup and exits non-zero if anything matches.

### Fail-closed semantics

- Hook script panics → emits a hard "INTERNAL ERROR" deny envelope.
- Veto binary missing on PATH → deny with "DO NOT retry" message so
  you notice the mis-install instead of believing the gate is running.
- Malformed JSON input → defer to Claude Code (we can't tell what the
  tool is; gating it isn't safe either way).

### Uninstall

```sh
veto uninstall-claude-hook
```

Removes our entry from the `PreToolUse[Bash]` chain. Other hooks in the
same chain (rtk-rewrite, status lines, etc.) are preserved.

---

## Layer 2 — PATH shims

The shim subsystem creates symlinks in `~/.local/bin` for every covered
PM, each pointing at the veto binary. Veto detects shim
invocations by `os.Args[0]` basename and routes through the gate.

### Install

```sh
veto install-shims                                # default: ~/.local/bin
veto install-shims --dir /custom/dir              # alternate dir
veto install-shims --force                        # overwrite non-veto files
veto install-shell                                 # PATH pinning + pip/uv age quarantine
```

`install-shims` refuses to overwrite anything that isn't already a
veto-managed symlink unless `--force` is passed — replacing real
binaries silently is exactly the kind of surprise a security tool must
not cause.

`install-shell` writes one managed block to `.zshrc`, `.bashrc`, or
`config.fish`. The block keeps `~/.local/bin` ahead of mise/asdf/pyenv/nvm
after prompt hooks run and wraps `pip`, `pip3`, `uv`, and `uvx` with native
package-age gates (`PIP_UPLOADED_PRIOR_TO` / `UV_EXCLUDE_NEWER`).

### PATH ordering

The shim dir must come BEFORE the real PM directories in `PATH`. If you
use mise, homebrew, asdf, or any other version manager, their dirs are
typically already in PATH; the shim dir needs to win the lookup.

Run `veto install-shell` instead of hand-editing your rc
file. `veto doctor` checks for that managed block and reports incomplete
markers as a failure.

`install-shims` prints a warning if it detects a real PM earlier in
PATH than the shim dir.

### Codex

Codex CLI does not expose a per-tool hook protocol (as of 0.130). For
Codex coverage, run:

```sh
veto install-codex
```

This is `install-shims` plus a scan of `~/.codex/config.toml` —
specifically the `[shell_environment_policy]` section, which controls
whether Codex's agent shells inherit your PATH. If `inherit = "core"`
is set, the user PATH is stripped and the shims won't be reached;
`install-codex` flags this and tells you the one-line fix.

### Sirene

Same shim approach. Sirene's workflow runtime inherits the parent's
PATH and exec's steps as subprocesses, so the shims engage
transparently. Run `veto install-shims` and ensure `~/.local/bin` is
on PATH for the shell that launches Sirene.

### Uninstall

```sh
veto uninstall-shims
```

Only removes symlinks that point at the veto binary — your real PMs
and unrelated symlinks are left alone.

---

## Layer 3 — Native interposer

The interposer is a tiny C shared library that hooks `execve`,
`execvp`, `execv`, `posix_spawn`, and `posix_spawnp`. When the calling
process has the library loaded (via `DYLD_INSERT_LIBRARIES` on macOS or
`LD_PRELOAD` on Linux), the hook intercepts every package-manager
invocation — including those by absolute path that bypass PATH lookup
entirely — and rewrites argv to invoke veto instead.

This closes the "direct child-process invocation" hole the README's
threat model used to call out:

```py
# Without the interposer, this bypasses both the Claude hook and PATH shims.
subprocess.run(["/opt/homebrew/bin/npm", "install", "evil"], shell=False)
```

### Build and install

```sh
make interposer                   # produces libveto_interpose.{dylib,so}
veto install-preload \         # copies the lib + writes the shell-rc block
  --lib ./libveto_interpose.dylib \
  --shell-rc auto                 # or: --shell-rc ~/.zshrc, or --print
```

`--shell-rc auto` detects your shell from `$SHELL` and writes to the
matching rc (`~/.zshrc`, `~/.bashrc`, `~/.config/fish/config.fish`).
The managed block is bracketed with markers so subsequent installs
upgrade in place:

```
# >>> veto preload (managed) >>>
export DYLD_INSERT_LIBRARIES="/Users/.../libveto_interpose.dylib"
export VETO_PATH="/Users/.../veto"
# <<< veto preload (managed) <<<
```

Open a fresh shell (or `source ~/.zshrc`) for the env vars to take
effect.

### macOS caveat

`DYLD_INSERT_LIBRARIES` is stripped by dyld for SIP-protected binaries
(`/usr/bin/*`, `/usr/sbin/*`, `/System/...`). If an agent shells out to
one of those binaries to fetch packages, the interposer won't load.
This is a macOS-level constraint, not a veto bug — user-installed
binaries (homebrew, mise, asdf, nvm) are all covered.

The interposer is built as a fat dylib (`arm64` + `arm64e`) so it loads
into both regular Go binaries and `arm64e` shells like `/bin/bash`.

### Uninstall

```sh
veto uninstall-preload --shell-rc auto
```

Strips the managed block from the shell rc and removes the installed
library file.

---

## Layer 4 — Real-binary wrappers

The strongest single layer. Layers 2–3 protect "things that go through
the shell" and "things that load libc with our preload env." Layer 4
protects the *bytes at the absolute path* — veto literally
substitutes itself for `/opt/homebrew/bin/npm`, the mise install dirs,
and so on. No env-var dependency, no PATH-order dependency, no process
cooperation needed.

### Install

```sh
veto install-wrappers              # discover + wrap homebrew + mise + asdf + .bun
veto install-wrappers --dry-run    # show what would change without writing
veto install-wrappers --only npm   # restrict to one PM
veto install-wrappers --dir /path  # add an extra discovery root
```

For each known install dir (`/opt/homebrew/bin`, `~/.local/share/mise/installs/*/*/bin`,
`~/.asdf/installs/*/*/bin`, `~/.bun/bin`, plus any `--dir` you pass),
veto:

1. atomically renames `<dir>/<pm>` to `<dir>/<pm>.veto-original`
2. installs a symlink at `<dir>/<pm>` pointing at the veto binary

When a caller execs `/opt/homebrew/bin/npm install foo`, the kernel
runs the veto symlink. Veto's basename dispatch routes through
the gate. If allowed, `findRealBinary` finds the `.veto-original`
sibling and exec's it.

### What this catches that Layer 3 doesn't

```py
# Caller scrubs env so DYLD_INSERT_LIBRARIES doesn't propagate.
subprocess.run(
    ["/opt/homebrew/bin/npm", "install", "evil"],
    shell=False,
    env={"PATH": "/usr/bin:/bin"},   # interposer NOT inherited
)
```

The interposer (Layer 3) doesn't fire because the dylib isn't loaded
into this child process. Layer 4 doesn't care — the file at
`/opt/homebrew/bin/npm` *is* veto.

### Tradeoffs

- **Brew/mise/asdf upgrades wipe the wrappers.** Every `brew upgrade
  node` and `mise install node@whatever` rewrites the file at the
  wrapper site. Re-run `veto install-wrappers` after any
  toolchain upgrade. `veto doctor` flags drift.
- **State is durable.** Wrapper installations are recorded in
  `~/.cache/veto/wrappers.json`. `veto uninstall-wrappers`
  replays every entry in reverse: remove the symlink, rename
  `.veto-original` back to `<pm>`.
- **SIP-protected dirs are unreachable.** Just like Layer 3,
  `/usr/bin/pip3` cannot be wrapped — the directory is read-only
  even to root.

### Uninstall

```sh
veto uninstall-wrappers
```

---

## Verifying your install

Before relying on veto in any agent session, run this checklist in a
fresh terminal:

```sh
# 1. Veto itself is on PATH.
which veto

# 2. The managed shell block exists and shims are in front of real PMs.
veto doctor                              # includes shell integration check
which npm                                   # should resolve to ~/.local/bin/npm

# 3. Intel store is healthy.
veto status                              # lists three sources, no errors
veto sync                                # forces a refresh

# 4. The hook is wired in Claude Code.
grep -q 'hook claude-code' ~/.claude/settings.json && echo "claude hook OK"

# 5. The interposer is loaded.
echo "$DYLD_INSERT_LIBRARIES"               # darwin
echo "$LD_PRELOAD"                          # linux
echo "$VETO_PATH"                        # should be your veto absolute path

# 6. End-to-end — should be refused by the gate.
VETO_LOG=debug veto npm install chai-as-upgraded
#   veto: install refused — package intelligence flagged the following:
#     - chai-as-upgraded@<any> (ecosystem: npm)
#         [aikido] MALWARE
```

If any step fails, fix it before treating the gate as in effect.

---

## Troubleshooting

### "command not found: veto" inside Claude Code

The hook is wired with an absolute path to `veto`, but Claude Code's
re-invocation uses bare-name PATH lookup. Make sure `~/.local/bin` (or
wherever you installed veto) is in the PATH that Claude Code
inherits. On macOS, Claude Code's shell environment can differ from
your terminal's; check the agent shell with `echo $PATH`.

### `which npm` resolves to mise/homebrew, not the shim

PATH ordering. Move `~/.local/bin` ahead of mise/homebrew in your
shell rc:

```sh
export PATH=$HOME/.local/bin:$PATH         # before any version-manager init
```

If mise rewrites PATH on every prompt, the workaround is `mise settings
set experimental_path_order='user_first'` or to use a doctored shim
inside mise's plugin dir (out of scope for this doc).

### Interposer "incompatible architecture" error

You probably built the dylib for one arch but the spawning process is
the other. Rebuild as a fat binary:

```sh
make clean
make interposer       # automatic on Apple Silicon
```

If you're on Apple Silicon and the build only produced a single arch,
check that your Xcode CLT supports `-arch arm64e`.

### Hook causes Claude Code to fail-OPEN

This should never happen with the Go hook — any panic is caught and
converted to a hard "deny" envelope. If you see it, file an issue with
the failing input. The Python hook had a documented fail-OPEN when
`python3` was missing at hook-invocation time; the Go port closes that
hole.

### Veto refuses to gate ("INTERNAL ERROR — intel store…")

The fail-closed sanity check fired. Either every source returned an
empty feed (probable upstream incident — try again later, or check
`veto status`), or `VETO_SOURCES` is pointed at non-existent
source IDs. Default is `aikido,openssf,osv,pypa`; add `ghsa` only if
you intentionally want broad CVE/GHSA blocking too.

### "could not be loaded" when an unrelated process starts

`DYLD_INSERT_LIBRARIES` propagates to every child process. If a process
is a different architecture than the interposer, the child fails to
start. The fat-dylib build above is the fix for arm64/arm64e mismatch;
for x86_64 children on Apple Silicon (Rosetta), you may need an
`-arch x86_64` build too. Open an issue if this affects you.

---

## Bypass mechanics

In all three layers, prepend `VETO_BYPASS=1 ` to the command to skip
the gate for that single invocation:

```sh
VETO_BYPASS=1 npm install some-package-i-trust-personally
```

Use sparingly. The bypass exists for cases where you've already
verified the package out-of-band and the gate is producing a false
positive — not as a routine workaround.

---

## What veto does NOT cover

Documented limits, in addition to the threat-model section in
[`README.md`](../README.md):

- **SIP-protected binaries on macOS.** `/usr/bin/*` and similar reject
  `DYLD_INSERT_LIBRARIES`. An agent that exec's `/usr/bin/python3 -m
  pip install evil` is partially covered (the shim catches if PATH
  resolves to our shim; the interposer doesn't load inside the SIP'd
  process; the Claude hook still sees the Bash command).
- **Static binaries that don't use libc's exec wrappers.** Theoretical;
  unusual in practice.
- **Compromised upstream feeds with thinned-out data.** We refuse to
  gate against fewer than 1000 reports total, but a feed that drops
  most malware while still returning hundreds of entries would slip
  through.
- **Resolver pre-scan beyond npm.** Existing lockfiles are gated for
  live npm-family, Python-family, Go, and Cargo install/fetch commands,
  and `npm install`/`npm update` get a temp-dir `--package-lock=true
  --package-lock-only --ignore-scripts` pre-scan before the real
  install. Other ecosystems do not yet get a resolver probe for newly
  named packages; they rely on argv, manifests, and already-present
  lockfiles where live command gating exists.
- **Go and Cargo build/test/run preflight.** Phase 1 live gating covers
  dependency fetch/mutate commands only. `go build`, `go test`, local
  `go run`, `cargo build`, `cargo test`, and local `cargo run` are phase
  2 work.

Veto is one layer of defense, not a substitute for code review of
unpinned/unverified dependencies.
