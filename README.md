# package-bouncer

A command-level malware scanner for package managers. Aggregates intel from
multiple upstream feeds (Aikido, OpenSSF, OSV, …), deduplicates, and refuses
to let an install proceed if any source flags the requested package.

## Why

Existing shell-function-based protection (e.g. Aikido `safe-chain`) fails
open in several real-world cases:

- the package manager is invoked through a wrapper that `execvp`'s the
  binary directly (`timeout npm install …`, `xargs … npm install …`, build
  systems, subprocess calls from Python/Go),
- the command runs in a non-interactive shell that didn't source the shim
  init script (CI, agent shells),
- the underlying tool's network behavior bypasses HTTPS-proxy enforcement
  (observed with `bun`'s package resolver — the motivating case for this
  project).

`bouncer` operates at the command layer: it parses argv, looks up package
names against an aggregated malware database, and refuses or passes
through. Because the check happens before the package manager runs, none of
the above failure modes apply.

## Architecture

```
intel/             ← parent: Source interface, MalwareReport, Store
intel/sources/
  aikido/          ← https://malware-list.aikido.dev (implemented)
  openssf/         ← github.com/ossf/malicious-packages (stub)
  osv/             ← osv.dev MAL-* advisories (stub)

packagemanager/    ← parent: PackageManager interface, Install
packagemanager/
  npm/ pnpm/ yarn/ bun/      ← jsspec-backed
  pip/ uv/ poetry/ pdm/      ← pyspec-backed
  exec/                       ← parameterized for npx/bunx/pnpx/uvx/pipx
  jsspec/ pyspec/ argv/       ← shared parsers

gate/              ← decision logic (allow / refuse / passthrough)

cmd/bouncer/       ← CLI entrypoint (viper config)
hooks/             ← agent integrations
  claude-code/     ← PreToolUse Bash hook (Python, stdlib-only)
  codex/ sirene/   ← PATH-shim approach (see `bouncer install-shims`)
```

Per-source malware feeds are fetched concurrently with etag-based caching
in `~/.cache/package-bouncer/`. On network outage the last good snapshot
is used; if zero sources succeed on the very first run, the bouncer fails
closed (refuses installs) rather than fail open.

## Usage

```sh
# One-time: sync the malware feeds.
bouncer sync

# Gate an install (same shape as safe-chain's CLI).
bouncer npm install lodash         # → exec real npm
bouncer npm install chai-as-upgraded
# bouncer: install refused — malware intelligence flagged the following:
#   - chai-as-upgraded@<any> (ecosystem: npm)
#       [aikido] MALWARE

# Show source health and cache location.
bouncer status
```

### Environment

| Variable             | Default                                | Purpose                                |
|----------------------|----------------------------------------|----------------------------------------|
| `BOUNCER_CACHE_DIR`  | `$XDG_CACHE_HOME/package-bouncer`      | where intel snapshots live             |
| `BOUNCER_SOURCES`    | `aikido,openssf,osv`                   | comma-separated source IDs to enable   |
| `BOUNCER_LOG`        | (info)                                 | set `debug` for verbose logging        |

## Agent integration

A Claude Code `PreToolUse` hook lives in [`hooks/claude-code/`](hooks/claude-code/).
It intercepts Bash tool calls that reach a package manager and forces the
agent to route through `bouncer`. Wrappers (`timeout`, `xargs`, `env`,
`sudo`), `bash -c "…"`, and shell separators (`&&`, `;`, `|`) are all
handled.

For agents and shells without a hook protocol (Codex CLI, Sirene, CI
runners, plain terminals), use the PATH-shim subsystem:

```sh
bouncer install-shims                # symlinks ~/.local/bin/{npm,pnpm,…} → bouncer
export PATH=$HOME/.local/bin:$PATH   # in front of the real PM directories
```

Now `npm install foo` resolves via the shim, bouncer detects the
invocation by its basename (`os.Args[0]`), and dispatches through the
gate. `bouncer uninstall-shims` reverses it. Both refuse to clobber
non-bouncer files unless `--force` is passed.

## Threat model and fail-closed semantics

Bouncer is built to fail closed: if the gate can't reach a confident
allow/refuse decision, the package manager does not run. Distinct exit
codes and messages distinguish each failure mode so a colleague seeing
"refused" knows whether their package was flagged (malware) or whether
something else went wrong (mis-install, upstream outage, parser bug).

**Fail-closed guarantees** (the gate refuses the install in all of these):

- **Malicious package**: any source flags it → exit 1, "install refused —
  malware intelligence flagged …"
- **Intel store cannot refresh** (every source failed, no cache):
  exit 70, "INTERNAL ERROR — intel refresh failed"
- **Intel store implausibly empty** (< 1000 reports total — Aikido alone
  ships >120k): exit 70, "INTERNAL ERROR — intel store has only N reports"
- **Manifest file present but unreadable / malformed** (`package.json`,
  `pyproject.toml`, `requirements.txt`): exit 70, "INTERNAL ERROR —
  install aborted fail-closed"
- **Claude Code hook crashes** (parser bug, malformed input): hook emits
  a "deny" with "INTERNAL ERROR in hook script" reason; if even that
  fails, exits 2 which Claude Code treats as a blocking error
- **Claude Code hook detects bouncer binary missing on PATH**: hook denies
  with a hard "DO NOT retry" message naming the mis-install

**Known fail-OPEN paths** (what bouncer cannot protect against):

- **Hook not wired**: if `~/.claude/settings.json` doesn't list
  `bouncer-hook.py` in PreToolUse, Claude Code's Bash tool calls reach
  the shell directly. The PATH shim is the second line of defense if it
  was installed.
- **Shim not installed and not in front of mise/PATH**: a fully-qualified
  path invocation (`/opt/.../bin/npm install …`) bypasses the shim
  entirely. The Claude Code hook still catches it (it matches on
  basename), but Codex and other shells with no hook protocol can't be
  routed.
- **Python interpreter missing**: the Claude Code hook is a Python script
  via shebang. If `python3` isn't on PATH at hook invocation, Claude Code
  fails-OPEN (allows the tool call). The hook itself can't fix this; a
  Go-rewrite of the hook would close this hole and is tracked.
- **Direct child-process invocation that doesn't go through the shell**:
  an agent that does `subprocess.run(["/full/path/to/npm", "install",
  "foo"], shell=False)` bypasses both the hook and any shell-level PATH
  lookup. Out of bouncer's reach by design — it's a command-layer
  scanner, not a kernel-level interposer.
- **Compromised upstream returning near-empty feeds**: the 1000-report
  floor catches the worst case (literally empty), but a feed that omits
  most malware while still returning hundreds of entries would slip
  through. Track-and-alert on report-count drops is future work.

### Verifying your install

Before relying on bouncer in any agent session, confirm three things in
a fresh terminal:

1. `which bouncer` resolves to the installed binary (not "not found").
2. `which npm` resolves to `~/.local/bin/npm` (the shim) — if it shows
   mise's path or homebrew's, the shim is shadowed and won't engage.
3. `bouncer status` prints all three sources without errors.

A red flag in any of these means the gate isn't actually in front of
your installs.

## Status

v0. End-to-end working against three live intel sources (Aikido,
OpenSSF malicious-packages, OSV) with ~620k reports indexed. 14 package
managers covered (npm/pnpm/yarn/bun + their x-variants, pip/pip3/uv/uvx/
poetry/pipx/pdm). Manifest-driven gating for `package.json`,
`pyproject.toml` (PEP 621 + Poetry tables), and `requirements.txt`.
Fail-closed semantics throughout the gate, hook, and intel paths.

Sirene integration is still TBD (see `hooks/sirene/README.md`).

## License

TBD (planning open source once the design has settled).
