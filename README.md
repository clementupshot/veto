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
  codex/ sirene/   ← planned (PATH-shim approach)
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
| `BOUNCER_SOURCES`    | `aikido`                               | comma-separated source IDs to enable   |
| `BOUNCER_LOG`        | (info)                                 | set `debug` for verbose logging        |

## Agent integration

A Claude Code `PreToolUse` hook lives in [`hooks/claude-code/`](hooks/claude-code/).
It intercepts Bash tool calls that reach a package manager and forces the
agent to route through `bouncer`. Wrappers (`timeout`, `xargs`, `env`,
`sudo`), `bash -c "…"`, and shell separators (`&&`, `;`, `|`) are all
handled.

Codex and Sirene integrations will land via the PATH-shim subsystem
(see [`hooks/codex/`](hooks/codex/), [`hooks/sirene/`](hooks/sirene/)).

## Status

v0 — works end-to-end against Aikido's feed; OpenSSF and OSV sources are
stubs returning `ErrUnsupportedEcosystem`; pip/uv/poetry/pdm parsing is
intentionally narrow (PEP 508 extras and requirements.txt expansion
deferred). See `@@TODO` markers in source for tracked gaps.

## License

TBD (planning open source once the design has settled).
