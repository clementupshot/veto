# veto scan capability plan — 2026-05-23

## Purpose

`veto` currently blocks risky package-manager invocations before install.
The next capability should detect existing exposure on a workstation:
projects already checked out, lockfiles already present, package-manager
caches already populated, and agent/tooling persistence surfaces that can
launch package-manager or MCP code later.

This plan adds three related commands:

```sh
veto scan [--root ~/projects] [--json] [--no-projects] [--no-caches] [--no-agent-surface]
veto quarantine-cache [--dry-run] [--purge] [--json]
veto audit-agent-surface [--json]
```

`veto scan` is the single broad command. By default it runs the project
scanner, cache exposure scanner, and agent-surface audit in one read-only
pass. Narrower commands remain useful for targeted follow-up, but the default
operator experience should be "run one command and see every relevant
surface." Any deletion or quarantine action must require an explicit
`--purge` or future interactive confirmation.

## Goals

- Recursively scan `~/projects` for package manifests and lockfiles, parse
  them through the same package-manager expanders used by the gate, and
  compare every discovered package ref against the current intel store.
- Scan package-manager caches for known malicious package artifacts or
  suspicious fetch-and-run residue, with enough path metadata to let a user
  inspect and remove the artifacts safely.
- Add a cache quarantine command that defaults to dry-run and can purge only
  artifacts that are confidently tied to flagged package refs or explicit IOC
  rules.
- Audit agent persistence and execution surfaces: Claude/Codex/Cursor/Sirene
  hooks, MCP server configs, `npx`-spawned MCP tools, launchd entries, and
  suspicious `SessionStart` hooks.
- Reuse existing intel/store/parser code where possible. The scan feature
  should make the existing gate primitives more reusable, not fork a second
  parser stack.

## Non-Goals

- Do not build a general antivirus scanner. This is package-manager and
  agent-surface focused.
- Do not recursively scan every file under `$HOME` by default. Start with
  known project roots, known cache roots, and known agent config roots.
- Do not execute package managers, lifecycle scripts, or MCP servers during
  scan. The command is read-only unless the user explicitly runs a purge.
- Do not claim host cleanliness from absence of findings. Output should say
  what was checked and what was not checked.

## Command UX

### `veto scan`

Default:

```sh
veto scan
```

Equivalent to:

```sh
veto scan --root ~/projects
```

Recommended flags:

```sh
veto scan --root ~/projects --json
veto scan --root ~/projects --no-agent-surface
veto scan --no-projects --no-agent-surface  # cache exposure only
veto scan --no-projects --no-caches         # agent surface only
```

Exit codes:

- `0`: scan completed and found no flagged exposure.
- `1`: scan completed and found flagged exposure.
- `70`: scan could not make a confident decision because intel refresh,
  parser errors, or required filesystem reads failed in a fail-closed way.

Text output should group findings by severity and surface:

```text
veto: scan found flagged exposure

Projects:
  - /Users/me/projects/app/package-lock.json
      npm evil-transitive@9.9.9 [aikido] MALWARE

Caches:
  - /Users/me/.cache/npm/_npx/abc/node_modules/mcp-mermaid/package.json
      npm mcp-mermaid@0.6.1 [ioc] npx-spawned MCP cache residue

Agent surface:
  - ~/.claude/settings.json SessionStart hook
      suspicious command references npx package mcp-mermaid
```

JSON output should be stable and include at least:

```json
{
  "schema_version": 1,
  "started_at": "...",
  "roots": ["/Users/me/projects"],
  "summary": {
    "files_scanned": 1234,
    "packages_checked": 4567,
    "flagged_packages": 2,
    "agent_findings": 1,
    "errors": 0
  },
  "findings": []
}
```

### `veto quarantine-cache`

Default dry-run:

```sh
veto quarantine-cache
veto quarantine-cache --dry-run
```

Purge:

```sh
veto quarantine-cache --purge
```

This command should run the cache scanner, print candidate removals, and only
delete artifacts when `--purge` is present. `--purge` must only remove paths
under known cache roots after resolving symlinks and verifying the path is
still inside that cache root.

### `veto audit-agent-surface`

```sh
veto audit-agent-surface
veto audit-agent-surface --json
```

This command should inspect agent configuration and persistence surfaces
without scanning package manifests. It is useful after an incident when the
operator wants a fast persistence check.

## Architecture

Add new packages under `internal/scan/`:

```text
internal/scan/
  types.go              shared Finding, Severity, Evidence, Scanner interfaces
  project/              manifest and lockfile discovery under project roots
  cache/                package-manager cache discovery and purge planning
  agentsurface/         Claude/Codex/Cursor/Sirene/MCP/launchd audits
  report/               text and JSON rendering
```

Suggested contracts:

```go
type Finding struct {
    ID          string
    Surface     Surface
    Severity    Severity
    Path        string
    PackageRef  *intel.PackageRef
    Verdict     *intel.Verdict
    Evidence    []Evidence
    Remediation string
}

type Scanner interface {
    Scan(ctx context.Context) ([]Finding, []error)
}

type PurgePlanner interface {
    PlanPurge(ctx context.Context) ([]PurgeAction, []error)
}
```

`cmd/veto` should wire these scanners to the existing config, logger, intel
store, and `newCompoundExpander()`. The scanner packages should not know
about CLI flags.

## Intel Store Handling

`scan` and `quarantine-cache` must use the same intel source and sanity
policy as `runGate`:

1. Build the store from `VETO_SOURCES` / config.
2. Refresh under `syncTimeout`.
3. Enforce `minHealthyReportCount` before trusting clean results.

If the store cannot refresh and no usable cache exists, scan exits `70`.
It is better to say “cannot scan confidently” than produce a clean report
from an empty intel store.

## Project Scanner

Default root: `~/projects`. This scanner always runs as part of `veto scan`
unless `--no-projects` is passed.

Discovery should walk recursively but prune high-noise/generated dirs:

- `.git`
- `node_modules`
- `.venv`, `venv`, `env`
- `.mypy_cache`, `.pytest_cache`, `.ruff_cache`
- `dist`, `build`, `target`, `.next`, `.turbo`

Files to detect:

- npm-family: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`,
  `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb` if supported later.
- Python-family: `requirements*.txt`, `constraints*.txt`, `pyproject.toml`,
  `uv.lock`, `poetry.lock`, `pdm.lock`.

Phase 1 should use existing expanders:

- `jsmanifest.Expander` for `package.json`.
- `jslock.Expander` for npm/pnpm/yarn lockfiles.
- `pymanifest.Expander` for `pyproject.toml`.
- `pylock.Expander` for uv/poetry/pdm lockfiles.
- `pyreq.Expander` for requirements and constraints files.

For each expanded `Install`, call `store.Lookup(ins.Ref)` and emit a finding
when the verdict is flagged. Local-path and opaque-remote policy findings
should be represented too, but separate from malware-intel findings:

- `opaque-remote`: warning or high severity depending on context.
- `local-path`: info unless it points outside the repo root or into a cache
  directory.
- unreadable/malformed manifest: error finding and scan exit `70` unless
  the user passed a future `--best-effort` flag.

Important implementation detail: requirements files can include other files.
The existing `pyreq.Expander` resolves nested refs relative to the parent
file; the project scanner should feed it absolute top-level paths so nested
relative resolution remains correct.

## Cache Scanner

The cache scanner always runs as part of `veto scan` unless `--no-caches` is
passed. It has two jobs:

1. Detect flagged packages already present in caches.
2. Detect suspicious fetch-and-run residue that matches known incident
   patterns, even when the package is not currently in an intel feed.

Initial cache roots:

- npm: `~/.npm`, `~/.cache/npm`, configured `npm config get cache` if cheap
  and safe to query later; special focus on `_npx`.
- pnpm: `~/Library/pnpm/store`, `~/.pnpm-store`, `~/.local/share/pnpm/store`.
- bun: `~/.bun/install/cache`.
- pip: `~/Library/Caches/pip`, `~/.cache/pip`.
- uv: `~/.cache/uv`.
- poetry: `~/Library/Caches/pypoetry`, `~/.cache/pypoetry`.

Phase 1 should avoid package-manager-specific binary cache parsing when a
safer artifact exists. Prefer:

- `package.json` under `_npx`, npm cache extraction dirs, and tool caches.
- lockfiles or metadata JSON where present.
- wheel filenames and `.dist-info/METADATA` for pip/uv/poetry caches.
- archive filenames as weak evidence only when metadata is unavailable.

Cache findings should include confidence:

- `confirmed`: metadata file names package + version and intel lookup flags it.
- `probable`: cache path strongly names package + version and intel flags it.
- `ioc`: known suspicious residue pattern such as npx-spawned MCP package,
  even without a malware-feed hit.

Do not purge `probable` or `ioc` by default in the first implementation.
`--purge` should remove only `confirmed` findings unless a future flag opts
into IOC purging.

## Quarantine/Purge Safety

`quarantine-cache --purge` must be conservative:

- Resolve every candidate with `filepath.EvalSymlinks`.
- Verify the resolved path is under a known cache root after symlink
  resolution.
- Refuse to delete if the path is `/`, `$HOME`, `~/projects`, or any parent
  of a configured cache root.
- Delete only the smallest safe cache artifact: the package extraction dir,
  `_npx/<id>` dir, wheel/archive file, or metadata dir, depending on scanner
  evidence.
- Print every action before executing it.
- Return a structured `PurgeAction` with `status: planned|deleted|skipped|failed`.

Consider a non-destructive quarantine move later:

```text
~/.cache/veto/quarantine/<timestamp>/<source-cache>/<artifact>
```

For MVP, deletion under explicit `--purge` is enough if the safety checks are
strict.

## Agent Surface Audit

This should be a separate scanner because many findings are not package refs,
but it still runs as part of `veto scan` unless `--no-agent-surface` is
passed. It should produce `Finding` records with evidence and remediation
text.

### Claude

Inspect:

- `~/.claude/settings.json`
- `~/.claude/settings.local.json`
- project `.claude/settings.json` under scan roots
- `~/.claude/hooks/**` referenced by config

Checks:

- `SessionStart` hooks.
- hooks invoking `npm`, `npx`, `pnpm dlx`, `bunx`, `uvx`, `pipx`, `curl | sh`,
  `bash -c`, or remote URLs.
- hook files with recent mtimes during an incident window if that becomes a
  future flag.

Known-good hooks should be reported as info, not hidden entirely. Prior host
triage found a known `~/.claude/hooks/gsd-check-update.js` SessionStart hook;
the audit should show it as present and explain why it is not automatically
classified as malicious.

### Codex

Inspect:

- `~/.codex/config.toml`
- `~/.codex/**/config*.toml` if present
- MCP config entries that use `command = "npx"`, `uvx`, `pipx`, shell wrappers,
  or remote URLs.

Checks:

- MCP servers spawned through package-manager fetch-and-run commands.
- unexpected env vars containing tokens in MCP config output should be redacted.
- custom hooks or session lifecycle entries if present in the installed Codex
  version.

### Cursor

Inspect:

- `~/.cursor/mcp.json`
- project `.cursor/mcp.json`
- `.cursor/rules/*.mdc`

Checks:

- MCP servers spawned through `npx`, `uvx`, `pipx`, shell commands, or remote
  bootstrap scripts.
- missing `veto` rule/instruction can be an informational hardening finding,
  not a security incident.

### Sirene

Inspect likely config and runtime paths:

- `~/.sirene/**`
- repo-local Sirene config under `~/projects/dev-cycle*` if present
- `~/.sirene/cli-tool-logs/**/command.txt`

Checks:

- workflow hooks or agent startup commands that spawn package managers.
- MCP server definitions that use fetch-and-run commands.
- recent CLI tool log commands invoking package managers outside veto.

### MCP Server Configs and npx Tools

Normalize MCP entries across Claude, Codex, Cursor, and Sirene into a common
shape:

```json
{
  "owner": "claude|codex|cursor|sirene",
  "path": "...",
  "name": "linear",
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-linear"],
  "env_keys": ["LINEAR_API_KEY"]
}
```

Then classify:

- `high`: command uses package-manager fetch-and-run for an unknown or flagged
  package.
- `medium`: command uses shell wrapping, remote URL, or unpinned package spec.
- `info`: command is pinned and not flagged.

The scanner should correlate npx MCP configs with `_npx` cache artifacts when
possible: config says `npx -y mcp-mermaid`, cache contains `mcp-mermaid@0.6.1`.

### launchd

macOS launchd audit should inspect:

- `~/Library/LaunchAgents/*.plist`
- `/Library/LaunchAgents/*.plist` read-only when accessible
- `launchctl print-disabled gui/$UID` output when available

Checks:

- labels matching known incident residue such as `com.user.kitty-monitor`.
- `Program` or `ProgramArguments` invoking package managers, shell wrappers,
  `curl`, `osascript`, or paths under caches.
- disabled labels without matching plist should be emitted as residual evidence,
  not active persistence.

If `launchctl` is unavailable or fails due sandbox/permissions, emit a scanner
error and continue with filesystem plist inspection.

## Severity Model

- `critical`: active persistence or executable hook invokes a flagged package,
  known malicious package, or known worm IOC.
- `high`: flagged package present in a lockfile, manifest, or confirmed cache
  artifact; active agent hook uses unpinned fetch-and-run package command.
- `medium`: suspicious agent/MCP surface using shell bootstrap, remote URL, or
  cache execution path without a feed hit.
- `low`: stale cache residue, disabled launchd residue, or missing hardening
  integration.
- `info`: known-good hooks, scanned surfaces, and skipped paths.

## Implementation Sequence

### Phase 1 — Project Exposure Scanner

1. Add `internal/scan/types` and report model.
2. Add project filesystem walker with pruning.
3. Map filenames to `packagemanager.ManifestKind`.
4. Reuse `newCompoundExpander()` or move compound expander construction into a
   small internal package so scan and gate share it without CLI coupling.
5. Lookup every expanded install against the intel store.
6. Add `veto scan --root DIR --json --no-caches --no-agent-surface` for
   project-scanner-focused tests while keeping the default command wired for
   all scanners.
7. Tests: fixture projects with clean and flagged package-lock, uv.lock,
   requirements includes, malformed manifests, and pruned `node_modules`.

### Phase 2 — Cache Scan and Dry-Run Quarantine

1. Add cache root discovery with explicit allowlisted roots.
2. Implement npm `_npx` package.json scanner first because prior triage found
   useful residue there.
3. Add pip/uv/poetry wheel metadata scanner.
4. Add pnpm and bun metadata scanners where package identity can be confirmed.
5. Add `veto quarantine-cache --dry-run` rendering `PurgeAction`s.
6. Tests: temp cache roots with symlinks, malicious package metadata, and
   path traversal attempts.

### Phase 3 — Safe Purge

1. Implement `--purge` only for confirmed cache findings.
2. Add symlink and root containment checks.
3. Add deletion status reporting.
4. Tests: ensure purge refuses paths outside cache roots, refuses symlink
   escapes, and removes only the intended artifact directory/file.

### Phase 4 — Agent Surface Audit

1. Add config parsers for Claude JSON, Cursor MCP JSON, Codex TOML, and simple
   Sirene TOML/JSON/YAML as needed.
2. Normalize MCP server entries into one struct.
3. Add hook command classifier for package-manager, shell, URL, and known IOC
   patterns.
4. Add launchd plist reader and disabled-label parser.
5. Add `veto audit-agent-surface` and ensure default `veto scan` includes the
   same agent-surface findings unless `--no-agent-surface` is passed.
6. Tests: fixtures for suspicious SessionStart hook, benign known hook,
   npx-spawned MCP, disabled launchd residue, and redacted env output.

### Phase 5 — Output Polish and Docs

1. Aggregate summary counts and highest severity into exit code across all
   default scanners.
2. Add stable JSON schema docs.
3. Add README/onboarding usage docs.
4. Add examples showing how to narrow `veto scan` with `--no-*` flags for
   targeted debugging.

## Testing Strategy

- Unit tests for each scanner using `t.TempDir()` fixtures.
- Golden JSON output tests for stable reporting.
- No tests should depend on the real host home directory.
- No test should run real package managers or network calls.
- Purge tests must create symlink escape attempts and prove they are refused.
- Agent-surface tests should redact fake secrets in env blocks.

## Open Questions

- Should `veto scan` refresh intel by default, or should `--offline` use only
  the current cache? Recommendation: refresh by default, add `--offline` later.
- Should the default `veto scan` allow users to skip expensive surfaces?
  Recommendation: yes, via negative flags (`--no-caches`, `--no-agent-surface`,
  `--no-projects`) so the safe default remains comprehensive.
- Should `quarantine-cache --purge` delete IOC-only findings? Decision for MVP:
  no. It deletes only confirmed intel-flagged cache artifacts; IOC-only residue
  remains report-only until confidence is higher.
- Should project scan include hidden repos outside `~/projects`? Recommendation:
  only when explicitly passed via `--root`.
- Should agent-surface audit run as part of `doctor`? Recommendation: eventually
  add a lightweight doctor check that says whether suspicious surfaces exist,
  but keep the full audit as a separate command.

## Acceptance Criteria

- `veto scan --root <fixture>` runs project, cache, and agent-surface scanners
  by default.
- `veto scan --root <fixture> --no-caches --no-agent-surface` detects a flagged
  package in npm and Python lockfiles using the current intel store lookup
  semantics.
- `veto scan --root <fixture>` exits `1` on flagged exposure from any default
  scanner and `0` when no findings exist.
- `veto scan --json` emits stable schema-versioned JSON with paths, package
  refs, verdict sources, and remediation text.
- `veto quarantine-cache --dry-run` reports confirmed malicious cache artifacts
  without deleting anything.
- `veto quarantine-cache --purge` deletes only confirmed artifacts inside known
  cache roots and refuses symlink/root escape cases.
- `veto audit-agent-surface` reports suspicious `SessionStart`, MCP, npx, and
  launchd surfaces with secret redaction.
- All new behavior is covered by fixture-based tests and does not require live
  package-manager execution.
