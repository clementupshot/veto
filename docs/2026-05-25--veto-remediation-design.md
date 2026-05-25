# Veto remediation design

Date: 2026-05-25
Status: Approved (brainstorming phase)
Source review: `Thermo-nuclear code quality review` — 10 parallel reviewers
covering every blocking layer + every package-manager family + gate + intel +
CLI/scan/doctor.

## Goal

Close all known fail-OPEN bugs in veto and make a contained set of structural
moves that prevent the same class of bugs from recurring. Reject pure
file-size or cosmetic refactors that have no drift-prevention story.

## Non-goals

- Decomposing files solely because they exceed an arbitrary line count.
  `main.go` at 1423 lines, `cache.go` at 653, `jslock.go` at 425 are left
  alone unless an unrelated task happens to shrink them.
- Adopting a CLI framework (cobra/kong). The hand-rolled dispatch stays.
- Adopting `renameio` or other tiny utility deps. Fsync pair is hand-rolled.
- Adding features beyond what the review surfaced.

## Phase structure

Four phases. Each phase ships independently. Phase 3 is gated on Phase 0.

```
Phase 0 — Dep pre-flight (~half day)
Phase 1 — Fail-OPEN bugs + override-env removal (security-critical)
Phase 2 — Enabling refactors (no new deps)
Phase 3 — Library swap-ins (gated on Phase 0)
```

Sequencing rule: Phase 1 may ship without 2 or 3. Phase 2 may ship without 3.
Phase 3 starts only after Phase 0 emits an "adopt" verdict for the candidate
library.

## Phase 0 — Dep pre-flight

Scan every library proposed for Phase 3 through veto itself before adopting.

Candidates:
- `mvdan.cc/sh/v3/syntax` — real shell AST parser (replaces L1 analyzer)
- `golang.org/x/mod` (modfile + module + semver) — replaces gomod scanner
- `aquasecurity/go-pep440-version` — replaces hand-rolled PEP 440
- `github.com/pelletier/go-toml/v2` — replaces Codex line-TOML scanner;
  shared by Cargo TOML parsers if not already in use

Steps per candidate:
1. `veto go get <pkg>@<latest>` — exercises the Go live-gating path
2. `veto scan --root <tmp clone of pkg>` — static manifest + lockfile audit
3. One level of transitive: same scan against each direct dep listed in the
   candidate's `go.mod`
4. Record verdict, fired source IDs, transitive concerns

Output: `docs/2026-05-25--deps-preflight.md` with one row per package:
`name, version, verdict (adopt/pin/reject), transitive concerns, recommendation`.

Gate: a Phase 3 task may proceed only when its row reads "adopt at <pinned
version>". A rejected lib drops the corresponding Phase 3 task; the
in-place fix from Phase 1 (where applicable) remains.

## Phase 1 — Fail-OPEN bugs + override-env removal

One commit per logical group. Each lands with a regression test that
encodes the originally-broken case.

### 1.1 Delete `VETO_BYPASS` and `VETO_ALLOW_OPAQUE`

- Remove from `claudecode.go`, `hook.go`, `main.go`, all docs, help text,
  README env-vars table, memory note
- Remove `gate.Policy.AllowOpaqueRemote` axis; opaque-spec installs are
  always refused (the policy was already the default; the override is what's
  going away)
- Remove the C interposer's `getenv("VETO_BYPASS")` call entirely
- Closes by removal: L1 positional-bypass check; L3 env-scope bug; Gate
  Policy axis sprawl

### 1.2 L1 hook parser evasions (band-aid)

Phase 3.1 replaces the analyzer with `sh/v3/syntax`. Phase 1 patches the
specific evasion vectors so veto isn't fail-OPEN in the interim:
- Apply `splitInlineSeparators` to the inner re-shlexed payload after
  `bash -c "…"` unwrap
- Detect `$(`, backticks, `<(`, `>(`, `<<<` in the raw command string
  before shlex; emit deny with `veto-hook: refusing to evaluate command
  substitution; reissue without $() / backticks`
- Regression tests for: `bash -c "cd /tmp;npm install foo"`,
  ``echo `npm install foo` ``, `echo $(npm install foo)`,
  `sh <<< 'npm install foo'`

### 1.3 L2 python shim hardening

- `pythonDashMTarget` correctly unwraps: `python -m pip ...`,
  `python -mpip ...` (no space), `python -I -m pip ...`,
  `python -E -m pip ...`, `python -S -m pip ...`, `python -B -m pip ...`,
  `python3.11 -m pip ...`, leading flag bundles
- Invert the existing `python -I -m pip "intentionally not unwrapped"`
  test
- Managed-shell wrappers use `${VAR:-default}` instead of unconditional
  overwrite (pip/pip3/uv/uvx — bash, zsh, and fish branches)
- `install-shims --force`: rename pre-existing real binary to
  `<path>.veto-displaced` instead of `os.Remove`; `uninstall-shims`
  restores if present

### 1.4 L3 interposer scoping

- Stop calling `getenv` for any policy decision (`VETO_BYPASS` is gone
  per 1.1)
- Replace process-global `setenv("VETO_PYTHON_M_ORIGINAL", ...)` with
  `rewrite_envp`. For `execv`/`execvp`/`execl` variants (no envp
  parameter), build a synthetic envp from `environ` + the new entry
- New e2e cases covering `execvpe`, `fexecve`, `execveat` on Linux
- New test asserting a multi-threaded caller doesn't leak the python-m
  env into a sibling exec

### 1.5 L4 wrapper atomicity

- `loadWrapperState` error propagates (no `_` swallow); a corrupt
  `wrappers.json` aborts with a clear message
- Per-candidate write-ahead order: write registry entry → rename real
  binary to `.veto-original` → symlink veto at target. Roll back the
  registry entry on FS failure
- `unwrap`: atomic via tmp-rename dance — rename `.veto-original` to
  `<path>.veto-restoring`, remove veto symlink, rename `.veto-restoring`
  to `<path>`. On failure, original is intact
- `saveWrapperState`: `tmpfile.Sync()` before close; parent-dir fsync
  after rename (~6 lines, hand-rolled, no `renameio`)
- Chmod registry to `0o600`, not `0o644`
- New tests: "crash between rename and symlink", "corrupt wrappers.json",
  "unwrap rename-back fails"

### 1.6 JS parser fail-OPENs

- Define `ManifestKindBunLock` + `jslock.expandBunLock` for text JSONC
  `bun.lock`. `bun.lockb` (binary) stays unsupported with a warning
  emitted at install time
- `pnpm dlx` / `yarn dlx` / `bun x` / `bun create` route through
  `exec.Manager` (consume `--package` flag value, ignore trailing
  positionals after the spec). Regression tests for each
- `jsspec.IsLocalPathSpec` recognizes `link:`, `portal:`, `workspace:`,
  `catalog:`, `patch:` prefixes (yarn berry + pnpm)
- `jsmanifest` reads `bundleDependencies`; walks `workspaces[]` glob
  patterns recursively
- `jslock` yarn parser skips `__metadata` pseudo-entries
- `jsmanifest.exactPin` wildcard check anchors `x`/`X` to segment
  boundaries; legitimate exact pins like `1.0.0-experimental` or
  `1.0.0-Xfix` no longer downgrade to name-only lookup
- `jsspec.tryParseAlias` only fires when the name portion is a legal
  npm name (closes the `user/repo@npm:evil@1` precedence quirk)

### 1.7 Python parser fail-OPENs

- `pyreq` glues line continuations before parsing (closes the
  `evil==9.9.9` continuation-line phantom-install)
- `pyspec.IsLocalPathSpec` recognizes bare-dir-with-slash (`evil/`),
  Windows drive paths (`C:\…`, `C:/…`)
- `pyspec.Parse` rejects names beginning with `-` (unknown flags don't
  become installs named `--unknown`)
- pip and uv resolver prescans forward: `--index-url`,
  `--extra-index-url`, `--find-links`, `--keyring-provider`,
  `--override`, `--prerelease`, `--resolution`, `--python` (or refuse
  to prescan if these are present and we don't know how to forward
  them)
- Both prescans strip `--no-deps` and `--no-build-isolation` before
  exec (or refuse with "unsafe flag for prescan")
- `uv add` / `uv install`: when current lockfile doesn't cover the new
  requirement, fall through to ResolverPreScan path
- `pylock` skips workspace-member entries (`source.editable`,
  `source.virtual`)
- `pymanifest` reads `tool.uv.dependencies`, `tool.uv.dev-dependencies`,
  `tool.pdm.dev-dependencies`
- `pymanifest` walks workspace members: `tool.uv.workspace.members`,
  `tool.poetry.workspaces`, PEP 621 workspace members. Recurses into each
  member's `pyproject.toml`. Parallels the JS workspace walk in 1.6
- `pymanifest.exactVersionOrEmpty` delegates to `intel.parsePEP440Version`
  instead of its bag-of-bytes heuristic

### 1.8 Go / Cargo parser fail-OPENs

- `golang.go`: add `install` to the `ManifestRefs` switch; emit
  `goModuleRefs` when `get` has zero or all-local positionals; add
  `install` no-args case to `ProjectPreflight`
- `cargo.go`: add `doc`, `publish`, `package` to `ProjectPreflight`;
  add `publish` to `ParseInstalls`
- `cargomanifest`: `registry = "<non-crates-io>"` → `OpaqueRemote`
- `cargomanifest`: parse `[workspace] members` (and `exclude`) and
  recurse into member `Cargo.toml` files
- `gomod`: `TrimSuffix` only when `filepath.Ext(modPath) == ".mod"`
- `replace` directive handling deferred to Phase 3.2 (lands with
  `modfile` swap)

## Phase 2 — Enabling refactors (no new deps)

Each item independently mergeable. Together they kill the drift hazards that
allowed Phase 1 bugs to exist.

### 2.1 `pmlist` as single source of truth for all policy tables

Move into `pmlist` (Go-side canonical):
- `pythonDashMTargets` + `pythonDashMTarget` classifier (from `main.go`,
  `claudecode.go`)
- `execPMs` (from `claudecode.go`, `veto_interpose.c`)
- `dangerousVerbs`, npm/pip/etc. verb tables (from `claudecode.go`,
  `veto_interpose.c`)
- `goFlagsWithValues`, `cargoFlagsWithValues` (from `claudecode.go`,
  `veto_interpose.c`)
- `pythonInterpreters` (from `claudecode.go`)

Extend `genpmlist` to emit `pm_constants.h` (verbs, flags, python-m
targets, exec PMs) alongside `pm_names.h`. Delete the duplicate
definitions from `main.go`, `claudecode.go`, `veto_interpose.c`.
Extend the consistency test to cover the new generated arrays.

### 2.2 Intel sources shared scaffold

New `internal/intel/sources/common/`:
- `Fetcher{URL, CacheDir, MaxBytes, Client, Logger}` with `FetchWithCache`
  (returns payload, etag, fromCache) and `FetchToFile` for streaming
  sources. Parse-then-etag invariant lives here, enforced once.
- Each of aikido/osv/openssf/ghsa/pypa becomes URL config + `decode(payload)
  ([]MalwareReport, error)` callback
- Promote `atomicwrite.go` and add `StreamAtomic` for tarball-streaming
  sources
- `Source.SupportedEcosystems() []Ecosystem`; `fetchAll` only spawns the
  supported `(source, ecosystem)` cross-product; `ErrUnsupportedEcosystem`
  goes away
- Short-TTL or singleflight HEAD cache so openssf/ghsa don't issue four
  serial HEAD requests per refresh
- `fsutil.EnsurePrivateDir(path)` helper consumed by all sources

### 2.3 Shared shell-rc helper

New `internal/shellrc/`:
- `TargetsForUser(shell string) []Target` — single source of truth for
  "what rc files to write to"
- `UpsertManagedBlock(path string, markers MarkerPair, body string) error`
  — atomic write + parent-dir fsync
- `RemoveManagedBlock(path string, markers MarkerPair) error`
- Both `install_shell.go` and `install_preload.go` consume `TargetsForUser`,
  so L3 fans out to every L2 target (closes the bash-login gap)
- Each installer keeps its own marker pair; multiple managed blocks coexist
- `shellKindForRC` ambiguity fixed: require explicit `--shell` when basename
  unrecognized

### 2.4 JS Manager factory

New `internal/packagemanager/jspm/`:
- `Spec{Binary, InstallVerbs, FlagsWithValues, AlwaysReadsManifest,
  ExecVerb, ExecSpecFlags, Lockfiles []ManifestKind, BareInstallSupported}`
- `New(Spec) PackageManager`
- npm/pnpm/yarn/bun become ~10-line `var Manager = jspm.New(...)`
  declarations
- Per-PM `Lockfiles` honored (no more "emit all four lockfiles
  speculatively"); each PM declares the lockfiles its resolver actually
  consults
- `npm exec` dispatches to `exec.Manager` (deletes `parseExec`)
- `jsspec.splitNameAndVersion` and `jslock.splitPnpmKeyBoundary` unified
  into one exported helper

### 2.5 Native PM verb tables

- `golang.go`: `var goVerbs = []goVerb{name, sub, parseMode,
  emitsModRefs, projectPreflight, goRunLocalOnly}`. One table queried by
  `ParseInstalls`, `ManifestRefs`, `ProjectPreflight`
- `cargo.go`: same shape. `parseAdd` + `parseInstall` collapse;
  `markInstallsOpaque` + `markInstallsLocal` collapse
- Shared `argv.FirstFlagValue` helper (deletes the duplicate
  `firstFlagValue` in both PMs)
- Shared "walk up for parent manifest" helper consumed by golang and
  cargo

### 2.6 Gate + shared parsers cleanup (single PR)

Lands as one PR. Mechanical edits across every file in
`internal/packagemanager/`.

- `Install` becomes a sum: `Kind` enum `{NamedRef, LocalPath, OpaqueRemote}`,
  `Ref` valid only when `Kind == NamedRef`. Two booleans deleted; the
  never-tested "Local AND Opaque" cell becomes unrepresentable
- `Outcome` becomes a typed sum: `Decision` interface with
  `Allow | Refuse{Verdicts} | Abort{Errors} | Passthrough` variants. The
  three duplicate switches in `main.go` collapse to one dispatch
- Delete `NopExpander`; gate nil-checks the expander inline
- Delete the duplicate `g.expander` field; read through
  `g.policy.ManifestExpander` directly
- `argv.FirstNonFlagWithTable` and `CollectPositionalsWithTable` share a
  single iterator
- `scan/types.go` splits into `types.go` + `report.go` + `render.go`; the
  duplicate verdict-printer in `main.go` consolidates
- Replace `"veto-policy"` magic-string `SourceID` with a typed
  `RefusalReason` on `Decision`; renderer dispatches on the typed reason

### 2.7 `veto_interpose.c` exec dispatcher

Collapse 13 exec wrappers (5 macOS + 8 Linux) through one core:
```c
static int gate_and_exec(
    const char *probe_path, char *const argv[], char *const envp_in[],
    int (*passthrough)(void *ctx), void *ctx_passthrough,
    int (*reroute)(const char *abs_veto_path, char *const new_argv[],
                   char *const new_envp[], void *ctx),
    void *ctx_reroute);
```
Each wrapper becomes a ~10-line adapter building a small ctx struct.
Expected delta: ~969 → ~500 lines. Future fixes land in one place.

### 2.8 Agent installer table

Three near-duplicate installers (`install_claude_hook.go`,
`install_codex.go`, `install_cursor.go`) collapse via:
```go
type agentIntegration struct {
    name        string
    banner      string
    preActions  []func(opts agentOpts) error
    postCheck   func(opts agentOpts)
    nextSteps   func(w io.Writer, opts agentOpts)
}
var agents = []agentIntegration{ /* claude, codex, cursor */ }
func runInstallAgent(name string, args []string) int { ... }
```
Single flag-parsing path. Closes the inconsistent `--force` semantics
across the three. Cursor's `flag.NewFlagSet` usage aligns with the
others.

### 2.9 Defense-layer registry

Both `install_all` and `doctor` know "what good looks like" for each
layer. Extract a layer interface:
```go
type layer interface {
    Name() string
    RequiredEnv() map[string]string
    Install(opts InstallOpts) error
    Status() (Result, error)
}
var layers = []layer{ shimsLayer, shellLayer, claudeHookLayer, ... }
```
`install_all` iterates `layers` calling `Install`; `doctor` iterates
calling `Status`. One source of truth.

### 2.10 doctor table-driven + parallel

```go
type check struct {
    name string
    run  func(ctx context.Context, cfg Config) []checkResult
}
var checks = []check{ /* ... */ }
```
`runDoctor` becomes a single `errgroup.Go` loop, writing per-check
results into pre-allocated slots; render in order after the wait.
Expected runtime: ~30s → ~5s.

## Phase 3 — Library swap-ins (gated on Phase 0)

Each task proceeds only when its corresponding Phase 0 row is "adopt".

### 3.1 L1 hook analyzer → `mvdan.cc/sh/v3/syntax`

Replace the token-pipeline analyzer in `claudecode.go` with a real shell
AST walker. Closes the Phase 1 band-aids by structure:
- `$(…)` / backticks → `CmdSubst` nodes
- `<(…)` / `>(…)` → `ProcSubst` nodes
- `<<<` → `Redirect` with `Op = DashHerestring`
- `bash -c "…"` → parse the literal as a nested `File`
- `&&` / `||` / `;` / `|` → `BinaryCmd` / pipeline nodes
- env-var prefixes → `Assign` nodes

Walk: for every `CallExpr` leaf, ask "is the resolved command a covered PM
with a dangerous verb?" using `pmlist` tables (from Phase 2.1).

Delete the Phase 1.2 band-aid code. Phase 1.2 regression tests remain as
the contract. Expected delete: ~400-500 lines from `claudecode.go`.

### 3.2 go.mod / go.sum → `golang.org/x/mod`

- `gomod.go` hand-rolled scanner deleted; uses `modfile.Parse`
- `replace` directives parsed; replaced-to-local modules marked
  `LocalPath`
- `splitModuleVersion` / `isExactGoVersion` delegate to `module.CheckVersion`
  + `module.PseudoVersion` classifiers

### 3.3 PEP 440 → `aquasecurity/go-pep440-version`

Conditional on Phase 0 verdict.
- Delete `intel/pep440.go` (~330 lines)
- `intel/range.go`'s PyPI arm delegates to the lib
- Phase 1 multi-digit-local-label test stays
- If Phase 0 rejects the lib: this task is dropped; Phase 1 fixes the
  multi-digit-local-label sort in place

### 3.4 Codex TOML + Cargo TOML → `pelletier/go-toml/v2`

- `install_codex.go` line-scanner deleted; uses real TOML decode
- Cargo TOML parsers consolidate to the same lib (if not already on it)

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Phase 1.2 band-aid regresses when Phase 3.1 lands | Phase 1.2 regression tests stay as the contract; Phase 3.1 must pass them |
| Phase 0 rejects sh/v3 | L1 evasions stay closed by Phase 1.2 band-aids; the analyzer rewrite drops, file stays large |
| Phase 0 rejects modfile | `replace` directive handling stays unimplemented (Phase 1.8 already deferred this); existing gomod parser stays |
| Phase 2.6 single-PR scope creep | Strict mechanical-edits-only discipline; no opportunistic refactors land in the same PR |
| Phase 2.1 generator drift between Go-side tables and emitted C header | Extend the existing consistency test; CI fails on drift |
| Deleting `VETO_BYPASS` breaks an undocumented user-side workflow | Memory note already flagged for removal; no documented dependency. If discovered, the rollback is one commit |

## Acceptance criteria

Phase 1 ships when:
- Every fail-OPEN listed has a regression test
- `VETO_BYPASS` and `VETO_ALLOW_OPAQUE` no longer appear in source, docs,
  or help text
- `make test` passes; existing e2e tests pass
- Doctor reports no new WARN/FAIL rows

Phase 2 ships when:
- `pm_constants.h` is generated, the consistency test covers it, and the
  hand-maintained mirrors are deleted from `main.go`, `claudecode.go`,
  `veto_interpose.c`
- Intel source files each shrink to URL config + `decode` callback
- `shellrc` package exists; both installers consume it
- `jspm.New(Spec)` factory exists; per-PM files are declarative
- golang.go / cargo.go each use a single verb table
- `Install` is a sum type; `Decision` is a typed variant; the three
  duplicate switches in `main.go` are collapsed
- `gate_and_exec` exists; the 13 wrappers are thin adapters
- `agentIntegration` table replaces the three installers
- `defense-layer` registry shared by `install_all` and `doctor`
- doctor runs checks in parallel; full doctor pass < 10s on a warm machine

Phase 3 ships when:
- Every "adopt" row from Phase 0 has its corresponding swap merged
- Library-rejected swaps are explicitly documented as "not adopted; reason"
- L1 analyzer line count is materially smaller (target: < 200 lines)
