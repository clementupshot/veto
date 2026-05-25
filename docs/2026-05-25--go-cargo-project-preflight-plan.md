# Go and Cargo project-state preflight plan — 2026-05-25

## Purpose

Phase 1 gates package-manager commands that explicitly fetch or mutate
dependencies: `go get`, `go install`, remote `go run pkg@version`, `go mod
download`, `go mod tidy`, `cargo add`, `cargo update`, `cargo fetch`, and
`cargo install`.

Phase 2 closes the next gap: commands that build, test, or run local project
code after dependencies are already declared in the checkout. These commands
can compile or execute dependency code and may fetch missing artifacts as a
side effect, so they should not pass through without checking the project state
against the current intel store.

The first implementation should cover Go and Cargo because the repo already
has parsers and expanders for `go.mod`, `go.sum`, `Cargo.toml`, and
`Cargo.lock`.

## Goals

- Gate local Go execution/build/test commands by reading the project module
  files before passing through to the real `go` binary.
- Gate local Cargo execution/build/test commands by reading the project
  manifest and lockfile before passing through to the real `cargo` binary.
- Reuse the existing `gate.Gate`, `packagemanager.ManifestRef`, and compound
  manifest expander path so refusal output and fail-closed behavior remain
  consistent with install gating.
- Update the Claude Code hook so agent Bash calls to phase-2 commands are
  classified as package-manager operations and routed through `veto`.
- Keep this phase read-only. Do not run `go list`, `cargo metadata`, package
  managers, resolvers, build scripts, lifecycle hooks, or MCP tools as part of
  the preflight.
- Keep path handling explicit and test-covered for the common flags that move
  project context: Go `-C`, Go `-modfile`, Cargo `--manifest-path`, and Cargo
  `--lockfile-path` where supported.

## Non-Goals

- Do not add resolver pre-scans for Go or Cargo in this phase.
- Do not attempt to prove that a clean result means the host or checkout is
  clean. This is a package-intel gate over known project files.
- Do not inspect arbitrary source files, generated build output, or vendored
  dependency directories.
- Do not block non-project informational commands such as `go version`,
  `go env`, `cargo version`, or `cargo metadata` unless a later phase makes a
  specific argument for them.
- Do not change the existing `veto scan` behavior except for any shared helper
  reuse that falls out naturally.

## Current State

- `internal/packagemanager/packagemanager.go` defines `PackageManager`,
  `ManifestRef`, `ManifestKind`, and `ResolverPreScanner`.
- `cmd/veto/main.go` runs normal argv parsing, then evaluates returned installs
  and manifest refs through `gate.Gate` with `newCompoundExpander()`.
- `newCompoundExpander()` already dispatches Go and Cargo kinds to:
  - `internal/packagemanager/gomod` for `go.mod` and `go.sum`
  - `internal/packagemanager/cargomanifest` for `Cargo.toml`
  - `internal/packagemanager/cargolock` for `Cargo.lock`
- `internal/packagemanager/golang` currently returns `nil` for `go build`,
  `go test`, and local `go run`, causing passthrough.
- `internal/packagemanager/cargo` currently returns `nil` for `cargo build`,
  `cargo test`, and local `cargo run`, causing passthrough.
- `internal/hook/claudecode` currently treats the same phase-2 commands as not
  risky, so Claude Code can run them raw instead of asking the agent to prefix
  with `veto`.

## Proposed Interface

Add a small optional interface in the parent package:

```go
// ProjectPreflighter is implemented by package managers that can identify
// project-state files that must be gated before a non-install command runs.
type ProjectPreflighter interface {
    ProjectPreflight(args []string) (ProjectPreflightPlan, bool)
}

// ProjectPreflightPlan describes read-only project files that must be checked
// before a build/test/run-style command passes through.
type ProjectPreflightPlan struct {
    ManifestRefs []ManifestRef
}
```

The interface belongs in `internal/packagemanager` because it is a contract
between CLI wiring and package-manager implementations. Go and Cargo managers
implement it in their existing subpackages with static contract checks.

The first version should avoid richer fields unless implementation pressure
requires them. If path handling needs a base directory, prefer resolving paths
inside the Go/Cargo package before returning refs rather than teaching the gate
about per-PM working-directory semantics.

## Gate Flow

`runGate` should keep the existing order:

1. Resolve package manager and parse normal install records.
2. Refresh and sanity-check intel store.
3. Evaluate normal installs and manifest refs.
4. Run resolver pre-scan where available.
5. Execute the real package manager.

Phase 2 inserts project preflight between the normal parse and final passthrough
decision:

1. If `ParseInstalls` and `ManifestRefs` indicate an install/fetch/mutate
   command, use the existing path exactly as today.
2. If the command would otherwise be `OutcomePassThrough`, check whether the
   manager implements `ProjectPreflighter`.
3. If `ProjectPreflight(args)` returns `ok=false`, pass through unchanged.
4. If it returns `ok=true`, evaluate `nil` installs plus the returned manifest
   refs through the same `gate.Gate`.
5. Refuse on flagged packages and abort on unreadable or malformed required
   project files.
6. Allow only after project refs expand and all discovered package refs are
   clean.

This keeps the gate as the single place that converts manifest expansion errors
into fail-closed aborts and package intel hits into refusals.

## Required Project State

Normal scan expanders tolerate missing files because recursive scans encounter
partial projects. Build/test/run preflight is stricter: if a command implies a
project and the authoritative project files cannot be read, veto should not
pretend the command was checked.

Implementation options:

- Add a `Required bool` field to `ManifestRef` if the distinction needs to live
  at the gate boundary.
- Add a small wrapper expander in `cmd/veto` for project preflight that verifies
  expected files before delegating to `newCompoundExpander()`.
- Add separate manifest kinds only if the required/optional behavior differs by
  file type in ways that cannot be represented cleanly otherwise.

Recommendation: start with a wrapper expander so `ManifestRef` stays stable.
The wrapper should require at least one authoritative file per ecosystem:

- Go: `go.mod` is required for module-mode project preflight. `go.sum` is
  optional evidence.
- Cargo: `Cargo.toml` is required. `Cargo.lock` is required for commands that
  normally use the local package graph when it exists, but missing lockfiles
  need careful treatment because libraries often omit them. The conservative
  first slice can require `Cargo.toml` and gate `Cargo.lock` when present.

Open decision before coding: whether missing `Cargo.lock` should abort for
applications only. Veto does not currently know whether a Cargo project is an
application or library, so requiring `Cargo.lock` globally may create too much
friction.

## Go Command Coverage

Gate these commands through project preflight:

- `go build [packages...]`
- `go test [packages...]`
- `go run <local package-or-file> [args...]`
- `go vet [packages...]`

Keep these out of phase 2 unless later evidence says otherwise:

- `go version`
- `go env`
- `go help`
- `go list` unless it is later shown to fetch or execute relevant dependency
  code in the target threat model

Path handling:

- Respect global `-C DIR` by resolving `go.mod` and `go.sum` relative to `DIR`.
- Respect `-modfile FILE` by using that file as the required module file and
  the matching sum file when Go's documented naming convention applies.
- Treat remote versioned `go run pkg@version` as phase-1 install-style gating,
  not project preflight.
- Treat local `go run ./cmd/app`, `go run .`, and `go run main.go` as project
  preflight.

First-slice simplification: do not attempt to resolve nested module roots for
package args like `./submodule/...`; preflight the command's effective working
directory. Nested-module support can be added later if tests show common false
allows.

## Cargo Command Coverage

Gate these commands through project preflight:

- `cargo build`
- `cargo check`
- `cargo test`
- `cargo run`
- `cargo bench`
- `cargo clippy`

Keep these out of phase 2 unless later evidence says otherwise:

- `cargo version`
- `cargo help`
- `cargo metadata`
- `cargo tree`
- `cargo fmt`

Path handling:

- Respect `--manifest-path PATH` by resolving `Cargo.toml` to that path and
  `Cargo.lock` to the same directory unless `--lockfile-path` is supplied.
- Respect `--lockfile-path PATH` where Cargo supports it.
- For default invocations, use `Cargo.toml` and `Cargo.lock` relative to the
  current working directory.
- Continue treating `cargo install` as install-style gating, not project
  preflight.

First-slice simplification: do not walk parent directories to find a workspace
root unless a test proves the current command shape needs it. Defaulting to the
current directory is easier to reason about and less surprising for a command
gate.

## Claude Hook Updates

Update `internal/hook/claudecode` so phase-2 commands are risky and get routed
through `veto`:

- Add Go to `dangerousVerbs` with `build`, `test`, `run`, and `vet`, while
  preserving current install/fetch verbs.
- Add Cargo verbs `build`, `check`, `test`, `run`, `bench`, and `clippy`.
- Update tests currently named like "go build is phase 2" and "cargo build is
  phase 2" to expect risky findings.
- Add negative tests for `go version`, `go env`, `cargo version`, and
  `cargo metadata`.

The hook does not need to understand project files. It only needs to ensure the
agent reissues the command through `veto`, where the real gate has access to
the filesystem and intel store.

## Implementation Sequence

1. Add `ProjectPreflighter` and `ProjectPreflightPlan` to
   `internal/packagemanager/packagemanager.go` with exported doc comments.
2. Wire `cmd/veto/main.go` so passthrough decisions get a project-preflight
   opportunity before exec.
3. Add project-preflight helper code in `cmd/veto` only if required to enforce
   required-file semantics around the existing compound expander.
4. Implement Go project preflight in `internal/packagemanager/golang`.
5. Implement Cargo project preflight in `internal/packagemanager/cargo`.
6. Update Claude Code analyzer verbs and tests.
7. Update `README.md`, `TODO.md`, `docs/onboarding.md`, and CLI help text to
   remove phase-2 language and describe the new coverage accurately.
8. Run focused tests, then full tests.

## Test Plan

Package-manager parser tests:

- Go `ProjectPreflight` returns refs for `build`, `test`, `vet`, and local
  `run`.
- Go `ProjectPreflight` respects `-C DIR` and `-modfile FILE`.
- Go remote `run pkg@version` remains install-style gating.
- Go informational commands return `ok=false`.
- Cargo `ProjectPreflight` returns refs for `build`, `check`, `test`, `run`,
  `bench`, and `clippy`.
- Cargo `ProjectPreflight` respects `--manifest-path` and `--lockfile-path`.
- Cargo informational commands return `ok=false`.

Gate/CLI tests:

- `veto go test ./...` refuses when `go.mod` contains a flagged module.
- `veto go run ./cmd/app` refuses when `go.sum` contains a flagged module.
- `veto cargo build` refuses when `Cargo.lock` contains a flagged crate.
- `veto cargo test --manifest-path nested/Cargo.toml` reads the nested project
  files.
- Malformed required project files abort fail-closed with exit 70.
- Non-project commands still pass through without intel-store work where
  possible.

Hook tests:

- Claude analyzer marks Go and Cargo phase-2 commands risky.
- Claude analyzer still ignores informational commands.
- Wrapped forms such as `timeout go test ./...` and `bash -c "cargo build"`
  are detected.

Regression tests:

- Existing phase-1 Go/Cargo tests continue passing.
- Existing npm resolver pre-scan tests continue passing.
- `go test ./...` passes after generated interposer headers are present.

Suggested validation commands:

```sh
go test ./internal/packagemanager/golang ./internal/packagemanager/cargo
go test ./internal/hook/claudecode ./cmd/veto
go test ./...
```

## Risks and Tradeoffs

- **False friction from missing lockfiles.** Cargo libraries often omit
  `Cargo.lock`. Requiring it globally may annoy users without adding enough
  security. Start by requiring `Cargo.toml` and gating `Cargo.lock` when
  present unless we decide application-only detection is reliable.
- **Nested project roots.** Go and Cargo can operate from subdirectories or
  workspaces. The first slice should handle explicit path flags, then add
  upward root discovery only with focused tests.
- **No resolver means incomplete graph in some cases.** This is intentional for
  phase 2. The command gate should not run tools that might fetch or execute
  code before it has made a decision.
- **Hook over-classification.** Routing `go build` and `cargo build` through
  veto adds friction, but this is the point of phase 2. Keep informational
  commands out so everyday diagnostics stay cheap.

## Acceptance Criteria

- `veto go build`, `veto go test`, local `veto go run`, and `veto go vet` gate
  Go project files before exec.
- `veto cargo build`, `veto cargo check`, `veto cargo test`, `veto cargo run`,
  `veto cargo bench`, and `veto cargo clippy` gate Cargo project files before
  exec.
- Flagged project dependencies refuse with the existing package-intel refusal
  format.
- Unreadable or malformed required project files abort fail-closed.
- Claude Code hook detection routes phase-2 commands through `veto`.
- README, onboarding docs, CLI help, and TODO no longer describe Go/Cargo
  build/test/run preflight as future phase-2 work.
