# Veto Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every fail-OPEN bug in veto and make the contained set of structural moves that prevent the same class of bugs from recurring. Reject pure file-size or cosmetic refactors.

**Architecture:** Four sequential phases. Phase 0 scans candidate Go libraries through veto itself. Phase 1 fixes all security/correctness bugs without new deps. Phase 2 lands enabling refactors (consolidate policy tables, intel-source shared core, JS Manager factory, gate sum types) with no new deps. Phase 3 swaps hand-rolled parsers for battle-tested libs, gated on Phase 0 verdicts.

**Tech Stack:** Go 1.26.2, `testify/require`, `BurntSushi/toml` (incumbent), `pelletier/go-toml/v2` (already a direct dep — used in Phase 3.4), `Masterminds/semver/v3`, `rs/zerolog`, `brynbellomy/go-utils/errors`, `google/shlex` (Phase 1 only; replaced by `mvdan.cc/sh/v3/syntax` in Phase 3.1 if Phase 0 adopts), C99 + dyld interpose (macOS) / LD_PRELOAD ELF symbol shadowing (Linux) for the native interposer.

**Test convention:** every functional change ships with a regression test that fails before the fix and passes after. Run `make test` (which is `go test -race ./...`) to validate. The interposer header gets regenerated automatically as a Make prerequisite.

**Commit convention:** atomic commits, one per task. Commit messages follow imperative-mood summary, optional blank line + body. Match existing repo style — see recent commits like `Compare PyPI ranges with PEP 440`, `Find nested Go and Cargo project roots`.

---

## File Structure

### Files created

```
docs/2026-05-25--deps-preflight.md                          (Phase 0 report)
internal/intel/sources/common/fetcher.go                    (Phase 2.2)
internal/intel/sources/common/atomicwrite.go                (Phase 2.2 — moved up from internal/fsutil)
internal/intel/sources/common/stream.go                     (Phase 2.2)
internal/intel/sources/common/dirperm.go                    (Phase 2.2)
internal/shellrc/targets.go                                 (Phase 2.3)
internal/shellrc/block.go                                   (Phase 2.3)
internal/shellrc/block_test.go                              (Phase 2.3)
internal/packagemanager/jspm/jspm.go                        (Phase 2.4)
internal/packagemanager/jspm/jspm_test.go                   (Phase 2.4)
internal/packagemanager/jslock/bunlock.go                   (Phase 1.6)
internal/packagemanager/jslock/bunlock_test.go              (Phase 1.6)
internal/packagemanager/projectroot/projectroot.go          (Phase 2.5)
internal/packagemanager/projectroot/projectroot_test.go     (Phase 2.5)
cmd/veto/agent_integrations.go                              (Phase 2.8)
cmd/veto/agent_integrations_test.go                         (Phase 2.8)
cmd/veto/layer.go                                           (Phase 2.9)
cmd/veto/doctor_checks.go                                   (Phase 2.10)
```

### Files modified (Phase 1 — bug fixes only)

```
cmd/veto/main.go                       (1.1 delete VETO_BYPASS/ALLOW_OPAQUE; 1.3 python -m parser)
cmd/veto/hook.go                       (1.1 VETO_BYPASS error text; 1.2 evasion band-aids glue)
cmd/veto/main_test.go                  (1.1 delete VETO_BYPASS tests)
cmd/veto/install_shell.go              (1.3 wrapper env defaults; both branches)
cmd/veto/install_cursor.go             (1.1 VETO_BYPASS in rule template)
cmd/veto/interposer_e2e_test.go        (1.1 delete VETO_BYPASS tests; 1.4 add execvpe/fexecve/execveat coverage)
cmd/veto/shims.go                      (1.3 .veto-displaced rename)
cmd/veto/install_wrappers.go           (1.5 atomicity + propagate load err + 0o600 + fsync)
cmd/veto/python_shim_test.go           (1.3 add regression cases)
internal/hook/claudecode/claudecode.go (1.2 band-aids: inner splitInlineSeparators; $/<<<  refusal)
internal/hook/claudecode/claudecode_test.go (1.2 regression cases)
internal/interposer/veto_interpose.c   (1.1 delete getenv VETO_BYPASS; 1.4 rewrite_envp for execv variants)
internal/intel/sources/aikido/aikido.go     (1.x parse-before-etag; uniform 0o600)
internal/intel/sources/osv/osv.go           (1.x consistency: align 0o600)
internal/intel/sources/openssf/openssf.go   (1.x parse-before-etag)
internal/intel/sources/ghsa/ghsa.go         (1.x parse-before-etag)
internal/intel/sources/pypa/pypa.go         (1.x parse-before-etag)
internal/intel/range.go / pep440.go    (1.x multi-digit local-label sort)
internal/packagemanager/bun/bun.go     (1.6 emit bun.lock manifest ref)
internal/packagemanager/jslock/jslock.go (1.6 yarn __metadata skip)
internal/packagemanager/jsspec/jsspec.go (1.6 link/portal/workspace/catalog/patch; alias-precedence)
internal/packagemanager/jsmanifest/jsmanifest.go (1.6 bundleDeps + workspaces walk; exactPin)
internal/packagemanager/pnpm/pnpm.go   (1.6 dlx via exec.Manager)
internal/packagemanager/yarn/yarn.go   (1.6 dlx via exec.Manager)
internal/packagemanager/{bun,pnpm,yarn,npm}/*.go (1.6 add dlx test cases)
internal/packagemanager/pyreq/pyreq.go (1.7 line continuations)
internal/packagemanager/pyspec/pyspec.go (1.7 bare-dir, win drive, leading-dash)
internal/packagemanager/pymanifest/pymanifest.go (1.7 tool.uv/pdm dev-deps; workspace; PEP 440 delegation)
internal/packagemanager/pylock/pylock.go (1.7 skip editable/virtual)
internal/packagemanager/pip/pip.go     (1.7 forward index flags; strip --no-deps)
internal/packagemanager/uv/uv.go       (1.7 same; uv add prescan fallback)
internal/packagemanager/golang/golang.go (1.8 install in switches; goVerb table prep)
internal/packagemanager/gomod/gomod.go (1.8 ext-suffix guard)
internal/packagemanager/cargo/cargo.go (1.8 publish/doc/package)
internal/packagemanager/cargomanifest/cargomanifest.go (1.8 registry classifier; workspace members)
internal/packagemanager/packagemanager.go (1.6 add ManifestKindBunLock)
internal/packagemanager/pmlist/pmlist.go (1.6 bunlock in canonical list)
internal/gate/gate.go                  (1.1 remove AllowOpaqueRemote axis)
internal/gate/gate_test.go             (1.1 remove the axis tests)
README.md                              (1.1 env-vars table)
TODO.md                                (post-phase pruning of completed items)
```

### Files modified (Phase 2 — refactors)

```
internal/packagemanager/pmlist/pmlist.go              (2.1 add pythonDashMTargets, execPMs, verbs, flag tables)
internal/interposer/cmd/genpmlist/main.go             (2.1 emit pm_constants.h alongside pm_names.h)
internal/interposer/gen/gen.go                        (2.1 update go:generate directive)
internal/interposer/pm_names.h                        (2.1 regenerated; will include pm_constants.h)
internal/interposer/pm_constants.h                    (2.1 NEW, generated)
internal/interposer/veto_interpose.c                  (2.1 #include "pm_constants.h", delete duplicates; 2.7 gate_and_exec dispatcher)
internal/hook/claudecode/claudecode.go                (2.1 read from pmlist; delete local tables)
cmd/veto/main.go                                      (2.1 read pythonDashMTarget from pmlist; 2.6 typed Decision; 2.9 layer registry)
internal/intel/sources/{aikido,osv,openssf,pypa,ghsa}/*.go (2.2 all reduce to URL + decode callback)
internal/intel/sources/internal/fsutil/atomicwrite.go (2.2 moved out)
internal/intel/intel.go                               (2.2 add SupportedEcosystems on Source; delete ErrUnsupportedEcosystem sentinel)
internal/intel/store.go                               (2.2 only spawn supported (source, eco) cross-product)
cmd/veto/install_shell.go                             (2.3 consume internal/shellrc)
cmd/veto/install_preload.go                           (2.3 consume internal/shellrc — fans out to all rc files)
internal/packagemanager/{npm,pnpm,yarn,bun}/*.go      (2.4 collapse to jspm.New(Spec))
internal/packagemanager/jsspec/jsspec.go              (2.4 export split helper; centralize)
internal/packagemanager/jslock/jslock.go              (2.4 use exported splitter)
internal/packagemanager/argv/argv.go                  (2.5 FirstFlagValue export; iterator)
internal/packagemanager/golang/golang.go              (2.5 verb table)
internal/packagemanager/cargo/cargo.go                (2.5 verb table; consolidate parseAdd/parseInstall + markInstalls*)
internal/packagemanager/packagemanager.go             (2.6 Install sum type)
internal/gate/gate.go                                 (2.6 Decision typed variant; delete NopExpander; delete duplicate expander field; typed RefusalReason)
internal/gate/gate_test.go                            (2.6 update for typed Decision)
all callers of Install / Decision / Outcome           (2.6 mechanical edits)
internal/scan/types.go                                (2.6 split into types/report/render)
internal/scan/report.go                               (2.6 NEW from split)
internal/scan/render.go                               (2.6 NEW from split)
cmd/veto/{install_claude_hook,install_codex,install_cursor}.go (2.8 collapse into agent_integrations.go)
cmd/veto/install_all.go                               (2.9 iterate layers)
cmd/veto/doctor.go                                    (2.9 + 2.10 layer-iterating, table-driven, parallel)
```

### Files modified (Phase 3 — library swaps, conditional on Phase 0)

```
internal/hook/claudecode/claudecode.go    (3.1 rewrite analyzer on sh/v3/syntax)
internal/hook/claudecode/claudecode_test.go (3.1 add AST-level cases; Phase 1.2 regression suite carries forward)
internal/packagemanager/gomod/gomod.go    (3.2 delegate to x/mod/modfile)
internal/packagemanager/golang/golang.go  (3.2 module.CheckVersion / PseudoVersion; replace directives)
internal/intel/range.go                   (3.3 PyPI delegates to go-pep440-version)
internal/intel/pep440.go                  (3.3 deleted; tests migrated)
cmd/veto/install_codex.go                 (3.4 use pelletier/go-toml/v2; delete line-TOML scanner)
internal/packagemanager/cargomanifest/cargomanifest.go (3.4 confirm/migrate to go-toml/v2)
internal/packagemanager/cargolock/cargolock.go         (3.4 same)
go.mod / go.sum                           (3.1/3.2/3.3 add libs gated on Phase 0; 3.4 no change — pelletier already present)
```

---

# Phase 0 — Dep pre-flight

This phase is a runbook, not TDD. Output is a single report document that gates Phase 3.

### Task 0.1: Scan candidate libraries via veto

**Files:**
- Create: `docs/2026-05-25--deps-preflight.md`

- [ ] **Step 1: Build veto from current main**

```bash
cd /Users/brynbellomy/projects/veto
git checkout main && git pull --ff-only
make build
make interposer
./veto status   # should print intel store status; if it fails, abort the plan
```

Expected: `veto` and `libveto_interpose.dylib` (or `.so`) produced. `veto status` lists the four default sources (aikido, openssf, osv, pypa) with non-zero report counts.

- [ ] **Step 2: For each candidate library, run `veto go get` against a throwaway module**

Candidates:
- `mvdan.cc/sh/v3@latest`
- `golang.org/x/mod@latest`
- `github.com/aquasecurity/go-pep440-version@latest`
- (skip pelletier/go-toml/v2 — already a direct dep)

```bash
TMP=$(mktemp -d)
cd "$TMP"
go mod init scratch
for pkg in "mvdan.cc/sh/v3" "golang.org/x/mod" "github.com/aquasecurity/go-pep440-version"; do
  echo "=== $pkg ==="
  /Users/brynbellomy/projects/veto/veto go get "$pkg@latest" 2>&1 | tee "/tmp/veto-preflight-$(echo "$pkg" | tr / _).log"
done
```

Expected: every line "veto: install allowed" or "veto: install refused — …". Refusal aborts adoption for that lib.

- [ ] **Step 3: Static scan each candidate's source tree**

```bash
for pkg in mvdan.cc/sh/v3 golang.org/x/mod github.com/aquasecurity/go-pep440-version; do
  dir="$TMP/scan-$(echo "$pkg" | tr / _)"
  git clone "https://$pkg" "$dir" 2>/dev/null || \
    GOPROXY=direct go mod download -x "$pkg@latest"  # falls back via module cache
  /Users/brynbellomy/projects/veto/veto scan --root "$dir" --no-caches --no-agent-surface --json \
    > "/tmp/veto-preflight-scan-$(echo "$pkg" | tr / _).json"
done
```

Expected: each JSON file has `findings: []` for malware sources. Note any non-empty findings explicitly.

- [ ] **Step 4: One-level transitive scan**

For each candidate, read its `go.mod`, list direct `require` lines, and `veto go get` each transitive (in a fresh scratch module so cached resolutions don't mask the network gate).

```bash
for pkg in mvdan.cc/sh/v3 golang.org/x/mod github.com/aquasecurity/go-pep440-version; do
  dir="$TMP/scan-$(echo "$pkg" | tr / _)"
  awk '/^require / {p=1;next} /^\)/{p=0} p && !/\/\/ indirect/ {print $1"@"$2}' "$dir/go.mod" \
    > "/tmp/veto-preflight-transitive-$(echo "$pkg" | tr / _).txt"
done
# Then iterate each transitive list through `veto go get <name>@<version>`
```

Expected: no transitive flagged. Document any non-trivial transitive (especially ones whose name matches a malware report's `package_name` substring — the false-positive surface).

- [ ] **Step 5: Write the preflight report**

Write `docs/2026-05-25--deps-preflight.md` with this exact structure:

```markdown
# Phase 0 — Dep pre-flight report

Date: <YYYY-MM-DD>
Scanned-with veto SHA: <git rev-parse HEAD>
Intel store snapshot: <ISO timestamp from `veto status`>

| Library | Version | Direct verdict | Transitive concerns | Recommendation |
|---|---|---|---|---|
| mvdan.cc/sh/v3 | <vX.Y.Z> | allow / refuse | <list or "none"> | adopt at <vX.Y.Z> / reject because <reason> |
| golang.org/x/mod | <vX.Y.Z> | … | … | … |
| github.com/aquasecurity/go-pep440-version | <vX.Y.Z> | … | … | … |

## Notes
<any per-library caveats, FP risks, or pin-rationale>
```

Each row's "Recommendation" is the gate for the corresponding Phase 3 task. "reject" means the Phase 3 task is dropped and the in-place Phase 1 fix stays.

- [ ] **Step 6: Commit**

```bash
cd /Users/brynbellomy/projects/veto
git add docs/2026-05-25--deps-preflight.md
git commit -m "Phase 0: dep pre-flight report

Scanned mvdan.cc/sh/v3, golang.org/x/mod, and go-pep440-version
through veto's Go live-gating path plus a static scan of each tree.
Recommendation rows gate the corresponding Phase 3 tasks."
```

---

# Phase 1 — Fail-OPEN bugs + override-env removal

## Group 1.1: Delete VETO_BYPASS and VETO_ALLOW_OPAQUE

### Task 1.1.1: Flip the interposer e2e tests that pin VETO_BYPASS behavior

**Files:**
- Modify: `cmd/veto/interposer_e2e_test.go:230-310`

- [ ] **Step 1: Read the current test pair**

Open `cmd/veto/interposer_e2e_test.go`. Find the two tests around lines 230-310:
- `TestInterposer_VETO_BYPASS_zero_does_not_disable` (line ~234)
- `TestInterposer_VETO_BYPASS_one_disables` (line ~281)

These pin the existing behavior: `VETO_BYPASS=0` must NOT disable Layer 3; `VETO_BYPASS=1` must disable it. We're removing the entire env, so the new contract is: BOTH values must NOT disable Layer 3.

- [ ] **Step 2: Replace the second test to assert VETO_BYPASS=1 is ignored**

Replace `TestInterposer_VETO_BYPASS_one_disables` with a test that asserts `VETO_BYPASS=1` is ignored — Layer 3 still intercepts:

```go
// TestInterposer_VETO_BYPASS_one_is_ignored proves the legacy escape hatch
// is gone: even a child explicitly setting VETO_BYPASS=1 must be gated.
// Counterpart to TestInterposer_VETO_BYPASS_zero_does_not_disable.
func TestInterposer_VETO_BYPASS_one_is_ignored(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("interposer is built only on darwin and linux")
	}
	libPath, fakeVeto, _, _, _, dir := setupInterposerFixture(t, "npm")
	spawner := buildExecSpawner(t, dir)
	cmd := exec.Command(spawner, "/opt/homebrew/bin/npm", "install", "evil-pkg")
	cmd.Env = append(withPreloadEnv(libPath, fakeVeto), "VETO_BYPASS=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "exec failed unexpectedly: %s", string(out))
	require.FileExists(t, filepath.Join(dir, "argv.log"),
		"VETO_BYPASS=1 must NOT disable Layer 3; fake veto should have run")
}
```

- [ ] **Step 3: Rename the surviving test to remove the "zero" qualifier**

The `_zero_does_not_disable` test becomes `_value_does_not_disable_when_ignored` (or just delete it — the new test in step 2 covers the case). Pick the cleaner option: delete the `_zero` test, keep only the `_one_is_ignored` test plus a `_unset_is_normal_path` test that asserts the normal interception still works when no VETO_BYPASS env is present at all.

- [ ] **Step 4: Run the tests — they should FAIL because VETO_BYPASS is still honored**

```bash
go test -race ./cmd/veto -run TestInterposer_VETO_BYPASS -v
```

Expected: the new test fails because the interposer currently honors `VETO_BYPASS=1`.

- [ ] **Step 5: Commit (test-only, red)**

```bash
git add cmd/veto/interposer_e2e_test.go
git commit -m "Phase 1.1: assert VETO_BYPASS is ignored by Layer 3

Inverts the existing test contract in preparation for ripping out
VETO_BYPASS. The test fails red until 1.1.2 removes the getenv call
from the C interposer."
```

### Task 1.1.2: Remove VETO_BYPASS handling from the C interposer

**Files:**
- Modify: `internal/interposer/veto_interpose.c:28-50` (header doc); `:233-260` (the getenv branch in `is_risky`)

- [ ] **Step 1: Read the existing getenv call in is_risky**

Open `internal/interposer/veto_interpose.c`. Find the `is_risky` function around line 200-260. The relevant block is approximately:

```c
// VETO_BYPASS env var honored at child-spawn time. We can only see
// the parent's env via getenv; the documented contract says ...
const char *bypass = getenv("VETO_BYPASS");
if (bypass && bypass[0] == '1' && bypass[1] == '\0') {
    return NULL;
}
```

- [ ] **Step 2: Delete the bypass block and update the header comment**

Delete the `getenv("VETO_BYPASS")` block in `is_risky`. Update the file-header comment around lines 28-50 — remove the "Escape hatch: VETO_BYPASS=1" paragraph and replace with:

```c
// No env-based escape hatch: veto refuses to provide one because the
// original VETO_BYPASS env had subtle scope bugs (parent's getenv vs
// child's envp). Bypass paths now go through `veto <pm> ...` argv form,
// where veto's own startup handles the request.
```

- [ ] **Step 3: Rebuild the interposer**

```bash
make interposer
```

Expected: clean build, no warnings about unused `bypass` variable. If the compiler now warns about an unused `const char *` declared elsewhere, remove it too.

- [ ] **Step 4: Run the e2e tests**

```bash
go test -race ./cmd/veto -run TestInterposer_VETO_BYPASS -v
```

Expected: PASS. Layer 3 now intercepts regardless of `VETO_BYPASS`.

- [ ] **Step 5: Commit**

```bash
git add internal/interposer/veto_interpose.c
git commit -m "Phase 1.1: delete VETO_BYPASS getenv from C interposer

is_risky() no longer consults VETO_BYPASS. The env is gone from the
contract; any per-invocation bypass must go through 'veto <pm> ...' argv
form so veto's own startup gates the call."
```

### Task 1.1.3: Remove VETO_BYPASS from the Go startup path

**Files:**
- Modify: `cmd/veto/main.go:259-300` (delete `vetoBypassEnabled` + caller); `:655` (printRefusal hint); `:1418` (usage string)
- Modify: `cmd/veto/main_test.go:120-160` (delete the VETO_BYPASS test block)
- Modify: `cmd/veto/hook.go:145` (deny-message text)
- Modify: `cmd/veto/install_cursor.go:153` (cursor rule template)
- Modify: `README.md:312` (env table)

- [ ] **Step 1: Write a failing test asserting VETO_BYPASS=1 is ignored at the Go layer too**

Add to `cmd/veto/main_test.go`:

```go
// TestRunGate_VETO_BYPASS_is_ignored proves the env no longer short-
// circuits the gate. Counterpart to the interposer-side e2e test.
func TestRunGate_VETO_BYPASS_is_ignored(t *testing.T) {
	// Build a synthetic gate-input that would be blocked by intel.
	// Then run with VETO_BYPASS=1 and assert refusal still happens.
	t.Setenv("VETO_BYPASS", "1")
	// ... wire through runGate with a mock store flagging "evil-pkg"
	// (use the existing test helpers in main_test.go)
	rc := runGate(/* logger, cfg, pm, args naming evil-pkg, store=mockFlagged */)
	require.Equal(t, exitRefused, rc,
		"VETO_BYPASS=1 must NOT short-circuit runGate; the env is gone")
}
```

Run: `go test -race ./cmd/veto -run TestRunGate_VETO_BYPASS_is_ignored -v`
Expected: FAIL (current code honors the env).

- [ ] **Step 2: Delete `vetoBypassEnabled` and its only caller**

In `cmd/veto/main.go`:
- Delete the entire `vetoBypassEnabled` function (around lines 259-271)
- Find its single caller in `runGate` (around line 287) — delete the `if vetoBypassEnabled() { ... }` block including the `logger.Info().Msg("VETO_BYPASS=1 set; ...")` line
- In `printRefusal` (around line 655), delete the "To override (you really shouldn't), set VETO_BYPASS=1 ..." line
- In `printUsage` (around line 1418), delete the `VETO_BYPASS` and `VETO_ALLOW_OPAQUE` rows from the env-table string literal

- [ ] **Step 3: Delete the existing VETO_BYPASS test block**

In `cmd/veto/main_test.go`, find the test around lines 120-160 that loops over `tc.value` settings of `VETO_BYPASS` (the `t.Setenv("VETO_BYPASS", tc.value)` block). Delete that test entirely.

- [ ] **Step 4: Update hook deny message**

In `cmd/veto/hook.go:145`, replace:

```go
"prepend `VETO_BYPASS=1 ` to the command.",
```

with:

```go
"invoke the package manager via `veto <pm> ...` which is the intended path.",
```

- [ ] **Step 5: Update cursor rule template**

In `cmd/veto/install_cursor.go:153`, replace the line:

```go
If veto refuses an install, **do not** retry with `VETO_BYPASS=1` or
```

with:

```go
If veto refuses an install, **do not** attempt to bypass it by editing
the rule, removing the shim, or invoking the package manager via an
alternate path. Treat the refusal as terminal until the underlying
intel reason is understood.
```

- [ ] **Step 6: Update README**

In `README.md` find the env-vars table (around line 307-315). Delete the rows for `VETO_BYPASS` and `VETO_ALLOW_OPAQUE`. Also update line 362 (the refuse-opaque-by-default paragraph) — delete the "Set `VETO_ALLOW_OPAQUE=1` to opt in after independently verifying the source." sentence.

- [ ] **Step 7: Run tests**

```bash
make test
```

Expected: PASS. All VETO_BYPASS-related tests are gone, the new "is ignored" test passes.

- [ ] **Step 8: Commit**

```bash
git add cmd/veto/main.go cmd/veto/main_test.go cmd/veto/hook.go \
        cmd/veto/install_cursor.go README.md
git commit -m "Phase 1.1: delete VETO_BYPASS from the Go startup path

vetoBypassEnabled and its single runGate caller are gone. The hook
deny-message, cursor rule template, README env table, and printUsage
output stop advertising the override. main_test.go's parameterized
VETO_BYPASS test is replaced by a single regression test asserting
the env is ignored."
```

### Task 1.1.4: Remove VETO_ALLOW_OPAQUE — drop the gate.Policy axis

**Files:**
- Modify: `internal/gate/gate.go:86-110` (Policy struct + DefaultPolicy); `:113-122` (DefaultPolicy comment); `:213-224` (Evaluate's opaque branch)
- Modify: `internal/gate/gate_test.go` (remove tests parameterized on AllowOpaqueRemote=true)
- Modify: `cmd/veto/main.go:345-352` (delete VETO_ALLOW_OPAQUE env read); `:1138-1142` (delete the field from Config); `:1418-1420` (already addressed in 1.1.3)

- [ ] **Step 1: Write a failing test asserting opaque specs are always refused**

In `internal/gate/gate_test.go`, add:

```go
func TestEvaluate_OpaqueRemote_AlwaysRefused(t *testing.T) {
	store := &mockStore{} // no flagged entries
	g := gate.New(store, gate.DefaultPolicy(), zerolog.Nop())
	ins := packagemanager.Install{
		Ref:          intel.PackageRef{Ecosystem: "npm", Name: "evil/repo"},
		OpaqueRemote: true,
	}
	d := g.Evaluate([]packagemanager.Install{ins})
	require.Equal(t, gate.OutcomeRefuse, d.Outcome,
		"opaque remote MUST refuse even with no malware intel hit (axis removed)")
	require.Len(t, d.Flagged(), 1)
	require.Equal(t, "veto-policy", d.Flagged()[0].Reports[0].SourceID)
}
```

Run it; it currently passes (DefaultPolicy already sets AllowOpaqueRemote=false). The test exists to lock in the contract before we delete the toggle.

- [ ] **Step 2: Delete `AllowOpaqueRemote` field from Policy**

In `internal/gate/gate.go`:
- Delete the `AllowOpaqueRemote bool` field from the `Policy` struct (around line 98-104)
- Update `DefaultPolicy()` to drop the field initialization
- In `Evaluate`, the opaque-handling branch becomes unconditional:

```go
if ins.OpaqueRemote {
    decision.Verdicts = append(decision.Verdicts, policyRefusalVerdict(ins,
        "opaque-spec install refused: URL/git/tarball specs bypass the package "+
            "registry and can carry payloads."))
    decision.Outcome = OutcomeRefuse
    continue
}
```

(Drop the "Set VETO_ALLOW_OPAQUE=1 to override" sentence from the message.)

- [ ] **Step 3: Update gate_test.go**

Find any test that constructs a `Policy` with `AllowOpaqueRemote: true` (it's the parameterization that proves the toggle works). Delete those test cases.

- [ ] **Step 4: Delete VETO_ALLOW_OPAQUE env reading in main.go**

In `cmd/veto/main.go`:
- Find the block around lines 345-352 that reads `os.Getenv("VETO_ALLOW_OPAQUE")` and sets the policy. Delete it.
- Find the `AllowOpaqueRemote bool` field in `Config` struct around line 1140. Delete it.
- Find any reference to `cfg.AllowOpaqueRemote` and delete those lines (likely the policy-building helper).

- [ ] **Step 5: Run tests**

```bash
make test
```

Expected: PASS. All opaque-remote tests still pass; the toggle is gone but behavior is unchanged (always refuse).

- [ ] **Step 6: Commit**

```bash
git add internal/gate/gate.go internal/gate/gate_test.go cmd/veto/main.go
git commit -m "Phase 1.1: drop VETO_ALLOW_OPAQUE axis from gate.Policy

AllowOpaqueRemote is gone from Policy; opaque remote specs are
unconditionally refused via the existing policyRefusalVerdict path.
Config.AllowOpaqueRemote and the env read in main.go are deleted."
```

## Group 1.2: L1 hook parser evasions (band-aid)

These are band-aid fixes. Phase 3.1 replaces the analyzer wholesale; the regression tests added here are the contract that Phase 3.1 must continue to satisfy.

### Task 1.2.1: Add regression tests for parser evasions (red)

**Files:**
- Modify: `internal/hook/claudecode/claudecode_test.go`

- [ ] **Step 1: Add failing test cases for nested `bash -c` payloads with unspaced separators**

Append to `internal/hook/claudecode/claudecode_test.go`:

```go
// TestAnalyze_NestedBashC_UnspacedSeparators proves the parser handles
// `bash -c "cd /tmp;npm install foo"` — the inner shlex-and-split must
// also recover unspaced separators, not just the top-level pass.
func TestAnalyze_NestedBashC_UnspacedSeparators(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"semicolon_unspaced", `bash -c "cd /tmp;npm install foo"`},
		{"and_unspaced",        `bash -c "true&&npm install foo"`},
		{"or_unspaced",         `bash -c "false||npm install foo"`},
		{"semicolon_then_chain", `bash -c "echo hi;true;npm install foo"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			risky, _ := Analyze(tc.cmd)
			require.True(t, risky, "must detect %q as risky", tc.cmd)
		})
	}
}

// TestAnalyze_CommandSubstitution_Refused proves $(...) / backticks /
// <(...) / >(...) are NOT silently passed; they emit a deny with a
// refuse-to-evaluate message.
func TestAnalyze_CommandSubstitution_Refused(t *testing.T) {
	cases := []string{
		`echo $(npm install foo)`,
		"echo `npm install foo`",
		`diff <(echo a) <(npm install foo)`,
		`echo >(npm install foo)`,
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			risky, _ := Analyze(c)
			require.True(t, risky, "command substitution must be treated as risky for %q", c)
		})
	}
}

// TestAnalyze_Herestring_Refused — `sh <<< 'npm install foo'`.
func TestAnalyze_Herestring_Refused(t *testing.T) {
	risky, _ := Analyze(`sh <<< 'npm install foo'`)
	require.True(t, risky, "<<< herestrings must not silently drop the payload")
}
```

- [ ] **Step 2: Run the tests — they should all FAIL**

```bash
go test -race ./internal/hook/claudecode -v -run "TestAnalyze_NestedBashC|TestAnalyze_CommandSubstitution|TestAnalyze_Herestring"
```

Expected: every new case FAILs because the current analyzer doesn't catch any of these.

- [ ] **Step 3: Commit (test-only, red)**

```bash
git add internal/hook/claudecode/claudecode_test.go
git commit -m "Phase 1.2: pin parser-evasion regressions (red)

Adds failing tests for bash -c with unspaced separators, command
substitution, and <<< herestrings. The Phase 1 band-aid lands in
1.2.2; Phase 3.1 (sh/v3/syntax rewrite) must continue to satisfy
these tests."
```

### Task 1.2.2: Apply splitInlineSeparators inside expandShellInvocations

**Files:**
- Modify: `internal/hook/claudecode/claudecode.go:300-330` (the bash -c re-shlex block in `expandShellInvocations`)

- [ ] **Step 1: Find expandShellInvocations**

Open `internal/hook/claudecode/claudecode.go`. Find `expandShellInvocations` (around line 290-330). The relevant block re-shlexes the payload of a `bash -c "..."`:

```go
inner, err := shlex.Split(payload)
if err != nil {
    return tokens
}
inner = stripRedirects(inner)
```

- [ ] **Step 2: Insert splitInlineSeparators recovery**

Insert a `splitInlineSeparators` call between the inner `shlex.Split` and the rest of the pipeline:

```go
inner, err := shlex.Split(payload)
if err != nil {
    return tokens
}
// Recover unspaced separators in the nested payload — the top-level
// loop already does this, but the inner re-shlex of `bash -c "cd
// /tmp;npm install foo"` would otherwise leave `cd /tmp;npm` glued.
// Regression: TestAnalyze_NestedBashC_UnspacedSeparators.
inner = splitInlineSeparators(inner)
inner = stripRedirects(inner)
```

If `expandShellInvocations` is recursive (look for the recursion site that handles further-nested shells), also apply `splitInlineSeparators` at every recursion entry.

- [ ] **Step 3: Run the nested-bash-c tests — they should now PASS**

```bash
go test -race ./internal/hook/claudecode -v -run TestAnalyze_NestedBashC
```

Expected: PASS.

- [ ] **Step 4: Run the full claudecode test suite — nothing should regress**

```bash
go test -race ./internal/hook/claudecode -v
```

Expected: all preexisting tests still pass (the splitInlineSeparators function is idempotent; calling it on already-split tokens is a no-op).

- [ ] **Step 5: Commit**

```bash
git add internal/hook/claudecode/claudecode.go
git commit -m "Phase 1.2: thread splitInlineSeparators into bash -c re-shlex

The inner shlex.Split of a bash -c payload now passes through
splitInlineSeparators before stripRedirects. Closes the
bash -c \"cd /tmp;npm install foo\" evasion."
```

### Task 1.2.3: Detect command substitution + herestring; refuse to evaluate

**Files:**
- Modify: `internal/hook/claudecode/claudecode.go` (add a `hasCommandSubstitution` check inside `Analyze`)

- [ ] **Step 1: Add a substring scan at the entry of Analyze**

Open `internal/hook/claudecode/claudecode.go`. Find the top of `Analyze` (around line 110-140). Insert a substring-level check before the shlex pass:

```go
// Command substitution and herestrings are opaque to shlex. Rather
// than half-parse them, refuse the install — the agent can re-issue
// without the construct. Regression suite: TestAnalyze_CommandSubstitution_Refused,
// TestAnalyze_Herestring_Refused.
if containsShellExpansion(command) {
    return true, "refusing to evaluate shell command-substitution / herestring; " +
        "re-issue the command without $() / backticks / <<< / process substitution"
}
```

Then add `containsShellExpansion` somewhere in the same file:

```go
// containsShellExpansion reports whether the raw command string contains
// constructs we cannot safely tokenize: $(...), `...`, <(...), >(...), <<<.
// Any of these can hide a PM invocation from the rest of the analyzer.
func containsShellExpansion(s string) bool {
    if strings.Contains(s, "$(") {
        return true
    }
    if strings.Contains(s, "`") {
        return true
    }
    if strings.Contains(s, "<(") || strings.Contains(s, ">(") {
        return true
    }
    if strings.Contains(s, "<<<") {
        return true
    }
    return false
}
```

- [ ] **Step 2: Adjust the function's existing return type**

If `Analyze` currently returns `(bool, string)`, the new signature is compatible. If it returns `(bool, []string)` or similar, adapt accordingly — match the existing signature so callers don't need updating.

- [ ] **Step 3: Run the new tests**

```bash
go test -race ./internal/hook/claudecode -v -run "TestAnalyze_CommandSubstitution|TestAnalyze_Herestring"
```

Expected: PASS.

- [ ] **Step 4: Run full claudecode suite — no regressions**

```bash
go test -race ./internal/hook/claudecode -v
```

Expected: PASS. The substring check is conservative; any legitimate Bash command without `$(`, `\``, `<(`, `>(`, `<<<` is unaffected.

- [ ] **Step 5: Commit**

```bash
git add internal/hook/claudecode/claudecode.go
git commit -m "Phase 1.2: refuse to evaluate command substitution and herestrings

Analyze() now scans the raw command for \$(...), backticks, <(...),
>(...), and <<<. Any of these flips the result to risky with a
refuse-to-evaluate message. Closes the command-substitution and
<<<-herestring evasion classes pending the Phase 3.1 sh/v3 rewrite."
```

## Group 1.3: L2 python shim + managed shell hardening

### Task 1.3.1: Robust python-flag-bundle parser (red)

**Files:**
- Modify: `cmd/veto/python_shim_test.go`

- [ ] **Step 1: Add failing cases to the existing python-m test**

Open `cmd/veto/python_shim_test.go`. Add to the existing table:

```go
// Regression cases for the L2 reviewer's findings: pre-`-m` flags and
// the no-space `-mpip` form must unwrap to the PM.
{"no_space_mpip",    []string{"-mpip", "install", "foo"},     "pip",    true},
{"no_space_muv",     []string{"-muv", "pip", "install", "x"}, "uv",     true},
{"flag_I_then_m",    []string{"-I", "-m", "pip", "install", "foo"},     "pip",  true},
{"flag_E_then_m",    []string{"-E", "-m", "pip", "install", "foo"},     "pip",  true},
{"flag_S_then_m",    []string{"-S", "-m", "pip", "install", "foo"},     "pip",  true},
{"flag_B_then_m",    []string{"-B", "-m", "pip", "install", "foo"},     "pip",  true},
{"flag_bundle_then_m", []string{"-IES", "-m", "pip", "install", "foo"}, "pip",  true},
// Non-PM `-m` modules must still pass through:
{"m_venv_passes",    []string{"-m", "venv", ".venv"},          "",       false},
{"flag_then_m_venv", []string{"-I", "-m", "venv", ".venv"},    "",       false},
```

- [ ] **Step 2: Run — they FAIL**

```bash
go test -race ./cmd/veto -run TestPythonDashMTarget -v
```

Expected: every new case marked `true` fails (current parser is strict on `args[0] == "-m"`).

- [ ] **Step 3: Commit (red)**

```bash
git add cmd/veto/python_shim_test.go
git commit -m "Phase 1.3: pin python shim flag-bundle regressions (red)"
```

### Task 1.3.2: Rewrite pythonDashMTarget to handle CPython short-flag bundle

**Files:**
- Modify: `cmd/veto/main.go:172-178` (`pythonDashMTarget` function)

- [ ] **Step 1: Replace the parser body**

In `cmd/veto/main.go` (around line 172-178), replace `pythonDashMTarget` with:

```go
// pythonDashMTarget reports whether args describes a `python -m <pm> …`
// invocation we should gate, returning the resolved PM name. The caller
// is expected to have already verified the invoking basename is one of
// the python interpreters.
//
// Accepts:
//   -m <pm> ...         (canonical)
//   -m<pm> ...          (no space — valid CPython syntax)
//   <short-flag-bundle> -m <pm> ...   (e.g. -I -m pip, -IES -m pip)
//   <short-flag-bundle> -m<pm> ...
//
// Pre-`-m` flag bundles are the union of CPython's no-argument short
// options: -b -B -d -E -h -i -I -O -OO -P -q -s -S -u -v -V -x -? .
// Options that take values (-c CMD, -m MOD, -W ARG, -X ARG) are NOT
// part of a "no-arg bundle"; if any of those appears before -m, we
// must yield because they could conceal arbitrary code.
func pythonDashMTarget(args []string) (string, bool) {
	const noArgShortFlags = "bBdEhiIOPqsSuvVxX?"

	i := 0
	for i < len(args) {
		tok := args[i]
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			return "", false
		}
		if tok == "--" {
			return "", false
		}
		// Try `-m<pm>` (no space).
		if strings.HasPrefix(tok, "-m") && len(tok) > 2 {
			pm, ok := pythonDashMTargets[tok[2:]]
			return pm, ok
		}
		if tok == "-m" {
			if i+1 >= len(args) {
				return "", false
			}
			pm, ok := pythonDashMTargets[args[i+1]]
			return pm, ok
		}
		// Anything starting with `--` (long option) is not in the no-arg
		// bundle; bail conservatively.
		if strings.HasPrefix(tok, "--") {
			return "", false
		}
		// Verify every char after the leading dash is in the no-arg set.
		for _, r := range tok[1:] {
			if !strings.ContainsRune(noArgShortFlags, r) {
				return "", false
			}
		}
		i++
	}
	return "", false
}
```

- [ ] **Step 2: Run the regression tests — they should PASS**

```bash
go test -race ./cmd/veto -run TestPythonDashMTarget -v
```

Expected: every case PASSes.

- [ ] **Step 3: Run the full cmd/veto suite**

```bash
go test -race ./cmd/veto -v
```

Expected: no regressions.

- [ ] **Step 4: Commit**

```bash
git add cmd/veto/main.go cmd/veto/python_shim_test.go
git commit -m "Phase 1.3: parse CPython short-flag bundles in python -m detector

pythonDashMTarget now accepts no-space `-mpip` and arbitrary
no-argument flag bundles (-I, -E, -S, -IES, …) before -m. Long
options and value-taking short options (-c, -W, -X) still bail
conservatively to avoid concealing arbitrary code."
```

### Task 1.3.3: Make managed-shell wrappers respect user-set env

**Files:**
- Modify: `cmd/veto/install_shell.go:350-380` (bash/zsh pip+uv functions) and `:372-395` (fish branch)

- [ ] **Step 1: Find the pip wrapper block**

Open `cmd/veto/install_shell.go`. Find the bash/zsh wrapper definitions around line 350 — look for `pip()`, `pip3()`, `uv()`, `uvx()`. They currently look like:

```sh
pip() { PIP_UPLOADED_PRIOR_TO="$(_veto_pkg_age_cutoff_3d_utc)" "$_veto_bin" pip "$@"; }
```

- [ ] **Step 2: Change to honor user-set env**

Replace each wrapper with the `${VAR:-default}` form so a user-set value wins:

```sh
pip() { PIP_UPLOADED_PRIOR_TO="${PIP_UPLOADED_PRIOR_TO:-$(_veto_pkg_age_cutoff_3d_utc)}" "$_veto_bin" pip "$@"; }
pip3() { PIP_UPLOADED_PRIOR_TO="${PIP_UPLOADED_PRIOR_TO:-$(_veto_pkg_age_cutoff_3d_utc)}" "$_veto_bin" pip3 "$@"; }
uv() { UV_EXCLUDE_NEWER="${UV_EXCLUDE_NEWER:-$(_veto_pkg_age_cutoff_3d_utc)}" "$_veto_bin" uv "$@"; }
uvx() { UV_EXCLUDE_NEWER="${UV_EXCLUDE_NEWER:-$(_veto_pkg_age_cutoff_3d_utc)}" "$_veto_bin" uvx "$@"; }
```

- [ ] **Step 3: Fix the fish branch**

Find the fish-shell wrapper block (around lines 372-395). Fish uses `set -q` to test if a var is set:

```fish
function pip
    set -q PIP_UPLOADED_PRIOR_TO; or set PIP_UPLOADED_PRIOR_TO (_veto_pkg_age_cutoff_3d_utc)
    $_veto_bin pip $argv
end
```

Apply the same pattern to `pip3`, `uv`, `uvx`.

- [ ] **Step 4: Update install_shell_test.go expectations**

Open `cmd/veto/install_shell_test.go`. Find the tests that compare against the literal wrapper bodies. Update the expected strings to match the new `${VAR:-…}` / `set -q` forms.

- [ ] **Step 5: Run tests**

```bash
go test -race ./cmd/veto -run TestInstallShell -v
```

Expected: PASS.

- [ ] **Step 6: Add a regression test for user-env preservation**

In `cmd/veto/install_shell_test.go`, add:

```go
// TestShellWrappers_PreserveUserSetEnv asserts that a user setting
// PIP_UPLOADED_PRIOR_TO or UV_EXCLUDE_NEWER wins over the wrapper's
// 3-day-default. We assert this via string substring on the rendered
// block — `${PIP_UPLOADED_PRIOR_TO:-` proves the default-only branch.
func TestShellWrappers_PreserveUserSetEnv(t *testing.T) {
	block, err := renderManagedBashBlock( /* args matching production */ )
	require.NoError(t, err)
	for _, snippet := range []string{
		"${PIP_UPLOADED_PRIOR_TO:-",
		"${UV_EXCLUDE_NEWER:-",
	} {
		require.Contains(t, block, snippet,
			"wrapper must honor user-set env via :-default, not unconditional overwrite")
	}
}
```

(Adjust function name `renderManagedBashBlock` to match whatever the file exports.)

- [ ] **Step 7: Run new test**

```bash
go test -race ./cmd/veto -run TestShellWrappers_PreserveUserSetEnv -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add cmd/veto/install_shell.go cmd/veto/install_shell_test.go
git commit -m "Phase 1.3: managed shell wrappers respect user-set quarantine env

pip/pip3/uv/uvx wrappers use \${VAR:-default} (bash/zsh) and `set -q`
(fish) so a user-set PIP_UPLOADED_PRIOR_TO or UV_EXCLUDE_NEWER wins
over the 3-day default."
```

### Task 1.3.4: install-shims --force renames existing real binaries instead of deleting

**Files:**
- Modify: `cmd/veto/shims.go:160-180` (the force branch in shim install)
- Modify: `cmd/veto/shims_test.go`

- [ ] **Step 1: Write a failing test**

Append to `cmd/veto/shims_test.go`:

```go
// TestInstallShims_Force_RenamesRealBinary asserts that --force preserves
// any pre-existing real binary at the target path by renaming it to
// <target>.veto-displaced, not deleting it.
func TestInstallShims_Force_RenamesRealBinary(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	target := filepath.Join(dir, "npm")
	realBinary := []byte("#!/bin/sh\necho real-npm\n")
	require.NoError(t, os.WriteFile(target, realBinary, 0o755))

	err := installShim(veto, target, true) // force=true
	require.NoError(t, err)

	// Target is now a symlink to veto.
	resolved, err := os.Readlink(target)
	require.NoError(t, err)
	require.Equal(t, veto, resolved)

	// Real binary preserved.
	displaced := target + ".veto-displaced"
	got, err := os.ReadFile(displaced)
	require.NoError(t, err)
	require.Equal(t, realBinary, got, "real binary must be renamed, not deleted")
}
```

(Adjust `installShim` to whatever the actual exported / unexported function name is in `shims.go`. If the function is `installSingleShim` or similar, use that.)

- [ ] **Step 2: Run — FAIL**

```bash
go test -race ./cmd/veto -run TestInstallShims_Force_RenamesRealBinary -v
```

Expected: FAIL. Current code calls `os.Remove` on the pre-existing target.

- [ ] **Step 3: Modify the force branch**

In `cmd/veto/shims.go` around lines 160-180, find the block that handles a regular-file (non-symlink) target under `--force`. It currently does something like:

```go
if !info.Mode().IsSymlink() && force {
    if err := os.Remove(target); err != nil {
        return err
    }
    if err := os.Symlink(vetoPath, target); err != nil {
        return err
    }
}
```

Replace with:

```go
if !info.Mode().IsSymlink() && force {
    // Rename the displaced real binary so uninstall can restore it.
    // Regression: TestInstallShims_Force_RenamesRealBinary.
    displaced := target + ".veto-displaced"
    if err := os.Rename(target, displaced); err != nil {
        return errors.With(err, "rename real binary to .veto-displaced", "target", target)
    }
    if err := os.Symlink(vetoPath, target); err != nil {
        // Roll back so the user isn't left with a missing binary.
        _ = os.Rename(displaced, target)
        return errors.With(err, "symlink veto over real binary", "target", target)
    }
}
```

- [ ] **Step 4: Update uninstall-shims to restore .veto-displaced**

Find `runUninstallShims` in `cmd/veto/shims.go`. After removing the symlink, check for a sibling `.veto-displaced` and rename it back:

```go
// Restore any binary we displaced with --force on the install side.
displaced := target + ".veto-displaced"
if _, err := os.Lstat(displaced); err == nil {
    if err := os.Rename(displaced, target); err != nil {
        logger.Warn().Err(err).Str("displaced", displaced).Msg("failed to restore displaced binary")
    }
}
```

- [ ] **Step 5: Run tests**

```bash
go test -race ./cmd/veto -run TestInstallShims -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/veto/shims.go cmd/veto/shims_test.go
git commit -m "Phase 1.3: install-shims --force renames displaced binary

A regular file at the shim target path is now renamed to
<target>.veto-displaced rather than deleted. uninstall-shims restores
it if present. Avoids silently destroying a user's hand-installed
homebrew npm under --force."
```

## Group 1.4: L3 interposer scoping

### Task 1.4.1: Replace process-global setenv with rewrite_envp in execv variants

**Files:**
- Modify: `internal/interposer/veto_interpose.c:474-587` (macOS variants) and `:694-967` (Linux variants)

- [ ] **Step 1: Identify the four setenv call sites**

Open `internal/interposer/veto_interpose.c`. Find every call to `setenv("VETO_PYTHON_M_ORIGINAL", ...)`. The L3 reviewer flagged these at approximately lines 509, 527, 725, 743 — confirm via grep:

```bash
grep -n 'setenv("VETO_PYTHON_M_ORIGINAL' internal/interposer/veto_interpose.c
```

These appear in the `execvp`/`execv` shadows (which lack an envp parameter — that's why the original code reached for process env). Note line numbers.

- [ ] **Step 2: Add a small environ-snapshot helper**

Near `rewrite_envp` (around line 332-363), add:

```c
// snapshot_environ returns a NULL-terminated argv-style copy of `environ`
// (caller frees via free_envp). Used by execv/execvp shadows that lack
// an envp parameter to feed rewrite_envp with the current process env
// without mutating it. Returns NULL on alloc failure (caller should fall
// back to the original syscall).
static char **snapshot_environ(void) {
    extern char **environ;
    size_t n = 0;
    while (environ && environ[n]) n++;
    char **out = (char **)calloc(n + 1, sizeof(char *));
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) {
        out[i] = strdup(environ[i]);
        if (!out[i]) {
            for (size_t j = 0; j < i; j++) free(out[j]);
            free(out);
            return NULL;
        }
    }
    out[n] = NULL;
    return out;
}

static void free_envp(char **envp) {
    if (!envp) return;
    for (size_t i = 0; envp[i]; i++) free(envp[i]);
    free(envp);
}
```

- [ ] **Step 3: Replace setenv calls with rewrite_envp + execvpe (Linux) / manual PATH-resolve + execve (macOS)**

For each shadowed `execvp` / `execv` that currently does `setenv("VETO_PYTHON_M_ORIGINAL", original)`, replace the block with:

```c
char **env_snap = snapshot_environ();
if (!env_snap) {
    // Allocation failed; fall through to the unmodified real syscall.
    return real_execv(...);
}
char **new_env = rewrite_envp(env_snap, "VETO_PYTHON_M_ORIGINAL=python3");
if (!new_env) {
    free_envp(env_snap);
    return real_execv(...);
}
int rc;
#if defined(__APPLE__)
    // macOS lacks execvpe; resolve via PATH ourselves, then call execve.
    char resolved[PATH_MAX];
    if (resolve_via_path(file, resolved, sizeof(resolved)) != 0) {
        free_envp(env_snap);
        // free_envp(new_env) — new_env shares pointers with env_snap; do not double-free
        errno = ENOENT;
        return -1;
    }
    rc = real_execve(resolved, new_argv, new_env);
#else
    rc = real_execvpe(file, new_argv, new_env);
#endif
free_envp(env_snap);
// new_env shares the pointers in env_snap plus one new entry — that one
// entry is the constant string passed to rewrite_envp; if rewrite_envp
// duplicated it, free_envp(new_env) would be safe. Verify the rewrite_envp
// contract before deleting this comment.
return rc;
```

Implementation note: `rewrite_envp` currently returns a new array that aliases the original entries by pointer. The new entry is the literal `kv` string the caller passed (a C string literal — no need to free). Confirm by reading `rewrite_envp` and add a comment to its docstring documenting this invariant.

If rewrite_envp does strdup the new entry, then `free_envp(new_env)` would be the right move; in that case use it.

- [ ] **Step 4: Add resolve_via_path for macOS**

Add a small PATH-resolution helper near the top of the file (macOS-only):

```c
#if defined(__APPLE__)
// resolve_via_path mimics execvp's PATH lookup. Returns 0 on success
// and writes the resolved absolute path into out; returns -1 on miss.
static int resolve_via_path(const char *file, char *out, size_t out_sz) {
    if (strchr(file, '/')) {
        if (strlen(file) >= out_sz) return -1;
        strncpy(out, file, out_sz - 1);
        out[out_sz - 1] = '\0';
        return 0;
    }
    const char *path = getenv("PATH");
    if (!path || !*path) path = "/usr/bin:/bin";
    const char *p = path;
    while (*p) {
        const char *q = strchr(p, ':');
        size_t seg_len = q ? (size_t)(q - p) : strlen(p);
        if (seg_len + 1 + strlen(file) + 1 < out_sz) {
            memcpy(out, p, seg_len);
            out[seg_len] = '/';
            memcpy(out + seg_len + 1, file, strlen(file) + 1);
            if (access(out, X_OK) == 0) return 0;
        }
        if (!q) break;
        p = q + 1;
    }
    return -1;
}
#endif
```

- [ ] **Step 5: Rebuild**

```bash
make interposer
```

Expected: clean build, no warnings.

- [ ] **Step 6: Add a multi-threaded leak regression test**

In `cmd/veto/interposer_e2e_test.go`, append:

```go
// TestInterposer_MultiThreaded_PythonM_NoEnvLeak proves the parent process
// is not mutated when a python -m PM rewrite happens. The L3 reviewer
// flagged process-global setenv as a multi-thread race; the fix is to
// build a synthetic envp instead.
func TestInterposer_MultiThreaded_PythonM_NoEnvLeak(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("interposer is built only on darwin and linux")
	}
	libPath, fakeVeto, _, _, _, dir := setupInterposerFixture(t, "pip")
	spawner := buildExecSpawner(t, dir)
	// Run a spawner that fork-execs python -m pip install ... then
	// reads its own environ to confirm VETO_PYTHON_M_ORIGINAL is NOT
	// set in the parent. The spawner's stderr captures the parent's env.
	cmd := exec.Command(spawner, "--check-parent-env", "python3", "-m", "pip", "install", "foo")
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	out, _ := cmd.CombinedOutput()
	require.NotContains(t, string(out), "VETO_PYTHON_M_ORIGINAL=",
		"parent env must not be mutated by Layer 3 rewrites")
}
```

(`--check-parent-env` is a new flag on the test spawner program in `cmd/veto/testdata/interpose_spawner/main.go`; add it: it forks the child via `execvp`, then prints its own `os.Environ()` to stderr.)

- [ ] **Step 7: Update the test spawner**

In `cmd/veto/testdata/interpose_spawner/main.go`, add the `--check-parent-env` mode that, after calling execvp on the rewritten command, prints the current process env to stderr before doing the exec.

(Concrete code depends on the existing spawner shape; consult the file.)

- [ ] **Step 8: Run the new test**

```bash
make interposer && go test -race ./cmd/veto -run TestInterposer_MultiThreaded -v
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/interposer/veto_interpose.c \
        cmd/veto/interposer_e2e_test.go \
        cmd/veto/testdata/interpose_spawner/main.go
git commit -m "Phase 1.4: rewrite_envp for execv variants; no more setenv in interposer

The execv/execvp/execl shadows now snapshot the current environ, build
a synthetic envp via rewrite_envp, and pass it to execvpe (Linux) or
manually PATH-resolve + execve (macOS). The parent process is no longer
mutated by VETO_PYTHON_M_ORIGINAL, closing the multi-threaded env race
and the post-failure env leak."
```

### Task 1.4.2: Add e2e coverage for execvpe / fexecve / execveat on Linux

**Files:**
- Modify: `cmd/veto/interposer_e2e_test.go`
- Modify: `cmd/veto/testdata/interpose_spawner/main.go`

- [ ] **Step 1: Extend the spawner with --mode switches**

In `cmd/veto/testdata/interpose_spawner/main.go`, add:

```go
// New top-level flag --mode determines which exec variant to use.
// Defaults to "execvp" (existing behavior).
var mode = flag.String("mode", "execvp", "exec variant: execvp|execvpe|fexecve|execveat|execl")
```

Then in the spawner's exec call, dispatch on `*mode`:

```go
switch *mode {
case "execvp":
    err = syscall.Exec(target, argv, env)
case "execvpe":
    // Linux only — call via syscall.Execvpe equivalent. Go's stdlib
    // doesn't expose execvpe; use golang.org/x/sys/unix or invoke
    // through a small cgo wrapper if needed. Practically: spawn via
    // `bash -c "exec -a <argv0> <target> <args...>"` is NOT a substitute
    // (different syscall). For an honest test, call execvpe via cgo:
    //   //go:build linux
    //   ... cgo helper ...
case "fexecve":
    fd, err := unix.Open(target, unix.O_RDONLY, 0)
    if err != nil { ... }
    err = unix.Fexecve(fd, argv, env)
case "execveat":
    err = unix.Execveat(unix.AT_FDCWD, target, argv, env, 0)
case "execl":
    // Existing C spawner already covers this.
}
```

Add the cgo helper for execvpe in a `//go:build linux` file alongside the spawner.

- [ ] **Step 2: Add a test for each Linux-only variant**

In `cmd/veto/interposer_e2e_test.go`:

```go
// TestInterposer_Execveat asserts the execveat shadow rewrites npm
// to veto. Linux-only.
func TestInterposer_Execveat(t *testing.T) {
	if runtime.GOOS != "linux" { t.Skip("execveat is linux-only") }
	libPath, fakeVeto, _, _, _, dir := setupInterposerFixture(t, "npm")
	spawner := buildExecSpawner(t, dir)
	cmd := exec.Command(spawner, "--mode=execveat", "/opt/homebrew/bin/npm", "install", "foo")
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	require.NoError(t, cmd.Run())
	require.FileExists(t, filepath.Join(dir, "argv.log"))
}

// Same shape for TestInterposer_Fexecve, TestInterposer_Execvpe.
```

- [ ] **Step 3: Build and run**

```bash
make interposer && go test -race ./cmd/veto -run TestInterposer_Execveat -v
go test -race ./cmd/veto -run TestInterposer_Fexecve -v
go test -race ./cmd/veto -run TestInterposer_Execvpe -v
```

Expected: PASS on Linux, SKIP on Darwin.

- [ ] **Step 4: Commit**

```bash
git add cmd/veto/interposer_e2e_test.go cmd/veto/testdata/interpose_spawner/
git commit -m "Phase 1.4: e2e coverage for execvpe, fexecve, execveat on Linux

Spawner gains --mode={execvp,execvpe,fexecve,execveat,execl}. Tests
prove the existing shadows intercept each variant. Closes the test
gap flagged by the L3 reviewer."
```

## Group 1.5: L4 wrapper atomicity

### Task 1.5.1: Propagate loadWrapperState errors

**Files:**
- Modify: `cmd/veto/install_wrappers.go:137` (the `_ :=` swallow)

- [ ] **Step 1: Find the swallow site**

```bash
grep -n "loadWrapperState(cfg)" cmd/veto/install_wrappers.go
```

Locate the line `state, _ := loadWrapperState(cfg)`.

- [ ] **Step 2: Write a failing test**

In `cmd/veto/install_wrappers_test.go`, add:

```go
// TestInstallWrappers_AbortsOnCorruptState asserts that a malformed
// wrappers.json fails the install loudly instead of silently
// truncating the registry.
func TestInstallWrappers_AbortsOnCorruptState(t *testing.T) {
	cfg := newWrapperTestConfig(t) // existing helper; if none, build inline
	// Plant a malformed wrappers.json under cfg.CacheDir.
	require.NoError(t, os.MkdirAll(cfg.CacheDir, 0o700))
	corruptPath := filepath.Join(cfg.CacheDir, "wrappers.json")
	require.NoError(t, os.WriteFile(corruptPath, []byte("{not json"), 0o600))

	logger := zerolog.Nop()
	rc := runInstallWrappers(logger, cfg, []string{"--dry-run"})
	require.NotEqual(t, exitOK, rc,
		"corrupt wrappers.json must abort, not silently truncate")
}
```

Run: `go test -race ./cmd/veto -run TestInstallWrappers_AbortsOnCorruptState -v` — expect FAIL.

- [ ] **Step 3: Propagate the error**

In `cmd/veto/install_wrappers.go` around line 137, change:

```go
state, _ := loadWrapperState(cfg)
```

to:

```go
state, err := loadWrapperState(cfg)
if err != nil {
    logger.Error().Err(err).Str("path", filepath.Join(cfg.CacheDir, "wrappers.json")).
        Msg("wrappers.json is malformed; refusing to overwrite a possibly load-bearing registry")
    return exitInternal
}
```

Hint to the user where to look — they need to inspect or delete the file before re-running.

- [ ] **Step 4: Run tests**

```bash
go test -race ./cmd/veto -run TestInstallWrappers_AbortsOnCorruptState -v
go test -race ./cmd/veto -v
```

Expected: new test PASSes; nothing else regresses.

- [ ] **Step 5: Commit**

```bash
git add cmd/veto/install_wrappers.go cmd/veto/install_wrappers_test.go
git commit -m "Phase 1.5: propagate loadWrapperState error in install-wrappers

Corrupt wrappers.json now aborts with a clear error pointing at the
file, instead of silently truncating the registry on the next save."
```

### Task 1.5.2: Per-candidate write-ahead order (state before FS)

**Files:**
- Modify: `cmd/veto/install_wrappers.go:150-200` (the install loop) and `:560-625` (`applyWrapper`)

- [ ] **Step 1: Write a failing crash-recovery test**

In `cmd/veto/install_wrappers_test.go`:

```go
// TestApplyWrapper_PartialFailure_RegistryRecoverable asserts that
// when the rename succeeds but the symlink fails, the registry entry
// is rolled back so a subsequent install can recover cleanly.
func TestApplyWrapper_PartialFailure_RegistryRecoverable(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("veto"), 0o755))
	target := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(target, []byte("npm"), 0o755))

	state := newWrapperState()
	// Use a hook to force os.Symlink to fail (use the test fault-injection
	// path or chmod the parent dir to 0o500 after the rename).
	// ... inject fault ...

	_, err := applyWrapper(state, veto, target, false, /*forceLink*/ )
	require.Error(t, err)

	// Registry must NOT contain a partially-applied entry.
	require.Empty(t, state.entries(), "registry must be rolled back when FS fails")
	// Original binary must be restored at its path.
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, []byte("npm"), got, "rename rollback must restore the original binary")
}
```

This will require some plumbing (a way to inject a fault). If the cleanest path is a `wrapperOps` interface that can be swapped in tests, introduce it now.

- [ ] **Step 2: Run — FAIL**

Expected: current code either leaves registry in a partial state, leaves target missing, or both.

- [ ] **Step 3: Refactor applyWrapper to a write-ahead-log order**

In `cmd/veto/install_wrappers.go`, around the existing `applyWrapper` body, restructure to:

```go
func applyWrapper(state *wrapperState, vetoPath string, c wrapCandidate, forceLink bool) (wrapAction, error) {
    // ... existing already-ours / drift detection branches stay ...

    original := c.path + ".veto-original"

    // 1. Register intent FIRST. saveWrapperState commits the write-ahead log.
    state.add(c.path, original, c.source)
    if err := saveWrapperState(state, vetoPath); err != nil {
        state.remove(c.path) // local rollback so the in-memory state matches disk
        return wrapperActionUnknown, errors.With(err, "save wrapper state before FS mutation")
    }

    // 2. Rename real binary to .veto-original.
    if err := os.Rename(c.path, original); err != nil {
        state.remove(c.path)
        _ = saveWrapperState(state, vetoPath) // best-effort: roll back the registry too
        return wrapperActionUnknown, errors.With(err, "rename real binary", "path", c.path)
    }

    // 3. Symlink veto at the target.
    if err := os.Symlink(vetoPath, c.path); err != nil {
        // Restore: rename original back, then unregister.
        _ = os.Rename(original, c.path)
        state.remove(c.path)
        _ = saveWrapperState(state, vetoPath)
        return wrapperActionUnknown, errors.With(err, "symlink veto over target", "path", c.path)
    }

    return wrapperActionWrapped, nil
}
```

Add `wrapperActionUnknown = 0` to the `iota` block so the zero value is a sentinel (the L4 reviewer's finding #9).

- [ ] **Step 4: Update the call site in `runInstallWrappers`**

Find the loop in `runInstallWrappers` (around lines 150-200). The pre-existing batch `saveWrapperState` call at the end of the loop becomes a no-op (state is already persisted per-wrap). Delete the trailing `saveWrapperState` call after the loop.

- [ ] **Step 5: Add unit + integration tests**

The fault-injection test from step 1 should now pass. Add another scenario where `saveWrapperState` itself fails (e.g., chmod the cache dir read-only mid-test):

```go
// TestApplyWrapper_SaveStateFails_NoFSMutation asserts the WAL contract:
// if registry persist fails, no on-disk rename happens.
func TestApplyWrapper_SaveStateFails_NoFSMutation(t *testing.T) { /* ... */ }
```

- [ ] **Step 6: Run tests**

```bash
go test -race ./cmd/veto -run TestApplyWrapper -v
go test -race ./cmd/veto -v
```

Expected: PASS, no regressions.

- [ ] **Step 7: Commit**

```bash
git add cmd/veto/install_wrappers.go cmd/veto/install_wrappers_test.go
git commit -m "Phase 1.5: write-ahead-log order for wrapper install

applyWrapper now persists the registry entry BEFORE the rename+symlink.
Each failure path rolls back the registry and (where possible) the FS,
so a crash mid-loop leaves either fully-installed-and-recorded or
nothing — never the silent half-state where wrappers exist on disk
without a registry entry."
```

### Task 1.5.3: Atomic unwrap via tmp-rename dance

**Files:**
- Modify: `cmd/veto/install_wrappers.go:665-690` (`unwrap` function)

- [ ] **Step 1: Write a failing test**

```go
// TestUnwrap_PreservesOriginalOnRenameFailure asserts that unwrap leaves
// the original binary intact at <path>.veto-original if it can't restore
// it — strictly better than today's "target missing" failure mode.
func TestUnwrap_PreservesOriginalOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink("/some/veto", target))
	original := target + ".veto-original"
	require.NoError(t, os.WriteFile(original, []byte("real-npm"), 0o755))

	// Inject failure at the final rename. Practically: chmod the parent
	// dir to remove the +w bit just before the rename, then restore.
	// (Test details depend on existing fault-injection patterns.)

	err := unwrap(/* args */)
	require.Error(t, err)

	// Original must STILL exist (either at .veto-original or at target).
	_, err = os.Stat(target)
	if os.IsNotExist(err) {
		// then .veto-original must exist
		_, err2 := os.Stat(original)
		require.NoError(t, err2, "either target or .veto-original must exist")
	}
}
```

- [ ] **Step 2: Refactor unwrap to tmp-rename dance**

In `cmd/veto/install_wrappers.go`, replace `unwrap`'s body:

```go
func unwrap(state *wrapperState, w wrapperEntry) error {
    // Phase 1: move the original to a sibling tmp path. If this fails,
    // nothing has changed on disk.
    tmp := w.Path + ".veto-restoring"
    if err := os.Rename(w.OriginalPath, tmp); err != nil {
        return errors.With(err, "stage .veto-original to .veto-restoring", "original", w.OriginalPath)
    }

    // Phase 2: remove the veto symlink. If this fails, restore.
    if err := os.Remove(w.Path); err != nil {
        _ = os.Rename(tmp, w.OriginalPath) // best-effort rollback
        return errors.With(err, "remove veto symlink", "path", w.Path)
    }

    // Phase 3: rename tmp to target. If this fails, .veto-restoring still
    // holds the original — the user can restore manually, and a second
    // unwrap attempt will succeed.
    if err := os.Rename(tmp, w.Path); err != nil {
        return errors.With(err, "rename .veto-restoring to target", "tmp", tmp, "target", w.Path)
    }
    return nil
}
```

- [ ] **Step 3: Tests pass**

```bash
go test -race ./cmd/veto -run TestUnwrap -v
go test -race ./cmd/veto -v
```

- [ ] **Step 4: Commit**

```bash
git add cmd/veto/install_wrappers.go cmd/veto/install_wrappers_test.go
git commit -m "Phase 1.5: atomic unwrap via .veto-restoring tmp rename

unwrap now stages the original to <path>.veto-restoring before
removing the veto symlink. If any step fails, the user is left with
either the original at .veto-restoring or at target — never with a
missing binary at target. Replaces the prior remove-then-rename
sequence."
```

### Task 1.5.4: fsync the registry write + tighten permissions

**Files:**
- Modify: `cmd/veto/install_wrappers.go:730-760` (`saveWrapperState`)

- [ ] **Step 1: Find saveWrapperState**

```bash
grep -n "func saveWrapperState\|0o644\|os.Chmod(tmpPath" cmd/veto/install_wrappers.go
```

Locate the function and the `0o644` chmod.

- [ ] **Step 2: Add fsync + use 0o600**

Replace the tail of `saveWrapperState`:

```go
if err := tmp.Sync(); err != nil {
    tmp.Close()
    os.Remove(tmpPath)
    return errors.With(err, "fsync wrappers.json tmpfile")
}
if err := tmp.Close(); err != nil {
    os.Remove(tmpPath)
    return errors.With(err, "close wrappers.json tmpfile")
}
if err := os.Chmod(tmpPath, 0o600); err != nil {
    os.Remove(tmpPath)
    return errors.With(err, "chmod wrappers.json tmpfile to 0o600")
}
if err := os.Rename(tmpPath, path); err != nil {
    os.Remove(tmpPath)
    return errors.With(err, "rename wrappers.json into place")
}
// fsync the parent directory so the rename survives an unclean shutdown.
if d, err := os.Open(filepath.Dir(path)); err == nil {
    _ = d.Sync()
    _ = d.Close()
}
return nil
```

(Replace `0o644` with `0o600` everywhere in this function.)

- [ ] **Step 3: Add a regression test for mode**

```go
// TestSaveWrapperState_PrivateMode asserts the registry is 0o600.
func TestSaveWrapperState_PrivateMode(t *testing.T) {
	cfg := newWrapperTestConfig(t)
	state := newWrapperState()
	state.add("/some/path", "/some/path.veto-original", "test")
	require.NoError(t, saveWrapperState(state, /* args */))
	info, err := os.Stat(filepath.Join(cfg.CacheDir, "wrappers.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
```

- [ ] **Step 4: Run tests**

```bash
go test -race ./cmd/veto -run "TestSaveWrapperState|TestApplyWrapper" -v
```

- [ ] **Step 5: Commit**

```bash
git add cmd/veto/install_wrappers.go cmd/veto/install_wrappers_test.go
git commit -m "Phase 1.5: fsync + 0o600 on wrappers.json

saveWrapperState now Sync()s the tmpfile before close, fsyncs the
parent dir after rename, and uses 0o600 permissions throughout.
Protects against unclean-shutdown zero-byte registry and against
accidental world-readability on shared hosts."
```

## Group 1.6: JS parser fail-OPENs

### Task 1.6.1: Add ManifestKindBunLock and bun.lock parser

**Files:**
- Modify: `internal/packagemanager/packagemanager.go` (add the kind)
- Modify: `internal/packagemanager/pmlist/pmlist.go` (extend the canonical list if needed)
- Create: `internal/packagemanager/jslock/bunlock.go`
- Create: `internal/packagemanager/jslock/bunlock_test.go`
- Modify: `internal/packagemanager/jslock/jslock.go` (dispatch)
- Modify: `internal/packagemanager/bun/bun.go` (emit manifest ref)

- [ ] **Step 1: Add the ManifestKind constant**

In `internal/packagemanager/packagemanager.go`, find the `ManifestKind` constants block (search for `ManifestKindPackageJSON`). Append:

```go
ManifestKindBunLock ManifestKind = "bun-lock"     // bun.lock (text JSONC)
// bun.lockb (binary) is intentionally unsupported until a stable
// format spec exists; bun.ManifestRefs emits a warning.
```

- [ ] **Step 2: Write a failing test for bunlock parsing**

Create `internal/packagemanager/jslock/bunlock_test.go`:

```go
package jslock

import (
	"testing"

	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/stretchr/testify/require"
)

func TestExpandBunLock_Basic(t *testing.T) {
	// Minimal bun.lock (JSONC: comments allowed, trailing commas).
	body := []byte(`{
  "lockfileVersion": 1,
  "packages": {
    "lodash": ["lodash@4.17.21", "lodash-4.17.21-ABC123"],
    "express": ["express@4.18.2", ""]
  }
}`)
	got, err := parseBunLock(body)
	require.NoError(t, err)
	require.ElementsMatch(t, []packagemanager.Install{
		{Ref: ref("npm", "lodash", "4.17.21"), RawSpec: "lodash@4.17.21"},
		{Ref: ref("npm", "express", "4.18.2"), RawSpec: "express@4.18.2"},
	}, got)
}

func TestExpandBunLock_StripsJSONCComments(t *testing.T) {
	body := []byte(`{
  // top-level comment
  "lockfileVersion": 1,
  "packages": {
    "react": ["react@18.2.0", ""] // inline comment
  }
}`)
	got, err := parseBunLock(body)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "react", got[0].Ref.Name)
	require.Equal(t, "18.2.0", got[0].Ref.Version)
}

// ref is a small helper; if jslock_test.go already has one, reuse it.
func ref(eco, name, version string) intel.PackageRef {
	return intel.PackageRef{Ecosystem: intel.Ecosystem(eco), Name: name, Version: version}
}
```

Run: `go test -race ./internal/packagemanager/jslock -run TestExpandBunLock -v` — FAIL (parser doesn't exist).

- [ ] **Step 3: Implement parseBunLock**

Create `internal/packagemanager/jslock/bunlock.go`:

```go
package jslock

import (
	"encoding/json"
	"strings"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// parseBunLock extracts (name, version) tuples from a text bun.lock
// (JSONC). The bun.lockb binary form is intentionally unsupported —
// callers must check the filename extension before invoking this.
func parseBunLock(data []byte) ([]packagemanager.Install, error) {
	clean := stripJSONComments(data)
	var doc struct {
		Packages map[string][]string `json:"packages"`
	}
	if err := json.Unmarshal(clean, &doc); err != nil {
		return nil, errors.With(err, "parse bun.lock")
	}
	out := make([]packagemanager.Install, 0, len(doc.Packages))
	for _, entries := range doc.Packages {
		if len(entries) == 0 || entries[0] == "" {
			continue
		}
		// entries[0] is the spec, e.g. "lodash@4.17.21".
		spec := entries[0]
		at := strings.LastIndexByte(spec, '@')
		if at <= 0 {
			continue
		}
		name := spec[:at]
		version := spec[at+1:]
		out = append(out, packagemanager.Install{
			Ref:     intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name, Version: version},
			RawSpec: spec,
		})
	}
	return out, nil
}

// stripJSONComments removes // line comments and /* ... */ block
// comments from a JSONC document so encoding/json can decode it.
// Trailing commas are also tolerated by JSON Decoder.More() being
// permissive enough for the simple shapes we care about; if needed,
// a second pass strips a comma followed by whitespace and `]`/`}`.
func stripJSONComments(in []byte) []byte {
	var out []byte
	i := 0
	inString := false
	for i < len(in) {
		c := in[i]
		if inString {
			out = append(out, c)
			if c == '\\' && i+1 < len(in) {
				out = append(out, in[i+1])
				i += 2
				continue
			}
			if c == '"' {
				inString = false
			}
			i++
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			i++
			continue
		}
		if c == '/' && i+1 < len(in) {
			if in[i+1] == '/' {
				for i < len(in) && in[i] != '\n' { i++ }
				continue
			}
			if in[i+1] == '*' {
				i += 2
				for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') { i++ }
				i += 2
				continue
			}
		}
		out = append(out, c)
		i++
	}
	return out
}
```

- [ ] **Step 4: Wire bunlock into the jslock dispatch**

In `internal/packagemanager/jslock/jslock.go`, find the `Expand` function. Add a case for `ManifestKindBunLock`:

```go
case packagemanager.ManifestKindBunLock:
    data, err := readFile(ref.Path)
    if err != nil { return nil, err }
    return parseBunLock(data)
```

- [ ] **Step 5: Emit the ref from bun.ManifestRefs**

In `internal/packagemanager/bun/bun.go`, `ManifestRefs`, append:

```go
// bun.lock (text JSONC) — primary; bun.lockb (binary) NOT supported.
refs = append(refs, packagemanager.ManifestRef{
    Kind: packagemanager.ManifestKindBunLock,
    Path: "bun.lock",
})
```

Also: if a `bun.lockb` is present without a `bun.lock`, log a warning at install-time. Add a tiny check in `bun.ManifestRefs` that consults the filesystem only if invoked from a context that has CWD — actually, the cleanest pattern is to let the gate's expander surface "file not found" and have the gate's caller log. So no warning logic here; just the ref. Skip the warning if it complicates the path.

- [ ] **Step 6: Run all jslock + bun tests**

```bash
go test -race ./internal/packagemanager/jslock -v
go test -race ./internal/packagemanager/bun -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/packagemanager/packagemanager.go \
        internal/packagemanager/jslock/bunlock.go \
        internal/packagemanager/jslock/bunlock_test.go \
        internal/packagemanager/jslock/jslock.go \
        internal/packagemanager/bun/bun.go
git commit -m "Phase 1.6: gate transitive bun.lock entries

Adds ManifestKindBunLock, a text-JSONC parser, and wires bun's
ManifestRefs to emit it. Closes the bun-lockfile transitive
coverage gap. bun.lockb (binary) remains unsupported."
```

### Task 1.6.2: Route dlx/x verbs through exec.Manager

**Files:**
- Modify: `internal/packagemanager/pnpm/pnpm.go` (route `dlx`)
- Modify: `internal/packagemanager/yarn/yarn.go` (route `dlx`)
- Modify: `internal/packagemanager/bun/bun.go` (route `x` and `create`)
- Modify: `internal/packagemanager/exec/exec.go` if needed to expose the manager-style API for these PMs

- [ ] **Step 1: Add failing tests for dlx misclassification**

In `internal/packagemanager/pnpm/pnpm_test.go`:

```go
// TestPnpmDlx_PackageFlag_Gated asserts that `pnpm dlx --package=evil cmd`
// gates `evil`, not `cmd`. Today the parser treats `cmd` as the install.
func TestPnpmDlx_PackageFlag_Gated(t *testing.T) {
	pm := New()
	installs := pm.ParseInstalls([]string{"dlx", "--package=evil-pkg", "some-cmd", "arg1", "arg2"})
	require.Len(t, installs, 1)
	require.Equal(t, "evil-pkg", installs[0].Ref.Name)
}

// TestPnpmDlx_NoExtraPositionals asserts that args after the dlx spec
// are NOT treated as additional installs.
func TestPnpmDlx_NoExtraPositionals(t *testing.T) {
	pm := New()
	installs := pm.ParseInstalls([]string{"dlx", "evil-pkg", "arg1", "arg2", "arg3"})
	require.Len(t, installs, 1)
	require.Equal(t, "evil-pkg", installs[0].Ref.Name)
}
```

Mirror these in `yarn_test.go` (`yarn dlx`) and `bun_test.go` (`bun x`, `bun create`).

- [ ] **Step 2: Run — FAIL**

```bash
go test -race ./internal/packagemanager/pnpm -run TestPnpmDlx -v
```

- [ ] **Step 3: Refactor pnpm.ParseInstalls to route dlx through exec.Manager**

In `internal/packagemanager/pnpm/pnpm.go`, add a private `execMgr` for the dlx verb:

```go
// dlxExecManager handles `pnpm dlx`: it parses --package=<spec> and treats
// the first non-flag positional as the spec if no --package flag is present.
var dlxExecManager = exec.New(exec.Options{
    Verbs:        []string{"dlx"},
    SpecFlags:    exec.PnpxSpecFlags,    // --package, -p
    ValueFlags:   exec.PnpxFlagsWithValues,
    // PipxStyle: false (default) — one spec per call
})

func (m Manager) ParseInstalls(args []string) []packagemanager.Install {
    if len(args) == 0 { return nil }
    if args[0] == "dlx" {
        return dlxExecManager.ParseInstalls(args)
    }
    // ... existing logic for install/add/update ...
}
```

If `exec.PnpxSpecFlags` doesn't yet exist, add it to `internal/packagemanager/exec/exec.go`:

```go
var PnpxSpecFlags = map[string]bool{
    "--package": true, "-p": true,
}
var PnpxFlagsWithValues = map[string]bool{
    "--package": true, "-p": true,
    "--prefer-online": false,  // example boolean — list per pnpm docs
}
```

(The L2 reviewer noted these may already partially exist; consult `exec.go` first and extend.)

- [ ] **Step 4: Mirror for yarn `dlx` and bun `x` / `create`**

In `internal/packagemanager/yarn/yarn.go`:

```go
var dlxExecManager = exec.New(exec.Options{
    Verbs:      []string{"dlx"},
    SpecFlags:  exec.YarnDlxSpecFlags,
    ValueFlags: exec.YarnDlxFlagsWithValues,
})

func (m Manager) ParseInstalls(args []string) []packagemanager.Install {
    if len(args) == 0 { return nil }
    if args[0] == "dlx" {
        return dlxExecManager.ParseInstalls(args)
    }
    // ... existing ...
}
```

In `internal/packagemanager/bun/bun.go`:

```go
var bunxExecManager = exec.New(exec.Options{
    Verbs:      []string{"x", "create"},
    SpecFlags:  exec.BunxSpecFlags,
    ValueFlags: exec.BunxFlagsWithValues,
})

func (m Manager) ParseInstalls(args []string) []packagemanager.Install {
    if len(args) == 0 { return nil }
    if args[0] == "x" || args[0] == "create" {
        return bunxExecManager.ParseInstalls(args)
    }
    // ... existing ...
}
```

Add the spec-flag maps in `exec/exec.go` matching each PM's actual flag set.

- [ ] **Step 5: Run all the dlx tests**

```bash
go test -race ./internal/packagemanager/pnpm -v
go test -race ./internal/packagemanager/yarn -v
go test -race ./internal/packagemanager/bun -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/packagemanager/{pnpm,yarn,bun,exec}/*.go
git commit -m "Phase 1.6: route dlx/x/create through exec.Manager

pnpm dlx, yarn dlx, bun x, and bun create now share the same
spec-flag-aware parser as npx/pnpx/bunx. Closes the
'pnpm dlx --package=evil cmd' misclassification and the
over-gating of trailing positionals."
```

### Task 1.6.3: jsspec recognizes link/portal/workspace/catalog/patch as LocalPath

**Files:**
- Modify: `internal/packagemanager/jsspec/jsspec.go:112-130` (`IsLocalPathSpec`)
- Modify: `internal/packagemanager/jsspec/jsspec_test.go`

- [ ] **Step 1: Add failing tests**

```go
func TestIsLocalPathSpec_YarnBerryAndPnpmPrefixes(t *testing.T) {
	cases := []struct{ spec string; want bool }{
		{"link:./pkg", true},      // yarn berry
		{"portal:./pkg", true},    // yarn berry
		{"workspace:^", true},     // pnpm/yarn berry
		{"workspace:*", true},     // pnpm
		{"catalog:", true},        // pnpm
		{"catalog:default", true}, // pnpm
		{"patch:lodash@4.17.21#./fix.patch", true}, // yarn berry
		// Non-local should NOT match:
		{"git+https://example.com/repo", false},
		{"https://example.com/foo.tgz", false},
		{"lodash@4.17.21", false},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			require.Equal(t, tc.want, IsLocalPathSpec(tc.spec))
		})
	}
}
```

- [ ] **Step 2: Extend IsLocalPathSpec**

In `internal/packagemanager/jsspec/jsspec.go`, update `IsLocalPathSpec`:

```go
// IsLocalPathSpec reports whether spec refers to a filesystem path or
// a workspace-local pin (yarn berry's link:/portal:/patch:, pnpm/yarn
// berry's workspace:, pnpm's catalog:). These do not hit a remote
// registry by name and so should pass through the gate as LocalPath.
func IsLocalPathSpec(spec string) bool {
    if spec == "." || spec == ".." { return true }
    if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") ||
        strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "file:") {
        return true
    }
    for _, prefix := range []string{"link:", "portal:", "workspace:", "catalog:", "patch:"} {
        if strings.HasPrefix(spec, prefix) {
            return true
        }
    }
    return false
}
```

- [ ] **Step 3: Run**

```bash
go test -race ./internal/packagemanager/jsspec -v
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/packagemanager/jsspec/jsspec.go internal/packagemanager/jsspec/jsspec_test.go
git commit -m "Phase 1.6: jsspec recognizes workspace/link/portal/catalog/patch as LocalPath

Closes the false-OpaqueRemote classification for yarn-berry and pnpm
workspace pins that broke legitimate monorepo installs."
```

### Task 1.6.4: jslock yarn parser skips __metadata; jsmanifest exactPin wildcard fix; jsspec alias precedence

**Files:**
- Modify: `internal/packagemanager/jslock/jslock.go:328-361` (yarn parser); also `:406-415` (`nameFromYarnHeader`)
- Modify: `internal/packagemanager/jsmanifest/jsmanifest.go:162-167` (`exactPin`)
- Modify: `internal/packagemanager/jsspec/jsspec.go:35-67` (alias precedence)

- [ ] **Step 1: Test for __metadata skip**

```go
func TestExpandYarnLock_SkipsMetadataPseudoEntry(t *testing.T) {
	body := `__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.0":
  version: "4.17.21"
  resolution: "lodash@npm:4.17.21"`
	got, err := expandYarnLock([]byte(body))
	require.NoError(t, err)
	for _, ins := range got {
		require.NotEqual(t, "__metadata", ins.Ref.Name)
	}
	require.Len(t, got, 1)
}
```

- [ ] **Step 2: Fix nameFromYarnHeader**

In `internal/packagemanager/jslock/jslock.go`, find `nameFromYarnHeader` (line ~406). If the header contains no `@` to split on, return empty string instead of the header itself:

```go
func nameFromYarnHeader(h string) string {
    // ... existing scope/@ handling ...
    idx := strings.IndexByte(h, '@')
    if idx <= 0 {
        return "" // headers like "__metadata" have no '@'; skip them
    }
    return h[:idx]
}
```

Then in the parser state machine, skip emission when `nameFromYarnHeader` returns empty:

```go
name := nameFromYarnHeader(pendingHeader)
if name == "" { continue }
```

- [ ] **Step 3: Test for exactPin wildcard**

```go
func TestExactPin_PreservesPrereleaseTags(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.0.0-experimental", "1.0.0-experimental"},
		{"1.2.3-Xfix", "1.2.3-Xfix"},     // contains X but not as wildcard
		{"2.0.0+build.x12", "2.0.0+build.x12"},
		{"1.x", ""},                       // legitimate wildcard
		{"1.2.x", ""},                     // legitimate wildcard
		{"^1.0.0", ""},                    // range, not exact
		{"1.0.0", "1.0.0"},                // exact
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.want, exactPin(tc.in))
		})
	}
}
```

- [ ] **Step 4: Fix exactPin**

In `internal/packagemanager/jsmanifest/jsmanifest.go:162-167`, replace the rune-scan with an anchored wildcard check:

```go
func exactPin(version string) string {
    // Range/comparator characters mean it's not an exact pin.
    if strings.ContainsAny(version, "^~><=*| ,") {
        return ""
    }
    // 'x' / 'X' wildcards: only count when they're the whole token or
    // a `.x` segment (so '1.0.x' is a wildcard but '1.0.0-Xfix' is not).
    if version == "x" || version == "X" { return "" }
    if hasSegmentWildcard(version) { return "" }
    return version
}

// hasSegmentWildcard reports whether version contains a '.x' or '.X'
// segment boundary (per npm semver wildcard syntax).
func hasSegmentWildcard(version string) bool {
    parts := strings.FieldsFunc(version, func(r rune) bool { return r == '.' })
    for _, p := range parts {
        if p == "x" || p == "X" { return true }
    }
    return false
}
```

- [ ] **Step 5: jsspec alias precedence test**

```go
func TestParseSpec_GithubShorthand_DoesNotUnwrapAlias(t *testing.T) {
	// `user/repo@npm:evil@1` looks like an alias but the name portion is
	// not a legal npm name (contains '/'). We should NOT treat the
	// alias-target as the install.
	got := Parse("user/repo@npm:evil@1")
	require.True(t, got.OpaqueRemote, "github shorthand with alias must be OpaqueRemote, not unwrapped to evil")
	require.NotEqual(t, "evil", got.Name)
}
```

- [ ] **Step 6: Fix alias precedence**

In `internal/packagemanager/jsspec/jsspec.go`, add an `isLegalNpmName` predicate and gate `tryParseAlias` on it:

```go
// isLegalNpmName reports whether s is a syntactically valid npm package
// name (per npm-validate-package-name rules, simplified). Specifically:
// no slashes (except a single one inside @scope/name), no spaces, no
// colons, lowercase.
func isLegalNpmName(s string) bool {
    if s == "" { return false }
    if strings.HasPrefix(s, "@") {
        // @scope/name
        slash := strings.IndexByte(s, '/')
        if slash <= 1 { return false }
        scope := s[1:slash]
        name := s[slash+1:]
        return validNamePart(scope) && validNamePart(name)
    }
    return validNamePart(s)
}

func validNamePart(s string) bool {
    if s == "" || len(s) > 214 { return false }
    if strings.IndexAny(s, " /:\\") >= 0 { return false }
    // npm requires lowercase, no leading dot/underscore.
    if s[0] == '.' || s[0] == '_' { return false }
    return true
}

// tryParseAlias is now gated on isLegalNpmName:
func tryParseAlias(name, version string) (string, string, bool) {
    if !isLegalNpmName(name) { return "", "", false }
    // ... existing body ...
}
```

- [ ] **Step 7: Run all the tests**

```bash
go test -race ./internal/packagemanager/jslock -v
go test -race ./internal/packagemanager/jsmanifest -v
go test -race ./internal/packagemanager/jsspec -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/packagemanager/jslock/jslock.go \
        internal/packagemanager/jsmanifest/jsmanifest.go \
        internal/packagemanager/jsspec/jsspec.go \
        internal/packagemanager/jslock/jslock_test.go \
        internal/packagemanager/jsmanifest/jsmanifest_test.go \
        internal/packagemanager/jsspec/jsspec_test.go
git commit -m "Phase 1.6: yarn __metadata skip, exactPin wildcard anchor, jsspec alias gate

Three small parser-correctness fixes: yarn berry's __metadata
pseudo-entry no longer emits a spurious Install named '__metadata';
exactPin treats x/X as wildcards only at segment boundaries (so
1.0.0-experimental stays an exact pin); jsspec.tryParseAlias only
fires when the name portion is a legal npm name (closes the
user/repo@npm:evil@1 precedence quirk)."
```

### Task 1.6.5: jsmanifest reads bundleDependencies and walks workspaces

**Files:**
- Modify: `internal/packagemanager/jsmanifest/jsmanifest.go:43-48` (struct + expander)

- [ ] **Step 1: Tests**

```go
func TestJsManifest_ReadsBundleDependencies(t *testing.T) {
	pkg := `{
  "name": "x",
  "bundleDependencies": ["evil-pkg", "other-pkg"]
}`
	got, err := Expander{}.Expand(packagemanager.ManifestRef{Kind: ManifestKindPackageJSON, Path: writeTemp(t, pkg)})
	require.NoError(t, err)
	names := names(got)
	require.Contains(t, names, "evil-pkg")
	require.Contains(t, names, "other-pkg")
}

func TestJsManifest_WalksWorkspaces(t *testing.T) {
	tmpRoot := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpRoot, "package.json"), []byte(`{
  "name": "root",
  "workspaces": ["packages/*"]
}`), 0o644))
	pkgADir := filepath.Join(tmpRoot, "packages", "a")
	require.NoError(t, os.MkdirAll(pkgADir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pkgADir, "package.json"), []byte(`{
  "name": "a",
  "dependencies": { "lodash": "4.17.21" }
}`), 0o644))

	got, err := Expander{}.Expand(packagemanager.ManifestRef{
		Kind: ManifestKindPackageJSON,
		Path: filepath.Join(tmpRoot, "package.json"),
	})
	require.NoError(t, err)
	require.Contains(t, names(got), "lodash")
}
```

- [ ] **Step 2: Extend the struct + expander**

In `internal/packagemanager/jsmanifest/jsmanifest.go`:

```go
type packageJSON struct {
    Name                 string                       `json:"name"`
    Dependencies         map[string]string            `json:"dependencies"`
    DevDependencies      map[string]string            `json:"devDependencies"`
    PeerDependencies     map[string]string            `json:"peerDependencies"`
    OptionalDependencies map[string]string            `json:"optionalDependencies"`
    BundleDependencies   []string                     `json:"bundleDependencies"`
    Workspaces           workspaceField               `json:"workspaces"`
}

// workspaceField accepts either ["packages/*"] (npm/pnpm/yarn classic) or
// {"packages": ["packages/*"]} (yarn classic alt form). UnmarshalJSON
// normalizes to a flat slice.
type workspaceField []string

func (w *workspaceField) UnmarshalJSON(b []byte) error {
    if len(b) > 0 && b[0] == '[' {
        return json.Unmarshal(b, (*[]string)(w))
    }
    var obj struct{ Packages []string `json:"packages"` }
    if err := json.Unmarshal(b, &obj); err == nil {
        *w = obj.Packages
        return nil
    }
    return nil
}
```

In the expander, after the four dependency maps:

```go
for _, name := range pkg.BundleDependencies {
    out = append(out, packagemanager.Install{
        Ref:     intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name},
        RawSpec: name,
    })
}
// Walk workspaces — each member's package.json is expanded recursively.
if len(pkg.Workspaces) > 0 {
    baseDir := filepath.Dir(ref.Path)
    for _, pattern := range pkg.Workspaces {
        matches, _ := filepath.Glob(filepath.Join(baseDir, pattern, "package.json"))
        for _, member := range matches {
            sub, _ := Expander{}.Expand(packagemanager.ManifestRef{
                Kind: ManifestKindPackageJSON,
                Path: member,
            })
            out = append(out, sub...)
        }
    }
}
```

(Use `filepath.Glob`; for `packages/**` recursive globs, document as a follow-up. Most JS monorepos use single-level globs.)

- [ ] **Step 3: Run**

```bash
go test -race ./internal/packagemanager/jsmanifest -v
```

- [ ] **Step 4: Commit**

```bash
git add internal/packagemanager/jsmanifest/jsmanifest.go internal/packagemanager/jsmanifest/jsmanifest_test.go
git commit -m "Phase 1.6: jsmanifest reads bundleDependencies + walks workspaces

Monorepos with workspaces declared in the root package.json now have
each member's package.json expanded. bundleDependencies (the array
form) are gated by name."
```

## Group 1.7: Python parser fail-OPENs

### Task 1.7.1: pyreq glues line continuations

**Files:**
- Modify: `internal/packagemanager/pyreq/pyreq.go:90-95`
- Modify: `internal/packagemanager/pyreq/pyreq_test.go`

- [ ] **Step 1: Failing test**

```go
func TestParseRequirements_GluesLineContinuations(t *testing.T) {
	body := []byte(`legit==1.0 \
evil==9.9.9
other==2.0
`)
	got, err := parseRequirements(body, "")
	require.NoError(t, err)
	names := []string{}
	for _, i := range got { names = append(names, i.Ref.Name) }
	require.Contains(t, names, "evil", "continuation-line content must NOT be silently dropped")
	require.Contains(t, names, "legit")
	require.Contains(t, names, "other")
}

func TestParseRequirements_GluesHashContinuations(t *testing.T) {
	body := []byte(`requests==2.31.0 \
    --hash=sha256:abc \
    --hash=sha256:def
`)
	got, err := parseRequirements(body, "")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "requests", got[0].Ref.Name)
}
```

- [ ] **Step 2: Implement continuation gluing**

In `internal/packagemanager/pyreq/pyreq.go`, replace the per-line scanning with a pre-pass that joins continuations:

```go
func parseRequirements(data []byte, basePath string) ([]packagemanager.Install, error) {
    lines := strings.Split(string(data), "\n")
    joined := make([]string, 0, len(lines))
    var acc strings.Builder
    for _, raw := range lines {
        line := strings.TrimRight(raw, "\r")
        if strings.HasSuffix(line, `\`) && !inComment(line) {
            acc.WriteString(strings.TrimSuffix(line, `\`))
            acc.WriteString(" ")
            continue
        }
        acc.WriteString(line)
        joined = append(joined, acc.String())
        acc.Reset()
    }
    if acc.Len() > 0 { joined = append(joined, acc.String()) }
    // ... existing per-line parsing using `joined` instead of raw lines ...
}

// inComment reports whether the line is entirely a comment (so the
// trailing backslash isn't a continuation).
func inComment(line string) bool {
    t := strings.TrimSpace(line)
    return strings.HasPrefix(t, "#")
}
```

- [ ] **Step 3: Run**

```bash
go test -race ./internal/packagemanager/pyreq -v
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/packagemanager/pyreq/pyreq.go internal/packagemanager/pyreq/pyreq_test.go
git commit -m "Phase 1.7: pyreq glues backslash line continuations

Previously a multi-line requirement like 'legit==1.0 \\\\\\n evil==9.9.9'
let evil pass unscanned. The new pre-pass joins continuations before
parsing so every spec is visible to the gate."
```

### Task 1.7.2: pyspec — bare dir, windows drive, leading-dash names

**Files:**
- Modify: `internal/packagemanager/pyspec/pyspec.go:40-160`
- Modify: `internal/packagemanager/pyspec/pyspec_test.go`

- [ ] **Step 1: Failing tests**

```go
func TestParse_BareDirWithSlash_IsLocalPath(t *testing.T) {
	cases := []string{"evil/", "evil/sub", "evil/sub/"}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			got := Parse(c)
			require.True(t, got.LocalPath, "%q must be LocalPath", c)
		})
	}
}

func TestParse_WindowsDriveLetter_IsLocalPath(t *testing.T) {
	for _, c := range []string{`C:\pkg`, `C:/pkg`, `D:\folder\sub`} {
		require.True(t, Parse(c).LocalPath, "%q must be LocalPath", c)
	}
}

func TestParse_LeadingDashName_RejectedNotInstall(t *testing.T) {
	got := Parse("--no-deps")
	require.Empty(t, got.Ref.Name, "names starting with '-' must not become installs")
}
```

- [ ] **Step 2: Extend isLocalPathSpec + Parse**

In `internal/packagemanager/pyspec/pyspec.go`:

```go
func isLocalPathSpec(spec string) bool {
    if spec == "." || spec == ".." { return true }
    if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") ||
        strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "file:") {
        return true
    }
    // Bare-name with path separator: 'evil/', 'evil/sub'. pip resolves any
    // existing on-disk path; if there's a slash anywhere AND no scheme
    // prefix, treat as local.
    if !isOpaqueRemoteSpec(spec) {
        if strings.ContainsAny(spec, `/\`) {
            return true
        }
    }
    // Windows drive letter (C:\, D:/).
    if len(spec) >= 2 && spec[1] == ':' &&
        ((spec[0] >= 'a' && spec[0] <= 'z') || (spec[0] >= 'A' && spec[0] <= 'Z')) {
        return true
    }
    return false
}
```

In `Parse`:

```go
func Parse(spec string) packagemanager.Install {
    spec = strings.TrimSpace(spec)
    if spec == "" || strings.HasPrefix(spec, "-") {
        return packagemanager.Install{RawSpec: spec} // empty Name; caller skips
    }
    // ... existing local/opaque/named dispatch ...
}
```

- [ ] **Step 3: Run**

```bash
go test -race ./internal/packagemanager/pyspec -v
```

- [ ] **Step 4: Commit**

```bash
git add internal/packagemanager/pyspec/pyspec.go internal/packagemanager/pyspec/pyspec_test.go
git commit -m "Phase 1.7: pyspec recognizes bare-dir-with-slash, drive letters, dash names

Closes three classification bugs: 'evil/' fell through to PyPI lookup
(now LocalPath), Windows 'C:\\pkg' silently became a registry name
(now LocalPath), and any unknown flag like '--no-deps' became an
install named '--no-deps' (now empty Name so caller skips)."
```

### Task 1.7.3: pip + uv resolver prescans forward / strip the right flags

**Files:**
- Modify: `internal/packagemanager/pip/pip.go:140-200` (`appendResolverFlags` + `ResolverPreScan`)
- Modify: `internal/packagemanager/uv/uv.go:200-260` (`ResolverPreScan` + `compileRequirementArgs`)
- Modify: corresponding test files

- [ ] **Step 1: Failing test for pip prescan flag forwarding**

```go
func TestPipPrescan_ForwardsIndexFlags(t *testing.T) {
	pm := New()
	plan, ok := pm.ResolverPreScan([]string{"install", "--index-url=https://internal.example/simple", "--extra-index-url=https://aux", "foo"})
	require.True(t, ok)
	args := plan.Args
	require.Contains(t, args, "--index-url=https://internal.example/simple")
	require.Contains(t, args, "--extra-index-url=https://aux")
}

func TestPipPrescan_StripsNoDeps(t *testing.T) {
	pm := New()
	plan, ok := pm.ResolverPreScan([]string{"install", "--no-deps", "foo"})
	require.True(t, ok)
	for _, a := range plan.Args {
		require.NotEqual(t, "--no-deps", a, "--no-deps must be stripped from prescan args")
	}
}
```

- [ ] **Step 2: Extract forwarded + stripped flag sets**

In `internal/packagemanager/pip/pip.go`, define:

```go
// flagsToForward are passed through to the dry-run resolver unchanged.
// These all affect WHERE pip looks, not WHETHER it resolves transitives.
var flagsToForward = map[string]bool{
    "--index-url": true, "-i": true,
    "--extra-index-url": true,
    "--find-links": true, "-f": true,
    "--keyring-provider": true,
    "--trusted-host": true,
    "--no-build-isolation": true,  // forwarded; isolation choice should match real install
}

// flagsToStrip are removed before the prescan because they would yield
// a misleading dry-run (fewer transitives than the real install).
var flagsToStrip = map[string]bool{
    "--no-deps": true,
}

// Modify appendResolverFlags accordingly: walk the user argv, forward
// or strip per the maps, then append the prescan-specific flags
// (--dry-run, --ignore-installed, --report, --only-binary=:all:).
```

(Adjust the existing `appendResolverFlags` to consult these tables.)

- [ ] **Step 3: Mirror for uv**

In `internal/packagemanager/uv/uv.go`, do the same for the `uv pip compile` invocation. The `compileRequirementArgs` builder needs to forward uv-equivalent flags: `--index`, `--default-index`, `--extra-index-url`, `--find-links`, `--keyring-provider`, `--override`, `--prerelease`, `--resolution`, `--python`.

- [ ] **Step 4: Tests pass**

```bash
go test -race ./internal/packagemanager/pip -v
go test -race ./internal/packagemanager/uv -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/packagemanager/pip/pip.go internal/packagemanager/uv/uv.go \
        internal/packagemanager/pip/pip_test.go internal/packagemanager/uv/uv_test.go
git commit -m "Phase 1.7: pip/uv prescans forward index flags, strip --no-deps

The dry-run resolver now honors user --index-url / --extra-index-url
/ --find-links / --keyring-provider / etc. so private-index installs
prescan correctly. --no-deps is stripped before the prescan so the
dry-run sees the full transitive set the real install will pull."
```

### Task 1.7.4: uv add / uv install — prescan fallback when lockfile is stale

**Files:**
- Modify: `internal/packagemanager/uv/uv.go:177-260`

- [ ] **Step 1: Failing test**

```go
func TestUvAdd_FallsBackToPrescan_WhenLockfileMissing(t *testing.T) {
	pm := New()
	dir := t.TempDir()
	// No uv.lock present.
	plan, ok := pm.ResolverPreScan([]string{"add", "evil-pkg"})
	require.True(t, ok, "uv add with no lockfile must fall back to prescan")
	require.NotEmpty(t, plan.Args)
}
```

- [ ] **Step 2: Extend ResolverPreScan to fire on add / install**

Today the prescan only triggers when the synthetic verb is `pip-install`. Extend to also fire on `add` and `install` (uv project verbs) — but with a guard: skip if a `uv.lock` exists AND already includes the requested package.

Concrete: in the `installVerbAndRest` switch (around line 96-132), the `add`/`install` arms should call `ResolverPreScan` instead of (or in addition to) emitting the existing-lockfile manifest ref. Then in `ResolverPreScan` itself, accept verb `add` and `install` and synthesize a temporary `requirements.txt` from argv before calling `uv pip compile`.

- [ ] **Step 3: Run**

```bash
go test -race ./internal/packagemanager/uv -v
```

- [ ] **Step 4: Commit**

```bash
git add internal/packagemanager/uv/uv.go internal/packagemanager/uv/uv_test.go
git commit -m "Phase 1.7: uv add/install fall back to prescan when lockfile stale

The existing uv.lock cannot describe transitives of a not-yet-added
package. uv add and uv install now run uv pip compile against a
synthetic requirements input to gate the actual transitive set the
real command will produce."
```

### Task 1.7.5: pylock skips workspace/editable members; pymanifest reads tool.uv/pdm dev-deps

**Files:**
- Modify: `internal/packagemanager/pylock/pylock.go:46-57`
- Modify: `internal/packagemanager/pymanifest/pymanifest.go:57-68`

- [ ] **Step 1: Failing tests**

For pylock:

```go
func TestPylock_SkipsEditableWorkspaceMembers(t *testing.T) {
	body := `lockfile-version = "1.0"
[[package]]
name = "my-workspace-member"
version = "0.1.0"
[package.source]
editable = true

[[package]]
name = "lodash-py"
version = "1.0.0"
`
	got, err := expandUvLock([]byte(body))
	require.NoError(t, err)
	for _, ins := range got {
		require.NotEqual(t, "my-workspace-member", ins.Ref.Name,
			"editable workspace members must not be gated as PyPI packages")
	}
}
```

For pymanifest:

```go
func TestPyManifest_ReadsToolUvDependencies(t *testing.T) {
	body := `[project]
name = "x"
[tool.uv]
dev-dependencies = ["pytest", "ruff>=0.4"]
`
	got, err := Expander{}.Expand(/* ... */)
	require.NoError(t, err)
	require.Contains(t, names(got), "pytest")
	require.Contains(t, names(got), "ruff")
}

func TestPyManifest_ReadsToolPdmDevDependencies(t *testing.T) {
	body := `[project]
name = "x"
[tool.pdm.dev-dependencies]
test = ["pytest", "hypothesis"]
`
	got, err := Expander{}.Expand(/* ... */)
	require.NoError(t, err)
	require.Contains(t, names(got), "pytest")
	require.Contains(t, names(got), "hypothesis")
}
```

- [ ] **Step 2: Extend pylock**

In `internal/packagemanager/pylock/pylock.go`, when iterating `[[package]]` entries, check `source.editable` or `source.virtual` and skip:

```go
for _, p := range doc.Packages {
    if p.Source != nil && (p.Source.Editable || p.Source.Virtual) {
        continue
    }
    // ... existing emit ...
}
```

Update the struct:

```go
type packageEntry struct {
    Name    string
    Version string
    Source  *struct {
        Editable bool `toml:"editable"`
        Virtual  bool `toml:"virtual"`
    } `toml:"source"`
}
```

- [ ] **Step 3: Extend pymanifest**

In `internal/packagemanager/pymanifest/pymanifest.go`, extend the struct:

```go
type pyproject struct {
    Project struct {
        Name                 string              `toml:"name"`
        Dependencies         []string            `toml:"dependencies"`
        OptionalDependencies map[string][]string `toml:"optional-dependencies"`
    } `toml:"project"`
    Tool struct {
        Poetry struct {
            Dependencies    map[string]any `toml:"dependencies"`
            DevDependencies map[string]any `toml:"dev-dependencies"`
        } `toml:"poetry"`
        Uv struct {
            Dependencies     []string `toml:"dependencies"`
            DevDependencies  []string `toml:"dev-dependencies"`
            Workspace        struct {
                Members []string `toml:"members"`
            } `toml:"workspace"`
        } `toml:"uv"`
        Pdm struct {
            DevDependencies map[string][]string `toml:"dev-dependencies"`
        } `toml:"pdm"`
    } `toml:"tool"`
}
```

Then in the expander, emit entries for each.

- [ ] **Step 4: Workspace walk for uv**

When `Tool.Uv.Workspace.Members` is non-empty, glob each pattern under the manifest's directory and recurse into member pyproject.toml files.

- [ ] **Step 5: Run**

```bash
go test -race ./internal/packagemanager/pylock -v
go test -race ./internal/packagemanager/pymanifest -v
```

- [ ] **Step 6: Commit**

```bash
git add internal/packagemanager/pylock/pylock.go \
        internal/packagemanager/pymanifest/pymanifest.go \
        internal/packagemanager/pylock/pylock_test.go \
        internal/packagemanager/pymanifest/pymanifest_test.go
git commit -m "Phase 1.7: pylock skips editable, pymanifest reads uv/pdm dev-deps + workspace

pylock skips entries with source.editable or source.virtual (workspace
members and venv-only entries). pymanifest expands [tool.uv]
dependencies / dev-dependencies / workspace.members and
[tool.pdm.dev-dependencies]."
```

### Task 1.7.6: pymanifest.exactVersionOrEmpty delegates to intel.parsePEP440Version

**Files:**
- Modify: `internal/packagemanager/pymanifest/pymanifest.go:263-274`
- Modify: `internal/intel/pep440.go` (export parsePEP440Version if not already)

- [ ] **Step 1: Export the canonical parser**

In `internal/intel/pep440.go`, find `parsePEP440Version`. If it's unexported, export as `ParsePEP440Version`. Update internal callers.

- [ ] **Step 2: Rewire pymanifest**

In `internal/packagemanager/pymanifest/pymanifest.go:263-274`, replace `exactVersionOrEmpty`:

```go
// exactVersionOrEmpty returns version unchanged if it parses as a single
// PEP 440 version (no range comparators, no wildcards), else "".
// Delegates to intel.ParsePEP440Version so there's one canonical PyPI
// version semantics in the codebase.
func exactVersionOrEmpty(version string) string {
    v := strings.TrimSpace(version)
    if v == "" { return "" }
    // Range/comparator characters disqualify.
    if strings.ContainsAny(v, "^~><=*! ,") { return "" }
    if _, ok := intel.ParsePEP440Version(v); !ok { return "" }
    return v
}
```

- [ ] **Step 3: Tests + run**

```bash
go test -race ./internal/packagemanager/pymanifest -v
go test -race ./internal/intel -v
```

- [ ] **Step 4: Commit**

```bash
git add internal/intel/pep440.go internal/packagemanager/pymanifest/pymanifest.go
git commit -m "Phase 1.7: pymanifest delegates exact-version check to intel.ParsePEP440Version

Replaces a bag-of-bytes heuristic with the canonical PEP 440 parser.
One source of truth for 'is this an exact version'."
```

## Group 1.8: Go / Cargo parser fail-OPENs

### Task 1.8.1: Go — `install` joins `get` in ManifestRefs; no-args `install` triggers preflight

**Files:**
- Modify: `internal/packagemanager/golang/golang.go:94-141`
- Modify: `internal/packagemanager/golang/golang_test.go`

- [ ] **Step 1: Failing tests**

```go
func TestGoInstall_LocalSpec_EmitsModRefs(t *testing.T) {
	pm := New()
	refs := pm.ManifestRefs([]string{"install", "./cmd/foo"})
	require.NotEmpty(t, refs, "go install ./cmd/foo must gate go.mod transitives")
	require.Equal(t, packagemanager.ManifestKindGoMod, refs[0].Kind)
}

func TestGoGet_NoPositionals_EmitsModRefs(t *testing.T) {
	pm := New()
	refs := pm.ManifestRefs([]string{"get", "-u"})
	require.NotEmpty(t, refs, "go get -u must gate go.mod transitives")
}

func TestGoInstall_NoArgs_PreflightSeesGoMod(t *testing.T) {
	pm := New()
	preflight := pm.ProjectPreflight([]string{"install"})
	require.True(t, preflight)
}
```

- [ ] **Step 2: Wire `install` into ManifestRefs**

In `internal/packagemanager/golang/golang.go`, around line 101-119, change the `ManifestRefs` switch:

```go
case "get", "install":
    // Both verbs read the local go.mod when invoked with local-path
    // positionals or no positionals at all.
    positionals := argv.CollectPositionalsWithTable(args[1:], flagsWithValues)
    allLocal := len(positionals) > 0
    for _, p := range positionals {
        if !isLocalGoSpec(p) {
            allLocal = false
            break
        }
    }
    if len(positionals) == 0 || allLocal {
        return goModuleRefs(/* ... */)
    }
```

- [ ] **Step 3: Add `install` to ProjectPreflight**

In the same file's `ProjectPreflight`:

```go
case "build", "test", "vet":
    return true
case "install":
    // `go install` with no positionals compiles current module's commands.
    return len(argv.CollectPositionalsWithTable(args[1:], flagsWithValues)) == 0
case "run":
    // ... existing local-only logic
```

- [ ] **Step 4: Run tests**

```bash
go test -race ./internal/packagemanager/golang -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/packagemanager/golang/golang.go internal/packagemanager/golang/golang_test.go
git commit -m "Phase 1.8: go install / go get -u gate go.mod transitives

Three holes closed: 'go install ./cmd/foo' now emits go.mod refs;
'go get -u' (no positionals) now emits go.mod refs; 'go install'
(no args) now triggers ProjectPreflight."
```

### Task 1.8.2: Cargo — publish / doc / package; registry classifier; workspace members

**Files:**
- Modify: `internal/packagemanager/cargo/cargo.go:108-185`
- Modify: `internal/packagemanager/cargomanifest/cargomanifest.go:71-133`

- [ ] **Step 1: Failing tests**

```go
// cargo/cargo_test.go
func TestCargoPublish_IsParseInstall(t *testing.T) {
	pm := New()
	installs := pm.ParseInstalls([]string{"publish"})
	require.NotEmpty(t, installs, "cargo publish is install-style (fetches + builds)")
}

func TestCargoDoc_TriggersPreflight(t *testing.T) {
	pm := New()
	require.True(t, pm.ProjectPreflight([]string{"doc"}))
}

// cargomanifest/cargomanifest_test.go
func TestCargoManifest_CustomRegistry_IsOpaque(t *testing.T) {
	body := `[dependencies]
foo = { version = "1", registry = "internal" }`
	got, err := Expander{}.Expand(/* with the toml body written to tmp */ )
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.True(t, got[0].OpaqueRemote, "custom registry must mark OpaqueRemote")
}

func TestCargoManifest_WorkspaceMembers_Expanded(t *testing.T) {
	// Root Cargo.toml with [workspace] members; each member has its
	// own [dependencies]. Assert all member deps are emitted.
	// (test details follow existing helpers in cargomanifest_test.go)
}
```

- [ ] **Step 2: Add publish/doc/package to verb switches**

In `internal/packagemanager/cargo/cargo.go`:

```go
case "publish":
    // cargo publish fetches and builds before uploading; gate as install.
    return parseInstall(rest)
```

```go
case "build", "check", "test", "run", "bench", "clippy", "doc", "package":
    return true
```

- [ ] **Step 3: Registry classifier in cargomanifest**

In `internal/packagemanager/cargomanifest/cargomanifest.go`, in the inline-table classifier (around line 118):

```go
if registry, ok := dep["registry"].(string); ok && registry != "" && registry != "crates-io" {
    return classifyOpaque("registry=" + registry)
}
if registryIdx, ok := dep["registry-index"].(string); ok && registryIdx != "" {
    return classifyOpaque("registry-index=" + registryIdx)
}
```

(Place this before the `path` / `git` / `version` arms.)

- [ ] **Step 4: Workspace member walking**

In `cargomanifest.go`, extend the parsing to read `[workspace] members` and `[workspace] exclude`:

```go
type cargoToml struct {
    Workspace *struct {
        Members []string `toml:"members"`
        Exclude []string `toml:"exclude"`
    } `toml:"workspace"`
    // ... existing fields
}
```

In `Expand`, when `Workspace != nil`:

```go
baseDir := filepath.Dir(ref.Path)
for _, pattern := range doc.Workspace.Members {
    matches, _ := filepath.Glob(filepath.Join(baseDir, pattern))
    for _, member := range matches {
        if isExcluded(member, doc.Workspace.Exclude, baseDir) { continue }
        memberManifest := filepath.Join(member, "Cargo.toml")
        if _, err := os.Stat(memberManifest); err != nil { continue }
        sub, _ := Expander{}.Expand(packagemanager.ManifestRef{
            Kind: ManifestKindCargoToml,
            Path: memberManifest,
        })
        out = append(out, sub...)
    }
}
```

- [ ] **Step 5: Run**

```bash
go test -race ./internal/packagemanager/cargo -v
go test -race ./internal/packagemanager/cargomanifest -v
```

- [ ] **Step 6: Commit**

```bash
git add internal/packagemanager/cargo/cargo.go \
        internal/packagemanager/cargomanifest/cargomanifest.go \
        internal/packagemanager/cargo/cargo_test.go \
        internal/packagemanager/cargomanifest/cargomanifest_test.go
git commit -m "Phase 1.8: cargo publish/doc/package gated; custom registries opaque; workspace expanded

cargo publish joins ParseInstalls; doc and package added to
ProjectPreflight. cargomanifest classifies dependencies with a custom
registry as OpaqueRemote (matching cargolock behavior). Workspace
roots now recurse into [workspace] members."
```

### Task 1.8.3: gomod — TrimSuffix only for .mod extension

**Files:**
- Modify: `internal/packagemanager/golang/golang.go:317` (the `.sum` derivation)

- [ ] **Step 1: Failing test**

```go
func TestGoSumDerivation_NonModExtension(t *testing.T) {
	cases := []struct{ modPath, want string }{
		{"go.mod", "go.sum"},
		{"alt.mod", "alt.sum"},
		{"foo.bar", "foo.bar.sum"},        // not .mod — append, don't strip
		{"my.special.mod", "my.special.sum"},
		{"alt", "alt.sum"},                 // no extension — append
	}
	for _, tc := range cases {
		t.Run(tc.modPath, func(t *testing.T) {
			require.Equal(t, tc.want, deriveSumPath(tc.modPath))
		})
	}
}
```

(Adjust function name if the existing one is anonymous; extract a `deriveSumPath` helper.)

- [ ] **Step 2: Fix**

In the relevant location in `golang.go`:

```go
func deriveSumPath(modPath string) string {
    if filepath.Ext(modPath) == ".mod" {
        return strings.TrimSuffix(modPath, ".mod") + ".sum"
    }
    return modPath + ".sum"
}
```

- [ ] **Step 3: Run + commit**

```bash
go test -race ./internal/packagemanager/golang -v
git add internal/packagemanager/golang/golang.go internal/packagemanager/golang/golang_test.go
git commit -m "Phase 1.8: derive go.sum only by trimming .mod extension

For -modfile=foo.bar (non-.mod ext), the derived sum path is
foo.bar.sum (append) rather than foo.sum (strip). Matches Go's
internal behavior."
```

## Group 1.9: Intel — etag-before-parse fix; uniform 0o600

### Task 1.9.1: aikido — parse before etag write

**Files:**
- Modify: `internal/intel/sources/aikido/aikido.go:163-246`
- Modify: `internal/intel/sources/aikido/aikido_test.go`

- [ ] **Step 1: Failing test**

```go
// TestAikido_EtagNotPersistedOnParseFailure asserts that a malformed
// payload doesn't poison the cache via a saved etag — the next
// refresh must re-download.
func TestAikido_EtagNotPersistedOnParseFailure(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "v1")
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	s := New(srv.URL, dir, /* ... */)
	_, err := s.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "malformed payload must produce a parse error")

	// Critical: etag file must NOT exist after the failed parse.
	etagFile := filepath.Join(dir, "aikido", "...etag.path...") // path per source
	_, statErr := os.Stat(etagFile)
	require.True(t, os.IsNotExist(statErr),
		"etag must not be persisted when parse failed; next refresh must re-download")
}
```

- [ ] **Step 2: Reorder fetch → parse → etag**

In `internal/intel/sources/aikido/aikido.go`, find the fetch helper that writes the etag (around line 235-243). Restructure so the etag write happens AFTER `parsePayload` returns success:

```go
func (s *Source) downloadAndParse(ctx context.Context) ([]intel.MalwareReport, string, error) {
    body, upstreamEtag, fromCache, err := s.fetchBody(ctx)
    if err != nil { return nil, "", err }
    if fromCache {
        // We already trusted this etag last time; parse stored body.
        return s.parsePayload(body)
    }
    reports, err := s.parsePayload(body)
    if err != nil {
        return nil, "", errors.With(err, "parse aikido payload")
    }
    // Etag and body persist ONLY after a successful parse.
    if err := s.persistBody(body); err != nil { return reports, "", err }
    if upstreamEtag != "" {
        if err := s.persistEtag(upstreamEtag); err != nil {
            return reports, "", err
        }
    }
    return reports, upstreamEtag, nil
}
```

(The exact code depends on the existing helper shape; the principle is "etag write moves after parse success".)

- [ ] **Step 3: Mirror in pypa, openssf, ghsa**

Apply the same reorder to:
- `internal/intel/sources/pypa/pypa.go:222-225`
- `internal/intel/sources/openssf/openssf.go:281`
- `internal/intel/sources/ghsa/ghsa.go:254`

Each gets the same "parse-then-etag" structure. Add the equivalent regression test per source.

- [ ] **Step 4: Uniform 0o600 for etag files**

In each of the four sources, change every `os.WriteFile(etagPath, ..., 0o644)` to `0o600`. Confirm consistency with `aikido/pypa`'s usage of `fsutil.WriteAtomic` (which already produces 0o600).

- [ ] **Step 5: Run**

```bash
go test -race ./internal/intel/... -v
```

- [ ] **Step 6: Commit**

```bash
git add internal/intel/sources/aikido/ internal/intel/sources/pypa/ \
        internal/intel/sources/openssf/ internal/intel/sources/ghsa/
git commit -m "Phase 1.9: persist intel etags only after a successful parse

Four sources (aikido, pypa, openssf, ghsa) now write the etag AFTER
the body parses cleanly. Previously a transient malformed payload
would persist the etag and then 304-loop on the bad body forever.
Also tightens etag-file mode to 0o600 uniformly."
```

### Task 1.9.2: PEP 440 — multi-digit local-version sort

**Files:**
- Modify: `internal/intel/pep440.go` (the `comparePEP440Local` function)
- Modify: `internal/intel/range_test.go` or `pep440_test.go`

- [ ] **Step 1: Failing test**

```go
func TestComparePEP440Local_MultiDigit(t *testing.T) {
	// 1.0+10 must sort AFTER 1.0+9 — per PEP 440, numeric segments
	// in the local label sort numerically.
	cmp := ComparePEP440("1.0+10", "1.0+9")
	require.Equal(t, 1, cmp, "1.0+10 must be greater than 1.0+9 (numeric segment compare)")
}
```

- [ ] **Step 2: Fix comparePEP440Local**

In `internal/intel/pep440.go`, find `comparePEP440Local`. Replace its `strings.Compare` with segment-by-segment numeric-or-string compare:

```go
func comparePEP440Local(a, b string) int {
    aSeg := splitLocalSegments(a)
    bSeg := splitLocalSegments(b)
    for i := 0; i < len(aSeg) && i < len(bSeg); i++ {
        ai, aIsNum := tryAtoi(aSeg[i])
        bi, bIsNum := tryAtoi(bSeg[i])
        switch {
        case aIsNum && bIsNum:
            if ai != bi { return signOf(ai - bi) }
        case aIsNum && !bIsNum:
            // Per PEP 440: numeric segments outrank alphanumeric.
            return 1
        case !aIsNum && bIsNum:
            return -1
        default:
            if c := strings.Compare(aSeg[i], bSeg[i]); c != 0 { return c }
        }
    }
    return signOf(len(aSeg) - len(bSeg))
}

func splitLocalSegments(s string) []string {
    return strings.FieldsFunc(s, func(r rune) bool { return r == '.' })
}

func tryAtoi(s string) (int, bool) {
    n, err := strconv.Atoi(s)
    return n, err == nil
}

func signOf(d int) int { if d > 0 { return 1 }; if d < 0 { return -1 }; return 0 }
```

- [ ] **Step 3: Run + commit**

```bash
go test -race ./internal/intel -v
git add internal/intel/pep440.go internal/intel/range_test.go
git commit -m "Phase 1.9: PEP 440 local-label numeric segment compare

Multi-digit local labels now sort correctly: 1.0+10 > 1.0+9. Previous
strings.Compare gave the opposite. Carried forward to Phase 3.3 if
the lib swap is approved."
```

---

# Phase 2 — Enabling refactors (no new deps)

Each item is independently mergeable. Together they kill the drift hazards that allowed Phase 1 bugs to exist.

## Group 2.1: pmlist as canonical source for all policy tables

### Task 2.1.1: Move policy tables into pmlist

**Files:**
- Modify: `internal/packagemanager/pmlist/pmlist.go` (add canonical tables)
- Modify: `internal/packagemanager/pmlist/pmlist_test.go`

- [ ] **Step 1: Inventory the duplicated tables**

Grep for the tables that live in multiple places:

```bash
grep -n "pythonDashMTargets\|execPMs\|dangerousVerbs\|NPM_VERBS\|PIP_VERBS\|goFlagsWithValues\|cargoFlagsWithValues\|pythonInterpreters" \
  cmd/veto/main.go internal/hook/claudecode/claudecode.go internal/interposer/veto_interpose.c | head -40
```

Record the current values. They MUST be identical across copies (verify before promoting; if there's already drift, that's the bug 2.1 closes).

- [ ] **Step 2: Define canonical exports in pmlist**

In `internal/packagemanager/pmlist/pmlist.go`, append:

```go
// PythonDashMTargets is the canonical set of `-m` modules whose
// invocation as `python -m <name>` counts as a gateable PM call.
// Source of truth for the Go-side python shim, the Claude Code hook,
// and the C interposer (via generated pm_constants.h).
var PythonDashMTargets = map[string]string{
    "pip":    "pip",
    "pip3":   "pip3",
    "uv":     "uv",
    "pipx":   "pipx",
    "poetry": "poetry",
    "pdm":    "pdm",
}

// PythonDashMTarget classifies python's argv tail. See main.go for the
// pre-Phase-1.3 strict variant; this is the Phase-1.3 robust parser.
func PythonDashMTarget(args []string) (string, bool) {
    const noArgShortFlags = "bBdEhiIOPqsSuvVxX?"
    // ... (copy the Phase 1.3.2 body verbatim) ...
}

// ExecPMs is the canonical set of fetch-and-run PMs (npx, bunx, pnpx,
// uvx, pipx + the bun-create / npm-exec / pnpm-exec verbs).
var ExecPMs = []string{"npx", "bunx", "pnpx", "uvx", "pipx"}

// DangerousVerbs maps PM names to the verbs that install/fetch code.
// Replaces the hand-maintained map in claudecode.go.
var DangerousVerbs = map[string]map[string]bool{
    "npm":   {"install": true, "i": true, "add": true, "ci": true, "update": true, "exec": true},
    "pnpm":  {"install": true, "i": true, "add": true, "update": true, "dlx": true},
    "yarn":  {"install": true, "add": true, "upgrade": true, "dlx": true},
    "bun":   {"install": true, "add": true, "update": true, "x": true, "create": true},
    "pip":   {"install": true},
    "pip3":  {"install": true},
    "uv":    {"add": true, "sync": true, "install": true, "tool": true, "run": true},
    "pipx":  {"install": true, "run": true, "inject": true, "upgrade": true},
    "poetry":{"add": true, "install": true, "update": true},
    "pdm":   {"add": true, "install": true, "update": true, "sync": true},
    "cargo": {"add": true, "install": true, "update": true, "fetch": true, "publish": true},
    "go":    {"get": true, "install": true},
}

// GoFlagsWithValues, CargoFlagsWithValues: flag tables that take values.
var GoFlagsWithValues = map[string]bool{
    "-mod": true, "-modfile": true, "-tags": true, "-ldflags": true, /* ... */
}

var CargoFlagsWithValues = map[string]bool{
    "--manifest-path": true, "--target": true, "--features": true, /* ... */
}

// PythonInterpreters is the set of basenames that count as a python
// interpreter (and so are eligible for `-m <pm>` rewriting).
var PythonInterpreters = []string{"python", "python3", "python2"}
```

(Use the values verified in Step 1.)

- [ ] **Step 3: Add tests asserting subset invariants**

In `internal/packagemanager/pmlist/pmlist_test.go`:

```go
func TestDangerousVerbs_OnlyKnownPMs(t *testing.T) {
    known := make(map[string]bool)
    for _, n := range Shimmed { known[n] = true }
    for pm := range DangerousVerbs {
        require.True(t, known[pm], "DangerousVerbs references unknown PM %q", pm)
    }
}

func TestPythonDashMTargets_AllInWrapped(t *testing.T) {
    for _, target := range PythonDashMTargets {
        require.True(t, IsWrapped(target), "PythonDashMTarget %q must be in Wrapped", target)
    }
}
```

- [ ] **Step 4: Run**

```bash
go test -race ./internal/packagemanager/pmlist -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/packagemanager/pmlist/pmlist.go internal/packagemanager/pmlist/pmlist_test.go
git commit -m "Phase 2.1: promote policy tables to pmlist (canonical source)

PythonDashMTargets, ExecPMs, DangerousVerbs, GoFlagsWithValues,
CargoFlagsWithValues, PythonInterpreters now live in pmlist with
invariant tests. Hand-maintained mirrors in main.go, claudecode.go,
and veto_interpose.c will be deleted in 2.1.2 (Go callers) and 2.1.3
(C interposer)."
```

### Task 2.1.2: Delete the Go-side mirrors; consume pmlist from main.go and claudecode.go

**Files:**
- Modify: `cmd/veto/main.go:143-178` (delete `pythonDashMTargets` + `pythonDashMTarget`; call pmlist)
- Modify: `internal/hook/claudecode/claudecode.go` (delete local tables; import from pmlist)

- [ ] **Step 1: In main.go, replace the local table and parser**

Delete lines 143-178 (the `pythonDashMEnvOriginal` constant stays; the table and the parser go). In their place:

```go
const pythonDashMEnvOriginal = "VETO_PYTHON_M_ORIGINAL"

// pythonDashMTarget is preserved as a thin wrapper for call-site
// readability. The implementation lives in pmlist.
func pythonDashMTarget(args []string) (string, bool) {
    return pmlist.PythonDashMTarget(args)
}
```

Add the import for `pmlist`.

- [ ] **Step 2: In claudecode.go, delete the local copies**

Find every reference to `dangerousVerbs`, `execPMs`, `goFlagsWithValues`, `cargoFlagsWithValues`, `pythonDashMTargets`, `pythonInterpreters`. Replace with `pmlist.DangerousVerbs`, `pmlist.ExecPMs`, etc. Add `import "github.com/brynbellomy/veto/internal/packagemanager/pmlist"`.

Delete the local map/slice definitions.

- [ ] **Step 3: Run all tests**

```bash
make test
```

Expected: PASS. The values are identical (Step 2.1.1 verified this), so behavior is unchanged.

- [ ] **Step 4: Commit**

```bash
git add cmd/veto/main.go internal/hook/claudecode/claudecode.go
git commit -m "Phase 2.1: Go callers consume pmlist for all policy tables

main.go and claudecode.go no longer carry hand-maintained copies of
DangerousVerbs / ExecPMs / PythonDashMTargets / GoFlagsWithValues /
CargoFlagsWithValues / PythonInterpreters. They import pmlist."
```

### Task 2.1.3: Generate pm_constants.h alongside pm_names.h

**Files:**
- Modify: `internal/interposer/cmd/genpmlist/main.go`
- Modify: `internal/interposer/gen/gen.go` (the `go:generate` directive)
- Create: `internal/interposer/pm_constants.h` (generated)
- Modify: `internal/interposer/veto_interpose.c` (include + delete duplicates)
- Modify: `internal/interposer/gen/pmnames_consistency_test.go`

- [ ] **Step 1: Extend genpmlist to emit pm_constants.h**

In `internal/interposer/cmd/genpmlist/main.go`, after the existing `pm_names.h` emission, add another emit block:

```go
// Emit pm_constants.h with verb tables, exec PMs, python-m targets,
// python interpreters, and flag-with-values lists.
constPath := filepath.Join(filepath.Dir(*outputPath), "pm_constants.h")
var buf bytes.Buffer
fmt.Fprintf(&buf, "/* Generated by genpmlist. DO NOT EDIT. */\n#pragma once\n\n")
fmt.Fprintf(&buf, "static const char *const VETO_EXEC_PMS[] = {\n")
for _, name := range pmlist.ExecPMs {
    fmt.Fprintf(&buf, "    %q,\n", name)
}
fmt.Fprintf(&buf, "    NULL\n};\n\n")

fmt.Fprintf(&buf, "static const char *const VETO_PYTHON_DASH_M_TARGETS[] = {\n")
keys := make([]string, 0, len(pmlist.PythonDashMTargets))
for k := range pmlist.PythonDashMTargets { keys = append(keys, k) }
sort.Strings(keys)
for _, k := range keys {
    fmt.Fprintf(&buf, "    %q,\n", k)
}
fmt.Fprintf(&buf, "    NULL\n};\n\n")

fmt.Fprintf(&buf, "static const char *const VETO_PYTHON_INTERPRETERS[] = {\n")
for _, n := range pmlist.PythonInterpreters {
    fmt.Fprintf(&buf, "    %q,\n", n)
}
fmt.Fprintf(&buf, "    NULL\n};\n\n")

// Per-PM verb tables.
fmt.Fprintf(&buf, "/* PM verbs (a struct table per PM). */\n")
pms := []string{}
for pm := range pmlist.DangerousVerbs { pms = append(pms, pm) }
sort.Strings(pms)
for _, pm := range pms {
    fmt.Fprintf(&buf, "static const char *const VETO_VERBS_%s[] = {\n", strings.ToUpper(pm))
    verbs := []string{}
    for v := range pmlist.DangerousVerbs[pm] { verbs = append(verbs, v) }
    sort.Strings(verbs)
    for _, v := range verbs {
        fmt.Fprintf(&buf, "    %q,\n", v)
    }
    fmt.Fprintf(&buf, "    NULL\n};\n\n")
}

if err := os.WriteFile(constPath, buf.Bytes(), 0o644); err != nil {
    log.Fatal(err)
}
```

- [ ] **Step 2: Run the generator**

```bash
go generate ./internal/interposer/...
```

Expected: `internal/interposer/pm_constants.h` exists and contains the tables.

- [ ] **Step 3: Update the consistency test**

In `internal/interposer/gen/pmnames_consistency_test.go`, extend the test to assert `pm_constants.h` matches the regenerated output:

```go
func TestPMConstantsHeaderInSync(t *testing.T) {
    var stdout bytes.Buffer
    cmd := exec.Command("go", "run", "../cmd/genpmlist", "--check")
    cmd.Stdout = &stdout
    err := cmd.Run()
    require.NoError(t, err, "pm_constants.h is stale; run `go generate ./internal/interposer/...`")
}
```

(Alternatively: regenerate to a temp dir and diff. Use whatever pattern the existing pm_names.h test uses.)

- [ ] **Step 4: Update veto_interpose.c**

In `internal/interposer/veto_interpose.c`, after the existing `#include "pm_names.h"`, add `#include "pm_constants.h"`.

Find every hand-maintained copy of `PYTHON_DASH_M_TARGETS`, `EXEC_PMS`, `NPM_VERBS`, `PIP_VERBS`, etc. — replace each with the generated `VETO_*` array.

- [ ] **Step 5: Rebuild**

```bash
go generate ./internal/interposer/...
make interposer
make test
```

Expected: clean build, all tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/interposer/cmd/genpmlist/main.go \
        internal/interposer/gen/pmnames_consistency_test.go \
        internal/interposer/pm_constants.h \
        internal/interposer/veto_interpose.c
git commit -m "Phase 2.1: generate pm_constants.h from pmlist

Verb tables, ExecPMs, PythonDashMTargets, PythonInterpreters now
flow Go → C via genpmlist into pm_constants.h. Hand-maintained
mirrors in veto_interpose.c are gone. The consistency test catches
any drift in CI."
```

## Group 2.2: Intel sources shared scaffold

### Task 2.2.1: Build common Fetcher

**Files:**
- Create: `internal/intel/sources/common/fetcher.go`
- Create: `internal/intel/sources/common/atomicwrite.go` (moved from `sources/internal/fsutil/`)
- Create: `internal/intel/sources/common/stream.go`
- Create: `internal/intel/sources/common/dirperm.go`
- Create: `internal/intel/sources/common/fetcher_test.go`

- [ ] **Step 1: Move atomicwrite up**

```bash
git mv internal/intel/sources/internal/fsutil/atomicwrite.go \
       internal/intel/sources/common/atomicwrite.go
```

Update the package name from `fsutil` to `common`. Fix imports in `aikido.go` and `pypa.go` accordingly.

- [ ] **Step 2: Implement common.Fetcher**

Create `internal/intel/sources/common/fetcher.go`:

```go
// Package common provides shared HTTP-fetch, etag-conditional GET, body-size
// capping, and parse-then-persist machinery used by every intel source.
// The contract: callers provide a URL + decode callback; the Fetcher
// guarantees the etag is persisted ONLY after decode returns nil.
package common

import (
    "context"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "time"

    "github.com/brynbellomy/go-utils/errors"
    "github.com/rs/zerolog"
)

// Fetcher centralizes the fetch-cache-parse pipeline.
type Fetcher struct {
    URL      string
    CacheDir string
    MaxBytes int64
    Client   *http.Client
    Logger   zerolog.Logger
}

// Result describes a successful fetch.
type Result struct {
    Body      []byte
    Etag      string
    FromCache bool
}

// Fetch performs an etag-conditional GET, downloads up to MaxBytes,
// and returns the body. Etag persistence happens via PersistOnDecodeSuccess.
func (f Fetcher) Fetch(ctx context.Context) (Result, error) {
    cachedEtag := f.readEtag()
    cachedBody, hasCachedBody := f.readBody()

    req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
    if err != nil { return Result{}, err }
    if cachedEtag != "" {
        req.Header.Set("If-None-Match", cachedEtag)
    }
    resp, err := f.Client.Do(req)
    if err != nil {
        if hasCachedBody {
            f.Logger.Warn().Err(err).Msg("network error; falling back to cached body")
            return Result{Body: cachedBody, Etag: cachedEtag, FromCache: true}, nil
        }
        return Result{}, errors.With(err, "fetch", "url", f.URL)
    }
    defer resp.Body.Close()
    if resp.StatusCode == http.StatusNotModified && hasCachedBody {
        return Result{Body: cachedBody, Etag: cachedEtag, FromCache: true}, nil
    }
    if resp.StatusCode != http.StatusOK {
        return Result{}, errors.New("upstream returned status", "status", resp.StatusCode)
    }
    body, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBytes+1))
    if err != nil { return Result{}, err }
    if int64(len(body)) > f.MaxBytes {
        return Result{}, &OversizeError{URL: f.URL, Limit: f.MaxBytes}
    }
    return Result{Body: body, Etag: resp.Header.Get("ETag"), FromCache: false}, nil
}

// PersistOnDecodeSuccess writes the body and etag to disk ONLY after
// the caller has confirmed a successful decode. This is the invariant
// the README promises and which 4-of-5 sources were violating.
func (f Fetcher) PersistOnDecodeSuccess(body []byte, etag string) error {
    if err := EnsurePrivateDir(f.CacheDir); err != nil { return err }
    if err := WriteAtomic(filepath.Join(f.CacheDir, "body"), body, 0o600); err != nil {
        return errors.With(err, "persist body")
    }
    if etag != "" {
        if err := WriteAtomic(filepath.Join(f.CacheDir, "etag"), []byte(etag), 0o600); err != nil {
            return errors.With(err, "persist etag")
        }
    }
    return nil
}

func (f Fetcher) readEtag() string {
    data, err := os.ReadFile(filepath.Join(f.CacheDir, "etag"))
    if err != nil { return "" }
    return string(data)
}

func (f Fetcher) readBody() ([]byte, bool) {
    data, err := os.ReadFile(filepath.Join(f.CacheDir, "body"))
    if err != nil { return nil, false }
    return data, true
}

// OversizeError is returned when a fetched body exceeds MaxBytes.
type OversizeError struct {
    URL   string
    Limit int64
}

func (e *OversizeError) Error() string {
    return "upstream body exceeded per-source size cap"
}

func (e *OversizeError) Unwrap() error { return nil }
```

Create `internal/intel/sources/common/dirperm.go`:

```go
package common

import (
    "os"

    "github.com/brynbellomy/go-utils/errors"
)

// EnsurePrivateDir creates dir with 0o700 if absent. Race-tolerant:
// if dir exists with looser mode, retighten via Chmod.
func EnsurePrivateDir(dir string) error {
    if err := os.MkdirAll(dir, 0o700); err != nil {
        return errors.With(err, "mkdir", "dir", dir)
    }
    return os.Chmod(dir, 0o700)
}
```

Create `internal/intel/sources/common/stream.go` (used by tarball-streaming sources):

```go
package common

import (
    "io"
    "os"

    "github.com/brynbellomy/go-utils/errors"
)

// StreamAtomic writes body (up to maxBytes) to dst atomically.
// Returns OversizeError when the body exceeds maxBytes.
func StreamAtomic(dst string, body io.Reader, maxBytes int64) (int64, error) {
    if err := EnsurePrivateDir(filepathDir(dst)); err != nil { return 0, err }
    tmp, err := os.CreateTemp(filepathDir(dst), ".tmp-*")
    if err != nil { return 0, err }
    n, err := io.Copy(tmp, io.LimitReader(body, maxBytes+1))
    if err != nil {
        tmp.Close()
        os.Remove(tmp.Name())
        return 0, err
    }
    if n > maxBytes {
        tmp.Close()
        os.Remove(tmp.Name())
        return n, &OversizeError{Limit: maxBytes}
    }
    if err := tmp.Sync(); err != nil { tmp.Close(); os.Remove(tmp.Name()); return 0, err }
    if err := tmp.Close(); err != nil { os.Remove(tmp.Name()); return 0, err }
    if err := os.Chmod(tmp.Name(), 0o600); err != nil { os.Remove(tmp.Name()); return 0, err }
    if err := os.Rename(tmp.Name(), dst); err != nil { os.Remove(tmp.Name()); return 0, err }
    return n, nil
}

func filepathDir(p string) string { return filepath.Dir(p) }
```

- [ ] **Step 3: Write tests for Fetcher**

`internal/intel/sources/common/fetcher_test.go`:

```go
func TestFetcher_EtagPersistOnlyOnSuccessfulDecode(t *testing.T) {
    dir := t.TempDir()
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("ETag", "v1")
        _, _ = w.Write([]byte("body"))
    }))
    defer srv.Close()

    f := Fetcher{URL: srv.URL, CacheDir: dir, MaxBytes: 1 << 20, Client: srv.Client()}
    res, err := f.Fetch(context.Background())
    require.NoError(t, err)

    // Caller's decode "fails" — don't call PersistOnDecodeSuccess.
    // Now assert the etag file does NOT exist.
    _, err = os.Stat(filepath.Join(dir, "etag"))
    require.True(t, os.IsNotExist(err), "etag must not be persisted before PersistOnDecodeSuccess")

    // Call PersistOnDecodeSuccess and verify both files now exist.
    require.NoError(t, f.PersistOnDecodeSuccess(res.Body, res.Etag))
    _, err = os.Stat(filepath.Join(dir, "etag"))
    require.NoError(t, err)
}
```

- [ ] **Step 4: Run + commit**

```bash
go test -race ./internal/intel/sources/common -v
git add internal/intel/sources/common/ internal/intel/sources/aikido/aikido.go internal/intel/sources/pypa/pypa.go
git commit -m "Phase 2.2: introduce internal/intel/sources/common scaffold

Fetcher (etag-conditional GET, size cap, parse-then-persist),
WriteAtomic (relocated from sources/internal/fsutil), StreamAtomic,
EnsurePrivateDir. Five sources will reduce to URL config + decode
callback in subsequent tasks."
```

### Task 2.2.2: Migrate aikido / osv / openssf / ghsa / pypa to common

**Files:**
- Modify: each source's main file

- [ ] **Step 1: Migrate aikido**

In `internal/intel/sources/aikido/aikido.go`:

```go
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
    if !s.supports(eco) { return nil, ErrUnsupportedEcosystem }

    f := common.Fetcher{
        URL:      s.urlFor(eco),
        CacheDir: filepath.Join(s.cacheDir, "aikido", string(eco)),
        MaxBytes: 256 << 20,
        Client:   s.client,
        Logger:   s.logger,
    }
    res, err := f.Fetch(ctx)
    if err != nil { return nil, err }
    reports, err := s.decode(res.Body)
    if err != nil { return nil, errors.With(err, "decode aikido", "ecosystem", eco) }
    if !res.FromCache {
        if err := f.PersistOnDecodeSuccess(res.Body, res.Etag); err != nil {
            // Persist failure is non-fatal — we already have the parsed
            // reports — but log loudly.
            s.logger.Error().Err(err).Msg("persist aikido cache")
        }
    }
    return reports, nil
}
```

Delete every hand-rolled fetch/cache helper from `aikido.go` that the Fetcher now subsumes.

- [ ] **Step 2: Repeat for osv, openssf, ghsa, pypa**

Each becomes URL config + `decode([]byte) ([]intel.MalwareReport, error)` callback. The decode callback retains all source-specific logic (zip unpacking for OSV, tarball walking for openssf/ghsa/pypa, JSON shape for aikido).

For streaming sources (openssf/ghsa/pypa — tarballs), use `common.StreamAtomic` + a separate parse step rather than `common.Fetcher` (which loads into memory).

- [ ] **Step 3: Delete the duplicates**

For each source file, delete:
- Local `fetchWithCacheBounded` / `downloadIfChanged` / `headEtag` / `loadGob` / `readGobFile` / `writeGob`
- Local `os.MkdirAll(0o700) + Chmod(0o700)` patterns
- Any local atomic-write helpers
- Local size-cap constants (they live as Fetcher.MaxBytes per source)

- [ ] **Step 4: Run**

```bash
go test -race ./internal/intel/... -v
```

Expected: PASS. The behavioral contract is unchanged; only the structure is.

- [ ] **Step 5: Commit**

```bash
git add internal/intel/sources/
git commit -m "Phase 2.2: migrate all five intel sources to common.Fetcher

Each source is now URL config + decode callback. ~600 lines of
fetch-cache-parse boilerplate deleted; the parse-then-persist
invariant is enforced in one place. The Phase 1.9 etag-before-parse
bug class can no longer recur — sources don't manage etag persistence
directly."
```

### Task 2.2.3: SupportedEcosystems API; delete ErrUnsupportedEcosystem

**Files:**
- Modify: `internal/intel/intel.go`
- Modify: `internal/intel/store.go`
- Modify: each source

- [ ] **Step 1: Add the method to the Source interface**

In `internal/intel/intel.go`:

```go
type Source interface {
    ID() string
    SupportedEcosystems() []Ecosystem
    Fetch(ctx context.Context, eco Ecosystem) ([]MalwareReport, error)
}
```

Delete the `ErrUnsupportedEcosystem` sentinel.

- [ ] **Step 2: Implement on each source**

Each source's `SupportedEcosystems()` returns its supported list (aikido: npm + pypi; pypa: pypi; osv: all four; openssf: all four; ghsa: all four).

- [ ] **Step 3: Update store.fetchAll to only spawn supported cross-product**

In `internal/intel/store.go`, find `fetchAll`. Replace the unconditional cross-product loop:

```go
for _, src := range s.sources {
    for _, eco := range src.SupportedEcosystems() {
        // spawn goroutine for (src, eco)
    }
}
```

Delete the `ErrUnsupportedEcosystem` handling in the channel-receive loop.

- [ ] **Step 4: Tests + commit**

```bash
go test -race ./internal/intel/... -v
git add internal/intel/ 
git commit -m "Phase 2.2: SupportedEcosystems on Source; delete ErrUnsupportedEcosystem

fetchAll only spawns goroutines for the actual (source, ecosystem)
cross-product. Eliminates ~30% of goroutines that previously did no
work and returned a sentinel error."
```

## Group 2.3: Shared shell-rc helper

### Task 2.3.1: Extract internal/shellrc package

**Files:**
- Create: `internal/shellrc/targets.go`
- Create: `internal/shellrc/block.go`
- Create: `internal/shellrc/block_test.go`
- Modify: `cmd/veto/install_shell.go` (consume)
- Modify: `cmd/veto/install_preload.go` (consume)

- [ ] **Step 1: Inventory the duplication**

```bash
grep -n "defaultShellIntegrationTargets\|autoDetectShellRC\|shellKindForRC\|upsertManagedBlock\|removeShellRCBlock" \
  cmd/veto/install_shell.go cmd/veto/install_preload.go
```

Confirm both files have their own copies.

- [ ] **Step 2: Define the public API**

Create `internal/shellrc/targets.go`:

```go
// Package shellrc centralizes shell-rc-file detection, marker-block
// upsert/remove, and atomic file writes. Both install_shell (Layer 2)
// and install_preload (Layer 3) consume this so they target the same
// set of rc files and use the same marker discipline.
package shellrc

import (
    "os"
    "path/filepath"
    "runtime"
    "strings"
)

type ShellKind int

const (
    ShellKindBash ShellKind = iota + 1
    ShellKindZsh
    ShellKindFish
    ShellKindProfile
)

type Target struct {
    Path string
    Kind ShellKind
}

// TargetsForUser returns the rc-file targets veto should write to,
// based on $SHELL and the user's home dir. Includes bash fallbacks
// when bash is detected on the system even if $SHELL is zsh.
func TargetsForUser(shell, home string) []Target {
    if home == "" {
        if h, err := os.UserHomeDir(); err == nil { home = h }
    }
    out := []Target{}
    switch detectShellFromEnv(shell) {
    case ShellKindZsh:
        out = append(out, Target{filepath.Join(home, ".zshrc"), ShellKindZsh})
        if BashDetected() {
            out = append(out, Target{filepath.Join(home, ".bashrc"), ShellKindBash})
            out = append(out, Target{filepath.Join(home, ".bash_profile"), ShellKindBash})
        }
        out = append(out, Target{filepath.Join(home, ".profile"), ShellKindProfile})
    case ShellKindFish:
        out = append(out, Target{filepath.Join(home, ".config", "fish", "config.fish"), ShellKindFish})
    default: // bash or unknown
        out = append(out, Target{filepath.Join(home, ".bashrc"), ShellKindBash})
        out = append(out, Target{filepath.Join(home, ".bash_profile"), ShellKindBash})
        out = append(out, Target{filepath.Join(home, ".profile"), ShellKindProfile})
    }
    return out
}

func detectShellFromEnv(shell string) ShellKind {
    base := filepath.Base(shell)
    switch base {
    case "zsh": return ShellKindZsh
    case "fish": return ShellKindFish
    case "bash": return ShellKindBash
    }
    return 0
}

// BashDetected reports whether a bash interpreter exists on $PATH.
func BashDetected() bool {
    _, err := os.Stat("/bin/bash")
    if err == nil { return true }
    _, err = os.Stat("/usr/local/bin/bash")
    return err == nil
}
```

Create `internal/shellrc/block.go`:

```go
package shellrc

import (
    "io"
    "os"
    "path/filepath"
    "strings"

    "github.com/brynbellomy/go-utils/errors"
)

type MarkerPair struct {
    Begin string
    End   string
}

// UpsertManagedBlock writes body between markers in path, atomically.
// If markers already exist, the body between them is replaced.
// Includes fsync of tmpfile and parent dir.
func UpsertManagedBlock(path string, markers MarkerPair, body string) error {
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { return err }
    existing, _ := os.ReadFile(path)
    updated := spliceMarkedBlock(string(existing), markers, body)
    return writeAtomic(path, []byte(updated), 0o644)
}

// RemoveManagedBlock removes the marked block from path (idempotent).
func RemoveManagedBlock(path string, markers MarkerPair) error {
    existing, err := os.ReadFile(path)
    if err != nil {
        if os.IsNotExist(err) { return nil }
        return err
    }
    updated := spliceMarkedBlock(string(existing), markers, "")
    if updated == string(existing) { return nil }
    return writeAtomic(path, []byte(updated), 0o644)
}

func spliceMarkedBlock(content string, markers MarkerPair, body string) string {
    begin := strings.Index(content, markers.Begin)
    end := strings.Index(content, markers.End)
    if begin == -1 || end == -1 || end < begin {
        // No prior block — append.
        if body == "" { return content }
        sep := "\n"
        if strings.HasSuffix(content, "\n") || content == "" { sep = "" }
        return content + sep + markers.Begin + "\n" + body + "\n" + markers.End + "\n"
    }
    // Replace the existing block (or remove if body is empty).
    before := content[:begin]
    after := content[end+len(markers.End):]
    if body == "" {
        // Remove a single leading newline from `after` if present, to
        // avoid blank line accumulation.
        return strings.TrimRight(before, "\n") + strings.TrimLeft(after, "\n")
    }
    return before + markers.Begin + "\n" + body + "\n" + markers.End + after
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
    tmp, err := os.CreateTemp(filepath.Dir(path), ".veto-shellrc-*")
    if err != nil { return err }
    if _, err := io.Copy(tmp, strings.NewReader(string(data))); err != nil {
        tmp.Close(); os.Remove(tmp.Name()); return err
    }
    if err := tmp.Sync(); err != nil { tmp.Close(); os.Remove(tmp.Name()); return err }
    if err := tmp.Close(); err != nil { os.Remove(tmp.Name()); return err }
    if err := os.Chmod(tmp.Name(), mode); err != nil { os.Remove(tmp.Name()); return err }
    if err := os.Rename(tmp.Name(), path); err != nil { os.Remove(tmp.Name()); return err }
    if d, err := os.Open(filepath.Dir(path)); err == nil { _ = d.Sync(); _ = d.Close() }
    return nil
}
```

- [ ] **Step 3: Tests**

In `internal/shellrc/block_test.go`, cover: fresh file with no prior block, replace existing block, idempotent re-upsert, remove on absent, atomic write survives intermediate-state inspection.

- [ ] **Step 4: Migrate install_shell.go and install_preload.go**

Both files now call `shellrc.TargetsForUser($SHELL, home)` and `shellrc.UpsertManagedBlock(path, markers, body)`. Delete their local copies of `defaultShellIntegrationTargets`, `autoDetectShellRC`, `shellKindForRC`, `upsertManagedBlock`, `removeShellRCBlock`.

`install_preload.go`'s `autoDetectShellRC` becomes a thin wrapper that returns `TargetsForUser(...)[0].Path` for backwards-compat — OR (preferred) update the install-preload flow to fan out across ALL targets (closing the bash-login coverage gap the L3 reviewer flagged).

- [ ] **Step 5: Run + commit**

```bash
make test
git add internal/shellrc/ cmd/veto/install_shell.go cmd/veto/install_preload.go
git commit -m "Phase 2.3: shared internal/shellrc; install_preload fans out across rc files

Both installers now consume the same shellrc.TargetsForUser, so Layer 3
writes to the same set of rc files as Layer 2 (closing the
bash-login coverage gap). Marker upsert/remove and atomic-write
helpers consolidated."
```

## Group 2.4: JS Manager factory

### Task 2.4.1: Build jspm.New(Spec)

**Files:**
- Create: `internal/packagemanager/jspm/jspm.go`
- Create: `internal/packagemanager/jspm/jspm_test.go`

- [ ] **Step 1: Define the Spec**

```go
// Package jspm constructs JavaScript package-manager parsers from a
// declarative Spec. npm, pnpm, yarn, and bun each become a one-line
// var Manager = jspm.New(Spec{...}).
package jspm

import (
    "github.com/brynbellomy/veto/internal/packagemanager"
    "github.com/brynbellomy/veto/internal/packagemanager/exec"
    "github.com/brynbellomy/veto/internal/packagemanager/jsspec"
)

type Spec struct {
    Binary               string                   // e.g. "npm"
    Ecosystem            packagemanager.Ecosystem
    InstallVerbs         map[string]bool
    FlagsWithValues      map[string]bool
    AlwaysReadsManifest  bool
    Lockfiles            []packagemanager.ManifestKind  // PM-specific list
    BareInstallSupported bool
    // ExecVerb wires up dlx/x/exec/create. When empty, no exec verb.
    ExecVerb     string
    ExecSpecFlags  map[string]bool
    ExecValueFlags map[string]bool
}

type Manager struct {
    spec    Spec
    execMgr *exec.Manager
}

func New(spec Spec) *Manager {
    m := &Manager{spec: spec}
    if spec.ExecVerb != "" {
        m.execMgr = exec.New(exec.Options{
            Verbs:      []string{spec.ExecVerb},
            SpecFlags:  spec.ExecSpecFlags,
            ValueFlags: spec.ExecValueFlags,
        })
    }
    return m
}

func (m *Manager) Name() string                    { return m.spec.Binary }
func (m *Manager) Ecosystem() packagemanager.Ecosystem { return m.spec.Ecosystem }

func (m *Manager) ParseInstalls(args []string) []packagemanager.Install {
    if len(args) == 0 { return nil }
    if m.execMgr != nil && args[0] == m.spec.ExecVerb {
        return m.execMgr.ParseInstalls(args)
    }
    return jsspec.ParseInstallArgs(args, m.spec.InstallVerbs, m.spec.FlagsWithValues, m.spec.BareInstallSupported)
}

func (m *Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
    refs := []packagemanager.ManifestRef{
        {Kind: packagemanager.ManifestKindPackageJSON, Path: "package.json"},
    }
    for _, k := range m.spec.Lockfiles {
        refs = append(refs, packagemanager.ManifestRef{Kind: k, Path: defaultPathFor(k)})
    }
    return refs
}

func defaultPathFor(k packagemanager.ManifestKind) string {
    switch k {
    case packagemanager.ManifestKindPackageLockJSON: return "package-lock.json"
    case packagemanager.ManifestKindNpmShrinkwrap:   return "npm-shrinkwrap.json"
    case packagemanager.ManifestKindYarnLock:        return "yarn.lock"
    case packagemanager.ManifestKindPnpmLock:        return "pnpm-lock.yaml"
    case packagemanager.ManifestKindBunLock:         return "bun.lock"
    }
    return ""
}
```

- [ ] **Step 2: Convert npm to jspm**

In `internal/packagemanager/npm/npm.go`, replace the whole file body with:

```go
package npm

import (
    "github.com/brynbellomy/veto/internal/packagemanager"
    "github.com/brynbellomy/veto/internal/packagemanager/jspm"
)

var Manager = jspm.New(jspm.Spec{
    Binary:    "npm",
    Ecosystem: packagemanager.EcosystemNPM,
    InstallVerbs: map[string]bool{
        "install": true, "i": true, "add": true, "ci": true, "update": true,
    },
    FlagsWithValues: map[string]bool{
        /* copy current set */
    },
    AlwaysReadsManifest:  true,
    Lockfiles:            []packagemanager.ManifestKind{packagemanager.ManifestKindPackageLockJSON, packagemanager.ManifestKindNpmShrinkwrap},
    BareInstallSupported: true,
    ExecVerb:             "exec",
    ExecSpecFlags:        map[string]bool{"--package": true, "-p": true},
    ExecValueFlags:       map[string]bool{"--package": true, "-p": true},
})
```

Delete `parseExec` (now handled by `execMgr`). Delete the `Manager` struct.

Some callers may reference functions like `Manager.ResolverPreScan` — keep those as methods on the jspm.Manager (extend `jspm.Spec` with optional `ResolverPreScan func(args []string) (resolverPlan, bool)` if needed; otherwise add a method override on the npm package).

- [ ] **Step 3: Convert pnpm, yarn, bun**

Same shape. Each gets its own `Spec`. The dlx/x/create verbs from 1.6.2 now flow through `Spec.ExecVerb`.

- [ ] **Step 4: Run all PM tests**

```bash
go test -race ./internal/packagemanager/... -v
```

Expected: PASS. The existing test files for npm/pnpm/yarn/bun continue to pass against the new jspm-driven manager.

- [ ] **Step 5: Commit**

```bash
git add internal/packagemanager/jspm/ \
        internal/packagemanager/{npm,pnpm,yarn,bun}/
git commit -m "Phase 2.4: jspm.New(Spec) factory; npm/pnpm/yarn/bun collapse to ~10 lines

Four near-identical Manager structs replaced by declarative Specs.
Per-PM Lockfiles now honored (no more emitting all four lockfiles
speculatively). npm.parseExec deleted — the exec verb flows through
the same exec.Manager that handles npx/bunx/pnpx/uvx."
```

### Task 2.4.2: Unify split helpers between jsspec and jslock

**Files:**
- Modify: `internal/packagemanager/jsspec/jsspec.go` (export `RawSplitNameVersion`)
- Modify: `internal/packagemanager/jslock/jslock.go` (delete `splitPnpmKeyBoundary`, call jsspec)

- [ ] **Step 1: Export and delete**

In `jsspec.go`, rename `rawSplitNameVersion` → `RawSplitNameVersion` and export it.

In `jslock.go`, find `splitPnpmKeyBoundary` (around line 287) and replace its body with `return jsspec.RawSplitNameVersion(key)`. Eventually delete `splitPnpmKeyBoundary` entirely and inline the call.

Similarly, find the scoped-name branch in `nameFromYarnHeader` (around line 406) — use the same helper.

- [ ] **Step 2: Run + commit**

```bash
make test
git add internal/packagemanager/jsspec/ internal/packagemanager/jslock/
git commit -m "Phase 2.4: unify name-version split between jsspec and jslock

One canonical splitter (jsspec.RawSplitNameVersion) is consumed by
every caller. Eliminates the three-copy drift hazard."
```

## Group 2.5: Native PM verb tables

### Task 2.5.1: argv.FirstFlagValue + shared iterator

**Files:**
- Modify: `internal/packagemanager/argv/argv.go`
- Modify: `internal/packagemanager/{golang,cargo}/*.go` (delete local `firstFlagValue`)

- [ ] **Step 1: Add FirstFlagValue**

In `internal/packagemanager/argv/argv.go`:

```go
// FirstFlagValue returns the first value for the named flag, supporting
// both --flag value and --flag=value forms. Returns ("", false) if absent.
func FirstFlagValue(args []string, flag string) (string, bool) {
    for i, a := range args {
        if a == flag {
            if i+1 < len(args) { return args[i+1], true }
            return "", false
        }
        if strings.HasPrefix(a, flag+"=") {
            return a[len(flag)+1:], true
        }
    }
    return "", false
}
```

- [ ] **Step 2: Delete local copies**

In `golang.go` and `cargo.go`, find `firstFlagValue` (golang's returns `string`; cargo's returns `(string, bool)`). Replace both with `argv.FirstFlagValue` calls. Delete the local definitions.

- [ ] **Step 3: Run + commit**

```bash
go test -race ./internal/packagemanager/... -v
git add internal/packagemanager/argv/ internal/packagemanager/golang/ internal/packagemanager/cargo/
git commit -m "Phase 2.5: argv.FirstFlagValue replaces duplicate firstFlagValue in golang/cargo"
```

### Task 2.5.2: golang.go verb table

**Files:**
- Modify: `internal/packagemanager/golang/golang.go`

- [ ] **Step 1: Define the table**

Top of file:

```go
type goVerb struct {
    name             string
    sub              string // e.g. for "mod download" / "mod tidy"
    parseInstalls    parseMode
    emitsModRefs     bool
    projectPreflight bool
    goRunLocalOnly   bool
}

type parseMode int

const (
    parseNone parseMode = iota
    parseAllPositionals
    parseFirstPositional
)

var goVerbs = []goVerb{
    {name: "get", parseInstalls: parseAllPositionals, emitsModRefs: true},
    {name: "install", parseInstalls: parseAllPositionals, emitsModRefs: true, projectPreflight: true},
    {name: "run", parseInstalls: parseFirstPositional, goRunLocalOnly: true},
    {name: "build", projectPreflight: true},
    {name: "test", projectPreflight: true},
    {name: "vet", projectPreflight: true},
    {name: "mod", sub: "download", parseInstalls: parseAllPositionals, emitsModRefs: true},
    {name: "mod", sub: "tidy", emitsModRefs: true},
}
```

Then `ParseInstalls`, `ManifestRefs`, and `ProjectPreflight` each query this table:

```go
func (m Manager) ParseInstalls(args []string) []packagemanager.Install {
    v, rest, ok := matchVerb(args, goVerbs)
    if !ok { return nil }
    switch v.parseInstalls {
    case parseAllPositionals:
        return parseModuleSpecs(rest, true)
    case parseFirstPositional:
        if !v.goRunLocalOnly || !goRunIsLocal(rest) {
            return parseModuleSpecs(rest, false)
        }
    }
    return nil
}
```

(Implement `matchVerb` to handle the `name` + optional `sub` token.)

- [ ] **Step 2: Tests pass**

```bash
go test -race ./internal/packagemanager/golang -v
```

- [ ] **Step 3: Commit**

```bash
git add internal/packagemanager/golang/golang.go
git commit -m "Phase 2.5: golang.go uses a single verb table for three dispatchers

ParseInstalls, ManifestRefs, and ProjectPreflight now query one
declarative goVerbs slice. Makes the Phase 1.8.1 drift hole
structurally impossible (a missing 'install' in one switch would
correspond to a missing field in the table)."
```

### Task 2.5.3: cargo.go verb table; consolidate parseAdd/parseInstall + markInstalls*

**Files:**
- Modify: `internal/packagemanager/cargo/cargo.go`

- [ ] **Step 1: Same shape for cargo**

Define a `cargoVerb` table covering the install-style verbs (`add`, `install`, `update`, `fetch`, `publish`) and the preflight verbs (`build`, `check`, `test`, `run`, `bench`, `clippy`, `doc`, `package`).

- [ ] **Step 2: Collapse parseAdd + parseInstall**

```go
func parseCrateInstalls(rest []string) []packagemanager.Install {
    specs := argv.CollectPositionalsWithTable(rest, cargoFlagsWithValues)
    out := make([]packagemanager.Install, 0, len(specs))
    for _, s := range specs {
        out = append(out, cargoSpec.Parse(s))
    }
    // Apply --git/--path overrides uniformly:
    if g, ok := argv.FirstFlagValue(rest, "--git"); ok {
        out = markInstalls(out, "git="+g, kindOpaque)
    }
    if p, ok := argv.FirstFlagValue(rest, "--path"); ok {
        out = markInstalls(out, "path="+p, kindLocal)
    }
    return out
}

type installKind int
const (
    kindOpaque installKind = iota
    kindLocal
)

func markInstalls(installs []packagemanager.Install, rawSuffix string, kind installKind) []packagemanager.Install {
    for i := range installs {
        installs[i].RawSpec += " (" + rawSuffix + ")"
        switch kind {
        case kindOpaque:
            installs[i].OpaqueRemote = true
        case kindLocal:
            installs[i].LocalPath = true
        }
    }
    return installs
}
```

Delete `parseAdd`, `parseInstall`, `markInstallsOpaque`, `markInstallsLocal`.

- [ ] **Step 3: Run + commit**

```bash
go test -race ./internal/packagemanager/cargo -v
git add internal/packagemanager/cargo/cargo.go
git commit -m "Phase 2.5: cargo.go verb table; parseCrateInstalls / markInstalls consolidated"
```

### Task 2.5.4: Shared projectroot walker

**Files:**
- Create: `internal/packagemanager/projectroot/projectroot.go`
- Create: `internal/packagemanager/projectroot/projectroot_test.go`
- Modify: `cmd/veto/main.go` (consume from `resolveProjectPreflightRoots` / `findParentCargoWorkspaceManifest`)

- [ ] **Step 1: Define WalkUp**

```go
// Package projectroot walks upward from a starting directory looking
// for project-anchor files (go.mod, Cargo.toml, ...). Shared by the
// Go and Cargo preflight wiring in main.go.
package projectroot

import (
    "os"
    "path/filepath"
)

// WalkUp finds the nearest ancestor directory that contains any of
// the anchor filenames. Returns the directory path and the matching
// anchor name, or ("", "", false) on miss.
func WalkUp(startDir string, anchors []string) (dir, anchor string, found bool) {
    cur := startDir
    for {
        for _, a := range anchors {
            if _, err := os.Stat(filepath.Join(cur, a)); err == nil {
                return cur, a, true
            }
        }
        parent := filepath.Dir(cur)
        if parent == cur { return "", "", false }
        cur = parent
    }
}
```

- [ ] **Step 2: Consume from main.go**

Find `findParentProjectFile` and `findParentCargoWorkspaceManifest`. Both reduce to `projectroot.WalkUp` calls plus the source-specific anchor names.

- [ ] **Step 3: Tests + commit**

```bash
go test -race ./internal/packagemanager/projectroot -v
git add internal/packagemanager/projectroot/ cmd/veto/main.go
git commit -m "Phase 2.5: shared projectroot.WalkUp; golang and cargo consume one helper"
```

## Group 2.6: Gate + shared parsers cleanup (single PR)

This task lands as a single PR. The edits across `internal/packagemanager/*` are mechanical, but they touch many files.

### Task 2.6.1: Install sum type

**Files:**
- Modify: `internal/packagemanager/packagemanager.go` (Install + InstallKind)
- Modify: every PM file that constructs an Install

- [ ] **Step 1: Define the sum**

In `internal/packagemanager/packagemanager.go`:

```go
type InstallKind int

const (
    InstallKindUnspecified InstallKind = iota
    InstallKindNamedRef
    InstallKindLocalPath
    InstallKindOpaqueRemote
)

type Install struct {
    Kind    InstallKind
    Ref     intel.PackageRef // valid only when Kind == InstallKindNamedRef
    RawSpec string
}
```

Delete the `LocalPath bool` and `OpaqueRemote bool` fields. Provide a brief deprecation shim if needed (`func (i Install) LocalPath() bool { return i.Kind == InstallKindLocalPath }`) and remove the shim after all callers migrate.

- [ ] **Step 2: Mechanical edits across PMs**

For every PM file that does `Install{LocalPath: true, ...}` or `Install{OpaqueRemote: true, ...}`, change to `Install{Kind: InstallKindLocalPath, ...}` / `Install{Kind: InstallKindOpaqueRemote, ...}`. Default constructions (named) get `Kind: InstallKindNamedRef`.

Use a single regex search to find all sites:

```bash
grep -rn "LocalPath:[[:space:]]*true\|OpaqueRemote:[[:space:]]*true" --include="*.go"
```

- [ ] **Step 3: Update gate.Evaluate**

In `internal/gate/gate.go`, the opaque/local branches become a `switch ins.Kind`:

```go
switch ins.Kind {
case packagemanager.InstallKindOpaqueRemote:
    decision.Verdicts = append(decision.Verdicts, policyRefusalVerdict(ins, ...))
    decision.Outcome = OutcomeRefuse
    continue
case packagemanager.InstallKindLocalPath:
    if g.policy.AllowLocalPath { continue }
    decision.Verdicts = append(decision.Verdicts, policyRefusalVerdict(ins, ...))
    decision.Outcome = OutcomeRefuse
    continue
case packagemanager.InstallKindNamedRef:
    verdict := g.store.Lookup(ins.Ref)
    decision.Verdicts = append(decision.Verdicts, verdict)
    if verdict.Flagged() { decision.Outcome = OutcomeRefuse }
}
```

- [ ] **Step 4: Update all tests**

Every test that constructs an Install or compares against one needs to use the new field names. Run `make test`, fix until green.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Phase 2.6: Install becomes a sum type {NamedRef, LocalPath, OpaqueRemote}

Two booleans (LocalPath, OpaqueRemote) replaced by a Kind enum.
gate.Evaluate dispatches via switch — the impossible 'Local AND
Opaque' state is unrepresentable. All PMs migrated; tests updated."
```

### Task 2.6.2: Decision becomes a typed variant

**Files:**
- Modify: `internal/gate/gate.go`
- Modify: `cmd/veto/main.go` (consumer)
- Modify: `internal/gate/gate_test.go`

- [ ] **Step 1: Define the variant**

In `internal/gate/gate.go`:

```go
// Decision is the result of Evaluate. Use the type-switch idiom:
//   switch d := decision.(type) {
//   case Allow:    ...
//   case Refuse:   ...
//   case Abort:    ...
//   case Passthrough: ...
//   }
type Decision interface {
    isDecision()
}

type Allow struct{}
type Refuse struct{ Verdicts []intel.Verdict }
type Abort struct{ Errors []error }
type Passthrough struct{}

func (Allow) isDecision()       {}
func (Refuse) isDecision()      {}
func (Abort) isDecision()       {}
func (Passthrough) isDecision() {}

// Backwards-compat helpers for callers that want booleans.
func (Allow) Flagged() []intel.Verdict      { return nil }
func (r Refuse) Flagged() []intel.Verdict   { return r.Verdicts }
```

Delete the old `Decision` struct, `Outcome` type, and the four `OutcomeXxx` constants.

- [ ] **Step 2: Update Evaluate**

`Evaluate` now returns `Decision` interface:

```go
func (g *Gate) Evaluate(...) Decision {
    if /* nil/empty case */ return Passthrough{}
    // expander errors:
    if len(expanderErrs) > 0 { return Abort{Errors: expanderErrs} }
    // ... build verdicts ...
    if anyFlagged { return Refuse{Verdicts: verdicts} }
    return Allow{}
}
```

- [ ] **Step 3: Migrate the three switches in main.go**

Find every `switch outcome {` block in `cmd/veto/main.go`. Replace with:

```go
switch d := decision.(type) {
case gate.Allow:       ...
case gate.Refuse:      ...
case gate.Abort:       ...
case gate.Passthrough: ...
default:               panic("unhandled gate.Decision variant")
}
```

Three sites collapse into a single helper if convenient:

```go
func handleDecision(logger zerolog.Logger, d gate.Decision) int {
    switch v := d.(type) { ... }
}
```

- [ ] **Step 4: Update tests**

Every gate_test.go assertion becomes `require.IsType(t, gate.Refuse{}, d)` plus an inspection of the typed fields.

- [ ] **Step 5: Run + commit**

```bash
make test
git add internal/gate/gate.go internal/gate/gate_test.go cmd/veto/main.go
git commit -m "Phase 2.6: gate.Decision is now a typed variant

Allow/Refuse/Abort/Passthrough are distinct types. Three duplicate
outcome switches in main.go collapse to one type-switch dispatch.
Invalid states (Refuse with no Verdicts, Abort with no Errors) are
unrepresentable."
```

### Task 2.6.3: Delete NopExpander; nil-check inline

**Files:**
- Modify: `internal/gate/gate.go`

- [ ] **Step 1: Inline the nil check**

In `Gate.Evaluate`'s manifest-expansion loop:

```go
for _, ref := range manifestRefs {
    if g.policy.ManifestExpander == nil { break }
    // ... existing expand call ...
}
```

Delete `NopExpander` and its constructor reference in `DefaultPolicy`.

Delete the duplicate `g.expander` field — read through `g.policy.ManifestExpander` directly.

- [ ] **Step 2: Update DefaultPolicy**

```go
func DefaultPolicy() Policy {
    return Policy{AllowLocalPath: true} // no more ManifestExpander field
}
```

- [ ] **Step 3: Run + commit**

```bash
make test
git add internal/gate/gate.go
git commit -m "Phase 2.6: delete NopExpander and the duplicate g.expander field

gate handles nil ManifestExpander inline. One field, one storage
location, no drift between g.policy.ManifestExpander and g.expander."
```

### Task 2.6.4: argv shared iterator

**Files:**
- Modify: `internal/packagemanager/argv/argv.go`

- [ ] **Step 1: Extract one iterator**

Define a single private iterator:

```go
func forEachToken(args []string, flagsWithValues map[string]bool,
    cb func(tok string, isFlag, isPositional bool) (stop bool)) {
    skipNext := false
    for i, tok := range args {
        if skipNext { skipNext = false; continue }
        // ... existing classification logic ...
        stop := cb(tok, isFlag, isPositional)
        if stop { return }
        if isFlag && flagsWithValues[strings.SplitN(tok, "=", 2)[0]] && !strings.Contains(tok, "=") {
            skipNext = true
        }
        _ = i
    }
}
```

Both `FirstNonFlagWithTable` and `CollectPositionalsWithTable` now call `forEachToken` with a small adapter. Reduces the file by ~30 lines.

- [ ] **Step 2: Run + commit**

```bash
go test -race ./internal/packagemanager/argv -v
git add internal/packagemanager/argv/argv.go
git commit -m "Phase 2.6: argv iterator unified; FirstNonFlag and CollectPositionals share state machine"
```

### Task 2.6.5: Split scan/types.go; consolidate printer

**Files:**
- Modify: `internal/scan/types.go` → trim to types only
- Create: `internal/scan/report.go`
- Create: `internal/scan/render.go`
- Modify: `cmd/veto/main.go` (printRefusal uses scan/render or a shared helper)

- [ ] **Step 1: Move NewReport into report.go**

```bash
# Mental split:
# types.go    — Surface, Severity, Evidence, Finding, Result, Scanner, PurgeAction, Summary, Report struct
# report.go   — NewReport(), IsActionable, HasActionable
# render.go   — WriteJSON, WriteText, groupBySurface, surfaceHeading, severityRank, displayVersion
```

- [ ] **Step 2: Consolidate the verdict printer**

`render.go`'s WriteText and `cmd/veto/main.go:printRefusal` share the loop over `v.Reports` printing `[SourceID]`. Extract to `scan.WriteVerdicts(w, verdicts)` and call from both sites.

- [ ] **Step 3: Run + commit**

```bash
make test
git add internal/scan/ cmd/veto/main.go
git commit -m "Phase 2.6: split scan/types.go; consolidate verdict printer

types.go now holds only types. report.go owns NewReport and
predicates. render.go owns JSON/text output and the verdict
formatter, which is now also consumed by main.go's printRefusal."
```

### Task 2.6.6: Typed RefusalReason replaces 'veto-policy' magic string

**Files:**
- Modify: `internal/gate/gate.go`
- Modify: `internal/intel/intel.go` (or wherever Verdict lives) — add RefusalReason
- Modify: every consumer of `SourceID == "veto-policy"`

- [ ] **Step 1: Define the typed reason**

```go
// In internal/gate/gate.go:
type RefusalReason int

const (
    RefusalReasonOpaqueSpec RefusalReason = iota + 1
    RefusalReasonLocalDisallowed
    // future: RefusalReasonRegistryMismatch, RefusalReasonVersionYanked
)
```

Carry it on the `Refuse` variant:

```go
type Refuse struct {
    Verdicts []intel.Verdict
    Reasons  []RefusalReason  // parallel to Verdicts; nil when verdict came from intel
}
```

- [ ] **Step 2: Delete policyRefusalVerdict's magic SourceID**

Replace its body — return a sentinel `intel.Verdict{Ref: ins.Ref}` and let the caller carry `RefusalReason`. The printer in `cmd/veto/main.go` (and `internal/scan/render.go`) dispatches on `RefusalReason`:

```go
switch reason {
case gate.RefusalReasonOpaqueSpec:
    fmt.Fprintln(w, "  - [veto policy] opaque-spec install refused")
case gate.RefusalReasonLocalDisallowed:
    fmt.Fprintln(w, "  - [veto policy] local-path install refused")
default:
    fmt.Fprintln(w, "  - [veto policy] refused")
}
```

(`[veto policy]` is still the displayed prefix — the magic string is gone from the data layer.)

- [ ] **Step 3: Tests + commit**

```bash
make test
git add internal/gate/ cmd/veto/main.go internal/scan/render.go
git commit -m "Phase 2.6: typed RefusalReason replaces 'veto-policy' SourceID magic string

The intel.Verdict slot is no longer overloaded with synthetic policy
verdicts. gate.Refuse carries a parallel Reasons slice; the printer
dispatches on the typed reason. Future policy classes (registry
mismatch, version yank) add an enum constant, not a magic string."
```

## Group 2.7: veto_interpose.c gate_and_exec dispatcher

### Task 2.7.1: Define the core dispatcher

**Files:**
- Modify: `internal/interposer/veto_interpose.c`

- [ ] **Step 1: Define gate_and_exec**

Add near the top of the file (after the helper functions):

```c
// gate_and_exec is the shared exec-family dispatch. Every exec
// shadow funnels through here. The two function-pointer adapters
// hide the per-variant calling convention.
//
// passthrough: called when veto declines to gate (basename doesn't
// match a PM, or argv classification yields "not risky"). Must call
// the real underlying syscall and return its result. ctx_passthrough
// carries variant-specific args (fd for fexecve, dirfd for execveat).
//
// reroute: called when veto wants to substitute itself. Receives the
// resolved absolute path to veto plus the rewritten argv and envp.
// Must invoke the real underlying syscall pointing at veto.
static int gate_and_exec(
    const char *probe_path,
    char *const argv[],
    char *const envp_in[],
    int (*passthrough)(void *ctx),
    void *ctx_passthrough,
    int (*reroute)(const char *abs_veto_path, char *const new_argv[],
                   char *const new_envp[], void *ctx),
    void *ctx_reroute)
{
    const char *risky_pm = is_risky(probe_path, argv);
    if (!risky_pm) {
        return passthrough(ctx_passthrough);
    }
    const char *veto_path = getenv("VETO_PATH");
    if (!veto_path || !*veto_path) {
        return passthrough(ctx_passthrough);
    }
    char *const *new_argv = rewrite_argv(argv, /* ... */);
    if (!new_argv) {
        return passthrough(ctx_passthrough);
    }
    char *const *new_envp = envp_in;
    int free_envp_after = 0;
    if (classify_invocation(probe_path, argv) == VETO_INV_PYTHON_DASH_M) {
        char *kv = build_python_m_envvar(argv);
        if (envp_in) {
            new_envp = rewrite_envp(envp_in, kv);
        } else {
            char **snap = snapshot_environ();
            new_envp = rewrite_envp(snap, kv);
            // free snap when done — see free_envp helper
            free_envp_after = 1;
            // store snap pointer for cleanup
        }
    }
    log_route(probe_path, risky_pm, veto_path, new_argv);
    int rc = reroute(veto_path, new_argv, (char *const *)new_envp, ctx_reroute);
    free_argv(new_argv);
    if (new_envp != envp_in) free_envp((char **)new_envp);
    return rc;
}
```

- [ ] **Step 2: Convert one wrapper as a pilot**

Take `veto_execve` (macOS variant) as the pilot. Replace its current body with:

```c
struct execve_ctx { const char *path; char *const *argv; char *const *envp; };

static int execve_passthrough(void *ctx) {
    struct execve_ctx *c = (struct execve_ctx *)ctx;
    return real_execve(c->path, c->argv, c->envp);
}

static int execve_reroute(const char *veto_path, char *const new_argv[],
                          char *const new_envp[], void *ctx) {
    (void)ctx;
    return real_execve(veto_path, new_argv, new_envp);
}

int veto_execve(const char *path, char *const argv[], char *const envp[]) {
    struct execve_ctx c = {path, argv, envp};
    return gate_and_exec(path, argv, envp,
                         execve_passthrough, &c,
                         execve_reroute, NULL);
}
```

Same shape, smaller per-wrapper code.

- [ ] **Step 3: Rebuild + test**

```bash
make interposer
go test -race ./cmd/veto -v
```

Expected: PASS.

- [ ] **Step 4: Convert remaining wrappers**

Mechanical: each of the remaining 12 wrappers (4 macOS + 8 Linux) becomes a `_passthrough` + `_reroute` pair plus an outer 3-line wrapper. Variants that need to manipulate fds (fexecve, execveat) put those into their `ctx` struct.

- [ ] **Step 5: Run all interposer e2e tests**

```bash
make interposer
go test -race ./cmd/veto -v
```

Expected: PASS. Behavior unchanged.

- [ ] **Step 6: Commit**

```bash
git add internal/interposer/veto_interpose.c
git commit -m "Phase 2.7: collapse 13 exec wrappers through gate_and_exec dispatcher

Each shadow is now a ~10-line ctx-builder calling the shared core.
~400 lines deleted. Future fixes (e.g., new exec variant, new env-
scoping rule) land in one place rather than 13."
```

## Group 2.8: Agent installer table

### Task 2.8.1: Collapse claude-hook / codex / cursor into agentIntegration

**Files:**
- Create: `cmd/veto/agent_integrations.go`
- Create: `cmd/veto/agent_integrations_test.go`
- Modify: `cmd/veto/install_claude_hook.go`, `install_codex.go`, `install_cursor.go` (or delete + replace)
- Modify: `cmd/veto/main.go` (dispatch)

- [ ] **Step 1: Define the table**

```go
// Package-level (or in agent_integrations.go):
type agentIntegration struct {
    name       string
    banner     string
    flagSet    func() *flag.FlagSet
    preActions []func(opts agentOpts, logger zerolog.Logger) error
    postCheck  func(opts agentOpts, logger zerolog.Logger)
    nextSteps  func(w io.Writer, opts agentOpts)
}

type agentOpts struct {
    Force      bool
    SettingsPath string  // for claude
    ConfigPath   string  // for codex
    RulePath     string  // for cursor
}

var agents = map[string]agentIntegration{
    "claude-hook": {
        name:    "Claude Code PreToolUse hook",
        banner:  "Installing Claude Code hook...",
        flagSet: claudeHookFlags,
        preActions: []func(agentOpts, zerolog.Logger) error{
            writeClaudeSettings,
        },
        nextSteps: claudeHookNextSteps,
    },
    "codex": {
        name:    "Codex shell-PATH",
        banner:  "Inspecting Codex config...",
        flagSet: codexFlags,
        postCheck: inspectCodexEnv,
        nextSteps: codexNextSteps,
    },
    "cursor": {
        name:    "Cursor project rule",
        banner:  "Installing Cursor rule...",
        flagSet: cursorFlags,
        preActions: []func(agentOpts, zerolog.Logger) error{
            writeCursorRule,
        },
        nextSteps: cursorNextSteps,
    },
}

func runInstallAgent(agentName string, args []string, logger zerolog.Logger) int {
    a, ok := agents[agentName]
    if !ok { return exitUsage }
    fs := a.flagSet()
    if err := fs.Parse(args); err != nil { return exitUsage }
    opts := optsFromFlags(fs)
    fmt.Fprintln(os.Stderr, a.banner)
    for _, pre := range a.preActions {
        if err := pre(opts, logger); err != nil {
            logger.Error().Err(err).Msg("install agent")
            return exitInternal
        }
    }
    if a.postCheck != nil { a.postCheck(opts, logger) }
    a.nextSteps(os.Stdout, opts)
    return exitOK
}
```

- [ ] **Step 2: Migrate existing per-agent files**

Each of `install_claude_hook.go`, `install_codex.go`, `install_cursor.go` shrinks to: (1) the per-agent helper functions (`writeClaudeSettings`, `claudeHookNextSteps`, etc.) plus (2) the flagSet builder. Each file goes from ~300 to ~100 lines.

In `cmd/veto/main.go`, the three case branches become:

```go
case "install-claude-hook":
    return runInstallAgent("claude-hook", args[1:], logger)
case "install-codex":
    return runInstallAgent("codex", args[1:], logger)
case "install-cursor":
    return runInstallAgent("cursor", args[1:], logger)
```

- [ ] **Step 3: Run + commit**

```bash
make test
git add cmd/veto/agent_integrations.go cmd/veto/agent_integrations_test.go \
        cmd/veto/install_claude_hook.go cmd/veto/install_codex.go \
        cmd/veto/install_cursor.go cmd/veto/main.go
git commit -m "Phase 2.8: agentIntegration table collapses claude/codex/cursor installers

Three near-clone installers (each with its own flag parser and 'next
steps' prose) share one driver. Adding a fourth agent (Aider, Zed,
…) is one map entry."
```

## Group 2.9: Defense-layer registry

### Task 2.9.1: Define the layer interface; both install_all and doctor consume it

**Files:**
- Create: `cmd/veto/layer.go`
- Modify: `cmd/veto/install_all.go` (iterate layers)
- Modify: `cmd/veto/doctor.go` (iterate layers)

- [ ] **Step 1: Define the interface**

```go
// cmd/veto/layer.go
type defenseLayer interface {
    Name() string
    Install(opts installOpts, logger zerolog.Logger) error
    Status(ctx context.Context, cfg Config) layerStatus
}

type layerStatus struct {
    Pass  bool
    Detail string
    FixHint string
}

var layers = []defenseLayer{
    shimsLayer{},
    shellLayer{},
    claudeHookLayer{},
    interposerLayer{},
    wrappersLayer{},
}
```

Each layer's `Install` calls into its existing per-layer install function; each layer's `Status` re-uses the existing doctor check.

- [ ] **Step 2: Update install_all.go**

The current sequential step list becomes:

```go
for _, l := range layers {
    fmt.Fprintf(os.Stderr, "==> Installing %s\n", l.Name())
    if err := l.Install(opts, logger); err != nil {
        logger.Error().Err(err).Str("layer", l.Name()).Msg("install layer")
        return exitInternal
    }
}
```

- [ ] **Step 3: Update doctor.go**

The doctor's layer-checks all flow through `l.Status(ctx, cfg)`. (Other doctor checks — intel-store freshness, version-manager shadowing — stay separate.)

- [ ] **Step 4: Run + commit**

```bash
make test
git add cmd/veto/layer.go cmd/veto/install_all.go cmd/veto/doctor.go
git commit -m "Phase 2.9: defenseLayer registry shared by install_all and doctor

The 'what good looks like' knowledge for each layer (shims, shell,
claude hook, interposer, wrappers) lives in one place. Adding a new
layer means one struct + table entry, not two separate edits in
install_all and doctor."
```

## Group 2.10: doctor table + parallel

### Task 2.10.1: Table-driven doctor with errgroup

**Files:**
- Create: `cmd/veto/doctor_checks.go`
- Modify: `cmd/veto/doctor.go`

- [ ] **Step 1: Define the check table**

In `cmd/veto/doctor_checks.go`:

```go
type doctorCheck struct {
    name    string
    run     func(ctx context.Context, cfg Config) []checkResult
}

var doctorChecks = []doctorCheck{
    {"veto on PATH", checkVetoOnPath},
    {"shim PATH ordering", checkShimPath},
    {"managed shell block", checkShellIntegration},
    {"Claude Code hook", checkClaudeHook},
    {"Codex shell PATH policy", checkCodexPosture},
    {"Cursor rule", checkCursorRule},
    {"Sirene posture", checkSirenePosture},
    {"native interposer", checkInterposer},
    {"Layer 4 wrappers", checkWrappers},
    {"intel store freshness", checkIntel},
}
```

- [ ] **Step 2: Refactor runDoctor to parallel dispatch**

In `cmd/veto/doctor.go`:

```go
func runDoctor(ctx context.Context, cfg Config) int {
    results := make([][]checkResult, len(doctorChecks))
    var wg sync.WaitGroup
    for i, c := range doctorChecks {
        i, c := i, c
        wg.Add(1)
        go func() {
            defer wg.Done()
            results[i] = c.run(ctx, cfg)
        }()
    }
    wg.Wait()
    // Render in stable order.
    anyFail := false
    for i, rs := range results {
        for _, r := range rs {
            renderCheck(doctorChecks[i].name, r)
            if r.Severity == severityFail { anyFail = true }
        }
    }
    if anyFail { return exitInternal }
    return exitOK
}
```

(If `errgroup` is preferred for cancel semantics, swap it in — `sync.WaitGroup` is fine if no check can cancel another.)

- [ ] **Step 3: Time the run**

Add a quick microbench / smoke test:

```go
func TestRunDoctor_FastEnough(t *testing.T) {
    start := time.Now()
    rc := runDoctor(context.Background(), testConfig(t))
    elapsed := time.Since(start)
    require.Less(t, elapsed, 10*time.Second,
        "parallel doctor must complete under 10s on a warm machine; got %s", elapsed)
    _ = rc
}
```

- [ ] **Step 4: Run + commit**

```bash
make test
git add cmd/veto/doctor.go cmd/veto/doctor_checks.go
git commit -m "Phase 2.10: doctor table + parallel run

Ten checks run concurrently via WaitGroup. Output is rendered in
stable order after all complete. Full doctor pass drops from ~30s
to ~5s on a warm machine."
```

---

# Phase 3 — Library swap-ins (gated on Phase 0)

Each task proceeds only when the corresponding Phase 0 row is "adopt at <version>". A rejected library means the task is dropped; the Phase 1 in-place fix remains.

## Group 3.1: L1 analyzer → mvdan.cc/sh/v3/syntax

### Task 3.1.1: Add dep and rewrite Analyze

**Files:**
- Modify: `go.mod` (add `mvdan.cc/sh/v3` at the version from Phase 0)
- Modify: `internal/hook/claudecode/claudecode.go` (rewrite)
- Phase 1.2 regression tests carry forward — they MUST still pass.

- [ ] **Step 1: Confirm Phase 0 verdict**

Read `docs/2026-05-25--deps-preflight.md`. If the mvdan.cc/sh/v3 row reads "adopt at vX.Y.Z", proceed. If "reject", skip Group 3.1 entirely; Phase 1.2 band-aids are the final fix.

- [ ] **Step 2: Add the dep**

```bash
go get mvdan.cc/sh/v3@<pinned-version>
go mod tidy
```

- [ ] **Step 3: Rewrite Analyze on AST**

In `internal/hook/claudecode/claudecode.go`, delete the entire token-pipeline analyzer (`splitInlineSeparators`, `stripRedirects`, `splitBySeparators`, `expandShellInvocations`, `stripWrappers`, `stripEnvAssignments`, `containsShellExpansion`). Replace with:

```go
import (
    "mvdan.cc/sh/v3/syntax"
    "github.com/brynbellomy/veto/internal/packagemanager/pmlist"
)

// Analyze parses the given command via sh/v3/syntax and walks the AST
// looking for CallExpr leaves that resolve to a covered PM with a
// dangerous verb. Returns risky + a brief reason.
func Analyze(command string) (bool, string) {
    parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
    file, err := parser.Parse(strings.NewReader(command), "")
    if err != nil {
        // Parse failure is fail-CLOSED — emit a deny rather than guess.
        return true, "refusing to evaluate unparseable shell command"
    }
    var risky bool
    var reason string
    syntax.Walk(file, func(node syntax.Node) bool {
        if call, ok := node.(*syntax.CallExpr); ok {
            if isRiskyCall(call) {
                risky = true
                reason = describeRiskyCall(call)
                return false // stop walking
            }
        }
        return true
    })
    return risky, reason
}

// isRiskyCall returns true when the call's resolved command name is a
// covered PM and the verb is in pmlist.DangerousVerbs.
func isRiskyCall(call *syntax.CallExpr) bool {
    if len(call.Args) == 0 { return false }
    // Extract command name (handle leading env assignments and path).
    cmd, args := extractCommand(call)
    pm := pmFromCommand(cmd)
    if pm == "" { return false }
    if len(args) == 0 { return false }
    return pmlist.DangerousVerbs[pm][args[0]]
}
```

(`extractCommand`, `pmFromCommand`, `describeRiskyCall` are small helpers; each ≤ 20 lines.)

- [ ] **Step 4: Run Phase 1.2 regression tests**

```bash
go test -race ./internal/hook/claudecode -v
```

Expected: EVERY Phase 1.2 regression test passes (`bash -c "cd /tmp;npm install foo"`, command substitution, herestrings, etc.). The AST approach naturally handles them.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/hook/claudecode/claudecode.go
git commit -m "Phase 3.1: rewrite L1 analyzer on mvdan.cc/sh/v3/syntax

The token-pipeline analyzer (splitInlineSeparators, stripRedirects,
expandShellInvocations, stripWrappers, stripEnvAssignments) is gone.
Analyze() walks a real bash AST: CmdSubst, ProcSubst, Redirect, and
nested BinaryCmd are all first-class nodes. Phase 1.2 regression
suite carried forward and passes."
```

## Group 3.2: gomod → golang.org/x/mod

### Task 3.2.1: Delegate go.mod parsing

**Files:**
- Modify: `internal/packagemanager/gomod/gomod.go` (delegate)
- Modify: `internal/packagemanager/golang/golang.go` (use module.CheckVersion, module.PseudoVersion)
- Modify: `go.mod`

- [ ] **Step 1: Confirm Phase 0 verdict; add dep**

```bash
go get golang.org/x/mod@<pinned-version>
```

- [ ] **Step 2: Rewrite gomod.go**

```go
import "golang.org/x/mod/modfile"

func Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
    data, err := os.ReadFile(ref.Path)
    if err != nil { return nil, errors.With(err, "read go.mod", "path", ref.Path) }
    f, err := modfile.Parse(ref.Path, data, nil)
    if err != nil { return nil, errors.With(err, "parse go.mod") }

    // Build a map of replace targets so replaced-to-local modules
    // are classified as LocalPath.
    replaceLocal := make(map[string]bool)
    for _, r := range f.Replace {
        if !strings.Contains(r.New.Path, ".") || strings.HasPrefix(r.New.Path, "./") || strings.HasPrefix(r.New.Path, "../") {
            replaceLocal[r.Old.Path] = true
        }
    }

    out := make([]packagemanager.Install, 0, len(f.Require))
    for _, r := range f.Require {
        ins := packagemanager.Install{
            Ref: intel.PackageRef{Ecosystem: intel.EcosystemGo, Name: r.Mod.Path, Version: r.Mod.Version},
            Kind: packagemanager.InstallKindNamedRef,
            RawSpec: r.Mod.Path + "@" + r.Mod.Version,
        }
        if replaceLocal[r.Mod.Path] {
            ins.Kind = packagemanager.InstallKindLocalPath
        }
        out = append(out, ins)
    }
    return out, nil
}
```

Delete the bespoke scanner.

- [ ] **Step 3: Use module.CheckVersion / module.PseudoVersion in golang.go**

In `internal/packagemanager/golang/golang.go`, replace `splitModuleVersion` and `isExactGoVersion` with:

```go
import "golang.org/x/mod/module"

func splitModuleVersion(spec string) (name, version string, hasVersion bool) {
    at := strings.LastIndexByte(spec, '@')
    if at <= 0 { return spec, "", false }
    return spec[:at], spec[at+1:], true
}

func isExactGoVersion(v string) bool {
    if v == "" { return false }
    if module.IsPseudoVersion(v) { return true }
    return module.CheckVersion("placeholder", v) == nil
}
```

- [ ] **Step 4: Run + commit**

```bash
make test
git add go.mod go.sum internal/packagemanager/gomod/gomod.go internal/packagemanager/golang/golang.go
git commit -m "Phase 3.2: gomod uses x/mod/modfile; golang uses module.CheckVersion

Bespoke go.mod scanner replaced. 'replace' directives now parsed —
replaced-to-local modules correctly classified as LocalPath."
```

## Group 3.3: PEP 440 → aquasecurity/go-pep440-version

### Task 3.3.1: Delegate PyPI version compare

**Files:**
- Modify: `go.mod`
- Modify: `internal/intel/range.go` (PyPI arm delegates)
- Delete: `internal/intel/pep440.go` (move tests forward)

- [ ] **Step 1: Confirm Phase 0 verdict**

Read `docs/2026-05-25--deps-preflight.md`. If "reject" — Group 3.3 is dropped; Phase 1.9.2 in-place fix is the final answer.

- [ ] **Step 2: Add the dep + delete the file**

```bash
go get github.com/aquasecurity/go-pep440-version@<pinned>
```

In `internal/intel/range.go`:

```go
import "github.com/aquasecurity/go-pep440-version"

func inRangePEP440(v, rng VersionRange) bool {
    parsed, err := version.Parse(v)
    if err != nil { return true } // over-block on unparseable
    // ... delegate to the lib's range comparison ...
}
```

Delete `internal/intel/pep440.go` and `pep440_test.go`. Keep the Phase 1.9.2 multi-digit-local-label test (move it into `range_test.go` so it asserts the same behavior against the lib).

- [ ] **Step 3: Run + commit**

```bash
make test
git rm internal/intel/pep440.go
git add go.mod go.sum internal/intel/range.go internal/intel/range_test.go
git commit -m "Phase 3.3: delegate PyPI version compare to go-pep440-version

330 hand-rolled lines deleted. The Phase 1.9.2 multi-digit-local-label
regression is preserved as a test against the lib."
```

## Group 3.4: Codex + Cargo TOML → pelletier/go-toml/v2

### Task 3.4.1: Replace Codex line-TOML scanner

**Files:**
- Modify: `cmd/veto/install_codex.go`
- (pelletier/go-toml/v2 is already a direct dep — no go.mod change)

- [ ] **Step 1: Replace the hand-rolled scanner**

In `cmd/veto/install_codex.go`, find `inspectCodexEnv` (or whichever function holds the line-scanner around lines 82-135). Replace with:

```go
import "github.com/pelletier/go-toml/v2"

type codexConfig struct {
    ShellEnvironmentPolicy struct {
        Inherit string `toml:"inherit"`
    } `toml:"shell_environment_policy"`
}

func inspectCodexEnv(opts agentOpts, logger zerolog.Logger) {
    data, err := os.ReadFile(opts.ConfigPath)
    if err != nil {
        if !os.IsNotExist(err) {
            logger.Warn().Err(err).Msg("read codex config")
        }
        return
    }
    var cfg codexConfig
    if err := toml.Unmarshal(data, &cfg); err != nil {
        logger.Warn().Err(err).Msg("parse codex config")
        return
    }
    if cfg.ShellEnvironmentPolicy.Inherit != "core" {
        // PATH is NOT inherited — no posture concern.
        return
    }
    fmt.Fprintln(os.Stdout, "codex inherits PATH; veto shims will be visible.")
}
```

- [ ] **Step 2: Run + commit**

```bash
make test
git add cmd/veto/install_codex.go
git commit -m "Phase 3.4: Codex env inspection uses pelletier/go-toml/v2

Hand-rolled line-TOML scanner deleted. The inspection is now correct
against multi-line strings, inline tables, and commented-out keys."
```

### Task 3.4.2: Confirm Cargo TOML parsers are on pelletier

**Files:**
- Inspect: `internal/packagemanager/cargomanifest/cargomanifest.go`
- Inspect: `internal/packagemanager/cargolock/cargolock.go`

- [ ] **Step 1: Check imports**

```bash
grep -l "BurntSushi/toml\|pelletier/go-toml" internal/packagemanager/cargomanifest/ internal/packagemanager/cargolock/
```

If both are on `pelletier/go-toml/v2`, no work needed. If either is on `BurntSushi/toml`, migrate to pelletier (mechanical: change the import path and call `toml.Unmarshal` instead of `toml.Decode`).

- [ ] **Step 2: Run + commit (if migration was needed)**

```bash
make test
git add internal/packagemanager/cargo{manifest,lock}/
git commit -m "Phase 3.4: Cargo TOML parsers consolidated on pelletier/go-toml/v2"
```

---

# Self-Review

## Spec coverage check

For each section of `docs/2026-05-25--veto-remediation-design.md`, point to the task that implements it:

- Phase 0 Dep pre-flight → Task 0.1
- Phase 1.1 VETO_BYPASS / VETO_ALLOW_OPAQUE removal → Tasks 1.1.1, 1.1.2, 1.1.3, 1.1.4
- Phase 1.2 L1 hook band-aids → Tasks 1.2.1, 1.2.2, 1.2.3
- Phase 1.3 Python shim + managed shell → Tasks 1.3.1, 1.3.2, 1.3.3, 1.3.4
- Phase 1.4 L3 interposer scoping → Tasks 1.4.1, 1.4.2
- Phase 1.5 L4 atomicity → Tasks 1.5.1, 1.5.2, 1.5.3, 1.5.4
- Phase 1.6 JS parser fixes → Tasks 1.6.1, 1.6.2, 1.6.3, 1.6.4, 1.6.5
- Phase 1.7 Python parser fixes → Tasks 1.7.1, 1.7.2, 1.7.3, 1.7.4, 1.7.5, 1.7.6
- Phase 1.8 Go/Cargo parser fixes → Tasks 1.8.1, 1.8.2, 1.8.3
- Phase 1.9 Intel etag-before-parse + PEP 440 sort → Tasks 1.9.1, 1.9.2
- Phase 2.1 pmlist consolidation → Tasks 2.1.1, 2.1.2, 2.1.3
- Phase 2.2 Intel shared scaffold → Tasks 2.2.1, 2.2.2, 2.2.3
- Phase 2.3 shared shellrc → Task 2.3.1
- Phase 2.4 JS Manager factory → Tasks 2.4.1, 2.4.2
- Phase 2.5 Native verb tables → Tasks 2.5.1, 2.5.2, 2.5.3, 2.5.4
- Phase 2.6 Gate + parsers cleanup → Tasks 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6
- Phase 2.7 C interposer dispatcher → Task 2.7.1
- Phase 2.8 Agent installer table → Task 2.8.1
- Phase 2.9 Layer registry → Task 2.9.1
- Phase 2.10 doctor table + parallel → Task 2.10.1
- Phase 3.1 L1 analyzer swap → Task 3.1.1
- Phase 3.2 gomod swap → Task 3.2.1
- Phase 3.3 PEP 440 swap → Task 3.3.1
- Phase 3.4 TOML swap → Tasks 3.4.1, 3.4.2

All spec items have at least one task.

## Type consistency check

- `agentIntegration` (2.8) — fields stable across the task.
- `defenseLayer` interface (2.9) — `Install` and `Status` signatures consistent.
- `jspm.Spec` (2.4) — `ExecVerb` / `ExecSpecFlags` / `ExecValueFlags` consistent between 2.4.1 and Phase 1.6.2 (which used `exec.New`).
- `gate.Decision` interface (2.6.2) — `Allow`, `Refuse`, `Abort`, `Passthrough` variants used consistently in 2.6.6 (`Refuse.Reasons`).
- `Install.Kind` enum (2.6.1) — `InstallKindNamedRef`, `InstallKindLocalPath`, `InstallKindOpaqueRemote`, `InstallKindUnspecified` — consistent across the migration in 2.6.1, 2.6.2, 3.2.1.
- `common.Fetcher` (2.2.1) — `URL`, `CacheDir`, `MaxBytes`, `Client`, `Logger` fields consistent in 2.2.2.
- `MarkerPair` (2.3.1) — `Begin`, `End` fields stable.

## Scope-and-ambiguity check

- Phase 0 produces a runbook-style report doc, not TDD-shaped tasks. Explicitly called out.
- The "Phase 1.2 band-aids must keep passing in Phase 3.1" contract is documented in both phases.
- The Phase 3 conditional-on-verdict gate is documented at the section header.
- The `replace` directive handling deferred from Phase 1.8 lands in Phase 3.2 — both phases reference each other.
- Phase 2.4's `jspm.Spec` covers per-PM lockfile sets, which is the structural fix for the "emit all four lockfiles speculatively" finding from the JS reviewer. Documented in the file structure.

---

# Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-25-veto-remediation.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration. Best for a plan this large; each subagent works on an isolated piece and the orchestrator catches drift.

2. **Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints. Reasonable for a contiguous sprint but the conversation context fills up fast given the plan's size.

Which approach?


