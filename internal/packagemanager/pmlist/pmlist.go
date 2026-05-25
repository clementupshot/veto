// Package pmlist is the single source of truth for "what binary names
// does veto recognise as a package manager." It exists to prevent the
// drift hazard documented in M1: prior to this package the same set
// was hand-maintained in five separate spots (isShimName in main.go,
// shimmedManagers in shims.go, wrappedManagers in install_wrappers.go,
// PM_NAMES in the C interposer, and shimmedPMs in the claudecode hook)
// — so a B2-style addition (python/python3) or B5-style addition (rush)
// had to be applied in five places, and any one omission would open a
// silent bypass.
//
// Layout of the canonical sets:
//
//   - Shimmed     — every PM we install Layer-2 PATH shims for and that
//     main()'s shim-dispatch must recognise. Includes
//     python/python3 because `python -m pip install …` is
//     the canonical install form inside virtualenvs and
//     Dockerfiles; main() fast-paths every non-`-m {pm}`
//     python call so the shim doesn't slow down REPLs,
//     `-V`, `-c`, scripts, `-m http.server`, etc.
//
//   - Wrapped     — every PM we install Layer-4 real-binary wrappers
//     for. Deliberately a *strict subset* of Shimmed:
//     python/python3 are shimmed but NOT wrapped because
//     Layer 4 replaces the binary on disk and would
//     route every python invocation (every script, every
//     REPL) through veto. Wrapping the bare interpreter
//     is an unacceptable hot path for a tool whose value
//     sits on install-style verbs only.
//
//   - Interposer  — every PM the Layer-3 native interposer (and the
//     Layer-1 claudecode hook) must recognise as "could
//     be a risky invocation; classify further." A
//     superset of Shimmed that also includes rush /
//     rushx — rush isn't a PM we install a shim/wrapper
//     for (rush projects are rare and use their own
//     bootstrapping), but if a process spawns one
//     directly we still want is_risky() / Analyze() to
//     route the install verbs through veto.
//
// All three sets are exported as both slices (stable order for install
// output and code generation) and presence maps (fast set membership
// for hot paths). The slices are the source of truth; the maps are
// derived in init().
//
// CGo / C-header generation: the interposer's PM_NAMES array is
// regenerated from InterposerPMs by `go generate
// ./internal/interposer/...` (see internal/interposer/generate.go). The
// Makefile runs `go generate` before compiling the dylib/so, so the
// canonical Go list is authoritative for the C side too — there is no
// hand-edited C list to drift.
package pmlist

// Shimmed lists every package-manager binary that:
//   - main()'s isShimName() must recognise so shim-dispatch works.
//   - `veto install-shims` creates a symlink for.
//
// Order is the stable install-output order; do not sort.
var Shimmed = []string{
	"npm", "pnpm", "yarn", "bun",
	"npx", "pnpx", "bunx",
	"pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
	"go", "cargo",
	"python", "python3",
}

// Wrapped lists every package-manager binary that `veto
// install-wrappers` will atomically replace on disk.
//
// Deliberately a *strict subset* of Shimmed: python and python3 are
// shimmed (so `python -m pip install …` is caught at Layer 2) but
// NOT wrapped, because Layer 4 routes every invocation of the wrapped
// binary through veto. That's fine for `npm` / `pip` (which are
// install-tools); it's unacceptable for `python` (every script run,
// every REPL).
var Wrapped = []string{
	"npm", "pnpm", "yarn", "bun",
	"npx", "pnpx", "bunx",
	"pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
	"go", "cargo",
}

// InterposerPMs lists every package-manager binary the Layer-3
// interposer (C) and Layer-1 claudecode hook (Go) must classify
// further. Superset of Shimmed: also includes rush/rushx, which veto
// does not install shims/wrappers for but DOES still want to gate
// when a process spawns them directly.
//
// This slice is the source the `go generate` step uses to emit the
// C header consumed by veto_interpose.c — see
// internal/interposer/generate.go and the resulting pm_names.h.
var InterposerPMs = []string{
	"npm", "npx", "yarn", "pnpm", "pnpx",
	"rush", "rushx", "bun", "bunx",
	"pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
	"go", "cargo",
	"python", "python3",
}

// shimmedSet, wrappedSet, interposerSet are the hot-path membership
// lookups. Built once at init from the slices above so the slices stay
// the source of truth.
var (
	shimmedSet    map[string]struct{}
	wrappedSet    map[string]struct{}
	interposerSet map[string]struct{}
)

func init() {
	shimmedSet = sliceToSet(Shimmed)
	wrappedSet = sliceToSet(Wrapped)
	interposerSet = sliceToSet(InterposerPMs)
}

func sliceToSet(s []string) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for _, v := range s {
		out[v] = struct{}{}
	}
	return out
}

// IsShimmed reports whether name is one of the binaries `veto
// install-shims` wires up. main()'s shim-dispatch consults this on
// every invocation; the map lookup is O(1) and keeps the hot path
// allocation-free.
func IsShimmed(name string) bool {
	_, ok := shimmedSet[name]
	return ok
}

// IsWrapped reports whether name is one of the binaries `veto
// install-wrappers` will replace on disk.
func IsWrapped(name string) bool {
	_, ok := wrappedSet[name]
	return ok
}

// IsInterposerPM reports whether name is one of the binaries the
// Layer-3 interposer / Layer-1 hook recognise as "potentially risky;
// classify further." Used by the claudecode hook's shimmedPMs lookup;
// the C interposer consumes the equivalent set via the generated
// pm_names.h.
func IsInterposerPM(name string) bool {
	_, ok := interposerSet[name]
	return ok
}
