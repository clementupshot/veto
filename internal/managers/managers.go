// Package managers is the single source of truth for the set of
// package-manager binary names veto recognises. Every other site that
// once had its own copy of this list (cmd/veto/install_wrappers.go's
// wrappedManagers, cmd/veto/shims.go's shimmedManagers,
// cmd/veto/main.go's isShimName, cmd/veto/main.go's
// buildPackageManagers, internal/hook/claudecode's shimmedPMs) now
// consults Supported / IsSupported.
//
// The list is derived from the in-tree PM implementations under
// internal/packagemanager — adding a new manager is a matter of
// implementing the PackageManager interface there and adding the
// binary name here.
//
// History: claudecode.go previously carried `rush` and `rushx` even
// though cmd/veto has no PackageManager implementation for either.
// The agent would deny `rush install` then suggest `veto rush
// install`, but the second invocation fell through to the "unknown
// package manager; passing through" warning and ran ungated. Dropping
// `rush` / `rushx` from the canonical list aligns the hook with what
// the gate actually enforces. If those two need real support later,
// add a packagemanager subpackage for them and append here.
package managers

// Supported is the canonical, ordered list of package-manager binary
// names veto wraps, shims, gates, and intercepts. Order is preserved
// for deterministic install output and to keep diffs stable.
//
// This slice is exported as a value (not a function) because every
// consumer is read-only. Callers must not mutate it; if you need a
// derived list, copy into a local slice first.
var Supported = []string{
	"npm", "pnpm", "yarn", "bun",
	"npx", "pnpx", "bunx",
	"pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
}

// supportedSet is the O(1) membership-test backing for IsSupported.
// Built at init from Supported so the two cannot drift.
var supportedSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(Supported))
	for _, name := range Supported {
		m[name] = struct{}{}
	}
	return m
}()

// IsSupported reports whether name is one of the package managers
// veto recognises. Reads supportedSet, which is initialised once at
// package init and never mutated — safe for concurrent reads.
func IsSupported(name string) bool {
	_, ok := supportedSet[name]
	return ok
}

// Set returns Supported as a map for callers that want O(1) lookup
// against many strings (e.g. the Claude Code hook's per-token check).
// Allocates a fresh map per call; cache at the call site if invoked
// in a hot loop.
func Set() map[string]struct{} {
	out := make(map[string]struct{}, len(Supported))
	for _, n := range Supported {
		out[n] = struct{}{}
	}
	return out
}
