package pmlist

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWrappedIsSubsetOfShimmed pins the documented invariant: every
// wrapped binary is also shimmed. Wrapping a PM that isn't shimmed
// would be incoherent — main()'s dispatch wouldn't recognise the
// resulting symlink as a shim.
//
// The converse is NOT required: python/python3 are shimmed but
// deliberately not wrapped (see package doc).
func TestWrappedIsSubsetOfShimmed(t *testing.T) {
	for _, w := range Wrapped {
		require.True(t, IsShimmed(w),
			"%q is in Wrapped but not in Shimmed; install-wrappers would create a symlink shim-dispatch cannot route",
			w)
	}
}

// TestShimmedIsSubsetOfInterposer pins the documented invariant: every
// shimmed binary is also recognised by the Layer-3 interposer / Layer-1
// hook. If a PM is shimmed but the interposer doesn't classify it,
// `subprocess.run(["/abs/path/<pm>", ...])` from a process with the
// interposer loaded would silently bypass the gate.
func TestShimmedIsSubsetOfInterposer(t *testing.T) {
	for _, s := range Shimmed {
		require.True(t, IsInterposerPM(s),
			"%q is in Shimmed but not in InterposerPMs; Layer 3 / Layer 1 would miss direct spawns of this PM",
			s)
	}
}

// TestMembershipHelpers spot-checks the IsX helpers against the
// expected outcomes for a few representative PMs.
func TestMembershipHelpers(t *testing.T) {
	require.True(t, IsShimmed("npm"))
	require.True(t, IsShimmed("go"))
	require.True(t, IsShimmed("cargo"))
	require.True(t, IsShimmed("python"))
	require.True(t, IsShimmed("python3"))
	require.False(t, IsShimmed("rush"), "rush is NOT shimmed; install-shims does not wire it up")
	require.False(t, IsShimmed("veto"))
	require.False(t, IsShimmed(""))

	require.True(t, IsWrapped("npm"))
	require.True(t, IsWrapped("go"))
	require.True(t, IsWrapped("cargo"))
	require.False(t, IsWrapped("python"), "python is shimmed but NOT wrapped (see package doc)")
	require.False(t, IsWrapped("python3"), "python3 is shimmed but NOT wrapped (see package doc)")
	require.False(t, IsWrapped("rush"))

	require.True(t, IsInterposerPM("npm"))
	require.True(t, IsInterposerPM("go"))
	require.True(t, IsInterposerPM("cargo"))
	require.True(t, IsInterposerPM("python"))
	require.True(t, IsInterposerPM("rush"), "rush is recognised by Layer 3 / Layer 1 even though we don't shim it")
	require.True(t, IsInterposerPM("rushx"))
	require.False(t, IsInterposerPM("veto"))
	require.False(t, IsInterposerPM(""))
}

// TestNoDuplicates guards against accidentally appending a name twice
// to one of the canonical slices. The membership sets would silently
// absorb the duplicate; the install-output side would print the name
// twice.
func TestNoDuplicates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		slice []string
	}{
		{"Shimmed", Shimmed},
		{"Wrapped", Wrapped},
		{"InterposerPMs", InterposerPMs},
	} {
		seen := map[string]bool{}
		for _, n := range tc.slice {
			require.False(t, seen[n], "%s contains duplicate %q", tc.name, n)
			seen[n] = true
		}
	}
}
