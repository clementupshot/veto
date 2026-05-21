package managers_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/hook/claudecode"
	"github.com/brynbellomy/veto/internal/managers"
)

// claudecodeShimmedPMsForTest names the indirection through the
// claudecode export, so the test name reflects intent rather than the
// generic export getter.
func claudecodeShimmedPMsForTest() map[string]struct{} {
	return claudecode.ShimmedPMs()
}

// Set returns a map snapshot of managers.Supported. Co-located with
// the test that uses it; not exported because production code
// constructs its own set inline (see e.g. claudecode's managersSet).
func setHelperUnused() {}

func TestSupportedAndIsSupportedAgree(t *testing.T) {
	require.NotEmpty(t, managers.Supported, "Supported must not be empty")
	for _, name := range managers.Supported {
		require.True(t, managers.IsSupported(name),
			"IsSupported must recognise every name in Supported (%q)", name)
	}
}

func TestIsSupportedRejectsUnknown(t *testing.T) {
	for _, name := range []string{
		"",
		"cargo",
		"go",
		"gem",
		"composer",
		"veto",
	} {
		require.False(t, managers.IsSupported(name),
			"IsSupported(%q) must be false", name)
	}
}

// TestRushRushxNotSupported pins the deliberate omission. Earlier versions of
// internal/hook/claudecode listed rush/rushx in its shimmedPMs map even though
// the gate had no PackageManager implementation for either — so denying
// `rush install` and prompting `veto rush install` made the second invocation
// fall through to "unknown package manager; passing through" and run ungated.
// If a future change re-adds rush, this test fails until a real PM
// implementation lands.
func TestRushRushxNotSupported(t *testing.T) {
	require.False(t, managers.IsSupported("rush"),
		"rush must not be in Supported until a packagemanager subpackage exists for it")
	require.False(t, managers.IsSupported("rushx"),
		"rushx must not be in Supported until a packagemanager subpackage exists for it")
}

func TestSupportedHasExpectedSize(t *testing.T) {
	require.Len(t, managers.Supported, 14,
		"Supported must have exactly 14 entries; update this test when adding a new PM")
}

// TestClaudeCodeHookMatchesSupported is the cross-package drift
// guard. The hook intercepts a set of PM binary names; if that set
// drifts from managers.Supported the hook will deny commands the
// veto-side cannot gate (causing the rush/rushx
// bypass-via-prompted-retry) or fail to deny commands the gate can
// run (silently letting them through).
//
// We import claudecode so this test fails at compile time when the
// hook's surface is removed, and at run time when the contents
// drift.
func TestClaudeCodeHookMatchesSupported(t *testing.T) {
	t.Helper()
	hookSet := claudecodeShimmedPMsForTest()
	want := managers.Set()
	require.Equal(t, want, hookSet,
		"internal/hook/claudecode's shimmedPMs drifted from managers.Supported. "+
			"Adding/removing a PM must happen in internal/managers; the hook follows automatically.")
}
