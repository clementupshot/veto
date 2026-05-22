package intel_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// TestNormalizeNamePyPI exercises PEP 503: lower-case, then collapse every
// run of `[-_.]` into a single `-`. Reference cases are drawn from PEP 503
// directly plus the typosquat shapes that motivated this fix.
func TestNormalizeNamePyPI(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// PEP 503 canonical examples.
		{"Evil_Pkg", "evil-pkg"},
		{"Foo.Bar", "foo-bar"},
		{"requests___OAUTH-lib", "requests-oauth-lib"},
		// Idempotent on already-normalized input.
		{"evil-pkg", "evil-pkg"},
		{"requests", "requests"},
		// Mixed runs of -._ collapse to a single dash.
		{"a_._-_b", "a-b"},
		{"EVIL.pkg", "evil-pkg"},
		// Empty stays empty.
		{"", ""},
		// Leading/trailing separators are not stripped by PEP 503;
		// they collapse to a single dash.
		{"-foo", "-foo"},
		{"foo-", "foo-"},
		{"__foo__", "-foo-"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := intel.NormalizeName(intel.EcosystemPyPI, tc.in)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestNormalizeNameNPM verifies the defensive lower-case applied to npm
// names. Scoped names keep their `@scope/` prefix; only case changes.
func TestNormalizeNameNPM(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"React", "react"},
		{"react", "react"},
		{"@scope/Foo", "@scope/foo"},
		{"@SCOPE/foo", "@scope/foo"},
		{"left-pad", "left-pad"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := intel.NormalizeName(intel.EcosystemNPM, tc.in)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestNormalizeNameUnknownEcosystem: an ecosystem the helper doesn't know
// about passes through untouched. New ecosystems must opt in explicitly.
func TestNormalizeNameUnknownEcosystem(t *testing.T) {
	got := intel.NormalizeName(intel.Ecosystem("unknown"), "Mixed_Case.Name")
	require.Equal(t, "Mixed_Case.Name", got)
}
