package intel_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

func TestVersionRangeIsUnbounded(t *testing.T) {
	cases := []struct {
		name string
		rng  intel.VersionRange
		want bool
	}{
		{"all empty", intel.VersionRange{}, true},
		{"introduced 0", intel.VersionRange{Introduced: "0"}, true},
		{"introduced 0 with fixed", intel.VersionRange{Introduced: "0", Fixed: "2.0.0"}, false},
		{"introduced 0 with last_affected", intel.VersionRange{Introduced: "0", LastAffected: "1.0.0"}, false},
		{"introduced concrete", intel.VersionRange{Introduced: "1.0.0"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, c.rng.IsUnbounded())
		})
	}
}

func TestInRangeNPMSemver(t *testing.T) {
	cases := []struct {
		name string
		v    string
		rng  intel.VersionRange
		want bool
	}{
		// [0, 2.0.0) — half-open
		{"below upper", "1.9.9", intel.VersionRange{Introduced: "0", Fixed: "2.0.0"}, true},
		{"at upper exclusive", "2.0.0", intel.VersionRange{Introduced: "0", Fixed: "2.0.0"}, false},
		{"above upper", "2.0.1", intel.VersionRange{Introduced: "0", Fixed: "2.0.0"}, false},

		// [1.1.5, 1.1.6] — inclusive upper via LastAffected
		{"below lower", "1.1.4", intel.VersionRange{Introduced: "1.1.5", LastAffected: "1.1.6"}, false},
		{"at lower inclusive", "1.1.5", intel.VersionRange{Introduced: "1.1.5", LastAffected: "1.1.6"}, true},
		{"at upper inclusive", "1.1.6", intel.VersionRange{Introduced: "1.1.5", LastAffected: "1.1.6"}, true},
		{"above upper inclusive", "1.1.7", intel.VersionRange{Introduced: "1.1.5", LastAffected: "1.1.6"}, false},

		// Open-ended right: [1.0.0, ∞)
		{"open right, far above", "99.99.99", intel.VersionRange{Introduced: "1.0.0"}, true},
		{"open right, below", "0.9.9", intel.VersionRange{Introduced: "1.0.0"}, false},

		// Prefer Fixed when both are set — tighter bound wins.
		{"both bounds, Fixed exclusive wins", "2.0.0", intel.VersionRange{Introduced: "0", Fixed: "2.0.0", LastAffected: "2.0.0"}, false},

		// Pre-release ordering: per semver 2.0.0, 1.0.0-beta < 1.0.0.
		{"prerelease below release", "1.0.0-beta", intel.VersionRange{Introduced: "0", Fixed: "1.0.0"}, true},
		{"release at exclusive upper", "1.0.0", intel.VersionRange{Introduced: "0", Fixed: "1.0.0"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, intel.InRange(intel.EcosystemNPM, c.v, c.rng))
		})
	}
}

func TestInRangeGoSemverStripsVPrefix(t *testing.T) {
	require.True(t, intel.InRange(intel.EcosystemGo, "v1.9.9", intel.VersionRange{Introduced: "0", Fixed: "v2.0.0"}))
	require.False(t, intel.InRange(intel.EcosystemGo, "v2.0.0", intel.VersionRange{Introduced: "0", Fixed: "v2.0.0"}))
	require.True(t, intel.InRange(intel.EcosystemGo, "1.9.9", intel.VersionRange{Introduced: "v1.0.0", Fixed: "v2.0.0"}))
}

func TestInRangeCratesSemver(t *testing.T) {
	require.True(t, intel.InRange(intel.EcosystemCrates, "1.9.9", intel.VersionRange{Introduced: "0", Fixed: "2.0.0"}))
	require.False(t, intel.InRange(intel.EcosystemCrates, "2.0.0", intel.VersionRange{Introduced: "0", Fixed: "2.0.0"}))
}

func TestInRangeUnboundedShortCircuits(t *testing.T) {
	// IsUnbounded short-circuits before any parser runs, so even a
	// garbage version string still returns true.
	require.True(t, intel.InRange(intel.EcosystemNPM, "not-a-version", intel.VersionRange{Introduced: "0"}))
	require.True(t, intel.InRange(intel.EcosystemNPM, "not-a-version", intel.VersionRange{}))
	require.True(t, intel.InRange(intel.EcosystemPyPI, "garbage", intel.VersionRange{Introduced: "0"}))
}

func TestInRangeParseErrorOverBlocks(t *testing.T) {
	// Bounded range with a malformed query version: refusing a clean
	// install is annoying; allowing a flagged install is the failure
	// mode the gate exists to prevent. Over-block on parse error.
	require.True(t, intel.InRange(intel.EcosystemNPM, "not-a-version", intel.VersionRange{Introduced: "1.0.0", Fixed: "2.0.0"}))
	// Malformed Introduced.
	require.True(t, intel.InRange(intel.EcosystemNPM, "1.0.0", intel.VersionRange{Introduced: "garbage", Fixed: "2.0.0"}))
	// Malformed Fixed.
	require.True(t, intel.InRange(intel.EcosystemNPM, "1.0.0", intel.VersionRange{Introduced: "0", Fixed: "garbage"}))
	// Malformed LastAffected.
	require.True(t, intel.InRange(intel.EcosystemNPM, "1.0.0", intel.VersionRange{Introduced: "0", LastAffected: "garbage"}))
}

func TestInRangePyPIBoundedOverBlocks(t *testing.T) {
	// PyPI bounded-range matching isn't implemented today (no feeds
	// emit bounded PyPI ranges in cache). Bounded ranges over-block
	// conservatively until PEP 440 lands.
	require.True(t, intel.InRange(intel.EcosystemPyPI, "3.0.0", intel.VersionRange{Introduced: "0", Fixed: "2.0.0"}))
}
