package intel_test

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// fakeSource is a hand-written stub used only inside this test file. We use a
// hand-stub here rather than a generated mock because the surface is tiny and
// the test asserts on behavior, not call counts; for cross-package consumers
// of intel.Source we will register the interface with mockery.
type fakeSource struct {
	id      string
	per     map[intel.Ecosystem][]intel.MalwareReport
	fetchEr error
}

func (f *fakeSource) ID() string { return f.id }

func (f *fakeSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if f.fetchEr != nil {
		return nil, f.fetchEr
	}
	return f.per[eco], nil
}

func TestStoreLookup(t *testing.T) {
	logger := zerolog.Nop()

	a := &fakeSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: {
				{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"}, SourceID: "alpha", Reason: "malware"},
				{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "always-bad", Version: ""}, SourceID: "alpha", Reason: "all versions"},
			},
		},
	}
	b := &fakeSource{
		id: "beta",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: {
				{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"}, SourceID: "beta", Reason: "also malware"},
			},
		},
	}

	store := intel.NewStore(logger, a, b)
	require.NoError(t, store.Refresh(context.Background()))

	t.Run("exact version match returns reports from all sources", func(t *testing.T) {
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"})
		require.True(t, v.Flagged())
		require.Len(t, v.Reports, 2)
		require.ElementsMatch(t, []string{"alpha", "beta"}, v.Sources())
	})

	t.Run("any-version report matches without explicit version", func(t *testing.T) {
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "always-bad", Version: "9.9.9"})
		require.True(t, v.Flagged())
		require.Len(t, v.Reports, 1)
		require.Equal(t, "alpha", v.Reports[0].SourceID)
	})

	t.Run("unversioned lookup catches any flagged version of the package", func(t *testing.T) {
		// User runs `npm install evil` with no pin — should be refused
		// because version 1.0.0 of evil is flagged in the store.
		// This is the regression for the chai-as-upgraded smoke-test failure.
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil"})
		require.True(t, v.Flagged())
		require.Len(t, v.Reports, 2)
		require.ElementsMatch(t, []string{"alpha", "beta"}, v.Sources())
	})

	t.Run("clean package returns empty verdict", func(t *testing.T) {
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "innocent", Version: "1.0.0"})
		require.False(t, v.Flagged())
		require.Empty(t, v.Reports)
	})

	t.Run("different ecosystem does not collide", func(t *testing.T) {
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil", Version: "1.0.0"})
		require.False(t, v.Flagged())
	})
}

func TestStoreRefreshAllSourcesFailingReturnsError(t *testing.T) {
	logger := zerolog.Nop()
	failing := &fakeSource{id: "fail", fetchEr: context.Canceled}
	store := intel.NewStore(logger, failing)

	err := store.Refresh(context.Background())
	require.Error(t, err)
}

func TestStoreRefreshUnsupportedEcosystemIsSilent(t *testing.T) {
	logger := zerolog.Nop()
	skipper := &fakeSource{id: "skip", fetchEr: intel.ErrUnsupportedEcosystem}
	good := &fakeSource{
		id: "ok",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: {
				{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1"}, SourceID: "ok"},
			},
		},
	}
	store := intel.NewStore(logger, skipper, good)
	require.NoError(t, store.Refresh(context.Background()))

	v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1"})
	require.True(t, v.Flagged())
}

func TestNopSource(t *testing.T) {
	var s intel.Source = intel.NopSource{}
	require.Equal(t, "nop", s.ID())

	reports, err := s.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Empty(t, reports)
}

func TestStoreReportCount(t *testing.T) {
	logger := zerolog.Nop()

	t.Run("empty store reports zero", func(t *testing.T) {
		store := intel.NewStore(logger, intel.NopSource{})
		require.NoError(t, store.Refresh(context.Background()))
		require.Equal(t, 0, store.ReportCount())
	})

	t.Run("counts unique (source, ref, version) tuples", func(t *testing.T) {
		src := &fakeSource{
			id: "alpha",
			per: map[intel.Ecosystem][]intel.MalwareReport{
				intel.EcosystemNPM: {
					{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"}, SourceID: "alpha"},
					{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.1"}, SourceID: "alpha"},
					{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "any-version-bad"}, SourceID: "alpha"},
				},
			},
		}
		store := intel.NewStore(logger, src)
		require.NoError(t, store.Refresh(context.Background()))
		require.Equal(t, 3, store.ReportCount())
	})
}
