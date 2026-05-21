package gate_test

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/gate"
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
)

type fakeSource struct {
	reports []intel.MalwareReport
}

func (fakeSource) ID() string { return "fake" }
func (f fakeSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	var out []intel.MalwareReport
	for _, r := range f.reports {
		if r.Ecosystem == eco {
			out = append(out, r)
		}
	}
	return out, nil
}

func buildStore(t *testing.T, reports ...intel.MalwareReport) intel.Store {
	t.Helper()
	store := intel.NewStore(zerolog.Nop(), fakeSource{reports: reports})
	require.NoError(t, store.Refresh(context.Background()))
	return store
}

func TestEvaluateNilInstallsPassesThrough(t *testing.T) {
	store := buildStore(t)
	g := gate.New(store, gate.DefaultPolicy())
	dec := g.Evaluate(nil)
	require.Equal(t, gate.OutcomePassThrough, dec.Outcome)
}

func TestEvaluateCleanInstallsAllow(t *testing.T) {
	store := buildStore(t)
	g := gate.New(store, gate.DefaultPolicy())
	dec := g.Evaluate([]packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}},
	})
	require.Equal(t, gate.OutcomeAllow, dec.Outcome)
	require.Empty(t, dec.Flagged())
}

func TestEvaluateMaliciousInstallRefuses(t *testing.T) {
	store := buildStore(t,
		intel.MalwareReport{
			PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"},
			SourceID:   "fake",
		},
	)
	g := gate.New(store, gate.DefaultPolicy())
	dec := g.Evaluate([]packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"}},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "innocent"}},
	})
	require.Equal(t, gate.OutcomeRefuse, dec.Outcome)
	require.Len(t, dec.Flagged(), 1)
	require.Equal(t, "evil", dec.Flagged()[0].Ref.Name)
}

func TestEvaluateLocalInstallAllowedUnderDefaultPolicy(t *testing.T) {
	store := buildStore(t)
	g := gate.New(store, gate.DefaultPolicy())
	dec := g.Evaluate([]packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "./local"}, Local: true},
	})
	require.Equal(t, gate.OutcomeAllow, dec.Outcome)
	require.Empty(t, dec.Verdicts)
}

func TestEvaluateEmptyInstallsAllow(t *testing.T) {
	// An install verb with no specs (e.g. `npm install` from package.json)
	// is currently allowed; manifest expansion is a documented @@TODO.
	store := buildStore(t)
	g := gate.New(store, gate.DefaultPolicy())
	dec := g.Evaluate([]packagemanager.Install{})
	require.Equal(t, gate.OutcomeAllow, dec.Outcome)
}
