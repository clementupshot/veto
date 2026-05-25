package gate_test

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gate"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
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
	g := gate.New(store, gate.DefaultPolicy(), zerolog.Nop())
	dec := g.Evaluate(nil)
	require.Equal(t, gate.OutcomePassThrough, dec.Outcome)
}

func TestEvaluateCleanInstallsAllow(t *testing.T) {
	store := buildStore(t)
	g := gate.New(store, gate.DefaultPolicy(), zerolog.Nop())
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
	g := gate.New(store, gate.DefaultPolicy(), zerolog.Nop())
	dec := g.Evaluate([]packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"}},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "innocent"}},
	})
	require.Equal(t, gate.OutcomeRefuse, dec.Outcome)
	require.Len(t, dec.Flagged(), 1)
	require.Equal(t, "evil", dec.Flagged()[0].Ref.Name)
}

func TestEvaluateLocalPathInstallAllowedUnderDefaultPolicy(t *testing.T) {
	store := buildStore(t)
	g := gate.New(store, gate.DefaultPolicy(), zerolog.Nop())
	dec := g.Evaluate([]packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "./local"}, LocalPath: true},
	})
	require.Equal(t, gate.OutcomeAllow, dec.Outcome)
	require.Empty(t, dec.Verdicts)
}

// TestEvaluateOpaqueRemoteAlwaysRefused asserts the post-Phase-1.1
// contract: URL/git/tarball/github-shorthand specs that bypass the
// registry name lookup are refused unconditionally. There is no
// override; the prior AllowOpaqueRemote axis is gone.
func TestEvaluateOpaqueRemoteAlwaysRefused(t *testing.T) {
	store := buildStore(t)
	g := gate.New(store, gate.DefaultPolicy(), zerolog.Nop())
	dec := g.Evaluate([]packagemanager.Install{
		{
			Ref:          intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "https://evil.com/x.tgz"},
			RawSpec:      "https://evil.com/x.tgz",
			OpaqueRemote: true,
		},
	})
	require.Equal(t, gate.OutcomeRefuse, dec.Outcome)
	require.Len(t, dec.Flagged(), 1)
	require.Equal(t, "veto-policy", dec.Flagged()[0].Reports[0].SourceID)
	require.Contains(t, dec.Flagged()[0].Reports[0].Reason, "opaque-spec install refused")
	require.NotContains(t, dec.Flagged()[0].Reports[0].Reason, "VETO_ALLOW_OPAQUE",
		"reason text must not advertise the removed override env")
}

// TestEvaluateLocalPathRefusedUnderStrictPolicy: callers who want the
// strictest possible mode can flip AllowLocalPath off too. Verifies the
// gate produces a clearly-distinct refusal (different reason string)
// from the opaque-remote case.
func TestEvaluateLocalPathRefusedUnderStrictPolicy(t *testing.T) {
	store := buildStore(t)
	policy := gate.DefaultPolicy()
	policy.AllowLocalPath = false
	g := gate.New(store, policy, zerolog.Nop())
	dec := g.Evaluate([]packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "./local"}, LocalPath: true},
	})
	require.Equal(t, gate.OutcomeRefuse, dec.Outcome)
	require.Equal(t, "veto-policy", dec.Flagged()[0].Reports[0].SourceID)
	require.Contains(t, dec.Flagged()[0].Reports[0].Reason, "local-path")
}

func TestEvaluateEmptyInstallsAllow(t *testing.T) {
	// An install verb with no specs AND no manifest refs evaluates to
	// Allow. When the parser emits package.json / lockfile ManifestRefs
	// (the common case for bare `npm install`), the expander handles
	// transitive gating — see TestEvaluateExpanderInstallsRefused below.
	store := buildStore(t)
	g := gate.New(store, gate.DefaultPolicy(), zerolog.Nop())
	dec := g.Evaluate([]packagemanager.Install{})
	require.Equal(t, gate.OutcomeAllow, dec.Outcome)
}

// fakeExpander returns a fixed slice of Installs for any ManifestRef it
// sees. Used in tests to simulate pyreq.Expander without touching disk.
type fakeExpander struct {
	installs []packagemanager.Install
	err      error
	seen     []packagemanager.ManifestRef
}

func (f *fakeExpander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	f.seen = append(f.seen, ref)
	if f.err != nil {
		return nil, f.err
	}
	return f.installs, nil
}

func TestEvaluateManifestExpansionRefusesOnFlaggedInstall(t *testing.T) {
	store := buildStore(t,
		intel.MalwareReport{
			PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil-py", Version: "1.0.0"},
			SourceID:   "fake",
		},
	)
	exp := &fakeExpander{installs: []packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil-py", Version: "1.0.0"}, RawSpec: "evil-py==1.0.0"},
	}}
	policy := gate.DefaultPolicy()
	policy.ManifestExpander = exp
	g := gate.New(store, policy, zerolog.Nop())

	dec := g.Evaluate(nil, packagemanager.ManifestRef{Path: "requirements.txt", Kind: packagemanager.ManifestKindRequirements})
	require.Equal(t, gate.OutcomeRefuse, dec.Outcome)
	require.Len(t, dec.Flagged(), 1)
	require.Equal(t, "evil-py", dec.Flagged()[0].Ref.Name)
	require.Len(t, exp.seen, 1)
	require.Equal(t, "requirements.txt", exp.seen[0].Path)
}

func TestEvaluateManifestExpansionGatesAlongsideArgvInstalls(t *testing.T) {
	store := buildStore(t,
		intel.MalwareReport{
			PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil-py", Version: "1.0.0"},
			SourceID:   "fake",
		},
	)
	exp := &fakeExpander{installs: []packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil-py", Version: "1.0.0"}, RawSpec: "evil-py==1.0.0"},
	}}
	policy := gate.DefaultPolicy()
	policy.ManifestExpander = exp
	g := gate.New(store, policy, zerolog.Nop())

	dec := g.Evaluate(
		[]packagemanager.Install{
			{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "innocent"}, RawSpec: "innocent"},
		},
		packagemanager.ManifestRef{Path: "requirements.txt", Kind: packagemanager.ManifestKindRequirements},
	)
	require.Equal(t, gate.OutcomeRefuse, dec.Outcome)
	require.Len(t, dec.Verdicts, 2)
	require.Len(t, dec.Flagged(), 1)
}

func TestEvaluateManifestExpanderErrorAbortsFailClosed(t *testing.T) {
	// I/O failure on the manifest must NOT silently pass argv-named installs
	// through — we can't prove the manifest's contents are safe, so the whole
	// install is aborted with a distinct outcome.
	store := buildStore(t)
	sentinel := errSentinel{}
	exp := &fakeExpander{err: sentinel}
	policy := gate.DefaultPolicy()
	policy.ManifestExpander = exp
	g := gate.New(store, policy, zerolog.Nop())

	dec := g.Evaluate(
		[]packagemanager.Install{
			{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "innocent"}, RawSpec: "innocent"},
		},
		packagemanager.ManifestRef{Path: "missing.txt", Kind: packagemanager.ManifestKindRequirements},
	)
	require.Equal(t, gate.OutcomeAbort, dec.Outcome)
	require.Len(t, dec.Errors, 1)
	require.ErrorIs(t, dec.Errors[0], sentinel)
}

type errSentinel struct{}

func (errSentinel) Error() string { return "fake io failure" }
