package intel_test

import (
	"context"
	"sync"
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

	t.Run("concrete-version advisory does NOT refuse a different version of the same name", func(t *testing.T) {
		// The store holds reports for evil@1.0.0 (both sources). A query
		// for evil@2.0.0 must NOT pick up those entries — they're scoped
		// to a specific version. This is the version-aware Lookup
		// semantics: byName entries with concrete-but-different versions
		// are skipped. Old policy would have refused; closing the
		// react@1.0.0/35.0.0 vs react@18.2.0 false-positive class.
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "2.0.0"})
		require.False(t, v.Flagged(), "evil@2.0.0 must be clean — only evil@1.0.0 is flagged")
		require.Empty(t, v.Reports)
	})

	t.Run("empty-version advisory refuses every concrete-version query", func(t *testing.T) {
		// always-bad has a byName entry with Version="" — the parser's
		// "applies to all versions" signal. Every concrete-version query
		// against this name must refuse.
		for _, v := range []string{"1.0.0", "2.0.0", "99.99.99"} {
			verdict := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "always-bad", Version: v})
			require.True(t, verdict.Flagged(), "always-bad@%s should refuse — has an all-versions advisory", v)
		}
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

// programmableSource lets a test return different per-ecosystem data and
// per-ecosystem errors on each Refresh call. It exists for the retention
// tests below, where the "second Refresh" is the case under test.
//
// Refresh fires len(AllEcosystems) goroutines concurrently, so Fetch is
// invoked in parallel. The fixture-index counter is bumped exactly once
// per Refresh — after every ecosystem has been served from the same
// fixture — by tracking which ecosystems have been served via a sync.Map.
type programmableSource struct {
	id       string
	mu       sync.Mutex
	calls    int
	served   map[intel.Ecosystem]bool
	fixtures []programmableFixture
}

type programmableFixture struct {
	per map[intel.Ecosystem][]intel.MalwareReport
	err map[intel.Ecosystem]error
}

func (p *programmableSource) ID() string { return p.id }

func (p *programmableSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	p.mu.Lock()
	idx := p.calls
	if idx >= len(p.fixtures) {
		idx = len(p.fixtures) - 1
	}
	fx := p.fixtures[idx]
	if p.served == nil {
		p.served = make(map[intel.Ecosystem]bool)
	}
	p.served[eco] = true
	// Every ecosystem served from this fixture → bump to next.
	if len(p.served) == len(intel.AllEcosystems) {
		p.calls++
		p.served = nil
	}
	p.mu.Unlock()

	if fx.err != nil {
		if e, ok := fx.err[eco]; ok {
			return nil, e
		}
	}
	return fx.per[eco], nil
}

// TestStoreRefreshRetainsPreviousOnFetchError: a per-(source, ecosystem)
// fetch that errors on the second Refresh must NOT silently drop that
// pair's data — the previous slice is retained instead. This closes the
// "MITM drops Aikido response → veto silently loses Aikido coverage"
// fail-open path the audit identified as C1.
func TestStoreRefreshRetainsPreviousOnFetchError(t *testing.T) {
	logger := zerolog.Nop()
	src := &programmableSource{
		id: "alpha",
		fixtures: []programmableFixture{
			// First Refresh: 2 reports.
			{
				per: map[intel.Ecosystem][]intel.MalwareReport{
					intel.EcosystemNPM: {
						{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"}, SourceID: "alpha"},
						{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "also-evil"}, SourceID: "alpha"},
					},
				},
			},
			// Second Refresh: npm fetch errors. Previous npm data must be retained.
			{
				err: map[intel.Ecosystem]error{
					intel.EcosystemNPM: context.DeadlineExceeded,
				},
			},
		},
	}
	store := intel.NewStore(logger, src)
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 2, store.ReportCount(), "first refresh populated index")

	// Second refresh: npm errors. The lookup must STILL find the
	// previously-flagged package — that's the retention.
	require.NoError(t, store.Refresh(context.Background()), "retention should let refresh succeed despite fetch error")
	v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"})
	require.True(t, v.Flagged(), "previous data must survive a per-source-ecosystem fetch failure")
}

// TestStoreRefreshRetainsPreviousOnPartialDrop: a per-(source, ecosystem)
// fetch that returns suspiciously few reports (below partialDropThreshold
// of the previous count) must be treated as a partial failure and the
// previous slice retained. Defends against an upstream that's been
// curated-down-to-empty by an attacker without TLS-level evidence.
func TestStoreRefreshRetainsPreviousOnPartialDrop(t *testing.T) {
	logger := zerolog.Nop()
	makeReports := func(n int) []intel.MalwareReport {
		out := make([]intel.MalwareReport, n)
		for i := range out {
			out[i] = intel.MalwareReport{
				PackageRef: intel.PackageRef{
					Ecosystem: intel.EcosystemNPM,
					Name:      "evil-" + string(rune('a'+i)),
					Version:   "1",
				},
				SourceID: "alpha",
			}
		}
		return out
	}
	src := &programmableSource{
		id: "alpha",
		fixtures: []programmableFixture{
			// First refresh: 100 reports.
			{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(100)}},
			// Second refresh: 1 report (1% of previous, well below 50% threshold).
			{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(1)}},
		},
	}
	store := intel.NewStore(logger, src)
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 100, store.ReportCount(), "first refresh populated 100 reports")

	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 100, store.ReportCount(),
		"steep drop should trigger retention; index should still have 100 reports")
}

// TestStoreRefreshAcceptsNewWhenAboveThreshold: the retention policy must
// not be so aggressive that legitimate small drops trigger it. A drop
// above the threshold should still let the new data through.
func TestStoreRefreshAcceptsNewWhenAboveThreshold(t *testing.T) {
	logger := zerolog.Nop()
	makeReports := func(n int) []intel.MalwareReport {
		out := make([]intel.MalwareReport, n)
		for i := range out {
			out[i] = intel.MalwareReport{
				PackageRef: intel.PackageRef{
					Ecosystem: intel.EcosystemNPM,
					Name:      "evil-" + string(rune('a'+i)),
					Version:   "1",
				},
				SourceID: "alpha",
			}
		}
		return out
	}
	src := &programmableSource{
		id: "alpha",
		fixtures: []programmableFixture{
			{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(100)}},
			// 80% retained — well above the 50% threshold; new data should win.
			{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(80)}},
		},
	}
	store := intel.NewStore(logger, src)
	require.NoError(t, store.Refresh(context.Background()))
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 80, store.ReportCount(),
		"drop above threshold should let new (smaller) data win")
}

// TestStoreRefreshAllUnsupportedReturnsError: if every (source, ecosystem)
// returns ErrUnsupportedEcosystem AND there's no prior data, Refresh must
// fail rather than silently swap in an empty index. Closes M4 in the audit.
func TestStoreRefreshAllUnsupportedReturnsError(t *testing.T) {
	logger := zerolog.Nop()
	src := &fakeSource{id: "u", fetchEr: intel.ErrUnsupportedEcosystem}
	store := intel.NewStore(logger, src)

	err := store.Refresh(context.Background())
	require.Error(t, err, "all-unsupported with no prior data must fail rather than swap in empty index")
}

// TestStoreDedupKeyHandlesPipeInNames: the dedup key must use struct
// fields, not "|"-joined strings, so package names containing "|"
// don't collide with each other. Closes M6 in the audit.
func TestStoreDedupKeyHandlesPipeInNames(t *testing.T) {
	logger := zerolog.Nop()
	src := &fakeSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: {
				// These would collide with a "|"-joined dedup key:
				//   "alpha|npm|a|b|1" == "alpha|npm|a|b|1"
				// vs the struct dedup which sees Name="a|b" Version="1"
				// distinct from Name="a"  Version="b|1".
				{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "a|b", Version: "1"}, SourceID: "alpha"},
				{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "a", Version: "b|1"}, SourceID: "alpha"},
			},
		},
	}
	store := intel.NewStore(logger, src)
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 2, store.ReportCount(),
		"struct dedup key must treat Name='a|b'+Ver='1' and Name='a'+Ver='b|1' as distinct")
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

// TestStoreLookupPyPINameNormalization: an attacker republishing a flagged
// PyPI distribution under a typo-equivalent capitalization (`Evil_Pkg` vs
// the registry-canonical `evil-pkg`) must still be refused. The store
// keys both the feed-side insert and the lookup-side query through PEP
// 503 normalization, so every equivalent shape resolves to the same
// indexed name. Closes B3 in the audit.
func TestStoreLookupPyPINameNormalization(t *testing.T) {
	logger := zerolog.Nop()
	src := &fakeSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			// Feed ships the un-normalized shape; index-build normalizes it.
			intel.EcosystemPyPI: {
				{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "Evil_Pkg", Version: "1.0.0"}, SourceID: "alpha"},
			},
		},
	}
	store := intel.NewStore(logger, src)
	require.NoError(t, store.Refresh(context.Background()))

	// Each of these is PEP 503-equivalent to "evil-pkg" and must hit.
	for _, name := range []string{"Evil_Pkg", "evil-pkg", "EVIL.pkg", "evil_pkg", "evil.pkg", "evil___pkg"} {
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: name, Version: "1.0.0"})
		require.True(t, v.Flagged(), "PEP 503 equivalence: %q must hit the same report as Evil_Pkg", name)
	}

	// Unversioned lookup also flows through normalization.
	v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "EVIL.pkg"})
	require.True(t, v.Flagged(), "unversioned PyPI lookup must also normalize")
}

// TestStoreLookupBoundedRangeRefusesInsideAllowsOutside: a ranged
// advisory `{introduced: 1.1.5, last_affected: 1.1.6}` must refuse
// queries inside the interval (1.1.5, 1.1.6) AND allow queries
// outside it (1.1.4, 1.1.7). This is the MAL-2022-466 / foo@3.0.0
// class of false positive: the pre-range-aware emitter would refuse
// every version of the name.
func TestStoreLookupBoundedRangeRefusesInsideAllowsOutside(t *testing.T) {
	logger := zerolog.Nop()
	rng := intel.VersionRange{Introduced: "1.1.5", LastAffected: "1.1.6"}
	src := &fakeSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: {
				{
					PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "react"},
					SourceID:   "alpha",
					Reason:     "ranged",
					Range:      &rng,
				},
			},
		},
	}
	store := intel.NewStore(logger, src)
	require.NoError(t, store.Refresh(context.Background()))

	t.Run("inside range refuses 1.1.5", func(t *testing.T) {
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "react", Version: "1.1.5"})
		require.True(t, v.Flagged())
	})
	t.Run("inside range refuses 1.1.6", func(t *testing.T) {
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "react", Version: "1.1.6"})
		require.True(t, v.Flagged())
	})
	t.Run("below range allows 1.1.4", func(t *testing.T) {
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "react", Version: "1.1.4"})
		require.False(t, v.Flagged(), "1.1.4 is below the range [1.1.5, 1.1.6] and must NOT be refused")
	})
	t.Run("above range allows 1.1.7", func(t *testing.T) {
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "react", Version: "1.1.7"})
		require.False(t, v.Flagged(), "1.1.7 is above the range [1.1.5, 1.1.6] and must NOT be refused")
	})
}

// TestStoreLookupUnboundedRangeRefusesEveryVersion: a ranged advisory
// `{introduced: 0}` (no upper bound) is the post-rewrite shape for
// the very common "all versions are bad" case. Every concrete-version
// query against the name must still refuse — regression for the
// post-183f807 behavior.
func TestStoreLookupUnboundedRangeRefusesEveryVersion(t *testing.T) {
	logger := zerolog.Nop()
	rng := intel.VersionRange{Introduced: "0"}
	src := &fakeSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: {
				{
					PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "always-bad"},
					SourceID:   "alpha",
					Reason:     "unbounded",
					Range:      &rng,
				},
			},
		},
	}
	store := intel.NewStore(logger, src)
	require.NoError(t, store.Refresh(context.Background()))

	for _, v := range []string{"0.0.1", "1.0.0", "2.0.0", "99.99.99"} {
		verdict := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "always-bad", Version: v})
		require.True(t, verdict.Flagged(), "unbounded range must refuse always-bad@%s", v)
	}
}

// TestStoreLookupPyPIUnboundedRangeRefuses: PyPI bounded-range matching
// isn't implemented, but the IsUnbounded short-circuit means
// `{introduced: 0}` advisories (the only shape today's PyPI feeds
// produce) still refuse every version without invoking PEP 440.
func TestStoreLookupPyPIUnboundedRangeRefuses(t *testing.T) {
	logger := zerolog.Nop()
	rng := intel.VersionRange{Introduced: "0"}
	src := &fakeSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemPyPI: {
				{
					PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil-py"},
					SourceID:   "alpha",
					Reason:     "unbounded pypi",
					Range:      &rng,
				},
			},
		},
	}
	store := intel.NewStore(logger, src)
	require.NoError(t, store.Refresh(context.Background()))

	for _, v := range []string{"1.0.0", "2.0.0", "9.9.9"} {
		verdict := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil-py", Version: v})
		require.True(t, verdict.Flagged(), "unbounded PyPI range must refuse evil-py@%s without PEP 440", v)
	}
}

// TestStoreLookupNPMNameNormalization: npm names are case-insensitive at
// the registry. A feed publishing a capitalized name (or a user typing
// one) must still match. Defensive ToLower at both boundaries.
func TestStoreLookupNPMNameNormalization(t *testing.T) {
	logger := zerolog.Nop()
	src := &fakeSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: {
				{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "React", Version: "1.0.0"}, SourceID: "alpha"},
			},
		},
	}
	store := intel.NewStore(logger, src)
	require.NoError(t, store.Refresh(context.Background()))

	for _, name := range []string{"React", "react", "REACT", "ReAcT"} {
		v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name, Version: "1.0.0"})
		require.True(t, v.Flagged(), "npm case-insensitive: %q must hit the same report as React", name)
	}
}
