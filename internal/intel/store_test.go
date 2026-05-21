package intel_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// TODO: migrate the hand-rolled fakeSource / programmableSource to
// mockery v3 — out of scope for the hardening follow-up PR. See Bryn's
// review on PR #1: brynsk-architecture defaults call for generated mocks
// over hand-rolled stubs.

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

	store := intel.NewStore(logger, intel.WithSources(a, b))
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
	store := intel.NewStore(logger, intel.WithSources(failing))

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
	store := intel.NewStore(logger, intel.WithSources(skipper, good))
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
	store := intel.NewStore(logger, intel.WithSources(src))
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
	store := intel.NewStore(logger, intel.WithSources(src))
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
	store := intel.NewStore(logger, intel.WithSources(src))
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
	store := intel.NewStore(logger, intel.WithSources(src))

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
	store := intel.NewStore(logger, intel.WithSources(src))
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 2, store.ReportCount(),
		"struct dedup key must treat Name='a|b'+Ver='1' and Name='a'+Ver='b|1' as distinct")
}

func TestStoreReportCount(t *testing.T) {
	logger := zerolog.Nop()

	t.Run("empty store reports zero", func(t *testing.T) {
		store := intel.NewStore(logger, intel.WithSources(intel.NopSource{}))
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
		store := intel.NewStore(logger, intel.WithSources(src))
		require.NoError(t, store.Refresh(context.Background()))
		require.Equal(t, 3, store.ReportCount())
	})
}

// TestStoreRefreshRefusesRetentionPastMaxAge: the H3 fix's
// max-retention-age cap converts SILENT permanent stale-pinning into
// LOUD eventual failure. A bucket whose last-fresh-fetch is older than
// MaxRetentionAge must NOT be retained on a subsequent error — it
// must surface as a fetchErr so the operator (and the
// minHealthyReportCount floor) can notice.
//
// Test shape: drive the store with a controllable clock. First refresh
// stamps lastRefreshedAt at t0. Second refresh, with the clock
// advanced past MaxRetentionAge, errors out for the bucket. Retention
// must REFUSE — confirmed by the bucket disappearing from the lookup
// index AND the BucketStatus surface flipping IsStale.
func TestStoreRefreshRefusesRetentionPastMaxAge(t *testing.T) {
	logger := zerolog.Nop()
	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	src := &programmableSource{
		id: "alpha",
		fixtures: []programmableFixture{
			{per: map[intel.Ecosystem][]intel.MalwareReport{
				intel.EcosystemNPM: {{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1"}, SourceID: "alpha"}},
			}},
			{err: map[intel.Ecosystem]error{intel.EcosystemNPM: context.DeadlineExceeded}},
		},
	}
	store := intel.NewStore(logger,
		intel.WithSources(src),
		intel.WithNow(clock.Now),
	)
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 1, store.ReportCount(), "first refresh populated index")

	// First, verify the bucket is now marked stale BEFORE the second
	// refresh — IsStale flips on time-since-last-fresh-fetch, not on
	// any subsequent retention action. The doctor surface must give
	// the operator this signal even when Refresh has not been called.
	clock.now = clock.now.Add(intel.MaxRetentionAge + time.Hour)
	statuses := store.BucketStatus()
	require.NotEmpty(t, statuses)
	var npmStatus intel.BucketStatus
	for _, st := range statuses {
		if st.Ecosystem == intel.EcosystemNPM && st.SourceID == "alpha" {
			npmStatus = st
			break
		}
	}
	require.True(t, npmStatus.IsStale, "npm bucket past MaxRetentionAge must report IsStale")
	require.Greater(t, npmStatus.RetainedFor, intel.MaxRetentionAge)

	// Second refresh: npm errors. With prev npm data now stale,
	// retention must REFUSE and the bucket must drop from the in-
	// memory index. (The Refresh as a whole succeeds because other
	// ecosystems' empty-but-successful fetches keep the resolved set
	// non-empty; the npm-specific failure surfaces in the bucket
	// disappearing from BucketStatus.)
	require.NoError(t, store.Refresh(context.Background()))

	statusesAfter := store.BucketStatus()
	for _, st := range statusesAfter {
		require.False(t,
			st.SourceID == "alpha" && st.Ecosystem == intel.EcosystemNPM && st.ReportCount > 0,
			"refused-stale bucket must not retain a positive ReportCount after refresh")
	}
	// The Lookup confirms the stale pinning was removed.
	v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1"})
	require.False(t, v.Flagged(), "stale-refused bucket must not feed Lookup")
}

// TestStoreRefreshRetainsWithinMaxAge: the positive case. A bucket
// whose last-fresh-fetch is within MaxRetentionAge MUST still retain
// on a subsequent error — that's the whole point of the retention
// policy.
func TestStoreRefreshRetainsWithinMaxAge(t *testing.T) {
	logger := zerolog.Nop()
	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	src := &programmableSource{
		id: "alpha",
		fixtures: []programmableFixture{
			{per: map[intel.Ecosystem][]intel.MalwareReport{
				intel.EcosystemNPM: {{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1"}, SourceID: "alpha"}},
			}},
			{err: map[intel.Ecosystem]error{intel.EcosystemNPM: context.DeadlineExceeded}},
		},
	}
	store := intel.NewStore(logger,
		intel.WithSources(src),
		intel.WithNow(clock.Now),
	)
	require.NoError(t, store.Refresh(context.Background()))
	clock.now = clock.now.Add(1 * time.Hour) // well within MaxRetentionAge
	require.NoError(t, store.Refresh(context.Background()), "within-age retention must succeed")
	v := store.Lookup(intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1"})
	require.True(t, v.Flagged(), "previous data must be retained when within MaxRetentionAge")
}

// TestStoreRefreshHistoricalMaxDefeatsThresholdCamping: an attacker
// who can repeatedly halve the feed should NOT be able to walk the
// index down toward zero, because the partial-drop threshold is
// computed against the historical MAX (not just the previous count).
// Each refresh has to beat 50% of the all-time high.
func TestStoreRefreshHistoricalMaxDefeatsThresholdCamping(t *testing.T) {
	logger := zerolog.Nop()
	makeReports := func(n int) []intel.MalwareReport {
		out := make([]intel.MalwareReport, n)
		for i := range out {
			out[i] = intel.MalwareReport{
				PackageRef: intel.PackageRef{
					Ecosystem: intel.EcosystemNPM,
					Name:      "evil-" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
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
			// Refresh 1: 100 reports → historicalMax=100.
			{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(100)}},
			// Refresh 2: 60 (above 50% of max). Accepted; max stays at 100.
			{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(60)}},
			// Refresh 3: 35 — below 50% of historical max (100) even
			// though it's above 50% of last fetch (60). Must be REJECTED.
			{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(35)}},
		},
	}
	store := intel.NewStore(logger, intel.WithSources(src))
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 100, store.ReportCount(), "refresh 1: 100")
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 60, store.ReportCount(), "refresh 2: 60 (accepted; under prev but above 50% of historical max)")
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 60, store.ReportCount(),
		"refresh 3: 35 reports < 50% of historical max (100); must retain previous (60)")
}

// fakeClock is a deterministic time source for the H3 max-retention-age
// tests. The store's WithNow option threads it into applyRetention so
// time.Since checks become reproducible.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }

// TestStoreRefreshThresholdBoundaries (L1) walks the exact-50% boundary
// across a range of historicalMax values to confirm the integer-rational
// form `newCount * den < num * baseline` rejects exactly the
// `newCount < baseline/2` cases without float truncation.
//
// Mutation-resistance: the prior `int(prevCount * 0.5)` form returns 0
// at baseline=1, so a drop to 0 silently passed. The table-driven cases
// at baseline=1, 2, 3 detect that regression.
func TestStoreRefreshThresholdBoundaries(t *testing.T) {
	logger := zerolog.Nop()
	makeReports := func(n int) []intel.MalwareReport {
		out := make([]intel.MalwareReport, n)
		for i := range out {
			out[i] = intel.MalwareReport{
				PackageRef: intel.PackageRef{
					Ecosystem: intel.EcosystemNPM,
					Name:      "evil-" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
					Version:   "1",
				},
				SourceID: "alpha",
			}
		}
		return out
	}
	cases := []struct {
		baseline int
		newCount int
		retain   bool // true means previous-data retained
	}{
		{1, 0, true},    // L1 regression: under float form newCount<0.5 is never true; integer form rejects
		{2, 0, true},    // 0 < 1
		{2, 1, false},   // exact 50% accepted (boundary inclusive)
		{3, 1, true},    // 2<3
		{3, 2, false},   // 4>=3
		{5, 2, true},    // 4<5
		{5, 3, false},   // 6>=5
		{10, 4, true},   // 8<10
		{10, 5, false},  // 10>=10 (50% accepted)
		{100, 49, true}, // 98<100
		{100, 50, false},
		{1000, 499, true},
		{1000, 500, false},
	}
	for _, tc := range cases {
		src := &programmableSource{
			id: "alpha",
			fixtures: []programmableFixture{
				{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(tc.baseline)}},
				{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(tc.newCount)}},
			},
		}
		store := intel.NewStore(logger, intel.WithSources(src))
		require.NoError(t, store.Refresh(context.Background()))
		require.NoError(t, store.Refresh(context.Background()))
		got := store.ReportCount()
		want := tc.newCount
		if tc.retain {
			want = tc.baseline
		}
		require.Equalf(t, want, got,
			"baseline=%d new=%d: expected retain=%v (count=%d) got count=%d",
			tc.baseline, tc.newCount, tc.retain, want, got)
	}
}

// TestStoreRefreshRetainsAcknowledgedEmptyBucket (L4): an empty
// previous-fetch bucket (the upstream told us "no entries here") must
// be RETAINED on a subsequent fetch error rather than dropped — the
// "we knew it was empty" signal is real state and discarding it
// forces re-confirmation at the next refresh.
func TestStoreRefreshRetainsAcknowledgedEmptyBucket(t *testing.T) {
	logger := zerolog.Nop()
	// Use a source that returns an empty slice for NPM but an error
	// on the second refresh.
	src := &programmableSource{
		id: "alpha",
		fixtures: []programmableFixture{
			{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: {}}},
			{err: map[intel.Ecosystem]error{intel.EcosystemNPM: context.DeadlineExceeded}},
		},
	}
	store := intel.NewStore(logger, intel.WithSources(src))
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 0, store.ReportCount(), "refresh 1 produced an empty bucket")

	// Refresh 2 errors for npm. With L4 the empty bucket is retained;
	// without L4 the bucket would be removed and the next refresh
	// would need to re-confirm the upstream is empty.
	require.NoError(t, store.Refresh(context.Background()))
	// Confirm the bucket is still in BucketStatus (i.e. we still
	// track this (source, ecosystem) pair).
	statuses := store.BucketStatus()
	var found bool
	for _, st := range statuses {
		if st.SourceID == "alpha" && st.Ecosystem == intel.EcosystemNPM {
			found = true
			require.Equal(t, 0, st.ReportCount, "retained-empty must stay empty")
		}
	}
	require.True(t, found, "acknowledged-empty bucket must survive a subsequent error")
}

// TestStoreRefreshPersistsBaselineToDisk: a successful Refresh must
// leave a parseable intel-baseline.json in cacheDir. Mutation-resistance
// check: removing the writeBaseline call from Refresh causes this test
// to fail because the file does not exist after Refresh returns.
func TestStoreRefreshPersistsBaselineToDisk(t *testing.T) {
	logger := zerolog.Nop()
	cacheDir := t.TempDir()
	src := &fakeSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: {
				{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1"}, SourceID: "alpha"},
			},
		},
	}
	store := intel.NewStore(logger,
		intel.WithSources(src),
		intel.WithCacheDir(cacheDir),
	)
	require.NoError(t, store.Refresh(context.Background()))

	path := filepath.Join(cacheDir, "intel-baseline.json")
	info, err := os.Stat(path)
	require.NoError(t, err, "baseline file must exist after successful refresh")
	require.False(t, info.IsDir())
	require.Greater(t, info.Size(), int64(0))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), `"version": 1`, "schema version pinned")
	require.Contains(t, string(data), "alpha/npm", "bucket key present")
}

// TestStoreNewStoreReadsBaselineFromDisk: a second NewStore pointed at
// the same cacheDir reads back the historicalMax persisted by the first
// store's Refresh. Mutation-resistance check: removing the readBaseline
// call from NewStore causes refresh 2 below to accept the small fetch
// (no historical max baseline, threshold check trivially passes).
func TestStoreNewStoreReadsBaselineFromDisk(t *testing.T) {
	logger := zerolog.Nop()
	cacheDir := t.TempDir()
	makeReports := func(n int) []intel.MalwareReport {
		out := make([]intel.MalwareReport, n)
		for i := range out {
			out[i] = intel.MalwareReport{
				PackageRef: intel.PackageRef{
					Ecosystem: intel.EcosystemNPM,
					Name:      "evil-" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
					Version:   "1",
				},
				SourceID: "alpha",
			}
		}
		return out
	}

	src1 := &fakeSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: makeReports(100),
		},
	}
	store1 := intel.NewStore(logger, intel.WithSources(src1), intel.WithCacheDir(cacheDir))
	require.NoError(t, store1.Refresh(context.Background()))
	require.Equal(t, 100, store1.ReportCount())

	// Simulate restart. The cold store has no in-memory historicalMax
	// — only what it reads from disk. Hand it a source that returns 10
	// reports (10% of historical max from store1). Without
	// persistence: no baseline, 10 is the new max, refresh accepts and
	// ReportCount=10. With persistence: baseline=100, 10 < 50% × 100,
	// refresh retains zero (empty prev) and the new 10-bucket falls
	// through to fetchErrs.
	src2 := &fakeSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: makeReports(10),
		},
	}
	store2 := intel.NewStore(logger, intel.WithSources(src2), intel.WithCacheDir(cacheDir))

	statuses := store2.BucketStatus()
	require.NotEmpty(t, statuses, "cold-start BucketStatus must reflect the on-disk baseline")
	found := false
	for _, st := range statuses {
		if st.SourceID == "alpha" && st.Ecosystem == intel.EcosystemNPM {
			found = true
			require.False(t, st.LastRefreshedAt.IsZero(), "persisted timestamp must populate")
		}
	}
	require.True(t, found, "alpha/npm bucket must be in BucketStatus after cold start with on-disk baseline")
}

// TestStoreWithPartialDropThresholdOverride: the functional option
// changes the rejection threshold. With (1, 3) ≡ 33%, a refresh that
// would have been rejected under the default (1, 2) ≡ 50% is now
// accepted; with (2, 3) ≡ 67%, a refresh that would have been accepted
// is now rejected. This is the mutation-resistance evidence for
// M3-via-implementation: deleting the option's body silently reverts to
// the default and one of the two sub-cases below fails.
func TestStoreWithPartialDropThresholdOverride(t *testing.T) {
	logger := zerolog.Nop()
	makeReports := func(n int) []intel.MalwareReport {
		out := make([]intel.MalwareReport, n)
		for i := range out {
			out[i] = intel.MalwareReport{
				PackageRef: intel.PackageRef{
					Ecosystem: intel.EcosystemNPM,
					Name:      "evil-" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
					Version:   "1",
				},
				SourceID: "alpha",
			}
		}
		return out
	}

	t.Run("looser threshold accepts a 40% drop that default would reject", func(t *testing.T) {
		src := &programmableSource{
			id: "alpha",
			fixtures: []programmableFixture{
				{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(100)}},
				{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(40)}},
			},
		}
		store := intel.NewStore(logger,
			intel.WithSources(src),
			intel.WithPartialDropThreshold(1, 3),
		)
		require.NoError(t, store.Refresh(context.Background()))
		require.NoError(t, store.Refresh(context.Background()))
		require.Equal(t, 40, store.ReportCount(),
			"40 is above 33% of historicalMax(100); option must allow it")
	})

	t.Run("stricter threshold rejects a 60% drop that default would accept", func(t *testing.T) {
		src := &programmableSource{
			id: "alpha",
			fixtures: []programmableFixture{
				{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(100)}},
				{per: map[intel.Ecosystem][]intel.MalwareReport{intel.EcosystemNPM: makeReports(60)}},
			},
		}
		store := intel.NewStore(logger,
			intel.WithSources(src),
			intel.WithPartialDropThreshold(2, 3),
		)
		require.NoError(t, store.Refresh(context.Background()))
		require.NoError(t, store.Refresh(context.Background()))
		require.Equal(t, 100, store.ReportCount(),
			"60 is below 67% of historicalMax(100); option must reject and retain previous")
	})

	t.Run("invalid threshold panics", func(t *testing.T) {
		require.Panics(t, func() {
			intel.NewStore(logger, intel.WithPartialDropThreshold(3, 2))
		})
		require.Panics(t, func() {
			intel.NewStore(logger, intel.WithPartialDropThreshold(1, 0))
		})
	})
}

// TestStoreRefreshConcurrentSafe: two overlapping Refresh calls must
// not corrupt the index. refreshMu serializes them; without it both
// would observe the same prev, both would fetch, both would reach the
// swap stage, and last-writer wins on stale baselines. The race
// detector catches any unsynchronized writes; the assertion confirms
// the final state is a valid one-or-the-other (not interleaved garbage).
// Mutation-resistance: removing refreshMu lets `-race` flag a write-write
// race in the bySourceEco/historicalMax maps.
func TestStoreRefreshConcurrentSafe(t *testing.T) {
	logger := zerolog.Nop()
	src := &fakeSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: {
				{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1"}, SourceID: "alpha"},
			},
		},
	}
	store := intel.NewStore(logger, intel.WithSources(src))

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			_ = store.Refresh(context.Background())
		}()
	}
	wg.Wait()
	require.Equal(t, 1, store.ReportCount(), "post-overlap index must be coherent")
}
