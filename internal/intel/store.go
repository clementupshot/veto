package intel

import (
	"context"
	stderrors "errors"
	"sync"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

// Store is the deduplicated, in-memory lookup index built from one or more
// Sources. Implementations must be safe for concurrent Lookup calls while a
// Refresh is in flight; Lookup is the hot path and runs on every install.
type Store interface {
	// Lookup returns a Verdict for the given package reference. Matching is
	// (ecosystem, name, version): an exact-version match returns reports that
	// specifically named that version; if the lookup ref has an empty Version,
	// reports for any version of the package are returned.
	Lookup(ref PackageRef) Verdict

	// Refresh re-fetches all configured sources concurrently and atomically
	// replaces the in-memory index on success. Per-source errors are logged
	// but do not abort the whole refresh; ErrUnsupportedEcosystem is silently
	// skipped. Returns the aggregate error only when every source failed.
	Refresh(ctx context.Context) error

	// SourceIDs returns the IDs of all sources registered with this Store, in
	// registration order.
	SourceIDs() []string

	// ReportCount returns the total number of indexed (source, package, version)
	// tuples. Callers can use this to fail closed when the index is implausibly
	// small (e.g. an upstream feed returning an empty payload).
	ReportCount() int

	// BucketStatus returns one entry per (source, ecosystem) bucket
	// that the store has any state for — either a successful fetch in
	// the current process lifetime, or a baseline loaded from
	// `<cache_dir>/intel-baseline.json` at startup. Used by `veto
	// doctor` to flag retained-from-stale-fetch buckets so an operator
	// can SEE the difference between "fresh data" and "data retained
	// from a week ago after the upstream went dark." Without this
	// surface the per-bucket retention policy (introduced by the
	// hardening pass) silently converted LOUD fetch failures into
	// SILENT stale pinning.
	BucketStatus() []BucketStatus
}

// BucketStatus describes one (source, ecosystem) bucket's freshness for
// diagnostic surfaces. LastRefreshedAt is the upstream-fetch timestamp;
// zero value means "never fetched in the current process AND no on-disk
// baseline." IsStale flips true once the bucket has been retained past
// MaxRetentionAge — at that point retention is REFUSED on the next
// failed refresh.
type BucketStatus struct {
	SourceID        string
	Ecosystem       Ecosystem
	ReportCount     int
	LastRefreshedAt time.Time
	RetainedFor     time.Duration
	IsStale         bool
}

// defaultThresholdNum / defaultThresholdDen express the partial-drop
// threshold as a rational so the comparison can be evaluated in
// integer arithmetic and stay exact at every bucket size. A new fetch
// is rejected when
//
//	newCount * den < num * historicalMax
//
// Default (1, 2) = "reject below 50%." Comparing against the all-time
// MAX (not the previous fetch) is the key threshold-camping defence:
// every refresh has to beat 50% of the historical high, not 50% of
// last time, so an attacker cannot walk the index down by repeatedly
// halving it.
//
// Why integer rationals over float64: at baseline=1 the float form
// `int(historicalMax * 0.5) = 0` made `newCount < 0` unreachable, so
// any single-entry bucket could be silently dropped to 0 entries. The
// rational form `0 * 2 < 1 * 1 → true` rejects the empty replacement
// correctly. (L1 in the audit; see TestStoreRefreshHistoricalMaxDefeatsThresholdCamping
// for the regression.)
const (
	defaultThresholdNum = 1
	defaultThresholdDen = 2
)

// MaxRetentionAge bounds how long a (source, ecosystem) bucket may be
// retained from a previous successful refresh while subsequent
// refreshes keep failing. Beyond this age the bucket is treated as
// unrecoverable and falls back to the LOUD failure mode (returned in
// fetchErrs) instead of silently pinning ancient data — the negative-
// trade-off of the retention pipeline introduced in the hardening pass.
//
// Why 7 days: malware feeds publish new IoCs daily and an operator SLA
// for "intel layer disagrees with reality" is on the order of a week
// before false negatives become routine. The retention policy is for
// transient MITM / upstream-outage; permanent attacks must surface
// eventually.
//
// Exported so `veto doctor` can compute and display per-bucket
// freshness against the same threshold the retention path uses.
const MaxRetentionAge = 7 * 24 * time.Hour

// versionKey targets exact (ecosystem, name, version) lookups.
type versionKey struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
}

// nameKey targets "any version of (ecosystem, name)" lookups. Used both for
// reports that flag every version of a package, and for unversioned install
// requests where the user is implicitly accepting whatever version resolves.
type nameKey struct {
	Ecosystem Ecosystem
	Name      string
}

// sourceEcoKey identifies the unit of work the store retains per Refresh:
// one (source, ecosystem) fetch. Retention happens at this granularity so a
// failure in (aikido, pypi) doesn't drag down (aikido, npm) — and so a
// network MITM that drops a single feed can't quietly remove every aikido
// finding from the lookup index.
type sourceEcoKey struct {
	SourceID  string
	Ecosystem Ecosystem
}

// dedupKey identifies a single MalwareReport in the deduplication pass.
// A struct (rather than a concatenated string) avoids the theoretical
// collision where any field contains the separator character, and the
// extra type-safety makes the dedup intent obvious at the call site.
type dedupKey struct {
	SourceID  string
	Ecosystem Ecosystem
	Name      string
	Version   string
}

type memStore struct {
	logger  zerolog.Logger
	sources []Source

	// refreshMu serialises Refresh against itself. The three-stage
	// pipeline (RLock snapshot prev → unlocked fetch → WLock swap) is
	// race-prone if two Refresh calls overlap: both would observe the
	// same `prev`, both would fetch the network, both would reach the
	// swap stage and last-writer wins on the in-memory index while
	// retention decisions were computed against stale baselines.
	// Lookups remain unblocked (they take only the read side of mu).
	refreshMu sync.Mutex

	mu        sync.RWMutex
	byVersion map[versionKey][]MalwareReport
	byName    map[nameKey][]MalwareReport
	// bySourceEco retains the most recent successful fetch of each
	// (source, ecosystem) pair so the next Refresh can decide, per
	// pair, whether the new data is plausible (use it) or implausibly
	// small (retain the previous slice and log a warning). Read +
	// written under mu alongside byVersion/byName.
	bySourceEco map[sourceEcoKey][]MalwareReport
	// lastRefreshedAt stamps the wall-clock time of the last
	// upstream-fetch acceptance per bucket (NOT retention-keep). The
	// retention path consults this to enforce MaxRetentionAge — once a
	// bucket's last-fresh-fetch ages past the cap, retention is
	// REFUSED and the failure surfaces. Persisted to
	// <cacheDir>/intel-baseline.json to survive restart (the cold-start
	// MITM-window mitigation).
	lastRefreshedAt map[sourceEcoKey]time.Time
	// historicalMax tracks the largest count ever observed for each
	// bucket. The partial-drop threshold is compared against this max
	// (not just the previous count) so an attacker cannot
	// threshold-camp by repeatedly halving the index: each refresh
	// would still have to beat 50% of the all-time max. Loaded from /
	// persisted to intel-baseline.json alongside lastRefreshedAt.
	historicalMax map[sourceEcoKey]int

	// cacheDir is the directory containing intel-baseline.json. Empty
	// when the caller did not configure persistence (programmatic
	// tests, e.g.) — disables disk read+write but keeps in-memory
	// freshness tracking working.
	cacheDir string
	// now is the clock used for freshness timestamps. Defaults to
	// time.Now and overridable by tests via WithNow.
	now func() time.Time

	// thresholdNum / thresholdDen are the partial-drop threshold as
	// a rational. See defaultThresholdNum/Den for the rationale.
	thresholdNum int
	thresholdDen int
}

var _ Store = (*memStore)(nil)

// StoreOption configures a memStore at construction time. Functional
// options keep the public surface stable as small, mostly-independent
// tunings accrete (sources, cache dir for the freshness ledger, clock
// injection for tests).
type StoreOption func(*memStore)

// WithSources registers the Source implementations the Store fetches
// from. Replaces any previously-set sources on the same builder.
func WithSources(sources ...Source) StoreOption {
	return func(s *memStore) { s.sources = sources }
}

// WithCacheDir wires the on-disk freshness ledger. When set, Refresh
// persists per-bucket counts + timestamps to
// <dir>/intel-baseline.json (see baseline.go) and NewStore loads any
// existing file at startup. Empty / unset disables persistence —
// useful in tests and in deployments where the daemon's process
// lifetime is long enough not to need cold-start recovery.
func WithCacheDir(dir string) StoreOption {
	return func(s *memStore) { s.cacheDir = dir }
}

// WithNow injects a clock. Defaults to time.Now. Set in tests to
// validate MaxRetentionAge behaviour deterministically.
func WithNow(now func() time.Time) StoreOption {
	return func(s *memStore) {
		if now != nil {
			s.now = now
		}
	}
}

// WithPartialDropThreshold overrides the per-(source, ecosystem)
// partial-drop threshold the retention pipeline uses to reject
// implausibly small fetches. The threshold is expressed as a rational
// num/den so the comparison is exact integer arithmetic at every
// bucket size — see defaultThresholdNum/Den for why the float form
// silently corrupted small buckets.
//
// Reject condition: newCount * den < num * historicalMax.
//
// Default (1, 2) = 50%. Pass e.g. (1, 3) for sources that legitimately
// curate aggressively (and so cross 50% boundary without an attack
// being in flight) and (2, 3) for sources whose feed size is stable
// enough that even a 33% drop is suspicious. Supersedes the doc-only
// fix in upstream commit 45f316a, which removed the doc reference to
// this option when no implementation existed.
//
// Panics on non-positive den or out-of-range num so configuration
// mistakes cannot silently disable the floor. The store would much
// rather refuse to construct than swap in a configuration that lets
// every refresh through.
func WithPartialDropThreshold(num, den int) StoreOption {
	return func(s *memStore) {
		if den <= 0 || num < 0 || num > den {
			panic("intel.WithPartialDropThreshold: require 0 <= num <= den and den > 0")
		}
		s.thresholdNum = num
		s.thresholdDen = den
	}
}

// NewStore builds a Store. Use WithSources to register the upstream
// feeds, WithCacheDir for the on-disk freshness ledger, and WithNow
// in tests for deterministic timing. Without WithSources the store
// is backed by a single NopSource — useful only for tests that don't
// drive Refresh.
func NewStore(logger zerolog.Logger, opts ...StoreOption) Store {
	s := &memStore{
		logger: logger.With().Str("component", "intel.store").Logger(),

		byVersion:       make(map[versionKey][]MalwareReport),
		byName:          make(map[nameKey][]MalwareReport),
		bySourceEco:     make(map[sourceEcoKey][]MalwareReport),
		lastRefreshedAt: make(map[sourceEcoKey]time.Time),
		historicalMax:   make(map[sourceEcoKey]int),
		now:             time.Now,
		thresholdNum:    defaultThresholdNum,
		thresholdDen:    defaultThresholdDen,
	}
	for _, opt := range opts {
		opt(s)
	}
	// Default-source fallback: a Store with zero sources would have an
	// empty AllEcosystems × sources loop and Refresh would fail with
	// "no intel source produced data" on every call. NopSource keeps
	// the lifecycle valid for tests that don't drive Refresh.
	if len(s.sources) == 0 {
		s.sources = []Source{NopSource{}}
	}
	// Load the on-disk freshness ledger if configured. Treat any error
	// as "no baseline" — the ledger is a hint, not a source of truth,
	// and a corrupted file must not block Refresh. The LOUD
	// minHealthyReportCount floor is the real safety net.
	if s.cacheDir != "" {
		last, maxes, err := readBaseline(s.cacheDir)
		if err != nil {
			s.logger.Warn().Err(err).Str("dir", s.cacheDir).
				Msg("intel-baseline.json present but unreadable; cold-start without freshness baseline")
		} else {
			s.lastRefreshedAt = last
			s.historicalMax = maxes
		}
	}
	return s
}

// Lookup implements Store. Semantics:
//
//   - ref.Version == "":   unpinned install. Returns every report against any
//     version of the package.
//   - ref.Version != "":   pinned install. Returns reports for that exact
//     version, AND any other report for the same name — every source we
//     ingest is malware-only, so a name match at any version is a hit.
//
// Why name-match wins regardless of recorded version: aikido / openssf /
// osv / pypa entries assert "this package name is malicious." The
// Version field on the report is the version the source happened to
// sample, not "only this version is bad." Treating a different-version
// query as a miss would let an attacker republish the same name under a
// new version and bypass the gate; a lockfile pinning a version the
// source didn't sample would also slip through. We refuse on name.
//
// If a future source introduces version-specific non-malware advisories,
// this policy must be revisited — but every source today is malware-only
// (filtered to MAL-* IDs / aikido's malware feed), so name = refuse is
// the right default.
func (s *memStore) Lookup(ref PackageRef) Verdict {
	s.mu.RLock()
	defer s.mu.RUnlock()

	verdict := Verdict{Ref: ref}

	if ref.Version == "" {
		if reports, ok := s.byName[nameKey{ref.Ecosystem, ref.Name}]; ok {
			verdict.Reports = append(verdict.Reports, reports...)
		}
		return verdict
	}

	// Exact-version hits go first so their position in the verdict
	// reflects "this is the version the upstream feed flagged."
	if reports, ok := s.byVersion[versionKey{ref.Ecosystem, ref.Name, ref.Version}]; ok {
		verdict.Reports = append(verdict.Reports, reports...)
	}
	// Name-match: include every other report for this name. The
	// equality test at line below dedups against the exact-version
	// hits above so a single entry doesn't appear twice in the
	// refusal output.
	if reports, ok := s.byName[nameKey{ref.Ecosystem, ref.Name}]; ok {
		for _, r := range reports {
			if r.Version == ref.Version {
				continue
			}
			verdict.Reports = append(verdict.Reports, r)
		}
	}

	return verdict
}

// fetchResult bundles one (source, ecosystem) fetch outcome.
type fetchResult struct {
	key     sourceEcoKey
	reports []MalwareReport
	err     error
}

// Refresh implements Store.
//
// Three-stage pipeline:
//
//  1. fetchAll: concurrent per-(source, ecosystem) fetch.
//  2. applyRetention: per-(source, ecosystem) decision to USE the new
//     slice or RETAIN the previous one. Retention triggers when:
//     - the fetch returned an error (and we have previous data within
//     MaxRetentionAge), OR
//     - the new count drops below partialDropThreshold * historicalMax
//     This closes the partial-refresh hole where a single MITM'd feed
//     could silently wipe an entire source's coverage. The
//     MaxRetentionAge bound is the negative-trade-off mitigation:
//     retention must not become PERMANENT stale-pinning.
//  3. reindex+swap: build byVersion / byName from the resolved
//     per-source-ecosystem slices, then swap under the write lock.
//
// Fail-closed conditions (Refresh returns an error and the in-memory
// index is left unchanged):
//
//   - every (source, ecosystem) fetch returned a real error AND every
//     bucket either had no prior data OR was too stale to retain.
//   - every (source, ecosystem) fetch returned ErrUnsupportedEcosystem
//     (the prior code accepted this case as "success" and would have
//     swapped in an empty index — M4 in the audit).
func (s *memStore) Refresh(ctx context.Context) error {
	// Serialise Refresh callers. Lookup uses mu (RWMutex) and is
	// unaffected; refreshMu only guards the snapshot/fetch/swap
	// pipeline from entering itself concurrently. Without this, two
	// overlapping Refresh calls would observe the same prev, both
	// fetch the network, and both reach the swap stage — last writer
	// wins on the in-memory index while retention decisions were
	// computed against stale baselines.
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	results := s.fetchAll(ctx)

	// Snapshot previous bySourceEco + retention metadata under the
	// read lock so retention can fall back to them without holding
	// the write lock during the decision. Slice contents are never
	// mutated post-publication.
	s.mu.RLock()
	prevBySourceEco := make(map[sourceEcoKey][]MalwareReport, len(s.bySourceEco))
	for k, v := range s.bySourceEco {
		prevBySourceEco[k] = v
	}
	prevLast := make(map[sourceEcoKey]time.Time, len(s.lastRefreshedAt))
	for k, v := range s.lastRefreshedAt {
		prevLast[k] = v
	}
	prevMax := make(map[sourceEcoKey]int, len(s.historicalMax))
	for k, v := range s.historicalMax {
		prevMax[k] = v
	}
	s.mu.RUnlock()

	now := s.now()
	resolved, nextLast, nextMax, retentionInfo, fetchErrs := s.applyRetention(
		results, prevBySourceEco, prevLast, prevMax, now)

	if len(resolved) == 0 {
		if len(fetchErrs) > 0 {
			return errors.WithNew("all intel sources failed to refresh").
				Set("failures", len(fetchErrs)).
				Cause(stderrors.Join(fetchErrs...))
		}
		// Every (source, ecosystem) returned ErrUnsupportedEcosystem
		// AND there was no prior data to retain. Without successful
		// fetches we cannot safely swap in a (presumably empty) index.
		return errors.WithNew("no intel source produced data").
			Set("hint", "check VETO_SOURCES configuration and feed ecosystem support")
	}

	nextByVersion, nextByName, totalReports := buildIndices(resolved)

	s.mu.Lock()
	s.byVersion = nextByVersion
	s.byName = nextByName
	s.bySourceEco = resolved
	s.lastRefreshedAt = nextLast
	s.historicalMax = nextMax
	s.mu.Unlock()

	// Persist the freshness ledger so a restart can pick up where we
	// left off. Best-effort — the in-memory index is already swapped
	// in; a persistence failure should not refuse the Refresh.
	if err := writeBaseline(s.cacheDir, resolved, nextLast, nextMax); err != nil {
		s.logger.Warn().Err(err).Msg("persist intel-baseline.json failed; retention state will be lost on restart")
	}

	s.logger.Info().
		Int("reports", totalReports).
		Int("source_ecos_fresh", retentionInfo.fresh).
		Int("source_ecos_retained", retentionInfo.retained).
		Int("source_ecos_refused_stale", retentionInfo.refusedStale).
		Int("source_ecos_failed", len(fetchErrs)).
		Msg("intel store refreshed")

	return nil
}

// fetchAll runs every (source, ecosystem) fetch concurrently and collects
// every result. Caller decides what to do with errors / empty slices.
func (s *memStore) fetchAll(ctx context.Context) []fetchResult {
	out := make(chan fetchResult, len(s.sources)*len(AllEcosystems))
	var wg sync.WaitGroup
	for _, src := range s.sources {
		for _, eco := range AllEcosystems {
			wg.Add(1)
			go func(src Source, eco Ecosystem) {
				defer wg.Done()
				// If the caller already cancelled the context, skip
				// the per-source network call entirely instead of
				// fanning out and immediately failing. Cheap, and
				// keeps shutdown-time refresh logs free of N stale
				// "ctx cancelled" errors. (PR #1 review nit.)
				select {
				case <-ctx.Done():
					out <- fetchResult{
						key: sourceEcoKey{SourceID: src.ID(), Ecosystem: eco},
						err: ctx.Err(),
					}
					return
				default:
				}
				defer func() {
					// A panicking Source MUST NOT crash the daemon —
					// fetchAll is one of two paths Refresh dispatches
					// concurrently per source/ecosystem (the other is
					// applyRetention which runs sequentially). Recover
					// converts the panic into a regular fetch error so
					// the retention layer treats this bucket the same
					// as an upstream timeout: retain prior data, or
					// surface a failure when nothing to retain.
					if r := recover(); r != nil {
						out <- fetchResult{
							key: sourceEcoKey{SourceID: src.ID(), Ecosystem: eco},
							err: errors.WithNew("source panicked during Fetch").
								Set("panic", r),
						}
					}
				}()
				reports, err := src.Fetch(ctx, eco)
				out <- fetchResult{
					key:     sourceEcoKey{SourceID: src.ID(), Ecosystem: eco},
					reports: reports,
					err:     err,
				}
			}(src, eco)
		}
	}
	go func() { wg.Wait(); close(out) }()

	results := make([]fetchResult, 0, len(s.sources)*len(AllEcosystems))
	for r := range out {
		results = append(results, r)
	}
	return results
}

// retentionStats reports how the per-bucket retention decisions broke
// down this refresh. Logged for observability; the
// `source_ecos_refused_stale` counter is the most operationally
// interesting one — it ticks up when retention was the right
// recovery but the bucket has been retained for so long that we now
// refuse to keep pinning it.
type retentionStats struct {
	fresh        int
	retained     int
	refusedStale int
}

// applyRetention turns raw fetch results into the resolved
// per-(source, ecosystem) report slices that will populate the next
// index. Per-bucket retention triggers on either a fetch error or a
// drop below partialDropThreshold * historicalMax, and is itself
// bounded by MaxRetentionAge so a sustained MITM cannot pin stale data
// indefinitely.
//
// Inputs and outputs:
//   - prev / prevLast / prevMax: snapshot of the store's retention
//     metadata at the start of this Refresh.
//   - returns (resolved, nextLast, nextMax, stats, errs) — the
//     nextLast/nextMax maps include ONLY buckets that ended up in
//     resolved (fresh acceptance OR within-cap retention). Buckets
//     refused for staleness or with no recoverable state at all are
//     dropped from both maps so the on-disk baseline doesn't keep
//     remembering them.
//   - fetchErrs include buckets that errored AND had no eligible
//     prior data (no prev, OR prev exists but is older than
//     MaxRetentionAge).
func (s *memStore) applyRetention(
	results []fetchResult,
	prev map[sourceEcoKey][]MalwareReport,
	prevLast map[sourceEcoKey]time.Time,
	prevMax map[sourceEcoKey]int,
	now time.Time,
) (map[sourceEcoKey][]MalwareReport, map[sourceEcoKey]time.Time, map[sourceEcoKey]int, retentionStats, []error) {
	resolved := make(map[sourceEcoKey][]MalwareReport)
	nextLast := make(map[sourceEcoKey]time.Time)
	nextMax := make(map[sourceEcoKey]int)
	var stats retentionStats
	var fetchErrs []error

	// retainOrRefuse encapsulates the MaxRetentionAge bound. Called
	// from BOTH the fetch-error path AND the partial-drop path so the
	// staleness check happens uniformly. Returns true when retention
	// was kept; false when the bucket should fall through to the LOUD
	// failure path.
	retainOrRefuse := func(key sourceEcoKey, prevReports []MalwareReport, reason string) bool {
		lastFresh, hadStamp := prevLast[key]
		if hadStamp && !lastFresh.IsZero() && now.Sub(lastFresh) > MaxRetentionAge {
			stats.refusedStale++
			s.logger.Warn().
				Str("source", key.SourceID).
				Str("ecosystem", string(key.Ecosystem)).
				Time("last_fresh_fetch", lastFresh).
				Dur("retained_for", now.Sub(lastFresh)).
				Dur("max_retention_age", MaxRetentionAge).
				Str("reason", reason).
				Msg("refusing to retain bucket past MaxRetentionAge; surfacing failure")
			return false
		}
		resolved[key] = prevReports
		// Retention preserves prior timestamp and rolling-max. We
		// deliberately do NOT bump lastRefreshedAt on a retention-keep
		// — that's the whole point of the freshness ledger: only
		// upstream-acceptance counts.
		if hadStamp {
			nextLast[key] = lastFresh
		}
		if prevHigh, ok := prevMax[key]; ok && prevHigh > 0 {
			nextMax[key] = prevHigh
		} else {
			nextMax[key] = len(prevReports)
		}
		stats.retained++
		return true
	}

	for _, r := range results {
		// ErrUnsupportedEcosystem is not a failure — the source simply
		// doesn't cover this ecosystem. Skip without contributing to
		// either fresh or retained.
		if r.err != nil && stderrors.Is(r.err, ErrUnsupportedEcosystem) {
			continue
		}

		if r.err != nil {
			// Real fetch error. Retain prior data if any AND within
			// MaxRetentionAge; otherwise record the failure so the
			// caller can decide whether the Refresh as a whole is
			// salvageable. Note: we retain an empty-but-recorded
			// previous state (the brand-new-ecosystem case) so a
			// transient error doesn't bury the "knew it was empty"
			// signal — L4 in the audit.
			if prevReports, ok := prev[r.key]; ok {
				if retainOrRefuse(r.key, prevReports, "fetch failed") {
					msg := "source fetch failed; retaining previous data"
					if len(prevReports) == 0 {
						// L4: distinguish "we had no entries last time"
						// from "we had data and are pinning it." The
						// former is real state — the upstream once told
						// us this (source, ecosystem) tuple is empty
						// — and dropping it would force re-confirmation
						// at the next refresh.
						msg = "source fetch failed; preserving acknowledged-empty bucket"
					}
					s.logger.Warn().
						Err(r.err).
						Str("source", r.key.SourceID).
						Str("ecosystem", string(r.key.Ecosystem)).
						Int("retained_reports", len(prevReports)).
						Msg(msg)
					continue
				}
				// Retention refused for staleness. Fall through to
				// the LOUD failure record below.
			} else {
				s.logger.Warn().
					Err(r.err).
					Str("source", r.key.SourceID).
					Str("ecosystem", string(r.key.Ecosystem)).
					Msg("source fetch failed; no prior fetch recorded — nothing to retain")
			}
			fetchErrs = append(fetchErrs,
				errors.With(r.err, "fetch failed").
					Set("source", r.key.SourceID).
					Set("ecosystem", string(r.key.Ecosystem)))
			continue
		}

		// Fetch succeeded. Decide between new and previous based on
		// partial-drop threshold compared against the rolling-max
		// (NOT just the previous count). Comparing against the
		// historical max defeats the threshold-camping attack where
		// each refresh halves the index and always passes the prev-
		// only check.
		newCount := len(r.reports)
		prevReports, hadPrev := prev[r.key]
		baseline := prevMax[r.key]
		// Configurable threshold as a rational (num/den) so the
		// comparison stays in exact integer arithmetic at every
		// bucket size. Default (1, 2) reproduces the old "below 50%
		// retain" — `newCount * 2 < 1 * baseline`. L1 in the audit:
		// the prior `int(prevCount * 0.5)` truncation let baseline=1
		// drop to zero without tripping the floor; the rational form
		// rejects 0 * 2 < 1 * 1 correctly.
		if hadPrev && baseline > 0 && newCount*s.thresholdDen < s.thresholdNum*baseline {
			if retainOrRefuse(r.key, prevReports, "implausibly few reports") {
				s.logger.Warn().
					Str("source", r.key.SourceID).
					Str("ecosystem", string(r.key.Ecosystem)).
					Int("new_count", newCount).
					Int("historical_max", baseline).
					Int("threshold_num", s.thresholdNum).
					Int("threshold_den", s.thresholdDen).
					Msg("source returned implausibly few reports; retaining previous data")
				continue
			}
			// Refused for staleness. Fall through and accept the
			// (suspiciously small) new data — the LOUD signal is now
			// the retentionInfo.refusedStale counter + doctor's
			// per-bucket display, not silent pinning.
			fetchErrs = append(fetchErrs,
				errors.WithNew("partial-drop retention refused for staleness").
					Set("source", r.key.SourceID).
					Set("ecosystem", string(r.key.Ecosystem)).
					Set("new_count", newCount).
					Set("historical_max", baseline))
			continue
		}

		// Fresh acceptance. Stamp last-fresh-fetch and update rolling
		// max.
		resolved[r.key] = r.reports
		nextLast[r.key] = now
		if newCount > baseline {
			nextMax[r.key] = newCount
		} else {
			nextMax[r.key] = baseline
		}
		stats.fresh++
	}

	return resolved, nextLast, nextMax, stats, fetchErrs
}

// buildIndices flattens per-(source, ecosystem) slices into the two
// lookup maps the Store serves Lookups from. Dedup is keyed by
// dedupKey so that distinct sources reporting the same package stay
// distinct, but a single source reporting the same finding twice
// (unusual but legal in OSV-style feeds) collapses to one entry.
func buildIndices(resolved map[sourceEcoKey][]MalwareReport) (
	map[versionKey][]MalwareReport,
	map[nameKey][]MalwareReport,
	int,
) {
	byVersion := make(map[versionKey][]MalwareReport)
	byName := make(map[nameKey][]MalwareReport)
	seen := make(map[dedupKey]struct{})
	total := 0
	for _, reports := range resolved {
		for _, report := range reports {
			k := dedupKey{
				SourceID:  report.SourceID,
				Ecosystem: report.Ecosystem,
				Name:      report.Name,
				Version:   report.Version,
			}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			if report.Version != "" {
				vk := versionKey{report.Ecosystem, report.Name, report.Version}
				byVersion[vk] = append(byVersion[vk], report)
			}
			nk := nameKey{report.Ecosystem, report.Name}
			byName[nk] = append(byName[nk], report)
			total++
		}
	}
	return byVersion, byName, total
}

// SourceIDs implements Store.
func (s *memStore) SourceIDs() []string {
	out := make([]string, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, src.ID())
	}
	return out
}

// ReportCount implements Store. Sums the size of every value slice in the
// version-keyed index plus name-only reports (those with empty Version, kept
// only in byName). The number is a coarse signal of intel-store health — a
// healthy store has hundreds of thousands of reports.
func (s *memStore) ReportCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	for _, reports := range s.byVersion {
		total += len(reports)
	}
	// Add reports that are name-only (no entry in byVersion). These
	// are the "any version of this package is bad" findings.
	for _, reports := range s.byName {
		for _, r := range reports {
			if r.Version == "" {
				total++
			}
		}
	}
	return total
}

// BucketStatus implements Store. Returns one entry per known bucket,
// sorted by SourceID then Ecosystem for deterministic doctor output.
// Empty when no Refresh has succeeded AND no on-disk baseline was
// loaded — the operator sees a single "store is empty" line from the
// caller instead of N empty rows.
func (s *memStore) BucketStatus() []BucketStatus {
	s.mu.RLock()
	now := s.now()
	out := make([]BucketStatus, 0, len(s.bySourceEco))
	keys := make(map[sourceEcoKey]struct{}, len(s.bySourceEco))
	for k := range s.bySourceEco {
		keys[k] = struct{}{}
	}
	for k := range s.lastRefreshedAt {
		keys[k] = struct{}{}
	}
	for k := range keys {
		last := s.lastRefreshedAt[k]
		var retained time.Duration
		if !last.IsZero() {
			retained = now.Sub(last)
		}
		out = append(out, BucketStatus{
			SourceID:        k.SourceID,
			Ecosystem:       k.Ecosystem,
			ReportCount:     len(s.bySourceEco[k]),
			LastRefreshedAt: last,
			RetainedFor:     retained,
			IsStale:         !last.IsZero() && retained > MaxRetentionAge,
		})
	}
	s.mu.RUnlock()

	// Stable order — operators read this every time they run doctor;
	// jitter would obscure regressions.
	sortBucketStatus(out)
	return out
}

func sortBucketStatus(out []BucketStatus) {
	// Simple insertion sort; the slice is at most ~16 entries (sources
	// × ecosystems) so this is cheaper than pulling in sort.Slice and
	// keeps the implementation dependency-free.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if a.SourceID < b.SourceID ||
				(a.SourceID == b.SourceID && a.Ecosystem <= b.Ecosystem) {
				break
			}
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
}
