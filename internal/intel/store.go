package intel

import (
	"context"
	stderrors "errors"
	"sync"

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
}

// NewStore builds a Store backed by the given sources. The Store is empty
// until Refresh is called.
func NewStore(logger zerolog.Logger, sources ...Source) Store {
	if len(sources) == 0 {
		sources = []Source{NopSource{}}
	}
	return &memStore{
		logger:    logger.With().Str("component", "intel.store").Logger(),
		sources:   sources,
		byVersion: make(map[versionKey][]MalwareReport),
		byName:    make(map[nameKey][]MalwareReport),
	}
}

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

type memStore struct {
	logger  zerolog.Logger
	sources []Source

	mu        sync.RWMutex
	byVersion map[versionKey][]MalwareReport
	byName    map[nameKey][]MalwareReport
}

var _ Store = (*memStore)(nil)

// Lookup implements Store. Semantics:
//
//   - ref.Version == "":   unpinned install. Returns every report against any
//     version of the package — the user is implicitly accepting whatever
//     version resolves, so any flagged version is a hit.
//   - ref.Version != "":   pinned install. Returns reports for that exact
//     version, plus any "all versions" reports (those stored with Version="").
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

	if reports, ok := s.byVersion[versionKey{ref.Ecosystem, ref.Name, ref.Version}]; ok {
		verdict.Reports = append(verdict.Reports, reports...)
	}
	// "all versions of this package" reports (stored with empty Version on
	// the report itself) live only in byName; pick them up too.
	if reports, ok := s.byName[nameKey{ref.Ecosystem, ref.Name}]; ok {
		for _, r := range reports {
			if r.Version == "" {
				verdict.Reports = append(verdict.Reports, r)
			}
		}
	}

	return verdict
}

// Refresh implements Store.
func (s *memStore) Refresh(ctx context.Context) error {
	type result struct {
		sourceID string
		reports  []MalwareReport
		err      error
	}

	results := make(chan result, len(s.sources)*len(AllEcosystems))
	var wg sync.WaitGroup

	for _, src := range s.sources {
		for _, eco := range AllEcosystems {
			wg.Add(1)
			go func(src Source, eco Ecosystem) {
				defer wg.Done()
				reports, err := src.Fetch(ctx, eco)
				results <- result{sourceID: src.ID(), reports: reports, err: err}
			}(src, eco)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	nextByVersion := make(map[versionKey][]MalwareReport)
	nextByName := make(map[nameKey][]MalwareReport)
	dedup := make(map[string]struct{}) // dedup within a refresh by source+ref

	totalReports := 0
	successCount := 0
	failureCount := 0
	var fetchErrs []error

	for r := range results {
		if r.err != nil {
			if stderrors.Is(r.err, ErrUnsupportedEcosystem) {
				continue
			}
			failureCount++
			fetchErrs = append(fetchErrs, errors.With(r.err, "fetch failed").Set("source", r.sourceID))
			s.logger.Warn().Err(r.err).Str("source", r.sourceID).Msg("source fetch failed")
			continue
		}
		successCount++
		for _, report := range r.reports {
			// Dedup identical (source, ecosystem, name, version) tuples within
			// a single refresh; same finding from different sources stays
			// distinct because dedup includes SourceID.
			dedupKey := r.sourceID + "|" + string(report.Ecosystem) + "|" + report.Name + "|" + report.Version
			if _, ok := dedup[dedupKey]; ok {
				continue
			}
			dedup[dedupKey] = struct{}{}

			// Index by exact version (only when the report names one).
			if report.Version != "" {
				vk := versionKey{report.Ecosystem, report.Name, report.Version}
				nextByVersion[vk] = append(nextByVersion[vk], report)
			}
			// Also index by name regardless of version, so unversioned
			// lookups catch every flagged version.
			nk := nameKey{report.Ecosystem, report.Name}
			nextByName[nk] = append(nextByName[nk], report)
			totalReports++
		}
	}

	// If every source failed, surface the aggregate so the caller can decide
	// whether to keep using the previous index or fail closed.
	if successCount == 0 && failureCount > 0 {
		return errors.WithNew("all intel sources failed to refresh").
			Set("failures", failureCount).
			Cause(stderrors.Join(fetchErrs...))
	}

	s.mu.Lock()
	s.byVersion = nextByVersion
	s.byName = nextByName
	s.mu.Unlock()

	s.logger.Info().
		Int("reports", totalReports).
		Int("sources_ok", successCount).
		Int("sources_failed", failureCount).
		Msg("intel store refreshed")

	return nil
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
	// Add reports that are name-only (no entry in byVersion). These are
	// the "any version of this package is bad" findings.
	for k, reports := range s.byName {
		for _, r := range reports {
			if r.Version == "" {
				_ = k
				total++
			}
		}
	}
	return total
}
