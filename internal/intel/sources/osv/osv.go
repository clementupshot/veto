// Package osv will implement intel.Source for Google's OSV database
// (https://osv.dev). The OSV bulk-download zips at gs://osv-vulnerabilities/
// expose per-ecosystem JSON files; we filter to advisories whose IDs start
// with "MAL-" (the malware namespace).
//
// OSV partially overlaps with OpenSSF malicious-packages (which is one of OSV's
// upstreams) but also pulls from GHSA, PyPA, and other feeds — running both
// gives belt-and-suspenders coverage at the cost of one extra HTTP fetch.
//
// This stub satisfies the interface so dependents can already reference the
// source by ID. The Store skips it silently via ErrUnsupportedEcosystem.
package osv

import (
	"context"

	"github.com/brynbellomy/package-bouncer/internal/intel"
)

const sourceID = "osv"

// Options configures the OSV source.
type Options struct {
	// CacheDir is where downloaded zip snapshots are kept.
	CacheDir string
}

// Source is the OSV implementation of intel.Source.
type Source struct {
	cacheDir string
}

var _ intel.Source = (*Source)(nil)

// New builds an OSV source.
func New(opts Options) (*Source, error) {
	return &Source{cacheDir: opts.CacheDir}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source.
//
// @@TODO: download per-ecosystem zip from gs://osv-vulnerabilities/<eco>/all.zip,
// parse JSON entries, filter to MAL-* IDs, translate affected.ranges into
// intel.MalwareReports.
func (s *Source) Fetch(_ context.Context, _ intel.Ecosystem) ([]intel.MalwareReport, error) {
	return nil, intel.ErrUnsupportedEcosystem
}
