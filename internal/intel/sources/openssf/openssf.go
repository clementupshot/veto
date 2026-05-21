// Package openssf will implement intel.Source for the OpenSSF malicious-packages
// repository at https://github.com/ossf/malicious-packages.
//
// Planned data flow: clone or shallow-fetch the repo, walk the OSV-format JSON
// files under osv/<ecosystem>/ and translate each MAL-* advisory into one or
// more intel.MalwareReports. The repo contains historical and current findings
// with per-version granularity, making it the closest single-source overlap
// with Aikido's feed.
//
// This stub satisfies the interface and registers the source ID so wiring
// elsewhere already references the eventual production implementation.
package openssf

import (
	"context"

	"github.com/brynbellomy/package-bouncer/internal/intel"
)

const sourceID = "openssf"

// Options configures the OpenSSF source.
type Options struct {
	// CacheDir is where the cloned/fetched repo and parsed snapshot live.
	CacheDir string
}

// Source is the OpenSSF malicious-packages implementation of intel.Source.
type Source struct {
	cacheDir string
}

var _ intel.Source = (*Source)(nil)

// New builds an OpenSSF source.
func New(opts Options) (*Source, error) {
	return &Source{cacheDir: opts.CacheDir}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source. Returns ErrUnsupportedEcosystem until the
// real implementation lands; this is a fail-silent skip in the Store.
//
// @@TODO: implement OSV parsing from ossf/malicious-packages.
func (s *Source) Fetch(_ context.Context, _ intel.Ecosystem) ([]intel.MalwareReport, error) {
	return nil, intel.ErrUnsupportedEcosystem
}
