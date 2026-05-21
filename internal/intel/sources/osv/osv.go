// Package osv implements intel.Source for OSV's open vulnerability database
// at https://osv.dev. The bulk-download endpoint serves a per-ecosystem ZIP
// containing one JSON file per advisory:
//
//	https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip
//
// OSV mixes regular vulnerabilities with malware advisories. We filter to
// entries whose ID starts with "MAL-" (OSV's malware namespace) via
// osvschema.IsMalware.
//
// OSV aggregates upstreams including OpenSSF's malicious-packages, so
// running both yields duplicate findings — that's intentional belt-and-
// suspenders coverage. The Store dedups by (source, ecosystem, name,
// version), which keeps each source's "I flagged it" signal distinct in
// the verdict.
package osv

import (
	"archive/zip"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/osvschema"
)

const (
	defaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"
	sourceID       = "osv"
)

// Options configures the OSV source.
type Options struct {
	// BaseURL overrides the upstream GCS bucket root.
	BaseURL string

	// CacheDir is where per-ecosystem zip payloads and etags live.
	// Required; typically ~/.cache/veto/osv.
	CacheDir string

	// HTTPClient overrides the default 2-minute-timeout client.
	HTTPClient *http.Client

	// Logger receives structured log events.
	Logger zerolog.Logger
}

// Source is the OSV implementation of intel.Source.
type Source struct {
	baseURL  string
	cacheDir string
	client   *http.Client
	logger   zerolog.Logger

	mu     sync.Mutex
	cached map[intel.Ecosystem]ecosystemEntry
}

type ecosystemEntry struct {
	etag    string
	reports []intel.MalwareReport
}

var _ intel.Source = (*Source)(nil)

// New builds an OSV source.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("osv: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o755); err != nil {
		return nil, errors.With(err, "osv: create cache dir").Set("path", opts.CacheDir)
	}

	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}

	return &Source{
		baseURL:  baseURL,
		cacheDir: opts.CacheDir,
		client:   client,
		logger:   opts.Logger.With().Str("component", "intel.osv").Logger(),
		cached:   make(map[intel.Ecosystem]ecosystemEntry),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source.
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	ecoPath, ok := ecosystemPath(eco)
	if !ok {
		return nil, intel.ErrUnsupportedEcosystem
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	url := s.baseURL + "/" + ecoPath + "/all.zip"
	zipPath := filepath.Join(s.cacheDir, ecoPath+".zip")
	etagPath := filepath.Join(s.cacheDir, ecoPath+".etag")

	prevEtag, _ := os.ReadFile(etagPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.With(err, "build request")
	}
	if len(prevEtag) > 0 {
		req.Header.Set("If-None-Match", string(prevEtag))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// Network blip — use in-memory cache if we have one.
		if entry, ok := s.cached[eco]; ok {
			s.logger.Warn().Err(err).Str("ecosystem", string(eco)).Msg("osv unreachable, using in-memory")
			return entry.reports, nil
		}
		// Or fall back to on-disk zip if present (re-parse).
		if _, statErr := os.Stat(zipPath); statErr == nil {
			s.logger.Warn().Err(err).Str("ecosystem", string(eco)).Msg("osv unreachable, re-parsing cached zip")
			reports, parseErr := parseZip(zipPath, s.logger)
			if parseErr != nil {
				return nil, errors.With(parseErr, "parse cached zip after network failure")
			}
			s.cached[eco] = ecosystemEntry{etag: string(prevEtag), reports: reports}
			return reports, nil
		}
		return nil, errors.With(err, "osv request")
	}
	defer resp.Body.Close()

	upstreamEtag := resp.Header.Get("ETag")

	switch resp.StatusCode {
	case http.StatusNotModified:
		if entry, ok := s.cached[eco]; ok && entry.etag == string(prevEtag) {
			return entry.reports, nil
		}
		reports, err := parseZip(zipPath, s.logger)
		if err != nil {
			return nil, errors.With(err, "parse cached zip on 304")
		}
		s.cached[eco] = ecosystemEntry{etag: string(prevEtag), reports: reports}
		return reports, nil

	case http.StatusOK:
		// Stream to a temp file, then atomic rename.
		tmp, err := os.CreateTemp(s.cacheDir, ecoPath+".zip.tmp-")
		if err != nil {
			return nil, errors.With(err, "create temp zip")
		}
		tmpPath := tmp.Name()
		if _, err := io.Copy(tmp, resp.Body); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return nil, errors.With(err, "stream zip")
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmpPath)
			return nil, errors.With(err, "close temp zip")
		}
		if err := os.Rename(tmpPath, zipPath); err != nil {
			os.Remove(tmpPath)
			return nil, errors.With(err, "rename zip")
		}
		if upstreamEtag != "" {
			if err := os.WriteFile(etagPath, []byte(upstreamEtag), 0o644); err != nil {
				s.logger.Warn().Err(err).Msg("write etag")
			}
		}

		reports, err := parseZip(zipPath, s.logger)
		if err != nil {
			return nil, errors.With(err, "parse fresh zip")
		}
		s.cached[eco] = ecosystemEntry{etag: upstreamEtag, reports: reports}
		s.logger.Info().Str("ecosystem", string(eco)).Int("reports", len(reports)).Msg("osv parsed")
		return reports, nil

	default:
		return nil, errors.WithNew("unexpected osv status").Set("status", resp.StatusCode, "url", url)
	}
}

func parseZip(path string, logger zerolog.Logger) ([]intel.MalwareReport, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, errors.With(err, "open zip")
	}
	defer zr.Close()

	var reports []intel.MalwareReport
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			logger.Debug().Err(err).Str("entry", f.Name).Msg("skip unreadable")
			continue
		}
		payload, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			logger.Debug().Err(err).Str("entry", f.Name).Msg("skip unreadable")
			continue
		}
		adv, err := osvschema.Parse(payload)
		if err != nil {
			logger.Debug().Err(err).Str("entry", f.Name).Msg("skip unparseable")
			continue
		}
		if !osvschema.IsMalware(adv) {
			continue
		}
		reports = append(reports, osvschema.Reports(adv, sourceID)...)
	}
	return reports, nil
}

// ecosystemPath translates intel.Ecosystem to OSV's URL path component.
// OSV is case-sensitive: npm is lowercase but PyPI is mixed-case.
func ecosystemPath(eco intel.Ecosystem) (string, bool) {
	switch eco {
	case intel.EcosystemNPM:
		return "npm", true
	case intel.EcosystemPyPI:
		return "PyPI", true
	default:
		return "", false
	}
}
