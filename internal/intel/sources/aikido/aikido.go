// Package aikido implements intel.Source for Aikido's open malware feed at
// https://malware-list.aikido.dev. The feed is a static JSON array per
// ecosystem, served with etag headers so refreshes can be cheap.
//
// Data shape (npm and pypi feeds share it):
//
//	[
//	  { "package_name": "evil-pkg", "version": "1.0.0", "reason": "MALWARE" },
//	  ...
//	]
package aikido

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
)

const (
	defaultBaseURL = "https://malware-list.aikido.dev"
	sourceID       = "aikido"
)

// Options configures the Aikido source.
type Options struct {
	// BaseURL overrides the upstream URL. Defaults to https://malware-list.aikido.dev.
	BaseURL string

	// CacheDir is where fetched payloads and etags are persisted between runs.
	// Required; typically ~/.cache/veto/aikido.
	CacheDir string

	// HTTPClient is used for fetches. Defaults to a client with a 30s timeout.
	HTTPClient *http.Client

	// Logger receives structured log events. Defaults to zerolog.Nop().
	Logger zerolog.Logger
}

// Source is the Aikido implementation of intel.Source. Construct via New.
type Source struct {
	baseURL string
	cache   string
	client  *http.Client
	logger  zerolog.Logger
}

var _ intel.Source = (*Source)(nil)

// New builds an Aikido source. Returns an error if CacheDir is empty or cannot
// be created.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("aikido: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o755); err != nil {
		return nil, errors.With(err, "aikido: create cache dir").Set("path", opts.CacheDir)
	}

	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	return &Source{
		baseURL: baseURL,
		cache:   opts.CacheDir,
		client:  client,
		logger:  opts.Logger.With().Str("component", "intel.aikido").Logger(),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source.
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	path, ok := feedPath(eco)
	if !ok {
		return nil, intel.ErrUnsupportedEcosystem
	}

	url := s.baseURL + "/" + path
	cachedPayload := filepath.Join(s.cache, string(eco)+".json")
	cachedEtag := filepath.Join(s.cache, string(eco)+".etag")

	payload, err := s.fetchWithCache(ctx, url, cachedPayload, cachedEtag)
	if err != nil {
		return nil, errors.With(err, "aikido fetch").Set("ecosystem", string(eco), "url", url)
	}

	return parsePayload(eco, payload)
}

// fetchWithCache returns the latest payload bytes for url. It honors etag-based
// conditional fetches: if the cached etag still matches upstream, the cached
// payload is returned without re-downloading the body. On network failure, a
// previously-cached payload is returned with a logged warning rather than
// failing the refresh.
func (s *Source) fetchWithCache(ctx context.Context, url, payloadPath, etagPath string) ([]byte, error) {
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
		// Network failure — fall back to cached payload if we have one. This
		// keeps the lookup index hot across transient outages.
		if cached, readErr := os.ReadFile(payloadPath); readErr == nil {
			s.logger.Warn().Err(err).Str("url", url).Msg("upstream unreachable, using cached payload")
			return cached, nil
		}
		return nil, errors.With(err, "http request")
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		cached, err := os.ReadFile(payloadPath)
		if err != nil {
			// Upstream told us nothing changed but we have no local copy.
			// Treat this as a cache invariant break — drop the etag and refetch.
			s.logger.Warn().Err(err).Msg("304 received but cached payload missing; forcing refetch")
			_ = os.Remove(etagPath)
			return s.fetchWithCache(ctx, url, payloadPath, etagPath)
		}
		return cached, nil
	case http.StatusOK:
		// fall through
	default:
		return nil, errors.WithNew("unexpected status").Set("status", resp.StatusCode, "url", url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.With(err, "read body")
	}

	if err := writeAtomic(payloadPath, body); err != nil {
		return nil, errors.With(err, "cache payload")
	}
	if etag := resp.Header.Get("ETag"); etag != "" {
		if err := writeAtomic(etagPath, []byte(etag)); err != nil {
			// Etag is an optimization — log and continue rather than failing.
			s.logger.Warn().Err(err).Msg("write etag")
		}
	}

	return body, nil
}

func feedPath(eco intel.Ecosystem) (string, bool) {
	switch eco {
	case intel.EcosystemNPM:
		return "malware_predictions.json", true
	case intel.EcosystemPyPI:
		return "malware_pypi.json", true
	default:
		return "", false
	}
}

// rawEntry mirrors one element of Aikido's feed.
type rawEntry struct {
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	Reason      string `json:"reason"`
}

func parsePayload(eco intel.Ecosystem, payload []byte) ([]intel.MalwareReport, error) {
	var raw []rawEntry
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.With(err, "parse aikido payload").Set("ecosystem", string(eco))
	}

	out := make([]intel.MalwareReport, 0, len(raw))
	for _, r := range raw {
		if r.PackageName == "" {
			continue
		}
		out = append(out, intel.MalwareReport{
			PackageRef: intel.PackageRef{
				Ecosystem: eco,
				Name:      r.PackageName,
				Version:   r.Version,
			},
			SourceID: sourceID,
			Reason:   r.Reason,
		})
	}
	return out, nil
}

// writeAtomic writes payload to dst by renaming a sibling temp file, so a
// crash mid-write leaves either the old file or the new file but never a
// truncated one.
func writeAtomic(dst string, payload []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp-")
	if err != nil {
		return errors.With(err, "create temp")
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return errors.With(err, "write temp")
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "close temp")
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "rename temp")
	}
	return nil
}
