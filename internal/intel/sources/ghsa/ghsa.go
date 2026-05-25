// Package ghsa implements intel.Source for GitHub Advisory Database.
//
// GitHub's advisory-database repository publishes reviewed GHSA/CVE advisories
// as OSV-shaped JSON files under advisories/github-reviewed/. Unlike the
// default veto sources, this feed is not malware-only: it includes ordinary
// vulnerable versions too. Keep it opt-in until the product has first-class
// vulnerability policy controls separate from malware blocking.
package ghsa

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/gob"
	stderrors "errors"
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
	defaultTarballURL = "https://github.com/github/advisory-database/archive/refs/heads/main.tar.gz"
	sourceID          = "ghsa"
	reviewedPrefix    = "advisories/github-reviewed/"

	// maxFeedBytes caps the whole GitHub Advisory Database archive. The archive
	// is substantially larger than malware-only feeds, but this still bounds a
	// compromised upstream that streams a multi-GB payload.
	maxFeedBytes = 1024 << 20

	// maxAdvisoryBytes bounds each per-advisory JSON file. Real GHSA documents
	// are usually a few KB; 5 MiB leaves room for long markdown details.
	maxAdvisoryBytes = 5 << 20
)

// Options configures the GitHub Advisory Database source.
type Options struct {
	// TarballURL overrides the upstream tarball location.
	TarballURL string

	// CacheDir is where the tarball and parsed gob blobs live.
	// Required; typically ~/.cache/veto/ghsa.
	CacheDir string

	// HTTPClient overrides the default 5-minute-timeout client.
	HTTPClient *http.Client

	// Logger receives structured log events.
	Logger zerolog.Logger
}

// Source is the GitHub Advisory Database implementation of intel.Source.
type Source struct {
	tarballURL string
	cacheDir   string
	client     *http.Client
	logger     zerolog.Logger

	mu      sync.Mutex
	cached  []intel.MalwareReport
	loaded  bool
	cacheEt string
}

var _ intel.Source = (*Source)(nil)

// New builds a GitHub Advisory Database source.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("ghsa: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "ghsa: create cache dir").Set("path", opts.CacheDir)
	}
	if err := os.Chmod(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "ghsa: tighten cache dir perms").Set("path", opts.CacheDir)
	}

	tarballURL := opts.TarballURL
	if tarballURL == "" {
		tarballURL = defaultTarballURL
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}

	return &Source{
		tarballURL: tarballURL,
		cacheDir:   opts.CacheDir,
		client:     client,
		logger:     opts.Logger.With().Str("component", "intel.ghsa").Logger(),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source. The first call downloads or revalidates the
// shared tarball; later ecosystem fetches reuse the parsed report set.
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if _, ok := ecosystemPath(eco); !ok {
		return nil, intel.ErrUnsupportedEcosystem
	}

	reports, err := s.ensureLoaded(ctx)
	if err != nil {
		return nil, err
	}

	out := reports[:0:0]
	for _, r := range reports {
		if r.Ecosystem == eco {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Source) ensureLoaded(ctx context.Context) ([]intel.MalwareReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	upstreamEtag, err := s.headEtag(ctx)
	if err != nil {
		if s.loaded {
			s.logger.Warn().Err(err).Msg("etag check failed, using in-memory cache")
			return s.cached, nil
		}
		if cached, ok := s.loadGob(""); ok {
			s.logger.Warn().Err(err).Msg("etag check failed, using disk gob")
			s.cached = cached
			s.loaded = true
			return s.cached, nil
		}
		return nil, errors.With(err, "ghsa: cannot reach upstream and no local cache")
	}

	if s.loaded && s.cacheEt == upstreamEtag {
		return s.cached, nil
	}

	if cached, ok := s.loadGob(upstreamEtag); ok {
		s.cached = cached
		s.cacheEt = upstreamEtag
		s.loaded = true
		return s.cached, nil
	}

	tarballPath, etag, err := s.downloadIfChanged(ctx, upstreamEtag)
	if err != nil {
		return nil, err
	}

	reports, err := s.parseTarball(tarballPath)
	if err != nil {
		etagPath := filepath.Join(s.cacheDir, "main.etag")
		if rmErr := os.Remove(etagPath); rmErr != nil && !os.IsNotExist(rmErr) {
			s.logger.Warn().Err(rmErr).Msg("remove etag after parse failure")
		}
		return nil, errors.With(err, "ghsa: parse tarball")
	}

	if err := s.writeGob(etag, reports); err != nil {
		s.logger.Warn().Err(err).Msg("write parsed gob")
	}

	s.cached = reports
	s.cacheEt = etag
	s.loaded = true
	s.logger.Info().Int("reports", len(reports)).Str("etag", etag).Msg("ghsa parsed")
	return s.cached, nil
}

func (s *Source) headEtag(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.tarballURL, nil)
	if err != nil {
		return "", errors.With(err, "build head request")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", errors.With(err, "head request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.WithNew("unexpected head status").Set("status", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		return "", errors.New("upstream returned no etag")
	}
	return etag, nil
}

func (s *Source) downloadIfChanged(ctx context.Context, upstreamEtag string) (string, string, error) {
	tarballPath := filepath.Join(s.cacheDir, "main.tar.gz")
	etagPath := filepath.Join(s.cacheDir, "main.etag")

	if existing, err := os.ReadFile(etagPath); err == nil && string(existing) == upstreamEtag {
		if _, err := os.Stat(tarballPath); err == nil {
			return tarballPath, upstreamEtag, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.tarballURL, nil)
	if err != nil {
		return "", "", errors.With(err, "build get request")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", errors.With(err, "get tarball")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", errors.WithNew("unexpected get status").Set("status", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(s.cacheDir, "main.tar.gz.tmp-")
	if err != nil {
		return "", "", errors.With(err, "create temp tarball")
	}
	tmpPath := tmp.Name()
	written, err := io.Copy(tmp, io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", "", errors.With(err, "stream tarball")
	}
	if written > maxFeedBytes {
		tmp.Close()
		os.Remove(tmpPath)
		return "", "", errors.WithNew("ghsa tarball exceeds size limit").
			Set("limit_bytes", maxFeedBytes)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", "", errors.With(err, "close temp tarball")
	}
	if err := os.Rename(tmpPath, tarballPath); err != nil {
		os.Remove(tmpPath)
		return "", "", errors.With(err, "rename tarball")
	}
	if err := os.WriteFile(etagPath, []byte(upstreamEtag), 0o644); err != nil {
		s.logger.Warn().Err(err).Msg("write etag")
	}
	return tarballPath, upstreamEtag, nil
}

func (s *Source) parseTarball(path string) ([]intel.MalwareReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.With(err, "open tarball")
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, errors.With(err, "gzip reader")
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var reports []intel.MalwareReport
	for {
		hdr, err := tr.Next()
		if stderrors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.With(err, "tar read")
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if !isReviewedAdvisoryEntry(hdr.Name) {
			continue
		}
		payload, err := io.ReadAll(io.LimitReader(tr, maxAdvisoryBytes+1))
		if err != nil {
			return nil, errors.With(err, "read entry").Set("name", hdr.Name)
		}
		if len(payload) > maxAdvisoryBytes {
			s.logger.Warn().Str("entry", hdr.Name).Int("limit_bytes", maxAdvisoryBytes).
				Msg("ghsa advisory exceeds size limit; skipping")
			continue
		}
		adv, err := osvschema.Parse(payload)
		if err != nil {
			s.logger.Debug().Err(err).Str("entry", hdr.Name).Msg("skip unparseable advisory")
			continue
		}
		reports = append(reports, osvschema.VulnerabilityReports(adv, sourceID)...)
	}
	return reports, nil
}

// isReviewedAdvisoryEntry returns true for GitHub-reviewed advisory JSON files
// inside GitHub archive tarballs. Tar entries include a repo-root prefix such
// as advisory-database-main/ that we deliberately do not pin.
func isReviewedAdvisoryEntry(name string) bool {
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	parts := strings.SplitN(name, "/", 2)
	if len(parts) != 2 {
		return false
	}
	return strings.HasPrefix(parts[1], reviewedPrefix)
}

func ecosystemPath(eco intel.Ecosystem) (string, bool) {
	switch eco {
	case intel.EcosystemNPM:
		return "npm", true
	case intel.EcosystemPyPI:
		return "pypi", true
	case intel.EcosystemGo:
		return "go", true
	case intel.EcosystemCrates:
		return "crates.io", true
	default:
		return "", false
	}
}

type gobBlob struct {
	Reports []intel.MalwareReport
}

func (s *Source) gobPath(etag string) string {
	clean := strings.NewReplacer(`"`, "", `/`, "_", `:`, "_", ` `, "_").Replace(etag)
	if clean == "" {
		clean = "no-etag"
	}
	return filepath.Join(s.cacheDir, "parsed-"+clean+".gob")
}

func (s *Source) loadGob(etag string) ([]intel.MalwareReport, bool) {
	if etag == "" {
		entries, err := os.ReadDir(s.cacheDir)
		if err != nil {
			return nil, false
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "parsed-") && strings.HasSuffix(e.Name(), ".gob") {
				return s.readGobFile(filepath.Join(s.cacheDir, e.Name()))
			}
		}
		return nil, false
	}
	return s.readGobFile(s.gobPath(etag))
}

func (s *Source) readGobFile(path string) ([]intel.MalwareReport, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var blob gobBlob
	if err := gob.NewDecoder(f).Decode(&blob); err != nil {
		s.logger.Warn().Err(err).Str("path", path).Msg("gob decode failed; ignoring cache")
		return nil, false
	}
	return blob.Reports, true
}

func (s *Source) writeGob(etag string, reports []intel.MalwareReport) error {
	path := s.gobPath(etag)
	tmp, err := os.CreateTemp(s.cacheDir, "parsed-tmp-")
	if err != nil {
		return errors.With(err, "create temp gob")
	}
	tmpPath := tmp.Name()
	enc := gob.NewEncoder(tmp)
	if err := enc.Encode(gobBlob{Reports: reports}); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return errors.With(err, "encode gob")
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "close gob")
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "rename gob")
	}
	return nil
}
