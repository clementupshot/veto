// Package openssf implements intel.Source for OpenSSF's malicious-packages
// repository at https://github.com/ossf/malicious-packages.
//
// The repo publishes per-package MAL-* advisories as JSON files under
// osv/malicious/<ecosystem>/<package>/<MAL-id>.json. We pull the main-branch
// tarball (~35 MB compressed), stream-walk the matching entries, and parse
// each via osvschema.
//
// Three caching layers:
//
//  1. on-disk tarball + etag (skip download when upstream etag unchanged),
//  2. on-disk parsed gob keyed by etag (skip re-parse on warm refresh),
//  3. in-memory reports (populated once per process, partitioned per Fetch).
//
// All three keep `veto <pm> install foo` from paying parse cost on the
// hot path while still doing a conditional GET to keep the malware view fresh.
package openssf

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
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
	defaultBaseURL = "https://github.com/ossf/malicious-packages/archive/refs/heads/main.tar.gz"
	sourceID       = "openssf"
	osvPrefix      = "osv/malicious/"

	// maxFeedBytes caps the size of the tarball download. The openssf
	// malicious-packages archive currently sits in the low tens of MB
	// uncompressed; 512 MiB leaves ample growth room while bounding a
	// compromised upstream that might stream a multi-GB body.
	maxFeedBytes = 512 << 20

	// maxAdvisoryBytes bounds each per-advisory JSON read from the
	// tar stream. Real advisories are a few KB; 5 MiB is generous.
	maxAdvisoryBytes = 5 << 20
)

// Options configures the OpenSSF source.
type Options struct {
	// TarballURL overrides the upstream tarball location.
	TarballURL string

	// CacheDir is where the tarball and parsed gob blobs live.
	// Required; typically ~/.cache/veto/openssf.
	CacheDir string

	// HTTPClient overrides the default 5-minute-timeout client. The first
	// sync downloads 35 MB so we allow more time than aikido's 30s.
	HTTPClient *http.Client

	// Logger receives structured log events.
	Logger zerolog.Logger
}

// Source is the OpenSSF implementation of intel.Source.
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

// New builds an OpenSSF source.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("openssf: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o755); err != nil {
		return nil, errors.With(err, "openssf: create cache dir").Set("path", opts.CacheDir)
	}

	tarballURL := opts.TarballURL
	if tarballURL == "" {
		tarballURL = defaultBaseURL
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}

	return &Source{
		tarballURL: tarballURL,
		cacheDir:   opts.CacheDir,
		client:     client,
		logger:     opts.Logger.With().Str("component", "intel.openssf").Logger(),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source. The first call within a refresh cycle
// downloads (or revalidates) and parses; subsequent calls for other
// ecosystems reuse the cached parse.
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

// ensureLoaded brings the in-memory reports into sync with upstream, doing
// only the work that's actually needed (etag check → maybe download → maybe
// re-parse → load gob).
func (s *Source) ensureLoaded(ctx context.Context) ([]intel.MalwareReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	upstreamEtag, err := s.headEtag(ctx)
	if err != nil {
		// Network blip: fall back to whatever we have in memory or on disk.
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
		return nil, errors.With(err, "openssf: cannot reach upstream and no local cache")
	}

	if s.loaded && s.cacheEt == upstreamEtag {
		return s.cached, nil
	}

	// Try the gob first — if disk matches upstream, we skip the heavy parse.
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
		return nil, errors.With(err, "openssf: parse tarball")
	}

	if err := s.writeGob(etag, reports); err != nil {
		// Gob cache is an optimization; log and keep going.
		s.logger.Warn().Err(err).Msg("write parsed gob")
	}

	s.cached = reports
	s.cacheEt = etag
	s.loaded = true
	s.logger.Info().Int("reports", len(reports)).Str("etag", etag).Msg("openssf parsed")
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

// downloadIfChanged returns the local tarball path and the etag we just saved,
// downloading only if the local etag differs from upstream.
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
	// LimitReader+1 lets us detect oversized payloads: writing more than
	// maxFeedBytes is treated as a refused fetch rather than a successful
	// download of a truncated tarball.
	written, err := io.Copy(tmp, io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", "", errors.With(err, "stream tarball")
	}
	if written > maxFeedBytes {
		tmp.Close()
		os.Remove(tmpPath)
		return "", "", errors.WithNew("openssf tarball exceeds size limit").
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

// parseTarball streams the tarball, extracting JSON files under
// osv/malicious/<ecosystem>/, and feeds each to osvschema.
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
	// reports accumulates one entry per malicious advisory we parse
	// out of the tarball. Trust per-feed entry count: each entry is
	// already capped at maxAdvisoryBytes, and OpenSSF currently
	// publishes ~hundreds of entries per ecosystem. An explicit
	// aggregate cap is intentionally omitted — it would cause silent
	// truncation of the malware index without an operator-visible
	// signal, which is exactly the failure mode H3 spent effort
	// removing for the (source, ecosystem) bucket retention. The
	// upstream tarball is already bounded by maxFeedBytes; that's the
	// real ceiling on this slice. (PR #1 review.)
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
		if !isMaliciousEntry(hdr.Name) {
			continue
		}
		// Per-advisory cap: a tar entry larger than maxAdvisoryBytes is
		// either malicious or malformed; we skip rather than abort the
		// whole parse, so a single bad entry can't deny the rest of the
		// feed.
		payload, err := io.ReadAll(io.LimitReader(tr, maxAdvisoryBytes+1))
		if err != nil {
			return nil, errors.With(err, "read entry").Set("name", hdr.Name)
		}
		if len(payload) > maxAdvisoryBytes {
			s.logger.Warn().Str("entry", hdr.Name).Int("limit_bytes", maxAdvisoryBytes).
				Msg("openssf advisory exceeds size limit; skipping")
			continue
		}
		adv, err := osvschema.Parse(payload)
		if err != nil {
			s.logger.Debug().Err(err).Str("entry", hdr.Name).Msg("skip unparseable advisory")
			continue
		}
		reports = append(reports, osvschema.Reports(adv, sourceID)...)
	}
	return reports, nil
}

// isMaliciousEntry returns true if name is `<repo>/osv/malicious/<eco>/.../*.json`.
func isMaliciousEntry(name string) bool {
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	// Strip the repo-root prefix (`malicious-packages-main/`).
	parts := strings.SplitN(name, "/", 2)
	if len(parts) != 2 {
		return false
	}
	return strings.HasPrefix(parts[1], osvPrefix)
}

func ecosystemPath(eco intel.Ecosystem) (string, bool) {
	switch eco {
	case intel.EcosystemNPM:
		return "npm", true
	case intel.EcosystemPyPI:
		return "pypi", true
	default:
		return "", false
	}
}

// gob cache layout: <CacheDir>/parsed-<etag-hex>.gob, with the etag baked into
// the filename so a stale gob can't shadow a fresh tarball.
type gobBlob struct {
	Reports []intel.MalwareReport
}

func (s *Source) gobPath(etag string) string {
	// Etag may contain quotes; strip them so we can use it in filenames.
	clean := strings.NewReplacer(`"`, "", `/`, "_", `:`, "_", ` `, "_").Replace(etag)
	if clean == "" {
		clean = "no-etag"
	}
	return filepath.Join(s.cacheDir, "parsed-"+clean+".gob")
}

func (s *Source) loadGob(etag string) ([]intel.MalwareReport, bool) {
	if etag == "" {
		// Cold path with no etag — pick whichever gob is on disk.
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

// readGobFile loads a parsed gob from disk with two integrity checks:
//
//  1. io.LimitReader caps decode input at maxFeedBytes so a tampered
//     local file can't OOM the daemon. The encoded gob is smaller
//     than the original tarball; maxFeedBytes is the right ceiling.
//  2. sha256 sidecar (<gobPath>.sha256) holds the hex-encoded hash of
//     the gob bytes at write time. On read we recompute and compare
//     BEFORE decode — a mismatch means an attacker has overwritten
//     the cache file (or the disk corrupted) and we MUST refetch
//     rather than feed malicious bytes into gob.Decode (which is
//     itself a code-execution-adjacent surface).
//
// On any check failure: delete the gob, sidecar, and etag so the
// next refresh re-downloads cleanly. M4 in the audit.
func (s *Source) readGobFile(path string) ([]intel.MalwareReport, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	if len(data) > maxFeedBytes {
		s.logger.Warn().Int("len", len(data)).Int("limit", maxFeedBytes).Str("path", path).
			Msg("gob cache exceeds size cap; refusing decode and invalidating")
		s.invalidateGobCache(path)
		return nil, false
	}
	sidecar := path + ".sha256"
	if expected, err := os.ReadFile(sidecar); err == nil {
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if strings.TrimSpace(string(expected)) != got {
			s.logger.Warn().Str("path", path).Str("expected", strings.TrimSpace(string(expected))).
				Str("got", got).Msg("gob cache sha256 mismatch; invalidating and forcing refetch")
			s.invalidateGobCache(path)
			return nil, false
		}
	}
	var blob gobBlob
	if err := gob.NewDecoder(io.LimitReader(bytes.NewReader(data), maxFeedBytes)).Decode(&blob); err != nil {
		s.logger.Warn().Err(err).Str("path", path).Msg("gob decode failed; ignoring cache")
		return nil, false
	}
	return blob.Reports, true
}

// invalidateGobCache wipes the cached gob, its sidecar, and the
// main.etag so the next refresh forces a full re-download and
// re-parse. Used when an integrity check fails.
func (s *Source) invalidateGobCache(gobPath string) {
	_ = os.Remove(gobPath)
	_ = os.Remove(gobPath + ".sha256")
	_ = os.Remove(filepath.Join(s.cacheDir, "main.etag"))
}

func (s *Source) writeGob(etag string, reports []intel.MalwareReport) error {
	path := s.gobPath(etag)
	// Encode to memory first so we can compute the integrity sha256
	// of exactly the bytes that hit disk. Streaming into a tmp file
	// then re-reading would race the sidecar against any concurrent
	// writer of the same cache.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(gobBlob{Reports: reports}); err != nil {
		return errors.With(err, "encode gob")
	}
	if buf.Len() > maxFeedBytes {
		return errors.WithNew("encoded gob exceeds size cap").
			Set("len", buf.Len()).Set("limit", maxFeedBytes)
	}
	tmp, err := os.CreateTemp(s.cacheDir, "parsed-tmp-")
	if err != nil {
		return errors.With(err, "create temp gob")
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return errors.With(err, "write temp gob")
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "close temp gob")
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "rename gob")
	}
	sum := sha256.Sum256(buf.Bytes())
	sidecar := path + ".sha256"
	if err := os.WriteFile(sidecar, []byte(hex.EncodeToString(sum[:])), 0o644); err != nil {
		s.logger.Warn().Err(err).Str("path", sidecar).
			Msg("write gob sha256 sidecar failed; cache will refresh on next start")
	}
	s.pruneOldGobs(path)
	return nil
}

func (s *Source) pruneOldGobs(keep string) {
	entries, err := os.ReadDir(s.cacheDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "parsed-") || !strings.HasSuffix(name, ".gob") {
			continue
		}
		full := filepath.Join(s.cacheDir, name)
		if full == keep {
			continue
		}
		_ = os.Remove(full)
	}
}
