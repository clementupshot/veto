package osv_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/osv"
)

// makeMinimalZip returns a tiny in-memory zip containing one MAL-* JSON
// advisory the parseZip helper will accept as malware.
func makeMinimalZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("MAL-2026-0001.json")
	require.NoError(t, err)
	_, err = w.Write([]byte(`{"id":"MAL-2026-0001","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"evil"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// TestFetchRejectsOversizedPayload (M6 parity with aikido): a feed
// body larger than maxFeedBytes must be refused for that refresh. The
// io.LimitReader+1 pattern detects truncation; removing the +1 or
// dropping the > maxFeedBytes guard lets a multi-GB body in and
// silently OOMs the daemon.
func TestFetchRejectsOversizedPayload(t *testing.T) {
	const maxFeedBytes = 256 << 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"oversized"`)
		w.WriteHeader(http.StatusOK)
		// Stream just over the cap. Use a small per-chunk write so the
		// test doesn't actually allocate a 256MiB buffer in memory.
		chunk := bytes.Repeat([]byte{0x00}, 1<<20)
		written := 0
		for written <= maxFeedBytes {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			written += len(chunk)
		}
	}))
	defer srv.Close()

	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds size limit")
}

// TestFetch304WithMissingCacheRetriesOnce (M5+M6 parity with aikido):
// when upstream returns 304 but our on-disk zip is gone, drop the
// etag and refetch ONCE. Mutation-resistance: removing the bounded
// retry from osv's NotModified branch causes this test to fail with
// the un-retried parseZip error.
func TestFetch304WithMissingCacheRetriesOnce(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.etag"), []byte(`"abc123"`), 0o644))

	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "304 with no cache after retry must surface an error")
	require.Equal(t, int64(2), hits.Load(),
		"bounded retry must take exactly one refetch (initial + 1)")
}

// TestFetch304WithCachePresentDoesNotRetry: a 304 with the cache file
// present must NOT trigger a refetch — exactly one hit. Without this
// test, a regression that always-refetches on 304 would silently pass.
func TestFetch304WithCachePresentDoesNotRetry(t *testing.T) {
	zipBody := makeMinimalZip(t)

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.etag"), []byte(`"abc123"`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.zip"), zipBody, 0o644))

	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.NotEmpty(t, reports)
	require.Equal(t, int64(1), hits.Load(), "cache-present 304 must not refetch")
}

// TestParseZipServesFromCacheAfterFreshOK: round-trips one full
// download + re-fetch with a matching etag (304 path) to ensure the
// in-memory cache short-circuits parsing.
func TestParseZipServesFromCacheAfterFreshOK(t *testing.T) {
	zipBody := makeMinimalZip(t)

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"abc123"` {
			w.Header().Set("ETag", `"abc123"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, bytes.NewReader(zipBody))
	}))
	defer srv.Close()

	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports1, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.NotEmpty(t, reports1)
	require.Equal(t, int64(1), hits.Load())

	reports2, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Equal(t, len(reports1), len(reports2))
	require.Equal(t, int64(2), hits.Load(), "second fetch must conditionally-GET")
}

// guard against package-import drift — keep one assertion that exercises
// the public type so the import is not "unused" if the rest of the suite
// is gutted.
var _ = strings.HasPrefix
