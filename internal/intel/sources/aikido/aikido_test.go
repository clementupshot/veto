package aikido_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/aikido"
)

const samplePayload = `[
  {"package_name": "evil-pkg", "version": "1.0.0", "reason": "MALWARE"},
  {"package_name": "evil-pkg", "version": "1.0.1", "reason": "MALWARE"},
  {"package_name": "rogue", "version": "9.9.9", "reason": "MALWARE"}
]`

func TestFetchParsesPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/malware_predictions.json", r.URL.Path)
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write([]byte(samplePayload))
	}))
	defer srv.Close()

	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 3)
	require.Equal(t, "aikido", reports[0].SourceID)
	require.Equal(t, intel.EcosystemNPM, reports[0].Ecosystem)
	require.Equal(t, "evil-pkg", reports[0].Name)
	require.Equal(t, "1.0.0", reports[0].Version)
}

func TestFetchUnsupportedEcosystem(t *testing.T) {
	src, err := aikido.New(aikido.Options{
		BaseURL:  "https://example.invalid",
		CacheDir: t.TempDir(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.Ecosystem("maven"))
	require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem)
}

func TestFetchEtagShortCircuit(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"abc123"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write([]byte(samplePayload))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	first, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, first, 3)

	second, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, second, 3)

	require.Equal(t, int32(2), hits.Load(), "expected two upstream calls")

	// Cache files exist after both fetches.
	require.FileExists(t, filepath.Join(cacheDir, "npm.json"))
	etag, err := os.ReadFile(filepath.Join(cacheDir, "npm.etag"))
	require.NoError(t, err)
	require.Equal(t, `"abc123"`, string(etag))
}

// TestFetchRejectsOversizedPayload: a MITM'd or compromised upstream
// cannot OOM the daemon by serving a multi-GB body. The fetcher caps
// payloads with io.LimitReader; reads past the cap are an error.
//
// Defends against C2 from the audit. The handler streams JSON-shaped
// bytes past the cap; if the cap is honored the fetch errors before
// completion, otherwise the handler would happily write the whole thing.
func TestFetchRejectsOversizedPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		const oversize = (256 << 20) + 1024 // 1 KB past the 256 MiB cap
		_, _ = w.Write([]byte("["))
		buf := make([]byte, 1<<20) // 1 MiB chunks
		written := 1
		for written < oversize {
			n, err := w.Write(buf)
			if err != nil {
				return // client closed — expected once we hit the cap
			}
			written += n
		}
	}))
	defer srv.Close()

	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "oversized payload must be rejected, not buffered into memory")
	require.Contains(t, err.Error(), "size limit")
}

// TestFetch304WithMissingCacheRetriesOnce verifies S3: if upstream returns
// 304 but our cache is gone, we drop the etag and refetch ONCE — and if
// the refetch ALSO returns 304 (server bug — should never happen without
// If-None-Match, but defensive bound), we surface an error rather than
// spinning. The bounded retry replaces the previous unbounded recursion.
func TestFetch304WithMissingCacheRetriesOnce(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	// Pre-seed an etag file so the first request includes If-None-Match.
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.etag"), []byte(`"abc123"`), 0o644))

	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "304 with no cache after retry must surface an error")
	require.LessOrEqual(t, hits.Load(), int64(2),
		"bounded retry must not spin — at most 2 hits (initial + 1 retry)")
}

func TestFetchNetworkFailureFallsBackToCache(t *testing.T) {
	// First serve the payload to populate the cache.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write([]byte(samplePayload))
	}))

	cacheDir := t.TempDir()
	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	// Kill the server to simulate network outage.
	srv.Close()

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 3)
}
