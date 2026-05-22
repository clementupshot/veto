package osv_test

import (
	"archive/zip"
	"bytes"
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
	"github.com/brynbellomy/veto/internal/intel/sources/osv"
)

// TestFetchParsesPayload exercises the happy path: a 200 with a valid zip
// produces the expected MalwareReports, the cached zip + etag files are
// written to disk, and the SourceID/Ecosystem fields are stamped correctly.
func TestFetchParsesPayload(t *testing.T) {
	t.Parallel()

	payload := makeOSVZip(t, "MAL-2026-1", "evil-pkg", "npm", []string{"1.0.0", "1.0.1"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/npm/all.zip", r.URL.Path)
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 2)
	require.Equal(t, "osv", reports[0].SourceID)
	require.Equal(t, intel.EcosystemNPM, reports[0].Ecosystem)
	require.Equal(t, "evil-pkg", reports[0].Name)

	// Both zip and etag should be on disk after a successful fetch.
	require.FileExists(t, filepath.Join(cacheDir, "npm.zip"))
	etag, err := os.ReadFile(filepath.Join(cacheDir, "npm.etag"))
	require.NoError(t, err)
	require.Equal(t, `"abc123"`, string(etag))
}

// TestFetchUnsupportedEcosystem confirms an ecosystem outside the supported
// set surfaces intel.ErrUnsupportedEcosystem so the store can skip it
// without aborting the refresh cycle.
func TestFetchUnsupportedEcosystem(t *testing.T) {
	t.Parallel()

	src, err := osv.New(osv.Options{
		BaseURL:  "https://example.invalid",
		CacheDir: t.TempDir(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.Ecosystem("maven"))
	require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem)
}

// TestFetchEtagShortCircuit verifies that once a payload has been parsed,
// a subsequent 304 reuses the in-memory cache (no re-parse off disk needed).
// We assert two upstream hits — the second carries If-None-Match and the
// server replies 304.
func TestFetchEtagShortCircuit(t *testing.T) {
	t.Parallel()

	payload := makeOSVZip(t, "MAL-2026-2", "evil-pkg", "npm", []string{"1.0.0"})

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"abc123"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	first, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, first, 1)

	second, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, second, 1)

	require.Equal(t, int32(2), hits.Load(), "expected two upstream calls (200 then 304)")

	require.FileExists(t, filepath.Join(cacheDir, "npm.zip"))
	etag, err := os.ReadFile(filepath.Join(cacheDir, "npm.etag"))
	require.NoError(t, err)
	require.Equal(t, `"abc123"`, string(etag))
}

// TestFetch304ReparsesCachedZip verifies the disk-fallback path on 304:
// when in-memory cache is cold (fresh process) but the etag + zip are on
// disk and upstream returns 304, the source re-parses the on-disk zip
// rather than erroring.
func TestFetch304ReparsesCachedZip(t *testing.T) {
	t.Parallel()

	payload := makeOSVZip(t, "MAL-2026-3", "cached-pkg", "npm", []string{"2.0.0"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	// Pre-seed the zip and etag on disk to simulate a warm-disk / cold-memory
	// process restart.
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.zip"), payload, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.etag"), []byte(`"v1"`), 0o644))

	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "304 with valid on-disk cache must re-parse, not error")
	require.Len(t, reports, 1)
	require.Equal(t, "cached-pkg", reports[0].Name)
}

// TestFetchRejectsOversizedPayload pins the 256 MiB ceiling on the
// per-ecosystem zip. A MITM'd upstream that streams a multi-GB body must
// be refused before it OOMs veto. The server writes maxFeedBytes+1 bytes
// of garbage so the LimitReader+1 trips.
func TestFetchRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		const oversize = (256 << 20) + 1024 // 1 KB past the 256 MiB cap
		buf := make([]byte, 1<<20)          // 1 MiB chunks
		written := 0
		for written < oversize {
			n, err := w.Write(buf)
			if err != nil {
				return // client closed — expected once we hit the cap
			}
			written += n
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
	require.Error(t, err, "oversized payload must be rejected, not buffered into memory")
	require.Contains(t, err.Error(), "size limit")
}

// TestFetchNetworkFailureFallsBackToCache verifies disk fallback when
// upstream becomes unreachable: after one successful fetch the zip is on
// disk, so a subsequent fetch against a dead server re-parses the cached
// zip rather than surfacing the network error.
func TestFetchNetworkFailureFallsBackToCache(t *testing.T) {
	t.Parallel()

	payload := makeOSVZip(t, "MAL-2026-4", "fallback-pkg", "npm", []string{"3.0.0"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(payload)
	}))

	cacheDir := t.TempDir()
	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	// Kill upstream — next Fetch should still succeed via in-memory cache.
	srv.Close()

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Equal(t, "fallback-pkg", reports[0].Name)
}

// TestFetchNetworkFailureReParsesDiskZip exercises the second fallback
// branch in osv.go: when there is no in-memory cache (fresh process) but
// a zip is on disk and upstream is unreachable, the source re-parses the
// disk zip rather than surfacing the network error.
func TestFetchNetworkFailureReParsesDiskZip(t *testing.T) {
	t.Parallel()

	payload := makeOSVZip(t, "MAL-2026-5", "disk-pkg", "npm", []string{"4.0.0"})

	// Build a server, immediately close it — every request fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Close()

	cacheDir := t.TempDir()
	// Pre-seed only the zip (no etag) — simulates the rare half-state
	// where an earlier run wrote the zip but the etag was lost (or
	// deliberately not persisted by a parse failure on a previous body).
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.zip"), payload, 0o644))

	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "network failure with disk zip must fall back to re-parse")
	require.Len(t, reports, 1)
	require.Equal(t, "disk-pkg", reports[0].Name)
}

// TestFetchParseFailureDropsEtag verifies H3: when the downloaded zip
// cannot be parsed (corrupt header, truncated central directory, etc.),
// the etag must NOT be persisted. Otherwise the next refresh sends
// If-None-Match, gets a 304, re-parses the same broken zip from disk,
// and fails forever.
//
// The current implementation moves the etag write AFTER parseZip
// succeeds; this test pins that invariant.
func TestFetchParseFailureDropsEtag(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	var serveValid atomic.Bool

	// Build a valid one-entry zip with a malware OSV advisory.
	validZip := makeOSVZip(t, "MAL-2026-99", "evil-pkg", "PyPI", []string{"1.0.0"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"broken"` {
			// If the client tries to revalidate against the broken etag,
			// fail loudly with a 304 so the test will surface the bug.
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if serveValid.Load() {
			w.Header().Set("ETag", `"good"`)
			_, _ = w.Write(validZip)
			return
		}
		w.Header().Set("ETag", `"broken"`)
		// Not a valid zip; small payload survives the size cap but
		// zip.OpenReader will reject it.
		_, _ = w.Write([]byte("definitely not a zip"))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemPyPI)
	require.Error(t, err, "corrupt zip must fail to parse")

	// OSV uses ecosystemPath-keyed filenames; for PyPI it's "PyPI.etag".
	etagPath := filepath.Join(cacheDir, "PyPI.etag")
	_, statErr := os.Stat(etagPath)
	require.True(t, os.IsNotExist(statErr),
		"etag must not persist for an unparseable zip (got stat err: %v)", statErr)

	serveValid.Store(true)
	reports, err := src.Fetch(context.Background(), intel.EcosystemPyPI)
	require.NoError(t, err, "next fetch must succeed instead of 304-looping on broken cache")
	require.Len(t, reports, 1)
	require.Equal(t, "evil-pkg", reports[0].Name)

	etag, err := os.ReadFile(etagPath)
	require.NoError(t, err)
	require.Equal(t, `"good"`, string(etag))

	require.Equal(t, int32(2), hits.Load(), "exactly two upstream hits expected")
}

// makeOSVZip builds an in-memory zip containing one OSV-shaped JSON
// advisory with the given fields. Sufficient for IsMalware to fire
// when the id starts with MAL-.
func makeOSVZip(t *testing.T, id, pkg, eco string, versions []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	var versionsJSON bytes.Buffer
	versionsJSON.WriteString("[")
	for i, v := range versions {
		if i > 0 {
			versionsJSON.WriteString(",")
		}
		versionsJSON.WriteString(`"` + v + `"`)
	}
	versionsJSON.WriteString("]")

	advisory := `{
  "id": "` + id + `",
  "summary": "malware",
  "affected": [
    {
      "package": {"ecosystem": "` + eco + `", "name": "` + pkg + `"},
      "versions": ` + versionsJSON.String() + `
    }
  ]
}`

	f, err := zw.Create(id + ".json")
	require.NoError(t, err)
	_, err = f.Write([]byte(advisory))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}
