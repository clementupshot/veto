package openssf_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
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
	"github.com/brynbellomy/veto/internal/intel/sources/openssf"
)

// TestFetchParsesPayload exercises the happy path: HEAD returns an etag,
// GET returns a valid tarball, parse succeeds, ecosystem-filtered reports
// come back with the expected fields. Side effects (tarball + etag + gob)
// are observable on disk for the next call.
func TestFetchParsesPayload(t *testing.T) {
	t.Parallel()

	tarball := makeMaliciousPackagesTarball(t, "MAL-2026-1", "evil-pkg", "npm", []string{"1.0.0"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc123"`)
		switch r.Method {
		case http.MethodHead:
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			_, _ = w.Write(tarball)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Equal(t, "openssf", reports[0].SourceID)
	require.Equal(t, intel.EcosystemNPM, reports[0].Ecosystem)
	require.Equal(t, "evil-pkg", reports[0].Name)

	require.FileExists(t, filepath.Join(cacheDir, "main.tar.gz"))
	etag, err := os.ReadFile(filepath.Join(cacheDir, "main.etag"))
	require.NoError(t, err)
	require.Equal(t, `"abc123"`, string(etag))

	// A gob file should have been written so the next refresh can skip parse.
	require.True(t, hasGobFile(t, cacheDir), "expected a parsed-*.gob file after a successful fetch")
}

// TestFetchFiltersByEcosystem confirms that a tarball with entries in two
// ecosystems returns only the requested one. The cached parse contains
// both; Fetch must filter.
func TestFetchFiltersByEcosystem(t *testing.T) {
	t.Parallel()

	tarball := makeMaliciousPackagesTarballMulti(t, []tarEntry{
		{id: "MAL-2026-1", pkg: "evil-npm", eco: "npm", versions: []string{"1.0.0"}},
		{id: "MAL-2026-2", pkg: "evil-py", eco: "pypi", versions: []string{"2.0.0"}},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"xyz"`)
		if r.Method == http.MethodGet {
			_, _ = w.Write(tarball)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	src, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   t.TempDir(),
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	npmReports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, npmReports, 1)
	require.Equal(t, "evil-npm", npmReports[0].Name)

	pyReports, err := src.Fetch(context.Background(), intel.EcosystemPyPI)
	require.NoError(t, err)
	require.Len(t, pyReports, 1)
	require.Equal(t, "evil-py", pyReports[0].Name)
}

// TestFetchUnsupportedEcosystem confirms ErrUnsupportedEcosystem is
// returned cleanly for ecosystems the source does not cover. Importantly
// this must happen WITHOUT hitting the network — the store relies on the
// error being free.
func TestFetchUnsupportedEcosystem(t *testing.T) {
	t.Parallel()

	// Use an invalid URL so any network hit would fail loudly.
	src, err := openssf.New(openssf.Options{
		TarballURL: "http://127.0.0.1:1", // closed port
		CacheDir:   t.TempDir(),
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.Ecosystem("maven"))
	require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem)
}

// TestFetchHeadEtagShortCircuit verifies that once a tarball + etag are on
// disk, a HEAD-only revalidation against an unchanged etag reuses the
// cached gob: no GET, no re-parse. We assert via the GET-hit counter
// staying at 1 across two calls.
func TestFetchHeadEtagShortCircuit(t *testing.T) {
	t.Parallel()

	tarball := makeMaliciousPackagesTarball(t, "MAL-2026-1", "shortcircuit-pkg", "npm", []string{"1.0.0"})

	var headHits, getHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc123"`)
		switch r.Method {
		case http.MethodHead:
			headHits.Add(1)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			getHits.Add(1)
			_, _ = w.Write(tarball)
		}
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	// First call: HEAD + GET + parse.
	first, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, int32(1), headHits.Load())
	require.Equal(t, int32(1), getHits.Load())

	// Second call from the SAME source instance: in-memory cache short-circuit.
	// HEAD still fires (the source re-checks upstream every refresh), GET
	// must not.
	second, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Equal(t, int32(2), headHits.Load())
	require.Equal(t, int32(1), getHits.Load(), "in-memory cache must short-circuit the GET")

	// Cold-start (new source) but warm disk: gob + etag are present, so the
	// gob path takes over and we still avoid the GET.
	src2, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)
	third, err := src2.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, third, 1)
	require.Equal(t, int32(3), headHits.Load())
	require.Equal(t, int32(1), getHits.Load(), "warm-disk gob must short-circuit the GET on a fresh source")
}

// TestFetchEtagChangedTriggersGet verifies that when upstream's etag
// changes, the source GETs the new tarball, parses it, and overwrites
// the on-disk artifacts.
func TestFetchEtagChangedTriggersGet(t *testing.T) {
	t.Parallel()

	first := makeMaliciousPackagesTarball(t, "MAL-2026-1", "old-pkg", "npm", []string{"1.0.0"})
	second := makeMaliciousPackagesTarball(t, "MAL-2026-2", "new-pkg", "npm", []string{"2.0.0"})

	var serveNew atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag := `"v1"`
		body := first
		if serveNew.Load() {
			etag = `"v2"`
			body = second
		}
		w.Header().Set("ETag", etag)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	}))
	defer srv.Close()

	src, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   t.TempDir(),
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	r1, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Equal(t, "old-pkg", r1[0].Name)

	serveNew.Store(true)
	r2, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Equal(t, "new-pkg", r2[0].Name)
}

// TestFetchHeadWithoutEtagErrors pins the behavior when upstream replies
// 200 to HEAD but omits the ETag header. The source treats this as a
// failure (it has no way to gate re-parses without the etag) and errors —
// unless an in-memory or disk cache is available to fall back to.
func TestFetchHeadWithoutEtagErrors(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No ETag header.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	src, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   t.TempDir(),
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "missing etag and no local cache must surface an error")
}

// TestFetchRejectsOversizedPayload pins the 512 MiB ceiling on the
// tarball download. The handler streams maxFeedBytes+1 bytes of garbage
// to trip the LimitReader+1 cap inside downloadIfChanged.
func TestFetchRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"oversized"`)
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		// GET: stream past the 512 MiB cap.
		const oversize = (512 << 20) + 1024
		buf := make([]byte, 1<<20)
		written := 0
		for written < oversize {
			n, err := w.Write(buf)
			if err != nil {
				return
			}
			written += n
		}
	}))
	defer srv.Close()

	src, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   t.TempDir(),
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "oversized tarball must be rejected, not buffered into memory")
	require.Contains(t, err.Error(), "size limit")
}

// TestFetchNetworkFailureFallsBackToInMemoryCache verifies that once a
// successful Fetch has populated the in-memory cache, a subsequent HEAD
// failure (network blip) returns the cached reports rather than erroring.
func TestFetchNetworkFailureFallsBackToInMemoryCache(t *testing.T) {
	t.Parallel()

	tarball := makeMaliciousPackagesTarball(t, "MAL-2026-9", "fallback-pkg", "npm", []string{"1.0.0"})

	var killed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if killed.Load() {
			// Simulate a flaky HEAD/GET by closing the connection rudely.
			hj, ok := w.(http.Hijacker)
			if ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodGet {
			_, _ = w.Write(tarball)
		}
	}))
	defer srv.Close()

	src, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   t.TempDir(),
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	// First fetch populates the in-memory cache.
	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	// Flip the server to fail every request.
	killed.Store(true)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "in-memory cache must absorb a HEAD failure")
	require.Len(t, reports, 1)
	require.Equal(t, "fallback-pkg", reports[0].Name)
}

// TestFetchNetworkFailureFallsBackToDiskGob covers the cold-memory /
// warm-disk fallback: a previous run left a gob blob in the cache dir,
// the current process is fresh (no in-memory cache), upstream is dead.
// The source must still produce reports.
func TestFetchNetworkFailureFallsBackToDiskGob(t *testing.T) {
	t.Parallel()

	tarball := makeMaliciousPackagesTarball(t, "MAL-2026-10", "disk-gob-pkg", "npm", []string{"1.0.0"})

	// Step 1: populate the gob cache against a live server.
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodGet {
			_, _ = w.Write(tarball)
		}
	}))

	cacheDir := t.TempDir()
	warm, err := openssf.New(openssf.Options{
		TarballURL: live.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)
	_, err = warm.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.True(t, hasGobFile(t, cacheDir))

	live.Close()

	// Step 2: build a fresh source pointed at a dead URL. The HEAD will
	// fail and the fallback path reads the gob off disk.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	dead.Close()

	cold, err := openssf.New(openssf.Options{
		TarballURL: dead.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := cold.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "fresh source with warm gob must survive a dead upstream")
	require.Len(t, reports, 1)
	require.Equal(t, "disk-gob-pkg", reports[0].Name)
}

// hasGobFile reports whether the cache dir contains at least one
// parsed-*.gob file — useful for asserting the gob cache layer engaged.
func hasGobFile(t *testing.T, dir string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "parsed-") && strings.HasSuffix(e.Name(), ".gob") {
			return true
		}
	}
	return false
}

// tarEntry describes a single OSV advisory to include in a synthetic
// malicious-packages tarball.
type tarEntry struct {
	id       string
	pkg      string
	eco      string
	versions []string
}

// makeMaliciousPackagesTarballMulti builds a gzipped tar with multiple
// advisories across ecosystems, mimicking the upstream repo layout.
func makeMaliciousPackagesTarballMulti(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for _, e := range entries {
		var versionsJSON bytes.Buffer
		versionsJSON.WriteString("[")
		for i, v := range e.versions {
			if i > 0 {
				versionsJSON.WriteString(",")
			}
			versionsJSON.WriteString(`"` + v + `"`)
		}
		versionsJSON.WriteString("]")

		advisory := `{
  "id": "` + e.id + `",
  "summary": "malware",
  "affected": [
    {
      "package": {"ecosystem": "` + e.eco + `", "name": "` + e.pkg + `"},
      "versions": ` + versionsJSON.String() + `
    }
  ]
}`

		name := "malicious-packages-main/osv/malicious/" + e.eco + "/" + e.pkg + "/" + e.id + ".json"
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(advisory)),
			Typeflag: tar.TypeReg,
		}))
		_, err := tw.Write([]byte(advisory))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// TestFetchParseFailureDropsEtag verifies H3 for the OpenSSF source.
// OpenSSF's caching shape is slightly different: a HEAD probes the etag,
// then downloadIfChanged short-circuits if the local etag still matches.
// If parseTarball fails, the etag-on-disk now references a known-bad
// tarball — and the next call will keep matching the upstream etag and
// reusing the broken file forever. The fix removes the etag on parse
// failure, so the next call re-downloads.
func TestFetchParseFailureDropsEtag(t *testing.T) {
	t.Parallel()

	var headHits atomic.Int32
	var getHits atomic.Int32
	var serveValid atomic.Bool

	validTarball := makeMaliciousPackagesTarball(t, "MAL-2026-X", "evil-pkg", "npm", []string{"1.0.0"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag := `"broken"`
		if serveValid.Load() {
			etag = `"good"`
		}
		w.Header().Set("ETag", etag)

		switch r.Method {
		case http.MethodHead:
			headHits.Add(1)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			getHits.Add(1)
			if serveValid.Load() {
				_, _ = w.Write(validTarball)
			} else {
				// Not a gzipped tarball: small payload below the size cap
				// that fails the gzip.NewReader in parseTarball.
				_, _ = w.Write([]byte("not a tarball"))
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "corrupt tarball must fail to parse")

	etagPath := filepath.Join(cacheDir, "main.etag")
	_, statErr := os.Stat(etagPath)
	require.True(t, os.IsNotExist(statErr),
		"etag must not persist for an unparseable tarball (stat err: %v)", statErr)

	// Now serve a valid tarball. Without the etag drop, downloadIfChanged
	// would see local etag == upstream and skip the GET, then parseTarball
	// would fail on the still-cached broken bytes.
	serveValid.Store(true)
	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "next fetch must succeed after parse-failure recovery")
	require.Len(t, reports, 1)
	require.Equal(t, "evil-pkg", reports[0].Name)

	require.GreaterOrEqual(t, getHits.Load(), int32(2),
		"expected the source to re-GET the tarball after a parse failure (got %d)", getHits.Load())
}

// makeMaliciousPackagesTarball builds a gzipped tar mimicking the
// ossf/malicious-packages repo layout: <repo>/osv/malicious/<eco>/<pkg>/<id>.json
func makeMaliciousPackagesTarball(t *testing.T, id, pkg, eco string, versions []string) []byte {
	t.Helper()

	var versionsJSON bytes.Buffer
	versionsJSON.WriteString("[")
	for i, v := range versions {
		if i > 0 {
			versionsJSON.WriteString(",")
		}
		versionsJSON.WriteString(`"` + v + `"`)
	}
	versionsJSON.WriteString("]")

	osvEco := eco
	if eco == "npm" {
		osvEco = "npm"
	}
	advisory := `{
  "id": "` + id + `",
  "summary": "malware",
  "affected": [
    {
      "package": {"ecosystem": "` + osvEco + `", "name": "` + pkg + `"},
      "versions": ` + versionsJSON.String() + `
    }
  ]
}`

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	entry := "malicious-packages-main/osv/malicious/" + eco + "/" + pkg + "/" + id + ".json"
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     entry,
		Mode:     0o644,
		Size:     int64(len(advisory)),
		Typeflag: tar.TypeReg,
	}))
	_, err := tw.Write([]byte(advisory))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}
