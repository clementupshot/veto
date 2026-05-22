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

// TestFetchParseFailureDropsEtag verifies H3: when the downloaded zip
// cannot be parsed (corrupt header, truncated central directory, etc.),
// the etag must NOT be persisted. Otherwise the next refresh sends
// If-None-Match, gets a 304, re-parses the same broken zip from disk,
// and fails forever.
//
// The current implementation moves the etag write AFTER parseZip
// succeeds; this test pins that invariant.
func TestFetchParseFailureDropsEtag(t *testing.T) {
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
