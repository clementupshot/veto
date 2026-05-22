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
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/openssf"
)

// TestFetchParseFailureDropsEtag verifies H3 for the OpenSSF source.
// OpenSSF's caching shape is slightly different: a HEAD probes the etag,
// then downloadIfChanged short-circuits if the local etag still matches.
// If parseTarball fails, the etag-on-disk now references a known-bad
// tarball — and the next call will keep matching the upstream etag and
// reusing the broken file forever. The fix removes the etag on parse
// failure, so the next call re-downloads.
func TestFetchParseFailureDropsEtag(t *testing.T) {
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
