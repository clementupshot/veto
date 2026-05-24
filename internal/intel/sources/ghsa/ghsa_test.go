package ghsa

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

func TestParseTarballExtractsReviewedVulnerabilities(t *testing.T) {
	t.Parallel()

	npmAdvisory := `{
  "id": "GHSA-1111-2222-3333",
  "summary": "prototype pollution in normal-pkg",
  "published": "2026-05-01T00:00:00Z",
  "affected": [
    {"package": {"ecosystem": "npm", "name": "normal-pkg"}, "versions": ["1.0.0"]}
  ]
}`
	pyPIAdvisory := `{
  "id": "GHSA-4444-5555-6666",
  "summary": "arbitrary code execution in py-pkg",
  "affected": [
    {"package": {"ecosystem": "pip", "name": "py-pkg"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}
  ]
}`
	withdrawn := `{
  "id": "GHSA-7777-8888-9999",
  "summary": "withdrawn advisory",
  "withdrawn": "2026-05-02T00:00:00Z",
  "affected": [
    {"package": {"ecosystem": "npm", "name": "withdrawn-pkg"}, "versions": ["1.0.0"]}
  ]
}`
	goAdvisory := `{
  "id": "GHSA-aaaa-bbbb-cccc",
  "summary": "unsupported ecosystem",
  "affected": [
    {"package": {"ecosystem": "Go", "name": "example.com/pkg"}, "versions": ["1.0.0"]}
  ]
}`

	tarballPath := makeTarballFile(t, map[string]string{
		"advisory-database-main/README.md":                                                             "# advisory database\n",
		"advisory-database-main/advisories/unreviewed/2026/05/GHSA-x/GHSA-x.json":                      npmAdvisory,
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-1111/GHSA-1111-2222-3333.json": npmAdvisory,
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-4444/GHSA-4444-5555-6666.json": pyPIAdvisory,
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-7777/GHSA-7777-8888-9999.json": withdrawn,
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-aaaa/GHSA-aaaa-bbbb-cccc.json": goAdvisory,
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-not-json/GHSA-not-json.md":     npmAdvisory,
	})

	src := &Source{logger: zerolog.Nop()}
	reports, err := src.parseTarball(tarballPath)
	require.NoError(t, err)
	require.Len(t, reports, 2)

	byName := map[string]intel.MalwareReport{}
	for _, r := range reports {
		byName[r.Name] = r
		require.Equal(t, "ghsa", r.SourceID)
	}

	npm := byName["normal-pkg"]
	require.Equal(t, intel.EcosystemNPM, npm.Ecosystem)
	require.Equal(t, "1.0.0", npm.Version)
	require.Equal(t, "GHSA-1111-2222-3333", npm.AdvisoryID)
	require.Equal(t, "prototype pollution in normal-pkg", npm.Reason)

	py := byName["py-pkg"]
	require.Equal(t, intel.EcosystemPyPI, py.Ecosystem)
	require.Empty(t, py.Version)
	require.NotNil(t, py.Range)
	require.Equal(t, "0", py.Range.Introduced)
	require.Equal(t, "2.0.0", py.Range.Fixed)
}

func TestFetchEndToEndUsesTarballCache(t *testing.T) {
	t.Parallel()

	tarball := makeTarballBytes(t, map[string]string{
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-test/GHSA-test.json": `{
  "id": "GHSA-test-test-test",
  "summary": "known vulnerable",
  "affected": [
    {"package": {"ecosystem": "npm", "name": "vulnerable"}, "versions": ["9.9.9"]}
  ]
}`,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		switch r.Method {
		case http.MethodHead:
			return
		case http.MethodGet:
			_, _ = w.Write(tarball)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := New(Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Equal(t, "vulnerable", reports[0].Name)
	require.Equal(t, "9.9.9", reports[0].Version)

	reports2, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Equal(t, reports, reports2)
	require.FileExists(t, filepath.Join(cacheDir, "main.tar.gz"))
	require.FileExists(t, filepath.Join(cacheDir, "main.etag"))
}

func TestFetchUnsupportedEcosystem(t *testing.T) {
	t.Parallel()

	src, err := New(Options{CacheDir: t.TempDir()})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.Ecosystem("maven"))
	require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem)
}

func TestIsReviewedAdvisoryEntry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		want bool
	}{
		{"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-x/GHSA-x.json", true},
		{"renamed-root/advisories/github-reviewed/2026/05/GHSA-x/GHSA-x.json", true},
		{"advisory-database-main/advisories/unreviewed/2026/05/GHSA-x/GHSA-x.json", false},
		{"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-x/GHSA-x.md", false},
		{"advisories/github-reviewed/2026/05/GHSA-x/GHSA-x.json", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, isReviewedAdvisoryEntry(c.name))
		})
	}
}

func makeTarballFile(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "advisory-database.tar.gz")
	require.NoError(t, os.WriteFile(path, makeTarballBytes(t, files), 0o644))
	return path
}

func makeTarballBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}
