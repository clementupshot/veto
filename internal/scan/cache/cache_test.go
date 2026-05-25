package cache_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/scan"
	"github.com/brynbellomy/veto/internal/scan/cache"
)

func TestScannerFindsFlaggedNpxPackage(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "_npx", "abc", "node_modules", "evil")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"evil","version":"1.0.0"}`), 0o644))
	store := buildStore(t, intel.MalwareReport{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"}, SourceID: "fake"})

	result := cache.New(cache.Options{Roots: []string{root}, Store: store}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.Equal(t, 1, result.FilesScanned)
	require.Equal(t, 1, result.PackagesChecked)
	require.Len(t, result.Findings, 1)
	require.Equal(t, scan.SurfaceCache, result.Findings[0].Surface)
	require.Equal(t, scan.SeverityHigh, result.Findings[0].Severity)
	require.Equal(t, "evil", result.Findings[0].PackageRef.Name)
	require.NotEmpty(t, result.Findings[0].PurgePath)
}

func TestScannerReportsButDoesNotPurgeNameOnlyCacheMetadata(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "_npx", "abc", "node_modules", "evil")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"evil"}`), 0o644))
	store := buildStore(t, intel.MalwareReport{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"}, SourceID: "fake"})

	result := cache.New(cache.Options{Roots: []string{root}, Store: store}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.Len(t, result.Findings, 1)
	require.Equal(t, scan.SeverityHigh, result.Findings[0].Severity)
	require.Empty(t, result.Findings[0].PurgePath)
	require.Equal(t, "name-only", evidenceValue(t, result.Findings[0], "confidence"))
}

func TestScannerReportsMCPNpxResidue(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "_npx", "abc", "node_modules", "mcp-mermaid")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"mcp-mermaid","version":"0.6.1"}`), 0o644))

	result := cache.New(cache.Options{Roots: []string{root}, Store: buildStore(t)}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.Len(t, result.Findings, 1)
	require.Equal(t, scan.SeverityLow, result.Findings[0].Severity)
	require.Contains(t, result.Findings[0].Title, "MCP-like")
}

func TestPlanPurgeDeletesOnlyConfirmedInsideCacheRoot(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "_npx", "abc", "node_modules", "evil")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"evil","version":"1.0.0"}`), 0o644))
	store := buildStore(t, intel.MalwareReport{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"}, SourceID: "fake"})
	result := cache.New(cache.Options{Roots: []string{root}, Store: store}).Scan(context.Background())
	require.Len(t, result.Findings, 1)

	planned := cache.PlanPurge(result.Findings, []string{root}, false)
	require.Len(t, planned, 1)
	require.Equal(t, "planned", planned[0].Status)
	_, err := os.Stat(pkgDir)
	require.NoError(t, err)

	deleted := cache.PlanPurge(result.Findings, []string{root}, true)
	require.Len(t, deleted, 1)
	require.Equal(t, "deleted", deleted[0].Status)
	_, err = os.Stat(pkgDir)
	require.True(t, os.IsNotExist(err))
}

func TestScannerFindsFlaggedGoModuleCacheDirectory(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "github.com", "!evil", "pkg@v1.2.3")
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	store := buildStore(t, intel.MalwareReport{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemGo, Name: "github.com/Evil/pkg", Version: "v1.2.3"}, SourceID: "fake"})

	result := cache.New(cache.Options{RootEntries: []cache.Root{cache.GoRoot(root)}, Store: store}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.Equal(t, 1, result.FilesScanned)
	require.Equal(t, 1, result.PackagesChecked)
	require.Len(t, result.Findings, 1)
	require.Equal(t, intel.EcosystemGo, result.Findings[0].PackageRef.Ecosystem)
	require.Equal(t, "github.com/Evil/pkg", result.Findings[0].PackageRef.Name)
	require.Equal(t, "v1.2.3", result.Findings[0].PackageRef.Version)
	require.Equal(t, modDir, result.Findings[0].PurgePath)
}

func TestScannerFindsFlaggedGoDownloadCacheFile(t *testing.T) {
	root := t.TempDir()
	zip := filepath.Join(root, "cache", "download", "example.com", "evil", "pkg", "@v", "v0.4.0.zip")
	require.NoError(t, os.MkdirAll(filepath.Dir(zip), 0o755))
	require.NoError(t, os.WriteFile(zip, []byte("zip"), 0o644))
	store := buildStore(t, intel.MalwareReport{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemGo, Name: "example.com/evil/pkg", Version: "v0.4.0"}, SourceID: "fake"})

	result := cache.New(cache.Options{RootEntries: []cache.Root{cache.GoRoot(root)}, Store: store}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.Len(t, result.Findings, 1)
	require.Equal(t, zip, result.Findings[0].PurgePath)
}

func TestScannerFindsFlaggedCargoRegistryArchive(t *testing.T) {
	root := t.TempDir()
	crate := filepath.Join(root, "cache", "index.crates.io-6f17d22bba15001f", "evil-crate-1.2.3.crate")
	require.NoError(t, os.MkdirAll(filepath.Dir(crate), 0o755))
	require.NoError(t, os.WriteFile(crate, []byte("crate"), 0o644))
	store := buildStore(t, intel.MalwareReport{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "evil-crate", Version: "1.2.3"}, SourceID: "fake"})

	result := cache.New(cache.Options{RootEntries: []cache.Root{cache.CargoRegistryRoot(root)}, Store: store}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.Len(t, result.Findings, 1)
	require.Equal(t, intel.EcosystemCrates, result.Findings[0].PackageRef.Ecosystem)
	require.Equal(t, "evil-crate", result.Findings[0].PackageRef.Name)
	require.Equal(t, "1.2.3", result.Findings[0].PackageRef.Version)
	require.Equal(t, crate, result.Findings[0].PurgePath)
}

func TestScannerFindsFlaggedCargoRegistrySourceDirectory(t *testing.T) {
	root := t.TempDir()
	crateDir := filepath.Join(root, "src", "index.crates.io-6f17d22bba15001f", "evil-crate-1.2.3")
	require.NoError(t, os.MkdirAll(crateDir, 0o755))
	store := buildStore(t, intel.MalwareReport{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "evil-crate", Version: "1.2.3"}, SourceID: "fake"})

	result := cache.New(cache.Options{RootEntries: []cache.Root{cache.CargoRegistryRoot(root)}, Store: store}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.Len(t, result.Findings, 1)
	require.Equal(t, crateDir, result.Findings[0].PurgePath)
}

func TestScannerFindsFlaggedCargoGitCheckout(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "checkouts", "evil-crate-abcd", "1234567", "Cargo.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(manifest), 0o755))
	require.NoError(t, os.WriteFile(manifest, []byte("[package]\nname = \"evil-crate\"\nversion = \"1.2.3\"\n"), 0o644))
	store := buildStore(t, intel.MalwareReport{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "evil-crate", Version: "1.2.3"}, SourceID: "fake"})

	result := cache.New(cache.Options{RootEntries: []cache.Root{cache.CargoGitRoot(root)}, Store: store}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.Len(t, result.Findings, 1)
	require.Equal(t, filepath.Dir(manifest), result.Findings[0].PurgePath)
}

func TestPlanPurgeDeletesGoCacheArtifact(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "example.com", "evil@v1.0.0")
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	store := buildStore(t, intel.MalwareReport{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemGo, Name: "example.com/evil", Version: "v1.0.0"}, SourceID: "fake"})
	result := cache.New(cache.Options{RootEntries: []cache.Root{cache.GoRoot(root)}, Store: store}).Scan(context.Background())
	require.Len(t, result.Findings, 1)

	actions := cache.PlanPurge(result.Findings, []string{root}, true)

	require.Len(t, actions, 1)
	require.Equal(t, "deleted", actions[0].Status)
	_, err := os.Stat(modDir)
	require.True(t, os.IsNotExist(err))
}

func TestPlanPurgeSkipsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsidePkg := filepath.Join(outside, "evil")
	require.NoError(t, os.MkdirAll(outsidePkg, 0o755))
	link := filepath.Join(root, "evil-link")
	require.NoError(t, os.Symlink(outsidePkg, link))
	ref := intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil", Version: "1.0.0"}
	verdict := intel.Verdict{Ref: ref, Reports: []intel.MalwareReport{{PackageRef: ref, SourceID: "fake"}}}

	actions := cache.PlanPurge([]scan.Finding{{
		ID:        "finding",
		Surface:   scan.SurfaceCache,
		Severity:  scan.SeverityHigh,
		Verdict:   &verdict,
		PurgePath: link,
	}}, []string{root}, true)

	require.Len(t, actions, 1)
	require.Equal(t, "skipped", actions[0].Status)
	_, err := os.Stat(outsidePkg)
	require.NoError(t, err)
}

func TestPlanPurgeDoesNotDeleteIocOnlyResidue(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "_npx", "abc", "node_modules", "mcp-mermaid")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"mcp-mermaid","version":"0.6.1"}`), 0o644))
	result := cache.New(cache.Options{Roots: []string{root}, Store: buildStore(t)}).Scan(context.Background())
	require.Len(t, result.Findings, 1)

	actions := cache.PlanPurge(result.Findings, []string{root}, true)

	require.Empty(t, actions)
	_, err := os.Stat(pkgDir)
	require.NoError(t, err)
}

type fakeSource struct{ reports []intel.MalwareReport }

func (fakeSource) ID() string { return "fake" }

func (f fakeSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	var out []intel.MalwareReport
	for _, r := range f.reports {
		if r.Ecosystem == eco {
			out = append(out, r)
		}
	}
	return out, nil
}

func buildStore(t *testing.T, reports ...intel.MalwareReport) intel.Store {
	t.Helper()
	store := intel.NewStore(zerolog.Nop(), fakeSource{reports: reports})
	require.NoError(t, store.Refresh(context.Background()))
	return store
}

func evidenceValue(t *testing.T, finding scan.Finding, label string) string {
	t.Helper()
	for _, evidence := range finding.Evidence {
		if evidence.Label == label {
			return evidence.Value
		}
	}
	t.Fatalf("missing evidence label %q", label)
	return ""
}
