package project_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gate"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/jslock"
	"github.com/brynbellomy/veto/internal/packagemanager/jsmanifest"
	"github.com/brynbellomy/veto/internal/packagemanager/pylock"
	"github.com/brynbellomy/veto/internal/packagemanager/pymanifest"
	"github.com/brynbellomy/veto/internal/packagemanager/pyreq"
	"github.com/brynbellomy/veto/internal/scan"
	"github.com/brynbellomy/veto/internal/scan/project"
)

func TestScannerFindsFlaggedPackageLock(t *testing.T) {
	root := t.TempDir()
	lock := `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/evil-transitive": {"version": "9.9.9"}
  }
}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lock), 0o644))
	store := buildStore(t, intel.MalwareReport{PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-transitive", Version: "9.9.9"}, SourceID: "fake"})

	result := project.New(project.Options{Roots: []string{root}, Store: store, Expander: testExpander()}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.Equal(t, 1, result.FilesScanned)
	require.Equal(t, 1, result.PackagesChecked)
	require.Len(t, result.Findings, 1)
	require.Equal(t, scan.SurfaceProject, result.Findings[0].Surface)
	require.Equal(t, scan.SeverityHigh, result.Findings[0].Severity)
	require.Equal(t, "evil-transitive", result.Findings[0].PackageRef.Name)
}

func TestScannerPrunesNodeModules(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "node_modules", "bad"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "node_modules", "bad", "package-lock.json"), []byte(`{not json`), 0o644))

	result := project.New(project.Options{Roots: []string{root}, Store: buildStore(t), Expander: testExpander()}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.Empty(t, result.Findings)
	require.Zero(t, result.FilesScanned)
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

func testExpander() gate.ManifestExpander {
	return compoundExpander{
		pyReq:  pyreq.New(),
		js:     jsmanifest.New(),
		pyPrj:  pymanifest.New(),
		jsLock: jslock.New(),
		pyLock: pylock.New(),
	}
}

type compoundExpander struct {
	pyReq  *pyreq.Expander
	js     *jsmanifest.Expander
	pyPrj  *pymanifest.Expander
	jsLock *jslock.Expander
	pyLock *pylock.Expander
}

func (c compoundExpander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	switch ref.Kind {
	case packagemanager.ManifestKindRequirements, packagemanager.ManifestKindConstraint:
		return c.pyReq.Expand(ref)
	case packagemanager.ManifestKindPackageJSON:
		return c.js.Expand(ref)
	case packagemanager.ManifestKindPyProject:
		return c.pyPrj.Expand(ref)
	case packagemanager.ManifestKindPackageLockJSON,
		packagemanager.ManifestKindNpmShrinkwrap,
		packagemanager.ManifestKindPnpmLockYAML,
		packagemanager.ManifestKindYarnLock:
		return c.jsLock.Expand(ref)
	case packagemanager.ManifestKindUvLock,
		packagemanager.ManifestKindPoetryLock,
		packagemanager.ManifestKindPdmLock:
		return c.pyLock.Expand(ref)
	default:
		return nil, nil
	}
}
