package pipreport_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/pipreport"
)

func TestExpand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pip-report.json")
	body := `{
  "version": "1",
  "install": [
    {"metadata": {"name": "clean-direct", "version": "1.0.0"}},
    {"metadata": {"name": "evil-transitive", "version": "9.9.9"}},
    {"metadata": {"name": "missing-version"}}
  ]
}`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	out, err := pipreport.New().Expand(packagemanager.ManifestRef{Path: path, Kind: packagemanager.ManifestKindPipReportJSON})

	require.NoError(t, err)
	require.Equal(t, []packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "clean-direct", Version: "1.0.0"}, RawSpec: "clean-direct==1.0.0"},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil-transitive", Version: "9.9.9"}, RawSpec: "evil-transitive==9.9.9"},
	}, out)
}

func TestExpandMissingFile(t *testing.T) {
	out, err := pipreport.New().Expand(packagemanager.ManifestRef{Path: filepath.Join(t.TempDir(), "missing.json"), Kind: packagemanager.ManifestKindPipReportJSON})

	require.NoError(t, err)
	require.Nil(t, out)
}

func TestExpandWrongKind(t *testing.T) {
	out, err := pipreport.New().Expand(packagemanager.ManifestRef{Path: "anything", Kind: packagemanager.ManifestKindRequirements})

	require.NoError(t, err)
	require.Nil(t, out)
}
