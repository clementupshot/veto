package gomod_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/gomod"
)

func TestExpandGoMod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	body := `module example.com/app

go 1.24

require github.com/pkg/errors v0.9.1

require (
	github.com/google/uuid v1.6.0
	golang.org/x/sys v0.35.0 // indirect
)

replace github.com/pkg/errors => ../errors
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	out, err := gomod.New().Expand(packagemanager.ManifestRef{Path: path, Kind: packagemanager.ManifestKindGoMod})
	require.NoError(t, err)
	requireContains(t, out, "github.com/pkg/errors", "v0.9.1")
	requireContains(t, out, "github.com/google/uuid", "v1.6.0")
	requireContains(t, out, "golang.org/x/sys", "v0.35.0")
	require.Len(t, out, 3)
}

func TestExpandGoSumDedupesModuleAndGoModRows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.sum")
	body := `github.com/google/uuid v1.6.0 h1:abc
github.com/google/uuid v1.6.0/go.mod h1:def
golang.org/x/sys v0.35.0 h1:ghi
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	out, err := gomod.New().Expand(packagemanager.ManifestRef{Path: path, Kind: packagemanager.ManifestKindGoSum})
	require.NoError(t, err)
	requireContains(t, out, "github.com/google/uuid", "v1.6.0")
	requireContains(t, out, "golang.org/x/sys", "v0.35.0")
	require.Len(t, out, 2)
}

func TestExpandMissingGoFileReturnsNilNil(t *testing.T) {
	out, err := gomod.New().Expand(packagemanager.ManifestRef{Path: "/no/such/go.mod", Kind: packagemanager.ManifestKindGoMod})
	require.NoError(t, err)
	require.Nil(t, out)
}

func TestExpandUnknownKindIsNoop(t *testing.T) {
	out, err := gomod.New().Expand(packagemanager.ManifestRef{Path: "go.mod", Kind: packagemanager.ManifestKindPackageJSON})
	require.NoError(t, err)
	require.Nil(t, out)
}

func requireContains(t *testing.T, installs []packagemanager.Install, name, version string) {
	t.Helper()
	for _, ins := range installs {
		if ins.Ref.Ecosystem == intel.EcosystemGo && ins.Ref.Name == name && ins.Ref.Version == version {
			return
		}
	}
	t.Fatalf("expected %s@%s in:\n%v", name, version, installs)
}
