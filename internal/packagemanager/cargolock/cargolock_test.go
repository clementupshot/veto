package cargolock_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/cargolock"
)

func TestExpandCargoLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cargo.lock")
	body := `version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "itoa"
version = "1.0.15"
source = "sparse+https://index.crates.io/"

[[package]]
name = "my-workspace-crate"
version = "0.1.0"

[[package]]
name = "git-crate"
version = "0.2.0"
source = "git+https://github.com/example/git-crate?rev=abc#abc"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	out, err := cargolock.New().Expand(packagemanager.ManifestRef{Path: path, Kind: packagemanager.ManifestKindCargoLock})
	require.NoError(t, err)
	requireContains(t, out, "serde", "1.0.228", false, false)
	requireContains(t, out, "itoa", "1.0.15", false, false)
	requireContains(t, out, "my-workspace-crate", "0.1.0", true, false)
	requireContains(t, out, "git-crate", "0.2.0", false, true)
	require.Len(t, out, 4)
}

func TestExpandMissingCargoLockReturnsNilNil(t *testing.T) {
	out, err := cargolock.New().Expand(packagemanager.ManifestRef{Path: "/no/such/Cargo.lock", Kind: packagemanager.ManifestKindCargoLock})
	require.NoError(t, err)
	require.Nil(t, out)
}

func TestExpandMalformedCargoLockErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cargo.lock")
	require.NoError(t, os.WriteFile(path, []byte("not [toml"), 0o644))

	_, err := cargolock.New().Expand(packagemanager.ManifestRef{Path: path, Kind: packagemanager.ManifestKindCargoLock})
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse Cargo.lock")
}

func TestExpandUnknownKindIsNoop(t *testing.T) {
	out, err := cargolock.New().Expand(packagemanager.ManifestRef{Path: "Cargo.lock", Kind: packagemanager.ManifestKindPackageJSON})
	require.NoError(t, err)
	require.Nil(t, out)
}

func requireContains(t *testing.T, installs []packagemanager.Install, name, version string, localPath, opaque bool) {
	t.Helper()
	for _, ins := range installs {
		if ins.Ref.Ecosystem == intel.EcosystemCrates && ins.Ref.Name == name && ins.Ref.Version == version && ins.LocalPath == localPath && ins.OpaqueRemote == opaque {
			return
		}
	}
	t.Fatalf("expected %s@%s local=%t opaque=%t in:\n%v", name, version, localPath, opaque, installs)
}
