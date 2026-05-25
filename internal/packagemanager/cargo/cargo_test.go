package cargo_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/cargo"
)

func TestParseInstalls(t *testing.T) {
	m := cargo.New()

	t.Run("cargo add gates crate specs", func(t *testing.T) {
		out := m.ParseInstalls([]string{"add", "serde@1.0.228", "regex", "--features", "derive", "--optional"})
		requireContains(t, out, "serde", "1.0.228", false, false)
		requireContains(t, out, "regex", "", false, false)
		require.Len(t, out, 2)
	})

	t.Run("cargo add flags git sources as opaque", func(t *testing.T) {
		out := m.ParseInstalls([]string{"add", "my-crate", "--git", "https://github.com/example/my-crate"})
		requireContains(t, out, "my-crate", "", false, true)
		require.Len(t, out, 1)
	})

	t.Run("cargo add path source is local", func(t *testing.T) {
		out := m.ParseInstalls([]string{"add", "my-crate", "--path", "../my-crate"})
		requireContains(t, out, "my-crate", "", true, false)
		require.Len(t, out, 1)
	})

	t.Run("cargo install gates crate specs and local paths", func(t *testing.T) {
		out := m.ParseInstalls([]string{"install", "ripgrep@14.1.1", "./local", "--dry-run"})
		requireContains(t, out, "ripgrep", "14.1.1", false, false)
		requireContains(t, out, "./local", "", true, false)
	})

	t.Run("cargo install git source is opaque", func(t *testing.T) {
		out := m.ParseInstalls([]string{"install", "my-crate", "--git", "https://github.com/example/my-crate"})
		requireContains(t, out, "my-crate", "", false, true)
		require.Len(t, out, 1)
	})

	t.Run("cargo update and fetch gate manifest refs only", func(t *testing.T) {
		require.Empty(t, m.ParseInstalls([]string{"update"}))
		require.Empty(t, m.ParseInstalls([]string{"fetch"}))
	})

	t.Run("non dependency-fetching commands parse no installs", func(t *testing.T) {
		require.Nil(t, m.ParseInstalls([]string{"build"}))
		require.Nil(t, m.ParseInstalls([]string{"test"}))
		require.Nil(t, m.ParseInstalls([]string{"version"}))
	})
}

func TestManifestRefs(t *testing.T) {
	m := cargo.New()
	for _, args := range [][]string{
		{"add", "serde"},
		{"update"},
		{"fetch"},
	} {
		refs := m.ManifestRefs(args)
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "Cargo.toml", Kind: packagemanager.ManifestKindCargoToml},
			{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock},
		}, refs)
	}

	require.Nil(t, m.ManifestRefs([]string{"install", "ripgrep"}))
	require.Nil(t, m.ManifestRefs([]string{"build"}))
}

func TestProjectPreflight(t *testing.T) {
	m := cargo.New()

	for _, args := range [][]string{
		{"build"},
		{"check"},
		{"test"},
		{"run"},
		{"bench"},
		{"clippy"},
	} {
		plan, ok := m.ProjectPreflight(args)
		require.True(t, ok, "expected project preflight for %v", args)
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "Cargo.toml", Kind: packagemanager.ManifestKindCargoToml},
			{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock},
		}, plan.ManifestRefs)
	}

	plan, ok := m.ProjectPreflight([]string{"test", "--manifest-path", filepath.Join("nested", "Cargo.toml")})
	require.True(t, ok)
	require.Equal(t, []packagemanager.ManifestRef{
		{Path: filepath.Join("nested", "Cargo.toml"), Kind: packagemanager.ManifestKindCargoToml},
		{Path: filepath.Join("nested", "Cargo.lock"), Kind: packagemanager.ManifestKindCargoLock},
	}, plan.ManifestRefs)

	plan, ok = m.ProjectPreflight([]string{"build", "--manifest-path", filepath.Join("nested", "Cargo.toml"), "--lockfile-path", filepath.Join("locks", "Cargo.lock")})
	require.True(t, ok)
	require.Equal(t, []packagemanager.ManifestRef{
		{Path: filepath.Join("nested", "Cargo.toml"), Kind: packagemanager.ManifestKindCargoToml},
		{Path: filepath.Join("locks", "Cargo.lock"), Kind: packagemanager.ManifestKindCargoLock},
	}, plan.ManifestRefs)

	_, ok = m.ProjectPreflight([]string{"version"})
	require.False(t, ok)
	_, ok = m.ProjectPreflight([]string{"metadata"})
	require.False(t, ok)
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
