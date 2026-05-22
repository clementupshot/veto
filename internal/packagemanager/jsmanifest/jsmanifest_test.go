package jsmanifest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/jsmanifest"
)

func TestExpandPackageJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")

	contents := `{
  "name": "demo",
  "dependencies": {
    "lodash": "^4.17.21",
    "@types/node": "20.0.0"
  },
  "devDependencies": {
    "typescript": "~5.0"
  },
  "peerDependencies": {
    "react": ">=17 <19"
  },
  "optionalDependencies": {
    "fsevents": "2.3.3"
  }
}`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))

	exp := jsmanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.NoError(t, err)
	require.Len(t, installs, 5)

	// Map-iteration order is non-deterministic per-section, so assert by
	// presence rather than position.
	byName := make(map[string]packagemanager.Install, len(installs))
	for _, ins := range installs {
		require.Equal(t, intel.EcosystemNPM, ins.Ref.Ecosystem)
		byName[ins.Ref.Name] = ins
	}

	require.Contains(t, byName, "lodash")
	require.Equal(t, "", byName["lodash"].Ref.Version, "caret-range collapses to empty for name-keyed lookup")

	require.Contains(t, byName, "@types/node")
	require.Equal(t, "20.0.0", byName["@types/node"].Ref.Version, "exact pin preserved")

	require.Contains(t, byName, "typescript")
	require.Equal(t, "", byName["typescript"].Ref.Version, "tilde-range collapses to empty")

	require.Contains(t, byName, "react")
	require.Equal(t, "", byName["react"].Ref.Version, "multi-clause range collapses to empty")

	require.Contains(t, byName, "fsevents")
	require.Equal(t, "2.3.3", byName["fsevents"].Ref.Version, "exact pin preserved")
}

func TestExpandMissingFileReturnsEmpty(t *testing.T) {
	exp := jsmanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: filepath.Join(t.TempDir(), "no-such-file.json"),
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.NoError(t, err)
	require.Empty(t, installs)
}

func TestExpandUnknownKindReturnsNil(t *testing.T) {
	exp := jsmanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: "irrelevant",
		Kind: packagemanager.ManifestKindRequirements,
	})
	require.NoError(t, err)
	require.Empty(t, installs)
}

func TestExpandMalformedJSONReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	require.NoError(t, os.WriteFile(path, []byte("{ not valid json"), 0o644))

	exp := jsmanifest.New()
	_, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.Error(t, err)
}

// TestExpandPackageJSONNpmAliases ensures values like "npm:realname@version"
// in package.json dependency maps unwrap to the real package, not the local
// alias name. Without this, a developer can shadow a clean-looking name over
// an attacker-controlled package and bypass the gate.
func TestExpandPackageJSONNpmAliases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")

	contents := `{
  "name": "demo",
  "dependencies": {
    "lodash": "npm:evil-pkg@1.0",
    "react": "npm:preact",
    "compat": "npm:@scope/real@2.0.0"
  }
}`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))

	exp := jsmanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.NoError(t, err)
	require.Len(t, installs, 3)

	byName := make(map[string]packagemanager.Install, len(installs))
	for _, ins := range installs {
		byName[ins.Ref.Name] = ins
	}

	require.NotContains(t, byName, "lodash", "alias name must not appear; real package wins")
	require.Contains(t, byName, "evil-pkg")
	require.Equal(t, "1.0", byName["evil-pkg"].Ref.Version)

	require.NotContains(t, byName, "react")
	require.Contains(t, byName, "preact")
	require.Equal(t, "", byName["preact"].Ref.Version, "unversioned alias → name-keyed lookup")

	require.NotContains(t, byName, "compat")
	require.Contains(t, byName, "@scope/real")
	require.Equal(t, "2.0.0", byName["@scope/real"].Ref.Version)
}

func TestExpandEmptyDeps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"name": "demo"}`), 0o644))

	exp := jsmanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.NoError(t, err)
	require.Empty(t, installs)
}
