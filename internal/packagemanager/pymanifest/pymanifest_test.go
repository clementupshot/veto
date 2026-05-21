package pymanifest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pymanifest"
)

func TestExpandPyProject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")

	contents := `
[project]
name = "demo"
dependencies = [
  "requests>=2.0,<3",
  "httpx==0.27.0",
]

[project.optional-dependencies]
dev = ["pytest>=7", "black==24.3.0"]
docs = ["sphinx>=7"]

[tool.poetry]
name = "demo"

[tool.poetry.dependencies]
python = "^3.10"
django = "^4.2"
gunicorn = "21.2.0"
fancy-dep = { version = "^1.0", optional = true }
path-dep = { path = "../sibling" }

[tool.poetry.group.dev.dependencies]
mypy = "^1.0"
ruff = "0.4.4"
`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))

	exp := pymanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPyProject,
	})
	require.NoError(t, err)
	require.NotEmpty(t, installs)

	byName := make(map[string]packagemanager.Install, len(installs))
	for _, ins := range installs {
		require.Equal(t, intel.EcosystemPyPI, ins.Ref.Ecosystem)
		byName[ins.Ref.Name] = ins
	}

	// PEP 621 [project] dependencies
	require.Contains(t, byName, "requests")
	require.Equal(t, "", byName["requests"].Ref.Version, "range collapses to empty version")
	require.Contains(t, byName, "httpx")
	require.Equal(t, "0.27.0", byName["httpx"].Ref.Version, "exact == version preserved")

	// PEP 621 optional-dependencies — all groups merged
	require.Contains(t, byName, "pytest")
	require.Contains(t, byName, "black")
	require.Equal(t, "24.3.0", byName["black"].Ref.Version)
	require.Contains(t, byName, "sphinx")

	// Poetry [tool.poetry.dependencies]
	require.NotContains(t, byName, "python", "python key must be excluded")
	require.Contains(t, byName, "django")
	require.Equal(t, "", byName["django"].Ref.Version, "Poetry ^4.2 range collapses to empty version")
	require.Contains(t, byName, "gunicorn")
	require.Equal(t, "21.2.0", byName["gunicorn"].Ref.Version, "Poetry literal version preserved")

	// Poetry inline-table with version key
	require.Contains(t, byName, "fancy-dep")
	require.Equal(t, "", byName["fancy-dep"].Ref.Version)

	// Poetry inline-table path dep — name present, version empty
	require.Contains(t, byName, "path-dep")
	require.Equal(t, "", byName["path-dep"].Ref.Version)

	// Poetry group deps
	require.Contains(t, byName, "mypy")
	require.Contains(t, byName, "ruff")
	require.Equal(t, "0.4.4", byName["ruff"].Ref.Version)
}

func TestExpandMissingFileReturnsEmpty(t *testing.T) {
	exp := pymanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: filepath.Join(t.TempDir(), "no-such-file.toml"),
		Kind: packagemanager.ManifestKindPyProject,
	})
	require.NoError(t, err)
	require.Empty(t, installs)
}

func TestExpandUnknownKindReturnsNil(t *testing.T) {
	exp := pymanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: "irrelevant",
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.NoError(t, err)
	require.Empty(t, installs)
}

func TestExpandMalformedTOMLReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	require.NoError(t, os.WriteFile(path, []byte("not [valid toml ===="), 0o644))

	exp := pymanifest.New()
	_, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPyProject,
	})
	require.Error(t, err)
}

func TestExpandDedupesAcrossSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")

	contents := `
[project]
dependencies = ["requests==2.31.0"]

[tool.poetry.dependencies]
requests = "^2.31"
`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))

	exp := pymanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPyProject,
	})
	require.NoError(t, err)
	require.Len(t, installs, 1, "duplicate dep across PEP 621 and Poetry sections should collapse")
	require.Equal(t, "requests", installs[0].Ref.Name)
}
