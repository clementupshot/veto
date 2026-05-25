package golang_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/golang"
)

func TestParseInstalls(t *testing.T) {
	m := golang.New()

	t.Run("go get gates module specs and skips removals", func(t *testing.T) {
		out := m.ParseInstalls([]string{"get", "github.com/evil/module@v1.2.3", "golang.org/x/sys@latest", "github.com/old/module@none"})
		requireContains(t, out, "github.com/evil/module", "v1.2.3", false, false)
		requireContains(t, out, "golang.org/x/sys", "", false, false)
		require.Len(t, out, 2)
	})

	t.Run("go install gates remote package forms", func(t *testing.T) {
		out := m.ParseInstalls([]string{"install", "github.com/evil/cmd@v0.2.0"})
		requireContains(t, out, "github.com/evil/cmd", "v0.2.0", false, false)
	})

	t.Run("go run only gates remote versioned package form", func(t *testing.T) {
		out := m.ParseInstalls([]string{"run", "github.com/evil/cmd@v0.2.0", "--arg"})
		requireContains(t, out, "github.com/evil/cmd", "v0.2.0", false, false)

		out = m.ParseInstalls([]string{"run", "github.com/evil/cmd@latest"})
		requireContains(t, out, "github.com/evil/cmd", "", false, false)

		require.Nil(t, m.ParseInstalls([]string{"run", "./cmd/app"}))
		require.Nil(t, m.ParseInstalls([]string{"run", "main.go"}))
	})

	t.Run("go mod download gates explicit modules", func(t *testing.T) {
		out := m.ParseInstalls([]string{"mod", "download", "github.com/evil/module@v1.2.3"})
		requireContains(t, out, "github.com/evil/module", "v1.2.3", false, false)
	})

	t.Run("go mod tidy gates manifest refs only", func(t *testing.T) {
		out := m.ParseInstalls([]string{"mod", "tidy"})
		require.Empty(t, out)
	})

	t.Run("non fetching commands pass through", func(t *testing.T) {
		require.Nil(t, m.ParseInstalls([]string{"build", "./..."}))
		require.Nil(t, m.ParseInstalls([]string{"test", "./..."}))
		require.Nil(t, m.ParseInstalls([]string{"version"}))
	})
}

func TestManifestRefs(t *testing.T) {
	m := golang.New()

	for _, args := range [][]string{
		{"get", "github.com/evil/module@v1.2.3"},
		{"mod", "download"},
		{"mod", "tidy"},
	} {
		refs := m.ManifestRefs(args)
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "go.mod", Kind: packagemanager.ManifestKindGoMod},
			{Path: "go.sum", Kind: packagemanager.ManifestKindGoSum},
		}, refs)
	}

	require.Nil(t, m.ManifestRefs([]string{"get", "github.com/old/module@none"}))
	require.Nil(t, m.ManifestRefs([]string{"get"}))
	require.Nil(t, m.ManifestRefs([]string{"install", "github.com/evil/cmd@v0.2.0"}))
	require.Nil(t, m.ManifestRefs([]string{"run", "github.com/evil/cmd@v0.2.0"}))
	require.Nil(t, m.ManifestRefs([]string{"build", "./..."}))
}

func requireContains(t *testing.T, installs []packagemanager.Install, name, version string, localPath, opaque bool) {
	t.Helper()
	for _, ins := range installs {
		if ins.Ref.Ecosystem == intel.EcosystemGo && ins.Ref.Name == name && ins.Ref.Version == version && ins.LocalPath == localPath && ins.OpaqueRemote == opaque {
			return
		}
	}
	t.Fatalf("expected %s@%s local=%t opaque=%t in:\n%v", name, version, localPath, opaque, installs)
}
