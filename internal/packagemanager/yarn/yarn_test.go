package yarn_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/yarn"
)

func TestParseInstalls(t *testing.T) {
	m := yarn.New()
	require.Equal(t, "yarn", m.Name())
	require.Equal(t, intel.EcosystemNPM, m.Ecosystem())

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			name: "global flag-with-value before verb is skipped",
			args: []string{"--cwd", "/tmp/proj", "add", "lodash"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
			},
		},
		{
			name: "--flag=value form before verb is skipped",
			args: []string{"--cwd=/tmp/proj", "add", "lodash"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
			},
		},
		{
			name: "flag-with-value after verb does not eat the package",
			args: []string{"add", "--registry", "https://example.com", "lodash"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
			},
		},
		{
			name: "plain flag (no value) still works",
			args: []string{"add", "--dev", "typescript"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "typescript"}, RawSpec: "typescript"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, m.ParseInstalls(c.args))
		})
	}
}

func TestManifestRefs(t *testing.T) {
	m := yarn.New()
	pkgRef := []packagemanager.ManifestRef{{Path: "package.json", Kind: packagemanager.ManifestKindPackageJSON}}

	cases := []struct {
		name string
		args []string
		want []packagemanager.ManifestRef
	}{
		{
			name: "non-install verb returns nil",
			args: []string{"run", "dev"},
			want: nil,
		},
		{
			name: "install with no specs emits package.json ref",
			args: []string{"install"},
			want: pkgRef,
		},
		{
			name: "add with explicit specs returns nil",
			args: []string{"add", "lodash"},
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, m.ManifestRefs(c.args))
		})
	}
}
