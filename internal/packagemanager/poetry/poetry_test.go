package poetry_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/poetry"
)

func TestParseInstalls(t *testing.T) {
	m := poetry.New()
	require.Equal(t, "poetry", m.Name())
	require.Equal(t, intel.EcosystemPyPI, m.Ecosystem())

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			name: "global flag-with-value before verb is skipped",
			args: []string{"--directory", "/tmp/proj", "add", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "--flag=value form before verb is skipped",
			args: []string{"--directory=/tmp/proj", "add", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "flag-with-value after verb does not eat the package",
			args: []string{"add", "--source", "private-pypi", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "plain flag (no value) still works",
			args: []string{"add", "--dev", "pytest"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pytest"}, RawSpec: "pytest"},
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
	m := poetry.New()
	pypRef := []packagemanager.ManifestRef{{Path: "pyproject.toml", Kind: packagemanager.ManifestKindPyProject}}

	cases := []struct {
		name string
		args []string
		want []packagemanager.ManifestRef
	}{
		{
			name: "non-install verb returns nil",
			args: []string{"shell"},
			want: nil,
		},
		{
			name: "poetry install emits pyproject ref",
			args: []string{"install"},
			want: pypRef,
		},
		{
			name: "poetry update emits pyproject ref",
			args: []string{"update"},
			want: pypRef,
		},
		{
			name: "poetry add with spec returns nil (no manifest pull)",
			args: []string{"add", "requests"},
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, m.ManifestRefs(c.args))
		})
	}
}
