package pip_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/pip"
)

func TestParseInstalls(t *testing.T) {
	m := pip.New("pip")
	require.Equal(t, "pip", m.Name())
	require.Equal(t, intel.EcosystemPyPI, m.Ecosystem())

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			name: "global flag-with-value before verb is skipped",
			args: []string{"--cache-dir", "/tmp/pip-cache", "install", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "--flag=value form before verb is skipped",
			args: []string{"--cache-dir=/tmp/pip-cache", "install", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "flag-with-value after verb does not eat the package",
			args: []string{"install", "--index-url", "https://example.com", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "short -i flag with value",
			args: []string{"install", "-i", "https://example.com", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "plain flag (no value) still works",
			args: []string{"install", "--user", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "-r requirements file is consumed as flag-value (gate expands the file)",
			args: []string{"install", "-r", "requirements.txt"},
			want: []packagemanager.Install{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, m.ParseInstalls(c.args))
		})
	}
}

func TestManifestRefs(t *testing.T) {
	m := pip.New("pip")

	cases := []struct {
		name string
		args []string
		want []packagemanager.ManifestRef
	}{
		{
			name: "no install verb returns nil",
			args: []string{"freeze"},
			want: nil,
		},
		{
			name: "install with no -r returns nil",
			args: []string{"install", "requests"},
			want: nil,
		},
		{
			name: "single -r",
			args: []string{"install", "-r", "requirements.txt"},
			want: []packagemanager.ManifestRef{
				{Path: "requirements.txt", Kind: packagemanager.ManifestKindRequirements},
			},
		},
		{
			name: "long --requirement",
			args: []string{"install", "--requirement", "dev-reqs.txt"},
			want: []packagemanager.ManifestRef{
				{Path: "dev-reqs.txt", Kind: packagemanager.ManifestKindRequirements},
			},
		},
		{
			name: "multiple -r values preserve order",
			args: []string{"install", "-r", "a.txt", "-r", "b.txt"},
			want: []packagemanager.ManifestRef{
				{Path: "a.txt", Kind: packagemanager.ManifestKindRequirements},
				{Path: "b.txt", Kind: packagemanager.ManifestKindRequirements},
			},
		},
		{
			name: "constraint -c flag",
			args: []string{"install", "-c", "constraints.txt", "requests"},
			want: []packagemanager.ManifestRef{
				{Path: "constraints.txt", Kind: packagemanager.ManifestKindConstraint},
			},
		},
		{
			name: "-r and -c together",
			args: []string{"install", "-r", "reqs.txt", "-c", "constraints.txt"},
			want: []packagemanager.ManifestRef{
				{Path: "reqs.txt", Kind: packagemanager.ManifestKindRequirements},
				{Path: "constraints.txt", Kind: packagemanager.ManifestKindConstraint},
			},
		},
		{
			name: "--requirement=path equals form",
			args: []string{"install", "--requirement=req.txt"},
			want: []packagemanager.ManifestRef{
				{Path: "req.txt", Kind: packagemanager.ManifestKindRequirements},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, m.ManifestRefs(c.args))
		})
	}
}
