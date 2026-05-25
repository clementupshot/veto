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
		{
			name: "-e captures editable local-path spec as a positional",
			args: []string{"install", "-e", "./local-pkg"},
			want: []packagemanager.Install{
				{
					Ref:       intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "./local-pkg"},
					RawSpec:   "./local-pkg",
					LocalPath: true,
				},
			},
		},
		{
			name: "--editable captures editable local-path spec as a positional",
			args: []string{"install", "--editable", "./local-pkg"},
			want: []packagemanager.Install{
				{
					Ref:       intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "./local-pkg"},
					RawSpec:   "./local-pkg",
					LocalPath: true,
				},
			},
		},
		{
			name: "bare dot (pip install .) captured as LocalPath spec",
			args: []string{"install", "."},
			want: []packagemanager.Install{
				{
					Ref:       intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "."},
					RawSpec:   ".",
					LocalPath: true,
				},
			},
		},
		{
			name: "bare dot-dot (pip install ..) captured as LocalPath spec",
			args: []string{"install", ".."},
			want: []packagemanager.Install{
				{
					Ref:       intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: ".."},
					RawSpec:   "..",
					LocalPath: true,
				},
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

func TestResolverPreScan(t *testing.T) {
	m := pip.New("pip")

	t.Run("install specs produce wheel-only dry-run report plan", func(t *testing.T) {
		plan, ok := m.ResolverPreScan([]string{"install", "clean-direct"})
		require.True(t, ok)
		require.Equal(t, []packagemanager.ManifestRef{{Path: "veto-pip-report.json", Kind: packagemanager.ManifestKindPipReportJSON}}, plan.ManifestRefs)
		require.Contains(t, plan.Args, "--dry-run")
		require.Contains(t, plan.Args, "--ignore-installed")
		require.Contains(t, plan.Args, "--report")
		require.Contains(t, plan.Args, "veto-pip-report.json")
		require.Contains(t, plan.Args, "--only-binary")
		require.Contains(t, plan.Args, ":all:")
		require.Equal(t, []packagemanager.Install{{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "clean-direct"}, RawSpec: "clean-direct"}}, plan.DirectInstalls)
	})

	t.Run("requirements file is seeded", func(t *testing.T) {
		plan, ok := m.ResolverPreScan([]string{"install", "-r", "requirements.txt"})
		require.True(t, ok)
		require.Contains(t, plan.SeedFiles, "requirements.txt")
	})

	t.Run("download is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"download", "clean-direct"})
		require.False(t, ok)
	})

	t.Run("empty install is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"install"})
		require.False(t, ok)
	})

	t.Run("local path is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"install", "./local-pkg"})
		require.False(t, ok)
	})

	t.Run("opaque remote is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"install", "https://example.com/pkg.whl"})
		require.False(t, ok)
	})

	t.Run("user no-binary flag is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"install", "--no-binary", ":all:", "clean-direct"})
		require.False(t, ok)
	})
}
