package uv_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/uv"
)

func TestParseInstalls(t *testing.T) {
	m := uv.New()
	require.Equal(t, "uv", m.Name())
	require.Equal(t, intel.EcosystemPyPI, m.Ecosystem())

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			name: "global flag-with-value before verb is skipped",
			args: []string{"--python", "3.12", "add", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "--flag=value form before verb is skipped",
			args: []string{"--python=3.12", "add", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "flag-with-value after verb does not eat the package",
			args: []string{"add", "--index-url", "https://example.com", "requests"},
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
		{
			name: "uv pip install with flag-value after verb",
			args: []string{"pip", "install", "--index-url", "https://example.com", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "uv pip install with global flag-value before pip subcommand",
			args: []string{"--cache-dir", "/tmp/uv-cache", "pip", "install", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
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
	m := uv.New()

	cases := []struct {
		name      string
		args      []string
		wantNil   bool
		wantKinds []packagemanager.ManifestKind
	}{
		{name: "non-install verb returns nil", args: []string{"build"}, wantNil: true},
		{
			name:      "uv add with -r",
			args:      []string{"add", "-r", "reqs.txt"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindRequirements, packagemanager.ManifestKindUvLock},
		},
		{
			name:      "uv pip install -r",
			args:      []string{"pip", "install", "-r", "reqs.txt"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindRequirements},
		},
		{
			name:      "uv pip install -c",
			args:      []string{"pip", "install", "-c", "constraints.txt"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindConstraint},
		},
		{
			name:      "uv pip install with --requirement long form",
			args:      []string{"pip", "install", "--requirement", "reqs.txt"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindRequirements},
		},
		{
			name:      "uv sync emits pyproject + uv.lock refs",
			args:      []string{"sync"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindPyProject, packagemanager.ManifestKindUvLock},
		},
		{
			name:      "uv add with no specs emits pyproject + uv.lock refs",
			args:      []string{"add"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindPyProject, packagemanager.ManifestKindUvLock},
		},
		{
			name:      "uv add with explicit spec emits uv.lock ref only",
			args:      []string{"add", "requests"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindUvLock},
		},
		{name: "uv pip install with no -r and no specs emits nothing (pip semantics)", args: []string{"pip", "install"}, wantNil: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.ManifestRefs(c.args)
			if c.wantNil {
				require.Nil(t, got)
				return
			}
			for _, kind := range c.wantKinds {
				requireKindUv(t, got, kind)
			}
		})
	}
}

func requireKindUv(t *testing.T, refs []packagemanager.ManifestRef, kind packagemanager.ManifestKind) {
	t.Helper()
	for _, r := range refs {
		if r.Kind == kind {
			return
		}
	}
	t.Fatalf("expected ref of kind %q in %v", kind, refs)
}
