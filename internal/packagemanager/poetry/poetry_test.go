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

	cases := []struct {
		name     string
		args     []string
		wantNil  bool
		wantPyp  bool
		wantLock bool
	}{
		{name: "non-install verb returns nil", args: []string{"shell"}, wantNil: true},
		{name: "poetry install emits pyproject + poetry.lock refs", args: []string{"install"}, wantPyp: true, wantLock: true},
		{name: "poetry update emits pyproject + poetry.lock refs", args: []string{"update"}, wantPyp: true, wantLock: true},
		{name: "poetry add with spec emits poetry.lock ref only", args: []string{"add", "requests"}, wantLock: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.ManifestRefs(c.args)
			if c.wantNil {
				require.Nil(t, got)
				return
			}
			if c.wantPyp {
				requireKindPoetry(t, got, packagemanager.ManifestKindPyProject)
			} else {
				requireNotKindPoetry(t, got, packagemanager.ManifestKindPyProject)
			}
			if c.wantLock {
				requireKindPoetry(t, got, packagemanager.ManifestKindPoetryLock)
			}
		})
	}
}

func requireKindPoetry(t *testing.T, refs []packagemanager.ManifestRef, kind packagemanager.ManifestKind) {
	t.Helper()
	for _, r := range refs {
		if r.Kind == kind {
			return
		}
	}
	t.Fatalf("expected ref of kind %q in %v", kind, refs)
}

func requireNotKindPoetry(t *testing.T, refs []packagemanager.ManifestRef, kind packagemanager.ManifestKind) {
	t.Helper()
	for _, r := range refs {
		if r.Kind == kind {
			t.Fatalf("did not expect ref of kind %q in %v", kind, refs)
		}
	}
}
