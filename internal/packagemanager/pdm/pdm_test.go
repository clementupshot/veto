package pdm_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pdm"
)

func TestParseInstalls(t *testing.T) {
	m := pdm.New()
	require.Equal(t, "pdm", m.Name())
	require.Equal(t, intel.EcosystemPyPI, m.Ecosystem())

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			name: "global flag-with-value before verb is skipped",
			args: []string{"--project", "/tmp/proj", "add", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "--flag=value form before verb is skipped",
			args: []string{"--project=/tmp/proj", "add", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "flag-with-value after verb does not eat the package",
			args: []string{"add", "--group", "dev", "pytest"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pytest"}, RawSpec: "pytest"},
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
	m := pdm.New()

	cases := []struct {
		name     string
		args     []string
		wantNil  bool
		wantPyp  bool
		wantLock bool
	}{
		{name: "non-install verb returns nil", args: []string{"build"}, wantNil: true},
		{name: "pdm install emits pyproject + pdm.lock refs", args: []string{"install"}, wantPyp: true, wantLock: true},
		{name: "pdm sync emits pyproject + pdm.lock refs", args: []string{"sync"}, wantPyp: true, wantLock: true},
		{name: "pdm add with spec emits pdm.lock ref only", args: []string{"add", "requests"}, wantLock: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.ManifestRefs(c.args)
			if c.wantNil {
				require.Nil(t, got)
				return
			}
			if c.wantPyp {
				requireKindPdm(t, got, packagemanager.ManifestKindPyProject)
			} else {
				requireNotKindPdm(t, got, packagemanager.ManifestKindPyProject)
			}
			if c.wantLock {
				requireKindPdm(t, got, packagemanager.ManifestKindPdmLock)
			}
		})
	}
}

func requireKindPdm(t *testing.T, refs []packagemanager.ManifestRef, kind packagemanager.ManifestKind) {
	t.Helper()
	for _, r := range refs {
		if r.Kind == kind {
			return
		}
	}
	t.Fatalf("expected ref of kind %q in %v", kind, refs)
}

func requireNotKindPdm(t *testing.T, refs []packagemanager.ManifestRef, kind packagemanager.ManifestKind) {
	t.Helper()
	for _, r := range refs {
		if r.Kind == kind {
			t.Fatalf("did not expect ref of kind %q in %v", kind, refs)
		}
	}
}
