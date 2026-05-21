package bun_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/bun"
)

func TestParseInstalls(t *testing.T) {
	m := bun.New()
	require.Equal(t, "bun", m.Name())
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
	m := bun.New()

	cases := []struct {
		name      string
		args      []string
		wantNil   bool
		wantPkg   bool
		wantLocks bool
	}{
		{name: "non-install verb returns nil", args: []string{"run", "dev"}, wantNil: true},
		{name: "install with no specs emits package.json + lockfile refs", args: []string{"install"}, wantPkg: true, wantLocks: true},
		{name: "add with explicit specs emits lockfile refs only", args: []string{"add", "lodash"}, wantLocks: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.ManifestRefs(c.args)
			if c.wantNil {
				require.Nil(t, got)
				return
			}
			if c.wantPkg {
				requireKind(t, got, packagemanager.ManifestKindPackageJSON)
			} else {
				requireNotKind(t, got, packagemanager.ManifestKindPackageJSON)
			}
			if c.wantLocks {
				requireKind(t, got, packagemanager.ManifestKindPackageLockJSON)
				requireKind(t, got, packagemanager.ManifestKindYarnLock)
			}
		})
	}
}

func requireKind(t *testing.T, refs []packagemanager.ManifestRef, kind packagemanager.ManifestKind) {
	t.Helper()
	for _, r := range refs {
		if r.Kind == kind {
			return
		}
	}
	t.Fatalf("expected ref of kind %q in %v", kind, refs)
}

func requireNotKind(t *testing.T, refs []packagemanager.ManifestRef, kind packagemanager.ManifestKind) {
	t.Helper()
	for _, r := range refs {
		if r.Kind == kind {
			t.Fatalf("did not expect ref of kind %q in %v", kind, refs)
		}
	}
}
