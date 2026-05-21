package npm_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/npm"
)

func TestParseInstalls(t *testing.T) {
	m := npm.New()
	require.Equal(t, "npm", m.Name())
	require.Equal(t, intel.EcosystemNPM, m.Ecosystem())

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			name: "no args returns nil",
			args: nil,
			want: nil,
		},
		{
			name: "non-install verb returns nil",
			args: []string{"run", "dev"},
			want: nil,
		},
		{
			name: "version-only flag returns nil",
			args: []string{"--version"},
			want: nil,
		},
		{
			name: "install with explicit packages",
			args: []string{"install", "lodash", "express@4.18"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "express", Version: "4.18"}, RawSpec: "express@4.18"},
			},
		},
		{
			name: "i alias works",
			args: []string{"i", "lodash"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
			},
		},
		{
			name: "install with no specs returns empty slice (implicit from package.json)",
			args: []string{"install"},
			want: []packagemanager.Install{},
		},
		{
			name: "ci returns empty slice",
			args: []string{"ci"},
			want: []packagemanager.Install{},
		},
		{
			name: "flags between verb and specs are skipped",
			args: []string{"install", "--save-dev", "typescript"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "typescript"}, RawSpec: "typescript"},
			},
		},
		{
			name: "scoped package",
			args: []string{"install", "@types/node@20"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "@types/node", Version: "20"}, RawSpec: "@types/node@20"},
			},
		},
		{
			name: "local filesystem path marked LocalPath",
			args: []string{"install", "./local-pkg"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "./local-pkg"}, RawSpec: "./local-pkg", LocalPath: true},
			},
		},
		{
			name: "tarball URL marked OpaqueRemote",
			args: []string{"install", "https://example.com/x.tgz"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "https://example.com/x.tgz"}, RawSpec: "https://example.com/x.tgz", OpaqueRemote: true},
			},
		},
		{
			// Regression for leading-dash typosquats: without `--` handling, a
			// package name starting with `-` would be filtered out as a flag,
			// silently bypassing the gate.
			name: "leading-dash package after -- separator is parsed",
			args: []string{"install", "--", "--hiljson"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "--hiljson"}, RawSpec: "--hiljson"},
			},
		},
		{
			name: "flags and positionals interleaved with separator",
			args: []string{"install", "--save-dev", "typescript", "--", "-evil-pkg"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "typescript"}, RawSpec: "typescript"},
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "-evil-pkg"}, RawSpec: "-evil-pkg"},
			},
		},
		// Flag-with-value table tests: these regress the bug where a value
		// like "/tmp" or "https://example.com" was misread as the verb or
		// as a positional package name.
		{
			name: "global flag-with-value before verb is skipped",
			args: []string{"--prefix", "/tmp", "install", "foo"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "foo"}, RawSpec: "foo"},
			},
		},
		{
			name: "--flag=value form before verb is skipped",
			args: []string{"--prefix=/tmp", "install", "foo"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "foo"}, RawSpec: "foo"},
			},
		},
		{
			name: "flag-with-value after verb does not eat the package",
			args: []string{"install", "--registry", "https://example.com", "lodash"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
			},
		},
		{
			name: "plain flag (no value) still works",
			args: []string{"install", "--save-dev", "typescript"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "typescript"}, RawSpec: "typescript"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.ParseInstalls(c.args)
			if c.want == nil {
				require.Nil(t, got)
				return
			}
			require.Equal(t, c.want, got)
		})
	}
}

func TestManifestRefs(t *testing.T) {
	m := npm.New()

	cases := []struct {
		name      string
		args      []string
		wantNil   bool
		wantPkg   bool
		wantLocks bool
	}{
		{name: "non-install verb returns nil", args: []string{"run", "dev"}, wantNil: true},
		{name: "install with no specs emits package.json + lockfile refs", args: []string{"install"}, wantPkg: true, wantLocks: true},
		{name: "i alias with no specs emits package.json + lockfile refs", args: []string{"i"}, wantPkg: true, wantLocks: true},
		{name: "install with explicit specs emits lockfile refs only", args: []string{"install", "lodash"}, wantLocks: true},
		{name: "ci always reads manifest + lockfile", args: []string{"ci"}, wantPkg: true, wantLocks: true},
		{name: "install with flags but no specs still emits manifest+lockfile refs", args: []string{"install", "--save-dev"}, wantPkg: true, wantLocks: true},
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
				requireKind(t, got, packagemanager.ManifestKindPnpmLockYAML)
				requireKind(t, got, packagemanager.ManifestKindYarnLock)
				requireKind(t, got, packagemanager.ManifestKindNpmShrinkwrap)
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
