package pyspec_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pyspec"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want packagemanager.Install
	}{
		{
			name: "bare name",
			spec: "requests",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"},
				RawSpec: "requests",
			},
		},
		{
			name: "exact version",
			spec: "requests==2.31.0",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests", Version: "2.31.0"},
				RawSpec: "requests==2.31.0",
			},
		},
		{
			name: "exact version with whitespace around operator",
			spec: "requests == 2.31.0",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests", Version: "2.31.0"},
				RawSpec: "requests == 2.31.0",
			},
		},
		{
			name: "single extra stripped, exact version kept",
			spec: "requests[security]==2.31.0",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests", Version: "2.31.0"},
				RawSpec: "requests[security]==2.31.0",
			},
		},
		{
			name: "multiple extras stripped",
			spec: "requests[security,socks]==2.31.0",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests", Version: "2.31.0"},
				RawSpec: "requests[security,socks]==2.31.0",
			},
		},
		{
			name: "range collapses to empty version (name-keyed lookup)",
			spec: "django>=4.0,<5.0",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "django"},
				RawSpec: "django>=4.0,<5.0",
			},
		},
		{
			name: "single inequality operator collapses to empty version",
			spec: "django>=4.0",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "django"},
				RawSpec: "django>=4.0",
			},
		},
		{
			name: "not-equal operator collapses to empty version",
			spec: "django!=4.1.0",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "django"},
				RawSpec: "django!=4.1.0",
			},
		},
		{
			name: "compatible-release operator collapses to empty version",
			spec: "django~=4.0",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "django"},
				RawSpec: "django~=4.0",
			},
		},
		{
			name: "environment marker stripped",
			spec: "requests==2.31.0; python_version >= '3.8'",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests", Version: "2.31.0"},
				RawSpec: "requests==2.31.0; python_version >= '3.8'",
			},
		},
		{
			name: "environment marker stripped from bare name",
			spec: "pywin32; sys_platform == 'win32'",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pywin32"},
				RawSpec: "pywin32; sys_platform == 'win32'",
			},
		},
		{
			name: "extras and marker and range together",
			spec: "requests[security,socks]>=2.0,<3.0; python_version >= '3.8'",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"},
				RawSpec: "requests[security,socks]>=2.0,<3.0; python_version >= '3.8'",
			},
		},
		{
			name: "local filesystem path marked LocalPath",
			spec: "./vendor/wheel",
			want: packagemanager.Install{
				Ref:       intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "./vendor/wheel"},
				RawSpec:   "./vendor/wheel",
				LocalPath: true,
			},
		},
		{
			name: "git URL marked OpaqueRemote",
			spec: "git+https://github.com/foo/bar.git",
			want: packagemanager.Install{
				Ref:          intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "git+https://github.com/foo/bar.git"},
				RawSpec:      "git+https://github.com/foo/bar.git",
				OpaqueRemote: true,
			},
		},
		{
			name: "absolute path marked LocalPath",
			spec: "/abs/path/to/wheel",
			want: packagemanager.Install{
				Ref:       intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "/abs/path/to/wheel"},
				RawSpec:   "/abs/path/to/wheel",
				LocalPath: true,
			},
		},
		{
			name: "https tarball URL marked OpaqueRemote",
			spec: "https://example.com/wheels/foo-1.0.tar.gz",
			want: packagemanager.Install{
				Ref:          intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "https://example.com/wheels/foo-1.0.tar.gz"},
				RawSpec:      "https://example.com/wheels/foo-1.0.tar.gz",
				OpaqueRemote: true,
			},
		},
		{
			name: "arbitrary-equality === collapses to empty version",
			spec: "pkg===1.0.0+local",
			want: packagemanager.Install{
				Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pkg"},
				RawSpec: "pkg===1.0.0+local",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, pyspec.Parse(c.spec))
		})
	}
}
