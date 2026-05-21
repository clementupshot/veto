package exec_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	pmexec "github.com/brynbellomy/package-bouncer/internal/packagemanager/exec"
)

func TestNpxParseInstalls(t *testing.T) {
	m := pmexec.New(pmexec.Options{
		Name:            "npx",
		Ecosystem:       intel.EcosystemNPM,
		FlagsWithValues: pmexec.NpxFlagsWithValues,
	})
	require.Equal(t, "npx", m.Name())
	require.Equal(t, intel.EcosystemNPM, m.Ecosystem())

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			name: "global flag-with-value before spec is skipped",
			args: []string{"--package", "create-react-app", "my-cli"},
			// Note: --package's value IS itself a package (the one npx fetches),
			// but per the simple "first non-flag" model the spec is what comes
			// after. We test only that the parser doesn't crash and returns
			// the trailing positional.
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "my-cli"}, RawSpec: "my-cli"},
			},
		},
		{
			name: "--flag=value form skipped",
			args: []string{"--package=create-react-app", "my-cli"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "my-cli"}, RawSpec: "my-cli"},
			},
		},
		{
			name: "plain flag (no value) still works",
			args: []string{"--yes", "create-react-app"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "create-react-app"}, RawSpec: "create-react-app"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, m.ParseInstalls(c.args))
		})
	}
}

func TestPipxParseInstalls(t *testing.T) {
	m := pmexec.New(pmexec.Options{
		Name:            "pipx",
		Ecosystem:       intel.EcosystemPyPI,
		PipxStyle:       true,
		FlagsWithValues: pmexec.PipxFlagsWithValues,
	})

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			name: "global flag-with-value before verb",
			args: []string{"--python", "python3.12", "run", "ruff"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "ruff"}, RawSpec: "ruff"},
			},
		},
		{
			name: "--flag=value before verb",
			args: []string{"--python=python3.12", "run", "ruff"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "ruff"}, RawSpec: "ruff"},
			},
		},
		{
			name: "flag-with-value after verb",
			args: []string{"install", "--python", "python3.12", "ruff"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "ruff"}, RawSpec: "ruff"},
			},
		},
		{
			name: "plain flag (no value) still works",
			args: []string{"install", "--force", "ruff"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "ruff"}, RawSpec: "ruff"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, m.ParseInstalls(c.args))
		})
	}
}
