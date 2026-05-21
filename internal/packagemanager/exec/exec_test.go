package exec_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	pmexec "github.com/brynbellomy/veto/internal/packagemanager/exec"
)

func TestNpxParseInstalls(t *testing.T) {
	m := pmexec.New(pmexec.Options{
		Name:            "npx",
		Ecosystem:       intel.EcosystemNPM,
		FlagsWithValues: pmexec.NpxFlagsWithValues,
		SpecFlags:       pmexec.NpxSpecFlags,
	})
	require.Equal(t, "npx", m.Name())
	require.Equal(t, intel.EcosystemNPM, m.Ecosystem())

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			// `npx --package pkg cmd` fetches pkg and runs cmd FROM IT — the
			// thing to gate is the value of --package, not the positional.
			name: "--package value is the spec, positional is the command name",
			args: []string{"--package", "evil-pkg", "my-cli"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-pkg"}, RawSpec: "evil-pkg"},
			},
		},
		{
			name: "-p alias works the same way",
			args: []string{"-p", "evil-pkg", "my-cli"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-pkg"}, RawSpec: "evil-pkg"},
			},
		},
		{
			name: "--package=value form",
			args: []string{"--package=evil-pkg", "my-cli"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-pkg"}, RawSpec: "evil-pkg"},
			},
		},
		{
			name: "repeated --package flags gate each value",
			args: []string{"-p", "eslint", "--package", "prettier", "lint-cmd"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "eslint"}, RawSpec: "eslint"},
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "prettier"}, RawSpec: "prettier"},
			},
		},
		{
			name: "no --package falls back to first positional",
			args: []string{"create-react-app", "myapp"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "create-react-app"}, RawSpec: "create-react-app"},
			},
		},
		{
			name: "non-spec flags before positional still work",
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
		SpecFlags:       pmexec.PipxSpecFlags,
	})

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			// `pipx run --spec pkg cmd` fetches pkg and runs cmd from it.
			name: "--spec value is the spec",
			args: []string{"run", "--spec", "evil-pkg", "actual-cmd"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil-pkg"}, RawSpec: "evil-pkg"},
			},
		},
		{
			name: "--spec=value form",
			args: []string{"run", "--spec=evil-pkg", "actual-cmd"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil-pkg"}, RawSpec: "evil-pkg"},
			},
		},
		{
			name: "no --spec falls back to first positional",
			args: []string{"run", "ruff"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "ruff"}, RawSpec: "ruff"},
			},
		},
		{
			name: "global flag-with-value before verb, no spec flag",
			args: []string{"--python", "python3.12", "run", "ruff"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "ruff"}, RawSpec: "ruff"},
			},
		},
		{
			name: "install verb with positional",
			args: []string{"install", "ruff"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "ruff"}, RawSpec: "ruff"},
			},
		},
		{
			name: "install verb with --spec",
			args: []string{"install", "--spec", "evil-pkg", "actual-cmd"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil-pkg"}, RawSpec: "evil-pkg"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, m.ParseInstalls(c.args))
		})
	}
}
