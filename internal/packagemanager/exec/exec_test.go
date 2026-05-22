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
		{
			// `pipx install pkg1 pkg2 pkg3` is the multi-install form;
			// every positional is a separate package being installed.
			name: "install verb with multiple positionals gates all",
			args: []string{"install", "pkg1", "pkg2", "pkg3"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pkg1"}, RawSpec: "pkg1"},
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pkg2"}, RawSpec: "pkg2"},
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pkg3"}, RawSpec: "pkg3"},
			},
		},
		{
			name: "upgrade verb with multiple positionals gates all",
			args: []string{"upgrade", "pkg1", "pkg2"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pkg1"}, RawSpec: "pkg1"},
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pkg2"}, RawSpec: "pkg2"},
			},
		},
		{
			// `pipx inject venv pkg1 pkg2 …` injects pkg1, pkg2, … into
			// the existing local venv `venv`. The venv name is NOT a
			// package and must not be gated; every positional after it
			// is a real install to gate.
			name: "inject verb skips venv name and gates injected packages",
			args: []string{"inject", "venv", "evil", "good"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil"}, RawSpec: "evil"},
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "good"}, RawSpec: "good"},
			},
		},
		{
			// `pipx inject venvname` with no packages to inject is a
			// no-op as far as gating is concerned — nothing is being
			// installed (pipx itself would error, but veto should not
			// gate the venv name).
			name: "inject verb with only venv name gates nothing",
			args: []string{"inject", "venvname"},
			want: nil,
		},
		{
			// Single-arg install is the common case; preserved as a
			// regression check.
			name: "install verb with single positional",
			args: []string{"install", "evil"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil"}, RawSpec: "evil"},
			},
		},
		{
			// --spec wins over positionals even when there are many of
			// them; the trailing positionals are command args, not
			// packages. Verified for the verbs that previously had
			// "first-positional-only" semantics.
			name: "install verb with --spec ignores trailing positionals",
			args: []string{"install", "--spec", "evil-pkg", "p1", "p2"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil-pkg"}, RawSpec: "evil-pkg"},
			},
		},
		{
			// Flag-with-value (--python takes a value) between verb and
			// positionals must not be misread as a package.
			name: "install verb with flag-with-value before positionals",
			args: []string{"install", "--python", "python3.12", "pkg1", "pkg2"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pkg1"}, RawSpec: "pkg1"},
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pkg2"}, RawSpec: "pkg2"},
			},
		},
		{
			// `pipx run pkg cmd-arg1 cmd-arg2` runs a single package
			// and forwards the rest as arguments to its command. Only
			// the first positional is the package.
			name: "run verb gates only the first positional",
			args: []string{"run", "ruff", "check", "."},
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
