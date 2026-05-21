// Package exec implements packagemanager.PackageManager for the "fetch and
// run" CLIs: npx, bunx, pnpx, uvx, and `pipx run`.
//
// Every non-help invocation of these tools fetches a remote package and
// executes it, so the entire command is treated as an install — the first
// non-flag token after the binary name (or the verb, for pipx) is the spec.
//
// A single parameterized Manager serves all five binaries; bouncer's main
// constructs one instance per supported binary at startup, passing its
// per-binary FlagsWithValues table so global flags-with-values (e.g.
// `npx --package foo my-cmd`, `pipx --python python3.12 run bar`) don't
// trick the parser into reading the value as the spec.
package exec

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/argv"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/jsspec"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pyspec"
)

// NpxFlagsWithValues is the realistic set of npx flags whose next argv
// token is the value (e.g. `npx --package foo cli-cmd`).
var NpxFlagsWithValues = argv.FlagsWithValues{
	"--package":   {},
	"-p":          {},
	"--call":      {},
	"-c":          {},
	"--workspace": {},
	"-w":          {},
	"--prefix":    {},
	"--registry":  {},
	"--userconfig": {},
}

// BunxFlagsWithValues mirrors `bunx` (a thin wrapper over `bun x`).
var BunxFlagsWithValues = argv.FlagsWithValues{
	"--cwd":       {},
	"--registry":  {},
	"--cache-dir": {},
	"--config":    {},
	"-c":          {},
}

// PnpxFlagsWithValues mirrors pnpm's dlx (pnpx is the legacy alias).
var PnpxFlagsWithValues = argv.FlagsWithValues{
	"--package":  {},
	"-p":         {},
	"--registry": {},
	"--store-dir": {},
	"--prefix":   {},
}

// UvxFlagsWithValues lists uvx flags whose next argv token is the value.
var UvxFlagsWithValues = argv.FlagsWithValues{
	"--python":          {},
	"-p":                {},
	"--with":            {},
	"--with-requirements": {},
	"--from":            {},
	"--index":           {},
	"--index-url":       {},
	"-i":                {},
	"--extra-index-url": {},
	"--cache-dir":       {},
	"--config-file":     {},
	"--resolution":      {},
	"--prerelease":      {},
}

// PipxFlagsWithValues lists pipx flags whose next argv token is the value.
// Note: pipx accepts both pre-verb global flags (`pipx --python python3.12
// run foo`) and per-verb flags after the verb. The same table covers both
// because the parser uses it on each side of the verb split.
var PipxFlagsWithValues = argv.FlagsWithValues{
	"--python":   {},
	"--pip-args": {},
	"--spec":     {},
	"--index-url": {},
	"--suffix":   {},
	"--editable": {},
	"-e":         {},
}

// Options configures one exec-style Manager.
type Options struct {
	// Name is the binary (e.g. "npx", "bunx", "pipx").
	Name string

	// Ecosystem identifies which spec parser to use.
	Ecosystem intel.Ecosystem

	// PipxStyle treats args as `pipx <verb> <pkg>` rather than `npx <pkg>`.
	// Set true for pipx; false for everything else.
	PipxStyle bool

	// FlagsWithValues lists flags whose next argv token is the flag's
	// value, so the parser doesn't mistake that value for the spec.
	// Optional — a nil table degrades to flag-name-only skipping.
	FlagsWithValues argv.FlagsWithValues
}

// Manager parses exec-style commands for one binary.
type Manager struct {
	opts Options
}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds an exec Manager.
func New(opts Options) *Manager {
	if opts.Name == "" {
		panic("exec: Options.Name is required")
	}
	if opts.Ecosystem == "" {
		panic("exec: Options.Ecosystem is required")
	}
	return &Manager{opts: opts}
}

// Name implements packagemanager.PackageManager.
func (m *Manager) Name() string { return m.opts.Name }

// Ecosystem implements packagemanager.PackageManager.
func (m *Manager) Ecosystem() intel.Ecosystem { return m.opts.Ecosystem }

// ParseInstalls implements packagemanager.PackageManager.
//
// For non-pipx exec tools, returns one Install for the first non-flag token
// (the package to fetch and run). For pipx, requires a "run" or "install"
// verb before the spec.
func (m *Manager) ParseInstalls(args []string) []packagemanager.Install {
	rest := args
	if m.opts.PipxStyle {
		verb, after, ok := argv.FirstNonFlagWithTable(args, m.opts.FlagsWithValues)
		if !ok {
			return nil
		}
		switch verb {
		case "run", "install", "upgrade", "inject":
			rest = after
		default:
			return nil
		}
	}

	spec, _, ok := argv.FirstNonFlagWithTable(rest, m.opts.FlagsWithValues)
	if !ok {
		return nil
	}
	// `--help`, `--version` already filtered out by the flag skip.
	// Special-case bare-help arguments that aren't flags:
	if spec == "help" {
		return nil
	}

	var install packagemanager.Install
	switch m.opts.Ecosystem {
	case intel.EcosystemNPM:
		install = jsspec.Parse(spec)
	case intel.EcosystemPyPI:
		install = pyspec.Parse(spec)
	default:
		install = packagemanager.Install{
			Ref:     intel.PackageRef{Ecosystem: m.opts.Ecosystem, Name: spec},
			RawSpec: spec,
		}
	}
	return []packagemanager.Install{install}
}

// ManifestRefs implements packagemanager.PackageManager. The exec-style
// tools fetch a single remote package; they don't follow on-disk manifests
// from argv.
func (m *Manager) ManifestRefs(args []string) []packagemanager.ManifestRef { return nil }
