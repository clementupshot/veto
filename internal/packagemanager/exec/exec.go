// Package exec implements packagemanager.PackageManager for the "fetch and
// run" CLIs: npx, bunx, pnpx, uvx, and `pipx run`.
//
// Every non-help invocation of these tools fetches a remote package and
// executes it, so the entire command is treated as an install — the first
// non-flag token after the binary name (or the verb, for pipx) is the spec.
//
// A single parameterized Manager serves all five binaries; bouncer's main
// constructs one instance per supported binary at startup.
package exec

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/argv"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/jsspec"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pyspec"
)

// Options configures one exec-style Manager.
type Options struct {
	// Name is the binary (e.g. "npx", "bunx", "pipx").
	Name string

	// Ecosystem identifies which spec parser to use.
	Ecosystem intel.Ecosystem

	// PipxStyle treats args as `pipx <verb> <pkg>` rather than `npx <pkg>`.
	// Set true for pipx; false for everything else.
	PipxStyle bool
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
		verb, after, ok := argv.FirstNonFlag(args)
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

	spec, _, ok := argv.FirstNonFlag(rest)
	if !ok {
		return nil
	}
	// `--help`, `--version` already filtered out by FirstNonFlag's flag skip.
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
