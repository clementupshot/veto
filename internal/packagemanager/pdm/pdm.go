// Package pdm implements packagemanager.PackageManager for PDM.
package pdm

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/argv"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pyspec"
)

const binaryName = "pdm"

var installVerbs = map[string]struct{}{
	"install": {}, "add": {}, "update": {}, "sync": {},
}

// flagsWithValues lists PDM flags whose next argv token is the value.
// Covers global routing (--project, --config) and `pdm add` value-taking
// options (--group, --venv, --python).
var flagsWithValues = argv.FlagsWithValues{
	"--project":         {},
	"-p":                {},
	"--config":          {},
	"-c":                {},
	"--python":          {},
	"--venv":            {},
	"--group":           {},
	"-G":                {},
	"--dev-group":       {},
	"--editable":        {},
	"-e":                {},
	"--extras":          {},
	"--platform":        {},
	"--lockfile":        {},
	"-L":                {},
	"--strategy":        {},
	"-S":                {},
	"--update":          {},
	"--save":            {},
}

// Manager parses pdm install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a pdm manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemPyPI }

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	if _, isInstall := installVerbs[verb]; !isInstall {
		return nil
	}
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	installs := make([]packagemanager.Install, 0, len(specs))
	for _, spec := range specs {
		installs = append(installs, pyspec.Parse(spec))
	}
	return installs
}

// pyprojectInstallVerbs names the verbs whose work is derived from
// pyproject.toml when no explicit specs are given. `pdm install` and
// `pdm sync` always read the manifest; `pdm add` only does so when invoked
// without a spec (rare but legal: `pdm add` with no args is a no-op).
var pyprojectInstallVerbs = map[string]struct{}{
	"install": {},
	"sync":    {},
	"add":     {},
	"update":  {},
}

// ManifestRefs implements packagemanager.PackageManager. Emits a pyproject.toml
// ref for `pdm install` / `pdm sync` and for `pdm add` / `pdm update` only
// when called without explicit specs, so the gate's expander can read the
// file and gate its direct dependencies.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	if _, isInstall := pyprojectInstallVerbs[verb]; !isInstall {
		return nil
	}
	if specs := argv.CollectPositionalsWithTable(rest, flagsWithValues); len(specs) > 0 {
		return nil
	}
	return []packagemanager.ManifestRef{{Path: "pyproject.toml", Kind: packagemanager.ManifestKindPyProject}}
}
