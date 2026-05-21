// Package poetry implements packagemanager.PackageManager for Poetry.
package poetry

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/argv"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pyspec"
)

const binaryName = "poetry"

var installVerbs = map[string]struct{}{
	"install": {}, "add": {}, "update": {}, "lock": {},
}

// flagsWithValues lists Poetry flags whose next argv token is the value.
// Covers the global options that fronted commands (--directory, --project,
// --source) plus `poetry add`'s own value-taking flags.
var flagsWithValues = argv.FlagsWithValues{
	"--directory":     {},
	"-C":              {},
	"--project":       {},
	"-P":              {},
	"--source":        {},
	"--python":        {},
	"--extras":        {},
	"-E":              {},
	"--group":         {},
	"-G":              {},
	"--with":          {},
	"--without":       {},
	"--only":          {},
	"--platform":      {},
	"--markers":       {},
	"--constraint":    {},
	"--cache-dir":     {},
	"--config":        {},
	"--verbosity":     {},
}

// Manager parses poetry install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a poetry manager.
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
// pyproject.toml when no explicit specs are given. `poetry add` is excluded
// because it requires a spec to act on. `poetry lock` doesn't install anything
// gateable, but it still reads the manifest — keep it conservative and skip.
var pyprojectInstallVerbs = map[string]struct{}{
	"install": {},
	"update":  {},
}

// ManifestRefs implements packagemanager.PackageManager. Emits a pyproject.toml
// ref for `poetry install` / `poetry update` (which derive their work from the
// project manifest), so the gate's expander can read the file and gate its
// direct dependencies.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	if _, isInstall := pyprojectInstallVerbs[verb]; !isInstall {
		return nil
	}
	if specs := argv.CollectPositionalsWithTable(rest, flagsWithValues); len(specs) > 0 {
		// Explicit specs supersede a manifest pull for these verbs in practice.
		return nil
	}
	return []packagemanager.ManifestRef{{Path: "pyproject.toml", Kind: packagemanager.ManifestKindPyProject}}
}
