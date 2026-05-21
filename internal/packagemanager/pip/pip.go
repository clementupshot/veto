// Package pip implements packagemanager.PackageManager for pip and pip3.
package pip

import (
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
	"github.com/brynbellomy/veto/internal/packagemanager/pyspec"
)

const binaryName = "pip"

var installVerbs = map[string]struct{}{
	"install":  {},
	"download": {},
}

// flagsWithValues lists pip flags whose next argv token is the value.
// Drawn from `pip install --help` plus pip's global options. `-r`/
// `--requirement` is included so it stops swallowing the requirements
// file as a positional; the gate then expands the file via ManifestRefs.
var flagsWithValues = argv.FlagsWithValues{
	"--index-url":       {},
	"-i":                {},
	"--extra-index-url": {},
	"--find-links":      {},
	"-f":                {},
	"--target":          {},
	"-t":                {},
	"--platform":        {},
	"--python-version":  {},
	"--implementation":  {},
	"--abi":             {},
	"--prefix":          {},
	"--src":             {},
	"-r":                {},
	"--requirement":     {},
	"-c":                {},
	"--constraint":      {},
	"--root":            {},
	"--proxy":           {},
	"--cache-dir":       {},
	"--log":             {},
	"--timeout":         {},
	"--retries":         {},
	"--cert":            {},
	"--client-cert":     {},
	"--trusted-host":    {},
	"--no-binary":       {},
	"--only-binary":     {},
	"--global-option":   {},
}

// Manager parses pip install commands.
type Manager struct {
	name string
}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a pip Manager. binName lets callers register both "pip" and
// "pip3" with the same parser.
func New(binName string) *Manager {
	if binName == "" {
		binName = binaryName
	}
	return &Manager{name: binName}
}

// Name implements packagemanager.PackageManager.
func (m *Manager) Name() string { return m.name }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemPyPI }

// requirementFlags are the flags whose value is a requirements-file path.
var requirementFlags = argv.FlagsWithValues{
	"-r":            {},
	"--requirement": {},
}

// constraintFlags are the flags whose value is a constraints-file path.
// Constraints files use the same grammar as requirements.txt.
var constraintFlags = argv.FlagsWithValues{
	"-c":           {},
	"--constraint": {},
}

// ParseInstalls implements packagemanager.PackageManager.
//
// VCS URL specs are passed through to pyspec, which marks them Local=true.
// Requirements-file expansion happens in the gate via ManifestRefs.
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

// ManifestRefs implements packagemanager.PackageManager. Returns one ref per
// -r/--requirement and -c/--constraint flag value, in argv order. Returns nil
// when args is not a pip install command or names no requirements/constraints
// files.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	if _, isInstall := installVerbs[verb]; !isInstall {
		return nil
	}
	return collectManifestRefs(rest)
}

// collectManifestRefs walks rest in a single pass so requirements and
// constraint files keep their argv order — useful for deterministic
// diagnostics when a refusal cites a manifest by path.
func collectManifestRefs(rest []string) []packagemanager.ManifestRef {
	reqs := argv.CollectFlagValues(rest, requirementFlags, flagsWithValues)
	cons := argv.CollectFlagValues(rest, constraintFlags, flagsWithValues)
	if len(reqs) == 0 && len(cons) == 0 {
		return nil
	}
	refs := make([]packagemanager.ManifestRef, 0, len(reqs)+len(cons))
	for _, p := range reqs {
		refs = append(refs, packagemanager.ManifestRef{Path: p, Kind: packagemanager.ManifestKindRequirements})
	}
	for _, p := range cons {
		refs = append(refs, packagemanager.ManifestRef{Path: p, Kind: packagemanager.ManifestKindConstraint})
	}
	return refs
}
