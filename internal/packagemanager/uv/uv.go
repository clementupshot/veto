// Package uv implements packagemanager.PackageManager for uv.
package uv

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/argv"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pyspec"
)

const binaryName = "uv"

// flagsWithValues lists uv flags whose next argv token is the value. Uv
// reuses pip's flag vocabulary for its `uv pip` subcommand and layers its
// own (--python, --index, --extra-index-url, --resolution, etc.) for the
// `uv add`/`uv sync` shape.
var flagsWithValues = argv.FlagsWithValues{
	"--python":          {},
	"-p":                {},
	"--index":           {},
	"--default-index":   {},
	"--index-url":       {},
	"-i":                {},
	"--extra-index-url": {},
	"--find-links":      {},
	"-f":                {},
	"--cache-dir":       {},
	"--config-file":     {},
	"--directory":       {},
	"--project":         {},
	"--resolution":      {},
	"--prerelease":      {},
	"--target":          {},
	"--prefix":          {},
	"--link-mode":       {},
	"--index-strategy":  {},
	"--keyring-provider": {},
	"--python-preference": {},
	"-r":                {},
	"--requirement":     {},
	"-c":                {},
	"--constraint":      {},
	"--override":        {},
	"--extra":           {},
	"--group":           {},
	"--with":            {},
	"--with-requirements": {},
	"--package":         {},
}

// Manager parses uv install commands. Handles both `uv pip install ...` and
// `uv add ...` shapes.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a uv manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemPyPI }

// requirementFlags are the flags whose value is a requirements-file path
// (uv reuses pip's -r / --requirement under `uv pip install`).
var requirementFlags = argv.FlagsWithValues{
	"-r":            {},
	"--requirement": {},
}

// constraintFlags are the flags whose value is a constraints-file path.
var constraintFlags = argv.FlagsWithValues{
	"-c":           {},
	"--constraint": {},
}

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	rest, ok := installArgs(args)
	if !ok {
		return nil
	}
	return parseSpecs(rest)
}

// ManifestRefs implements packagemanager.PackageManager.
//
// Two flavors of refs can appear:
//
//   - Requirements/constraint refs for `-r path` / `-c path` flags (the `uv pip
//     install` shape that mirrors pip).
//   - A pyproject.toml ref for the project-aware verbs (`uv sync` always;
//     `uv add` / `uv install` only when no explicit specs were named).
//
// Precedence: when a requirements/constraint ref is present we do NOT also
// emit a pyproject ref — the user pointed at a specific file, expand that one.
// `uv sync` is the exception: it reads pyproject regardless of argv since its
// whole purpose is to install the project's locked dep set.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	verb, rest, ok := installVerbAndRest(args)
	if !ok {
		return nil
	}

	reqs := argv.CollectFlagValues(rest, requirementFlags, flagsWithValues)
	cons := argv.CollectFlagValues(rest, constraintFlags, flagsWithValues)
	hasReqRefs := len(reqs) > 0 || len(cons) > 0

	refs := make([]packagemanager.ManifestRef, 0, len(reqs)+len(cons)+1)
	for _, p := range reqs {
		refs = append(refs, packagemanager.ManifestRef{Path: p, Kind: packagemanager.ManifestKindRequirements})
	}
	for _, p := range cons {
		refs = append(refs, packagemanager.ManifestRef{Path: p, Kind: packagemanager.ManifestKindConstraint})
	}

	if shouldReadPyProject(verb, rest, hasReqRefs) {
		refs = append(refs, packagemanager.ManifestRef{Path: "pyproject.toml", Kind: packagemanager.ManifestKindPyProject})
	}

	if len(refs) == 0 {
		return nil
	}
	return refs
}

// installVerbAndRest returns the canonical install verb and the argv tail to
// scan for flag values / positionals. `uv pip install ...` collapses to verb
// "pip-install" so callers can distinguish it from the project-aware shapes.
func installVerbAndRest(args []string) (string, []string, bool) {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return "", nil, false
	}
	if verb == "pip" {
		subVerb, subRest, subOK := argv.FirstNonFlagWithTable(rest, flagsWithValues)
		if !subOK || subVerb != "install" {
			return "", nil, false
		}
		return "pip-install", subRest, true
	}
	switch verb {
	case "add", "sync", "install":
		return verb, rest, true
	}
	return "", nil, false
}

// shouldReadPyProject decides whether the verb pulls pyproject.toml. `uv sync`
// always does. `uv add` and `uv install` do so only when the user named no
// explicit specs AND no requirements/constraints file was given.
func shouldReadPyProject(verb string, rest []string, hasReqRefs bool) bool {
	switch verb {
	case "sync":
		return true
	case "add", "install":
		if hasReqRefs {
			return false
		}
		return len(argv.CollectPositionalsWithTable(rest, flagsWithValues)) == 0
	default:
		// "pip-install" follows pip semantics: no pyproject involvement.
		return false
	}
}

// installArgs strips uv's command/subcommand prefix and returns the remaining
// argv for a recognized install verb. `uv pip install ...` and `uv add` /
// `uv sync` / `uv install` are all install-shaped. Returns ok=false when the
// command is not an install.
func installArgs(args []string) ([]string, bool) {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil, false
	}
	if verb == "pip" {
		subVerb, subRest, subOK := argv.FirstNonFlagWithTable(rest, flagsWithValues)
		if !subOK || subVerb != "install" {
			return nil, false
		}
		return subRest, true
	}
	switch verb {
	case "add", "sync", "install":
		return rest, true
	}
	return nil, false
}

func parseSpecs(rest []string) []packagemanager.Install {
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	installs := make([]packagemanager.Install, 0, len(specs))
	for _, spec := range specs {
		installs = append(installs, pyspec.Parse(spec))
	}
	return installs
}
