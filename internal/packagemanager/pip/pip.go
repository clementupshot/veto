// Package pip implements packagemanager.PackageManager for pip and pip3.
package pip

import (
	"strings"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
	"github.com/brynbellomy/veto/internal/packagemanager/pyspec"
)

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
	"--report":          {},
}

// Manager parses pip install commands.
type Manager struct {
	name string
}

var _ packagemanager.PackageManager = (*Manager)(nil)
var _ packagemanager.ResolverPreScanner = (*Manager)(nil)

// New builds a pip Manager. binName lets callers register both "pip" and
// "pip3" with the same parser.
func New(binName string) *Manager {
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

// ResolverPreScan implements packagemanager.ResolverPreScanner. Modern pip can
// emit the resolved install set as JSON without installing packages. Veto forces
// wheel-only dry-run resolution so the pre-scan does not build sdists or execute
// setup code in the temporary workdir.
func (Manager) ResolverPreScan(args []string) (packagemanager.ResolverPreScanPlan, bool) {
	verb, _, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok || verb != "install" {
		return packagemanager.ResolverPreScanPlan{}, false
	}
	directInstalls := Manager{}.ParseInstalls(args)
	manifestRefs := Manager{}.ManifestRefs(args)
	if len(directInstalls) == 0 && len(manifestRefs) == 0 {
		return packagemanager.ResolverPreScanPlan{}, false
	}
	if hasUnsafeResolverPreScanSpec(directInstalls) || hasUnsafeResolverPreScanFlag(args) {
		return packagemanager.ResolverPreScanPlan{}, false
	}
	seedFiles := make([]string, 0, len(manifestRefs)+1)
	seedFiles = append(seedFiles, "pyproject.toml")
	for _, ref := range manifestRefs {
		seedFiles = append(seedFiles, ref.Path)
	}
	return packagemanager.ResolverPreScanPlan{
		Args: appendResolverFlags(args,
			"--dry-run",
			"--ignore-installed",
			"--report", "veto-pip-report.json",
			"--only-binary", ":all:",
			"--disable-pip-version-check",
			"--no-input",
		),
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "veto-pip-report.json", Kind: packagemanager.ManifestKindPipReportJSON},
		},
		SeedFiles:      seedFiles,
		DirectInstalls: directInstalls,
	}, true
}

func hasUnsafeResolverPreScanSpec(installs []packagemanager.Install) bool {
	for _, ins := range installs {
		if ins.LocalPath || ins.OpaqueRemote {
			return true
		}
	}
	return false
}

func hasUnsafeResolverPreScanFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--no-binary" || strings.HasPrefix(arg, "--no-binary=") {
			return true
		}
	}
	return false
}

func appendResolverFlags(args []string, flags ...string) []string {
	out := make([]string, 0, len(args)+len(flags))
	for i, arg := range args {
		if arg == "--" {
			out = append(out, flags...)
			out = append(out, args[i:]...)
			return out
		}
		out = append(out, arg)
	}
	out = append(out, flags...)
	return out
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
