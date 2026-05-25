// Package uv implements packagemanager.PackageManager for uv.
package uv

import (
	"strings"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
	"github.com/brynbellomy/veto/internal/packagemanager/pyspec"
)

const binaryName = "uv"

// flagsWithValues lists uv flags whose next argv token is the value. Uv
// reuses pip's flag vocabulary for its `uv pip` subcommand and layers its
// own (--python, --index, --extra-index-url, --resolution, etc.) for the
// `uv add`/`uv sync` shape.
var flagsWithValues = argv.FlagsWithValues{
	"--python":            {},
	"-p":                  {},
	"--index":             {},
	"--default-index":     {},
	"--index-url":         {},
	"-i":                  {},
	"--extra-index-url":   {},
	"--find-links":        {},
	"-f":                  {},
	"--cache-dir":         {},
	"--config-file":       {},
	"--directory":         {},
	"--project":           {},
	"--resolution":        {},
	"--prerelease":        {},
	"--target":            {},
	"--prefix":            {},
	"--link-mode":         {},
	"--index-strategy":    {},
	"--keyring-provider":  {},
	"--python-preference": {},
	"-r":                  {},
	"--requirement":       {},
	"-c":                  {},
	"--constraint":        {},
	"--override":          {},
	"--extra":             {},
	"--group":             {},
	"--with":              {},
	"--with-requirements": {},
	"--package":           {},
}

// Manager parses uv install commands. Handles both `uv pip install ...` and
// `uv add ...` shapes.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)
var _ packagemanager.ResolverPreScanner = (*Manager)(nil)

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

// withFlags is the subset of flagsWithValues whose VALUE is itself a
// package spec that fetches code: `uv run --with X` and the multi-arg
// `uv run --with=X`. Mirrors NpxSpecFlags / PipxSpecFlags in spirit.
var withFlags = argv.FlagsWithValues{
	"--with": {},
}

// withRequirementsFlags points at a requirements file — same shape as
// pip's `-r`, but exposed via `uv run --with-requirements`.
var withRequirementsFlags = argv.FlagsWithValues{
	"--with-requirements": {},
}

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	verb, rest, ok := installVerbAndRest(args)
	if !ok {
		return nil
	}
	switch verb {
	case "tool-install", "tool-run", "tool-upgrade":
		// `uv tool {install,run,upgrade} <pkg>`: the first positional after
		// the sub-verb is the package to fetch. uv tool itself accepts a
		// `--with` flag too; gate those as well so `uv tool run --with evil
		// ruff` doesn't slip through.
		specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
		withSpecs := argv.CollectFlagValues(rest, withFlags, flagsWithValues)
		out := make([]packagemanager.Install, 0, len(specs)+len(withSpecs))
		if len(specs) > 0 {
			out = append(out, pyspec.Parse(specs[0]))
		}
		for _, s := range withSpecs {
			out = append(out, pyspec.Parse(s))
		}
		return out
	case "run":
		// `uv run` ONLY fetches a package when `--with X` is present
		// (or `--with-requirements file`, which is a manifest ref, not
		// argv specs). Bare `uv run script.py` passes through unchecked.
		withSpecs := argv.CollectFlagValues(rest, withFlags, flagsWithValues)
		if len(withSpecs) == 0 {
			return nil
		}
		out := make([]packagemanager.Install, 0, len(withSpecs))
		for _, s := range withSpecs {
			out = append(out, pyspec.Parse(s))
		}
		return out
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
	withReqs := argv.CollectFlagValues(rest, withRequirementsFlags, flagsWithValues)
	hasReqRefs := len(reqs) > 0 || len(cons) > 0 || len(withReqs) > 0

	refs := make([]packagemanager.ManifestRef, 0, len(reqs)+len(cons)+len(withReqs)+1)
	for _, p := range reqs {
		refs = append(refs, packagemanager.ManifestRef{Path: p, Kind: packagemanager.ManifestKindRequirements})
	}
	for _, p := range cons {
		refs = append(refs, packagemanager.ManifestRef{Path: p, Kind: packagemanager.ManifestKindConstraint})
	}
	// `uv run --with-requirements reqs.txt` and `uv tool {run,install,upgrade}
	// --with-requirements reqs.txt` reference a requirements-file the same
	// way `uv pip install -r reqs.txt` does. Same manifest kind so the
	// existing pyreq expander walks it.
	for _, p := range withReqs {
		refs = append(refs, packagemanager.ManifestRef{Path: p, Kind: packagemanager.ManifestKindRequirements})
	}

	if shouldReadPyProject(verb, rest, hasReqRefs) {
		refs = append(refs, packagemanager.ManifestRef{Path: "pyproject.toml", Kind: packagemanager.ManifestKindPyProject})
	}

	// Always emit the uv.lock ref when this is an install-shaped verb.
	// The expander tolerates absence, so this is a no-op in directories
	// without a lock — but in lockfile-using projects it surfaces the
	// resolved transitive tree to the gate. Closes the transitive-dep
	// gap that argv + pyproject expansion can't see by themselves.
	if verb == "add" || verb == "sync" || verb == "install" {
		refs = append(refs, packagemanager.ManifestRef{Path: "uv.lock", Kind: packagemanager.ManifestKindUvLock})
	}

	if len(refs) == 0 {
		return nil
	}
	return refs
}

// ResolverPreScan implements packagemanager.ResolverPreScanner for uv's
// pip-compatible install shape. uv pip compile can resolve requirements into a
// pylock.toml file without installing packages. Veto feeds it a synthetic input
// file for argv-named specs, seeds user requirements/constraints, and forces
// wheel-only resolution so sdists are not built in the temporary workdir.
func (Manager) ResolverPreScan(args []string) (packagemanager.ResolverPreScanPlan, bool) {
	verb, rest, ok := installVerbAndRest(args)
	if !ok || verb != "pip-install" {
		return packagemanager.ResolverPreScanPlan{}, false
	}
	directInstalls := Manager{}.ParseInstalls(args)
	manifestRefs := Manager{}.ManifestRefs(args)
	if len(directInstalls) == 0 && len(manifestRefs) == 0 {
		return packagemanager.ResolverPreScanPlan{}, false
	}
	if hasUnsafeResolverPreScanSpec(directInstalls) || hasUnsafeResolverPreScanFlag(rest) {
		return packagemanager.ResolverPreScanPlan{}, false
	}
	compileArgs := []string{"pip", "compile"}
	generatedFiles := map[string][]byte{}
	if len(directInstalls) > 0 {
		generatedFiles["veto-uv-requirements.in"] = []byte(directRequirementsInput(directInstalls))
		compileArgs = append(compileArgs, "veto-uv-requirements.in")
	}
	compileArgs = append(compileArgs, compileRequirementArgs(manifestRefs)...)
	compileArgs = append(compileArgs,
		"--output-file", "pylock.veto.toml",
		"--format", "pylock.toml",
		"--only-binary", ":all:",
		"--no-progress",
	)
	seedFiles := make([]string, 0, len(manifestRefs))
	for _, ref := range manifestRefs {
		seedFiles = append(seedFiles, ref.Path)
	}
	return packagemanager.ResolverPreScanPlan{
		Args: compileArgs,
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "pylock.veto.toml", Kind: packagemanager.ManifestKindUvLock},
		},
		SeedFiles:      seedFiles,
		GeneratedFiles: generatedFiles,
		DirectInstalls: directInstalls,
	}, true
}

func compileRequirementArgs(refs []packagemanager.ManifestRef) []string {
	out := make([]string, 0, len(refs)*2)
	for _, ref := range refs {
		switch ref.Kind {
		case packagemanager.ManifestKindRequirements:
			out = append(out, ref.Path)
		case packagemanager.ManifestKindConstraint:
			out = append(out, "--constraint", ref.Path)
		}
	}
	return out
}

func directRequirementsInput(installs []packagemanager.Install) string {
	var b strings.Builder
	for _, ins := range installs {
		if ins.RawSpec == "" {
			continue
		}
		b.WriteString(ins.RawSpec)
		b.WriteByte('\n')
	}
	return b.String()
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

// installVerbAndRest returns the canonical install verb and the argv tail to
// scan for flag values / positionals. `uv pip install ...` collapses to verb
// "pip-install" so callers can distinguish it from the project-aware shapes.
// `uv tool {install,run,upgrade}` collapses to "tool-install" / "tool-run" /
// "tool-upgrade" so ParseInstalls can branch on the fetch-y subverbs while
// `uv tool uninstall` (which never fetches) bails out.
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
	if verb == "tool" {
		subVerb, subRest, subOK := argv.FirstNonFlagWithTable(rest, flagsWithValues)
		if !subOK {
			return "", nil, false
		}
		switch subVerb {
		case "install", "run", "upgrade":
			return "tool-" + subVerb, subRest, true
		}
		return "", nil, false
	}
	switch verb {
	case "add", "sync", "install", "run":
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

func parseSpecs(rest []string) []packagemanager.Install {
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	installs := make([]packagemanager.Install, 0, len(specs))
	for _, spec := range specs {
		installs = append(installs, pyspec.Parse(spec))
	}
	return installs
}
