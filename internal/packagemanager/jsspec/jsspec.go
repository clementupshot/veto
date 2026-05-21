// Package jsspec parses npm-registry-style package specifiers shared across
// npm, pnpm, yarn, and bun: scoped/unscoped names with optional versions,
// plus local-path and git-url forms.
//
// This helper lives next to its consumers — siblings under
// internal/packagemanager/ — rather than in the parent, so the parent
// interface package stays ecosystem-agnostic.
package jsspec

import (
	"strings"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/argv"
)

// Parse turns a single command-line spec into an Install for the npm
// ecosystem. Recognizes:
//
//   - "lodash"                         → name only
//   - "lodash@4.17.21"                 → name + version
//   - "lodash@^4.17"                   → name + range (kept verbatim as version)
//   - "@scope/pkg"                     → scoped, no version
//   - "@scope/pkg@1.2.3"               → scoped + version
//   - "./local", "../sibling", "/abs"  → local path → Local=true
//   - "file:./local"                   → local file → Local=true
//   - "git+https://...", "github:org/repo", "user/repo" → git → Local=true
func Parse(spec string) packagemanager.Install {
	if isLocalOrGitSpec(spec) {
		return packagemanager.Install{
			Ref:     intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: spec},
			RawSpec: spec,
			Local:   true,
		}
	}

	name, version := splitNameVersion(spec)
	return packagemanager.Install{
		Ref:     intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name, Version: version},
		RawSpec: spec,
	}
}

func isLocalOrGitSpec(spec string) bool {
	if spec == "" {
		return false
	}
	if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, "/") {
		return true
	}
	for _, prefix := range []string{
		"file:", "git+", "git://", "github:", "gist:", "bitbucket:", "gitlab:", "http://", "https://",
	} {
		if strings.HasPrefix(spec, prefix) {
			return true
		}
	}
	// "user/repo" shorthand: a slash without a leading @scope is a github
	// shorthand in npm. We treat anything containing "/" and not starting
	// with "@" as non-registry.
	if !strings.HasPrefix(spec, "@") && strings.Contains(spec, "/") {
		return true
	}
	return false
}

// splitNameVersion handles both scoped (@scope/pkg@ver) and unscoped (pkg@ver)
// forms. Returns (name, version); version may be empty.
func splitNameVersion(spec string) (string, string) {
	if strings.HasPrefix(spec, "@") {
		// Scoped: find the SECOND '@' to split name from version.
		// "@scope/pkg@1.2.3" → name "@scope/pkg", version "1.2.3"
		if idx := strings.Index(spec[1:], "@"); idx >= 0 {
			return spec[:1+idx], spec[1+idx+1:]
		}
		return spec, ""
	}
	if name, version, ok := strings.Cut(spec, "@"); ok {
		return name, version
	}
	return spec, ""
}

// ParseInstallArgs is the shared parser for npm-family CLIs (npm/pnpm/yarn/bun).
// It identifies the install verb (first non-flag matching installVerbs) and
// returns Install records for every non-flag token after it. Returns nil when
// args do not start an install command; an empty slice when args ARE an install
// verb but no explicit specs were named (e.g. `npm install`, `npm ci`).
//
// Respects the POSIX `--` separator: every token after `--` is treated as a
// positional package spec even if it starts with `-` (so leading-dash
// typosquat names like `-chalk` are gated rather than silently bypassed).
//
// flagsTakingValues is the PM's table of flags whose next argv token is a
// value, not a positional (e.g. npm's "--prefix /tmp"). A nil/empty map is
// accepted; the parser then degrades to flag-name-only skipping, which can
// misread a flag's value as the verb. Pass the PM-specific table.
func ParseInstallArgs(args []string, installVerbs map[string]struct{}, flagsTakingValues argv.FlagsWithValues) []packagemanager.Install {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsTakingValues)
	if !ok {
		return nil
	}
	if _, isInstall := installVerbs[verb]; !isInstall {
		return nil
	}
	specs := argv.CollectPositionalsWithTable(rest, flagsTakingValues)
	installs := make([]packagemanager.Install, 0, len(specs))
	for _, spec := range specs {
		installs = append(installs, Parse(spec))
	}
	return installs
}

// PackageJSONManifestRefs returns a single package.json ManifestRef when the
// npm-family command would resolve its install set from the local manifest —
// i.e. an install verb was given but no explicit package specs were named —
// and nil otherwise.
//
// alwaysReadsManifest is the subset of install verbs that read the manifest
// regardless of argv (npm's `ci`, pnpm/yarn `install` after a lockfile, etc.).
// For verbs in this set the ref is emitted even when explicit specs were also
// named, because the PM still consults the manifest first.
//
// installVerbs and flagsTakingValues match the shape used by ParseInstallArgs
// so callers stay internally consistent: a manifest ref is emitted exactly
// when the gate would otherwise have nothing to look up.
func PackageJSONManifestRefs(
	args []string,
	installVerbs map[string]struct{},
	alwaysReadsManifest map[string]struct{},
	flagsTakingValues argv.FlagsWithValues,
) []packagemanager.ManifestRef {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsTakingValues)
	if !ok {
		return nil
	}
	if _, isInstall := installVerbs[verb]; !isInstall {
		return nil
	}
	if _, always := alwaysReadsManifest[verb]; always {
		return []packagemanager.ManifestRef{{Path: "package.json", Kind: packagemanager.ManifestKindPackageJSON}}
	}
	if specs := argv.CollectPositionalsWithTable(rest, flagsTakingValues); len(specs) > 0 {
		// User named explicit specs; the gate already has work to do.
		return nil
	}
	return []packagemanager.ManifestRef{{Path: "package.json", Kind: packagemanager.ManifestKindPackageJSON}}
}
