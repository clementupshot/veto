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
// @@TODO: support a per-PM table of flags-that-take-values so callers can
// position global flags before the verb without confusing the parser.
func ParseInstallArgs(args []string, installVerbs map[string]struct{}) []packagemanager.Install {
	verb, rest, ok := argv.FirstNonFlag(args)
	if !ok {
		return nil
	}
	if _, isInstall := installVerbs[verb]; !isInstall {
		return nil
	}
	installs := []packagemanager.Install{}
	for _, tok := range rest {
		if argv.IsFlag(tok) {
			continue
		}
		installs = append(installs, Parse(tok))
	}
	return installs
}
