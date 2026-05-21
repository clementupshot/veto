// Package pyspec parses Python-ecosystem package specifiers shared across pip,
// uv, poetry, and pdm. It accepts a useful subset of PEP 508 (name plus a
// single version operator); full extras/markers parsing is @@TODO.
package pyspec

import (
	"strings"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
)

// Operators ordered longest-first so "==" wins over the "=" prefix-match.
var operators = []string{"==", ">=", "<=", "~=", "!=", ">", "<"}

// Parse turns a single command-line spec into an Install for the PyPI
// ecosystem. Local paths and URLs are marked Local=true.
func Parse(spec string) packagemanager.Install {
	if isLocalOrURL(spec) {
		return packagemanager.Install{
			Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: spec},
			RawSpec: spec,
			Local:   true,
		}
	}
	name, version := splitVersion(spec)
	// Strip extras: "pkg[extra]" → "pkg". The intel store is name-keyed; extras
	// don't affect malware identity.
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	return packagemanager.Install{
		Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: name, Version: version},
		RawSpec: spec,
	}
}

func isLocalOrURL(spec string) bool {
	if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, "/") {
		return true
	}
	for _, p := range []string{"file:", "git+", "http://", "https://"} {
		if strings.HasPrefix(spec, p) {
			return true
		}
	}
	return false
}

func splitVersion(spec string) (string, string) {
	for _, op := range operators {
		if name, version, ok := strings.Cut(spec, op); ok {
			return name, version
		}
	}
	return spec, ""
}
