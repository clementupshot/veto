// Package pyspec parses Python-ecosystem package specifiers shared across pip,
// uv, poetry, and pdm.
//
// The parser accepts the practical subset of PEP 508 that turns up in
// command-line specs and requirements.txt lines:
//
//   - bare name: "requests"
//   - single operator: "pkg==1.0"
//   - whitespace around the operator: "pkg == 1.0"
//   - multiple version operators: "pkg>=1.0,<2.0" → name only, empty version
//     (the intel store does exact-version matching, so a range collapses to
//     "any version of this name" and the store's unversioned lookup catches
//     every flagged version)
//   - extras (single or comma list): "pkg[ext1,ext2]==1.0" → extras stripped
//   - environment markers: "pkg==1.0; python_version >= '3.8'" → marker
//     ignored, package emitted (over-include conditional deps; the veto
//     is a safety check, not a resolver)
//
// Local filesystem paths are flagged LocalPath=true; remote URLs and git
// refs are flagged OpaqueRemote=true. The gate's policy decides whether
// to pass each through (LocalPath default true) or refuse
// (OpaqueRemote default false; set VETO_ALLOW_OPAQUE=1 to opt in).
package pyspec

import (
	"strings"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// operators is the set of PEP 440 version comparison operators we recognize,
// ordered longest-first so "==" wins over the "=" prefix-match and "===" wins
// over "==".
var operators = []string{"===", "==", ">=", "<=", "~=", "!=", ">", "<"}

// Parse turns a single command-line spec into an Install for the PyPI
// ecosystem. Filesystem paths set LocalPath=true; remote URLs and git
// refs set OpaqueRemote=true. See package doc for policy semantics.
func Parse(spec string) packagemanager.Install {
	raw := spec
	if isLocalPathSpec(spec) {
		return packagemanager.Install{
			Ref:       intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: spec},
			RawSpec:   raw,
			LocalPath: true,
		}
	}
	if isOpaqueRemoteSpec(spec) {
		return packagemanager.Install{
			Ref:          intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: spec},
			RawSpec:      raw,
			OpaqueRemote: true,
		}
	}

	// Strip the environment marker (everything after the first ';'). We
	// deliberately ignore the marker — see package doc.
	body := spec
	if i := strings.IndexByte(body, ';'); i >= 0 {
		body = body[:i]
	}
	body = strings.TrimSpace(body)

	// PEP 508 URL spec: "<name> @ <url-or-path>". The grammar requires
	// whitespace around the '@' — see https://peps.python.org/pep-0508/#grammar
	// (urlspec ::= '@' wsp* URL_reference). Detect the " @ " sentinel
	// BEFORE operator splitting, because none of the operator characters
	// =<>!~ appear in the URL spec and the whole thing would otherwise be
	// parsed as a bare name and silently allowed.
	//
	// Note: we deliberately require space-at-space, not bare '@', so we
	// don't collide with version-spec shapes like "pkg@1.0" (which is not
	// valid PEP 508 anyway).
	if name, urlRef, ok := splitPEP508URLSpec(body); ok {
		name = stripExtras(name)
		install := packagemanager.Install{
			Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: name},
			RawSpec: raw,
		}
		if isLocalPathSpec(urlRef) {
			install.LocalPath = true
		} else {
			// Anything else on the right of " @ " — URL, git+, etc. — is
			// remote code fetching. Refuse by default; OpaqueRemote keeps the
			// known-name in the install so the policy can apply name-based
			// allowlists if needed.
			install.OpaqueRemote = true
		}
		return install
	}

	name, versionPart := splitNameAndVersion(body)
	name = stripExtras(name)

	version := resolveVersion(versionPart)
	return packagemanager.Install{
		Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: name, Version: version},
		RawSpec: raw,
	}
}

// stripExtras removes "[ext1,ext2]" suffixes from a package name. Extras
// don't affect the malware identity the intel store keys on.
func stripExtras(name string) string {
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	return strings.TrimSpace(name)
}

// splitPEP508URLSpec detects the PEP 508 urlspec form: `<name> @ <url-ref>`.
// Returns (name, urlRef, true) when the body contains a literal " @ "
// (space-at-space) — that whitespace is required by the grammar and lets us
// distinguish from non-PEP-508 shapes like "pkg@1.0".
func splitPEP508URLSpec(body string) (string, string, bool) {
	name, urlRef, ok := strings.Cut(body, " @ ")
	if !ok {
		return "", "", false
	}
	name = strings.TrimSpace(name)
	urlRef = strings.TrimSpace(urlRef)
	if name == "" || urlRef == "" {
		return "", "", false
	}
	return name, urlRef, true
}

// isLocalPathSpec reports whether spec is a filesystem path the gate
// can't look up but that doesn't fetch remote code on its own.
//
// The bare strings "." and "..", as used by `pip install .` and
// `pip install ..`, are filesystem paths in their own right (pwd /
// parent dir) and would otherwise fall through to PyPI lookup as
// literal "name == .", which always misses and silently allows.
func isLocalPathSpec(spec string) bool {
	if spec == "." || spec == ".." {
		return true
	}
	if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, "/") {
		return true
	}
	if strings.HasPrefix(spec, "file:") {
		return true
	}
	return false
}

// isOpaqueRemoteSpec reports whether spec is a remote URL or git
// reference. These pull code from outside PyPI and are refused by
// default; VETO_ALLOW_OPAQUE=1 opts each one through.
func isOpaqueRemoteSpec(spec string) bool {
	for _, p := range []string{"git+", "http://", "https://"} {
		if strings.HasPrefix(spec, p) {
			return true
		}
	}
	return false
}

// splitNameAndVersion returns (name, versionPart) where versionPart is
// everything from the first version operator onward (operator included), or
// empty if no operator was found. Whitespace around the operator is tolerated:
// "pkg == 1.0" splits as ("pkg", "== 1.0").
//
// We scan left-to-right looking for the earliest occurrence of any operator
// after a name character (so a leading "===" couldn't ever match here — names
// can't start with an operator), then return the boundary. The longest-first
// ordering of `operators` ensures e.g. ">=" doesn't get clipped to ">".
func splitNameAndVersion(spec string) (string, string) {
	// Find the earliest cut point across all operators.
	earliest := -1
	for i := 0; i < len(spec); i++ {
		c := spec[i]
		if c == '=' || c == '<' || c == '>' || c == '!' || c == '~' {
			earliest = i
			break
		}
	}
	if earliest < 0 {
		return strings.TrimSpace(spec), ""
	}
	return strings.TrimSpace(spec[:earliest]), spec[earliest:]
}

// resolveVersion extracts an exact version from versionPart, or returns "" if
// the spec is a range (multiple operators) or otherwise non-exact. versionPart
// includes the leading operator(s), e.g. "==1.0" or ">=1.0,<2.0" or "== 1.0".
//
// Returns the version literal (with surrounding whitespace stripped) only when
// the spec is a single "==" constraint. Anything else — multi-clause specs,
// non-equality operators — collapses to empty version, which makes the gate
// fall back to a name-keyed lookup that catches every flagged version.
func resolveVersion(versionPart string) string {
	versionPart = strings.TrimSpace(versionPart)
	if versionPart == "" {
		return ""
	}
	// Multi-clause spec: "pkg>=1.0,<2.0" → empty version, name-keyed lookup.
	if strings.ContainsRune(versionPart, ',') {
		return ""
	}
	for _, op := range operators {
		if strings.HasPrefix(versionPart, op) {
			if op != "==" {
				// Inequality / range / arbitrary-equality operators give us no
				// single version to look up. Collapse to name-keyed lookup.
				return ""
			}
			return strings.TrimSpace(versionPart[len(op):])
		}
	}
	return ""
}
