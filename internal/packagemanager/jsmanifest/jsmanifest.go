// Package jsmanifest reads npm-family package.json files and turns their
// direct-dependency maps into Install records.
//
// This is the I/O side of npm/pnpm/yarn/bun's "verb implies the manifest" flow
// (`npm install` with no specs, `npm ci`, etc.). The package manager returns a
// ManifestKindPackageJSON ref from argv; the gate's expander — implemented
// here — opens the JSON, walks the four direct-dependency maps, and emits
// []Install via jsspec.
//
// Direct deps only. Transitive resolution would require running the real
// package manager (parsing package-lock.json, resolving ranges against the
// registry), which defeats the purpose of a parse-only gate. The intel store's
// name-keyed fallback catches every flagged version when the range is too
// imprecise to pin a single version.
package jsmanifest

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"

	vetoerrors "github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/jsspec"
)

// Expander reads package.json files and emits the Install records the gate
// looks up.
//
// Safe for concurrent use; New() returns a stateless instance.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// packageJSON is the subset of fields the expander cares about. Anything not
// listed here is ignored. The four maps cover the dependency surfaces npm,
// pnpm, yarn, and bun all read from when resolving an install set.
type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// Expand reads ref.Path and returns the []Install its direct-dependency maps
// resolve to. Returns nil, nil for any ref.Kind other than
// ManifestKindPackageJSON so the compound expander can dispatch by kind.
//
// A missing file is not an error — some install verbs run from non-project
// directories (e.g. `npm install <pkg>` outside a project). Malformed JSON
// returns a wrapped error with the path attached.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	if ref.Kind != packagemanager.ManifestKindPackageJSON {
		return nil, nil
	}

	data, err := os.ReadFile(ref.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, vetoerrors.With(err, "reading package.json").Set("path", ref.Path)
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, vetoerrors.With(err, "parse package.json").Set("path", ref.Path)
	}

	// Pre-size for the realistic upper bound: one entry per name across all
	// four maps. Order is insertion-stable per Go's map iteration only within
	// a single map, so the resulting slice is grouped by section rather than
	// by name. That's fine — the gate's lookup is order-independent.
	approx := len(pkg.Dependencies) + len(pkg.DevDependencies) + len(pkg.PeerDependencies) + len(pkg.OptionalDependencies)
	installs := make([]packagemanager.Install, 0, approx)
	installs = appendDeps(installs, pkg.Dependencies)
	installs = appendDeps(installs, pkg.DevDependencies)
	installs = appendDeps(installs, pkg.PeerDependencies)
	installs = appendDeps(installs, pkg.OptionalDependencies)
	return installs, nil
}

// appendDeps turns a {name: versionSpec} map into Installs via jsspec.Parse.
//
// package.json version values are almost always range expressions ("^4.17.21",
// "~1.0", ">=2 <3", "*", "latest", "next"). The intel store's exact-version
// index would miss every flagged version under a range, so we strip non-exact
// versions before parsing: jsspec records an empty Version field, and the
// store's name-keyed lookup catches every flagged version of the package.
//
// An exact pin ("4.17.21") is preserved as Version so the store's exact-match
// path still applies — those are the common case for pinned monorepos.
//
// npm package aliases — values like "npm:realname@version" — are unwrapped to
// the real package name+version so the gate looks up the actually-installed
// package, not the local alias the developer typed. Without this, an attacker
// can hide a malicious package under a benign-looking local name.
//
// Opaque-remote values ("git+https://...", "github:user/repo", "user/repo",
// tarball URLs) and local-path values ("./local", "file:./local", "/abs") are
// detected on the VERSION side — package.json keys are always the local
// install name, never the spec — and emit Installs with the appropriate
// OpaqueRemote / LocalPath flag set, so the gate's policy can refuse opaque
// fetches by default. Without this, the version string would be passed to
// jsspec.Parse(name+"@"+version) and the resulting Install would look like a
// clean name with no remote-fetch indication.
func appendDeps(out []packagemanager.Install, deps map[string]string) []packagemanager.Install {
	for name, version := range deps {
		v := strings.TrimSpace(version)
		if alias, aliasVer, ok := jsspec.UnwrapNpmAlias(v); ok {
			spec := alias
			if p := exactPin(aliasVer); p != "" {
				spec = alias + "@" + p
			}
			out = append(out, jsspec.Parse(spec))
			continue
		}
		// Detect opaque-remote / local-path forms on the version side. These
		// fetch code from outside the registry (or from disk), so we MUST set
		// the appropriate flag rather than letting the value be parsed as a
		// "name@version" pin — otherwise the gate sees a clean Install and the
		// AllowOpaqueRemote policy never gets a chance to refuse it.
		if jsspec.IsLocalPathSpec(v) {
			out = append(out, packagemanager.Install{
				Ref:       intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name},
				RawSpec:   name + "@" + version,
				LocalPath: true,
			})
			continue
		}
		if jsspec.IsOpaqueRemoteSpec(v) {
			out = append(out, packagemanager.Install{
				Ref:          intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name},
				RawSpec:      name + "@" + version,
				OpaqueRemote: true,
			})
			continue
		}
		spec := name
		if p := exactPin(version); p != "" {
			spec = name + "@" + p
		}
		out = append(out, jsspec.Parse(spec))
	}
	return out
}

// exactPin returns version when it's a single exact semver-ish literal (no
// range or tag prefix). Anything operator-prefixed ("^1", "~1", ">=2"),
// multi-clause (" >=1 <2"), wildcard ("*"), or tag-named ("latest", "next")
// collapses to empty so the name-keyed lookup takes over.
func exactPin(version string) string {
	v := strings.TrimSpace(version)
	if v == "" || v == "*" || v == "latest" || v == "next" {
		return ""
	}
	// Range / comparator characters disqualify outright.
	if strings.ContainsAny(v, "^~><=| ,") {
		return ""
	}
	// Phase 1.6: anchor x/X wildcards to segment boundaries so legitimate
	// exact pins like "1.0.0-experimental", "1.2.3-Xfix", or
	// "2.0.0+build.x12" stay exact. A bare segment of "x" or "X" — or
	// the literal token "x" / "X" — still counts as a wildcard.
	if v == "x" || v == "X" {
		return ""
	}
	for _, seg := range strings.FieldsFunc(v, func(r rune) bool { return r == '.' }) {
		if seg == "x" || seg == "X" {
			return ""
		}
	}
	return v
}

var _ interface {
	Expand(packagemanager.ManifestRef) ([]packagemanager.Install, error)
} = (*Expander)(nil)
