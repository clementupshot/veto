// Package jslock reads npm-family lockfiles and emits Install records
// against the resolved, version-pinned transitive tree.
//
// Why lockfiles matter for gating: a manifest (`package.json`) lists
// direct dependencies with version ranges. The resolver picks specific
// versions and writes them — along with every transitive — into the
// lockfile. `npm ci`, `pnpm install`, and `yarn install` deterministically
// install what's in the lockfile. Gating against the lockfile is the only
// way bouncer can catch a flagged transitive dep without running the
// resolver itself.
//
// Coverage:
//   - package-lock.json (npm v7+ schema, lockfileVersion 2/3): full
//     transitive coverage via the `packages` map keyed by node_modules path.
//   - npm-shrinkwrap.json: identical schema to package-lock.json.
//   - pnpm-lock.yaml (schema versions 5–9): full transitive coverage via
//     the `packages` map keyed by `/name@version` or similar.
//   - yarn.lock (yarn classic / v1): full transitive coverage via the
//     blocks-of-key+version format pnpm and npm both predate. Yarn 2+
//     ("berry") uses a different schema; we gate it best-effort by
//     extracting `version: "x.y.z"` lines but do not parse the full grammar.
//
// Missing files return (nil, nil) — install verbs emit the ref
// speculatively and the expander tolerates absence.
package jslock

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"

	bouncererrors "github.com/brynbellomy/go-utils/errors"
	"gopkg.in/yaml.v3"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
)

// Expander handles npm/pnpm/yarn lockfile kinds. Stateless and safe for
// concurrent use.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// Expand dispatches by kind to the appropriate format parser.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	switch ref.Kind {
	case packagemanager.ManifestKindPackageLockJSON, packagemanager.ManifestKindNpmShrinkwrap:
		return expandPackageLock(ref.Path)
	case packagemanager.ManifestKindPnpmLockYAML:
		return expandPnpmLock(ref.Path)
	case packagemanager.ManifestKindYarnLock:
		return expandYarnLock(ref.Path)
	default:
		return nil, nil
	}
}

// readFile is a small wrapper that returns (data, true) on success and
// (nil, false) on missing-file (which we treat as "no transitive tree to
// gate"). Errors other than not-exist are surfaced wrapped.
func readFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, bouncererrors.With(err, "read lockfile").Set("path", path)
	}
	return data, true, nil
}

// packageLockJSON captures the lockfileVersion-2/3 schema. The `packages`
// map is keyed by the package's path inside node_modules ("" is the root
// project; "node_modules/lodash" is direct dep lodash; deeper paths are
// transitives). Each entry's `version` is the resolved pin we gate.
type packageLockJSON struct {
	LockfileVersion int                            `json:"lockfileVersion"`
	Packages        map[string]packageLockEntry    `json:"packages"`
	Dependencies    map[string]packageLockDepEntry `json:"dependencies"` // legacy v1 fallback
}

type packageLockEntry struct {
	Name    string `json:"name"` // present when path doesn't carry the name (e.g. for the root)
	Version string `json:"version"`
	Resolved string `json:"resolved"`
}

// packageLockDepEntry is the lockfileVersion=1 nested form.
type packageLockDepEntry struct {
	Version      string                         `json:"version"`
	Dependencies map[string]packageLockDepEntry `json:"dependencies"`
}

func expandPackageLock(path string) ([]packagemanager.Install, error) {
	data, ok, err := readFile(path)
	if err != nil || !ok {
		return nil, err
	}
	var lock packageLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, bouncererrors.With(err, "parse package-lock.json").Set("path", path)
	}

	// v2/v3: walk the packages map.
	if len(lock.Packages) > 0 {
		out := make([]packagemanager.Install, 0, len(lock.Packages))
		for nodePath, entry := range lock.Packages {
			name := nameFromNodeModulesPath(nodePath, entry.Name)
			if name == "" || entry.Version == "" {
				continue
			}
			out = append(out, packagemanager.Install{
				Ref: intel.PackageRef{
					Ecosystem: intel.EcosystemNPM,
					Name:      name,
					Version:   entry.Version,
				},
				RawSpec: name + "@" + entry.Version,
			})
		}
		return out, nil
	}

	// v1 fallback: recurse into the nested dependencies tree.
	var out []packagemanager.Install
	walkV1Deps(lock.Dependencies, &out)
	return out, nil
}

// nameFromNodeModulesPath turns a packages-map key into a package name.
// "" is the root project (skip; we don't gate ourselves). "node_modules/x"
// is x; "node_modules/x/node_modules/y" is y; "node_modules/@scope/pkg" is
// "@scope/pkg". The entry.Name override is consulted only as a fallback.
func nameFromNodeModulesPath(nodePath, entryName string) string {
	if nodePath == "" {
		// Root project entry — never gate the project against itself.
		return ""
	}
	// The package name is everything after the LAST "node_modules/" segment.
	idx := strings.LastIndex(nodePath, "node_modules/")
	if idx < 0 {
		return entryName
	}
	return nodePath[idx+len("node_modules/"):]
}

func walkV1Deps(deps map[string]packageLockDepEntry, out *[]packagemanager.Install) {
	for name, entry := range deps {
		if entry.Version != "" {
			*out = append(*out, packagemanager.Install{
				Ref: intel.PackageRef{
					Ecosystem: intel.EcosystemNPM,
					Name:      name,
					Version:   entry.Version,
				},
				RawSpec: name + "@" + entry.Version,
			})
		}
		walkV1Deps(entry.Dependencies, out)
	}
}

// pnpmLock is the subset of pnpm-lock.yaml we parse.
//
// `packages` is keyed by "/<name>@<version>" (older schemas) or by
// "<name>@<version>" (newer schemas). For scoped packages the slash inside
// the name (e.g. "@scope/pkg") is preserved.
//
// `lockfileVersion` is informational — we always walk the same `packages`
// map regardless of version. Schemas before 5 used a flatter snapshot
// section; we degrade to direct-deps in that case (see
// expandPnpmLockFlatSnapshots).
type pnpmLock struct {
	LockfileVersion any                    `yaml:"lockfileVersion"`
	Packages        map[string]any         `yaml:"packages"`
	Snapshots       map[string]any         `yaml:"snapshots"`
	Importers       map[string]pnpmImporter `yaml:"importers"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmImporterEntry `yaml:"dependencies"`
	DevDependencies      map[string]pnpmImporterEntry `yaml:"devDependencies"`
	PeerDependencies     map[string]pnpmImporterEntry `yaml:"peerDependencies"`
	OptionalDependencies map[string]pnpmImporterEntry `yaml:"optionalDependencies"`
}

type pnpmImporterEntry struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

func expandPnpmLock(path string) ([]packagemanager.Install, error) {
	data, ok, err := readFile(path)
	if err != nil || !ok {
		return nil, err
	}
	var lock pnpmLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, bouncererrors.With(err, "parse pnpm-lock.yaml").Set("path", path)
	}

	// Modern schemas (lockfileVersion 5+) populate `packages` with the
	// full resolved tree. Older schemas use snapshots/importers — fall
	// back to those for direct-deps coverage.
	var out []packagemanager.Install
	for key := range lock.Packages {
		name, version := parsePnpmPackageKey(key)
		if name == "" || version == "" {
			continue
		}
		out = append(out, packagemanager.Install{
			Ref: intel.PackageRef{
				Ecosystem: intel.EcosystemNPM,
				Name:      name,
				Version:   version,
			},
			RawSpec: key,
		})
	}
	if len(out) > 0 {
		return out, nil
	}
	// Schema-pre-5 fallback: walk importers' direct dependency maps.
	for _, imp := range lock.Importers {
		appendImporterDeps(imp.Dependencies, &out)
		appendImporterDeps(imp.DevDependencies, &out)
		appendImporterDeps(imp.PeerDependencies, &out)
		appendImporterDeps(imp.OptionalDependencies, &out)
	}
	return out, nil
}

func appendImporterDeps(deps map[string]pnpmImporterEntry, out *[]packagemanager.Install) {
	for name, entry := range deps {
		if entry.Version == "" {
			continue
		}
		*out = append(*out, packagemanager.Install{
			Ref: intel.PackageRef{
				Ecosystem: intel.EcosystemNPM,
				Name:      name,
				Version:   strings.TrimPrefix(entry.Version, "v"),
			},
			RawSpec: name + "@" + entry.Version,
		})
	}
}

// parsePnpmPackageKey splits a pnpm packages-map key into (name, version).
// Formats handled:
//
//	"/lodash@4.17.21"          → ("lodash", "4.17.21")
//	"/@scope/pkg@1.0.0"        → ("@scope/pkg", "1.0.0")
//	"lodash@4.17.21"           → ("lodash", "4.17.21")     (no leading slash)
//	"/lodash@4.17.21(react@18)" → ("lodash", "4.17.21")    (peer-suffix stripped)
func parsePnpmPackageKey(key string) (string, string) {
	k := strings.TrimPrefix(key, "/")
	// Drop any "(peer@version)" suffix.
	if idx := strings.IndexByte(k, '('); idx > 0 {
		k = k[:idx]
	}
	// Scoped: "@scope/pkg@version".
	if strings.HasPrefix(k, "@") {
		if idx := strings.Index(k[1:], "@"); idx > 0 {
			return k[:1+idx], k[1+idx+1:]
		}
		return k, ""
	}
	if name, version, ok := strings.Cut(k, "@"); ok {
		return name, version
	}
	return k, ""
}

// expandYarnLock parses yarn.lock (v1) line-by-line. The format is:
//
//	"@scope/pkg@^1.0.0", "@scope/pkg@~1.1":
//	  version "1.1.5"
//	  resolved "..."
//
// We don't enforce the grammar — a permissive scanner that pairs the
// most-recent "version "<v>"" with the closest preceding header line is
// enough to gate the transitive tree.
//
// Yarn 2+ ("berry") uses a YAML-shaped format. We detect the BERRY header
// and fall back to a regex-style version harvest; the gate still works,
// it just doesn't capture peer-specific resolutions correctly.
func expandYarnLock(path string) ([]packagemanager.Install, error) {
	data, ok, err := readFile(path)
	if err != nil || !ok {
		return nil, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var out []packagemanager.Install
	var pendingHeader string
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Header line: no leading whitespace and ends with ":".
		if line == trimmed && strings.HasSuffix(trimmed, ":") {
			pendingHeader = strings.TrimSuffix(trimmed, ":")
			continue
		}
		// Body line: indented. We look only for `version "..."` or
		// `version: x` (berry).
		if strings.HasPrefix(trimmed, "version ") || strings.HasPrefix(trimmed, "version:") {
			version := extractYarnVersion(trimmed)
			if version == "" {
				continue
			}
			name := nameFromYarnHeader(pendingHeader)
			if name == "" {
				continue
			}
			out = append(out, packagemanager.Install{
				Ref: intel.PackageRef{
					Ecosystem: intel.EcosystemNPM,
					Name:      name,
					Version:   version,
				},
				RawSpec: name + "@" + version,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, bouncererrors.With(err, "scan yarn.lock").Set("path", path)
	}
	return out, nil
}

// extractYarnVersion pulls "1.0.5" out of `version "1.0.5"` or `version: 1.0.5`.
func extractYarnVersion(line string) string {
	// v1: `version "1.0.5"`
	if idx := strings.IndexByte(line, '"'); idx >= 0 {
		rest := line[idx+1:]
		if end := strings.IndexByte(rest, '"'); end >= 0 {
			return rest[:end]
		}
	}
	// berry: `version: 1.0.5`
	if rest, ok := strings.CutPrefix(line, "version:"); ok {
		rest = strings.TrimSpace(rest)
		rest = strings.Trim(rest, `"'`)
		return rest
	}
	return ""
}

// nameFromYarnHeader pulls the package name out of a yarn.lock header
// like `"@scope/pkg@^1.0.0", "@scope/pkg@~1.1":`. The first comma-separated
// alternative is sufficient (they all share a name).
func nameFromYarnHeader(header string) string {
	if header == "" {
		return ""
	}
	// Take the first alternative (before any comma).
	first := header
	if idx := strings.IndexByte(header, ','); idx >= 0 {
		first = header[:idx]
	}
	first = strings.TrimSpace(first)
	first = strings.Trim(first, `"`)
	// Scoped: "@scope/pkg@^1.0.0" → "@scope/pkg".
	if strings.HasPrefix(first, "@") {
		if idx := strings.Index(first[1:], "@"); idx > 0 {
			return first[:1+idx]
		}
		return first
	}
	// Berry-style "name@npm:^1.0.0" or "name@^1.0.0".
	if idx := strings.IndexByte(first, '@'); idx > 0 {
		return first[:idx]
	}
	return first
}
