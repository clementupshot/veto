// Package packagemanager defines the contract for parsing install commands
// across the package managers we shadow (npm, pnpm, yarn, bun, pip, uv,
// poetry, pdm, and their "exec arbitrary remote code" siblings: npx, bunx,
// pnpx, rushx, uvx, pipx).
//
// Each PackageManager parses one binary's argv into a normalized slice of
// Install records. The bouncer then runs each Install through the gate before
// exec'ing the real binary.
//
// Per-PM implementations live in subpackages — the parent stays slim so
// consumers can wire any subset without inheriting the others' dependencies.
package packagemanager

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
)

// Install describes one package the user is about to install.
type Install struct {
	// Ref is the (ecosystem, name, version) tuple the bouncer queries the
	// intel store with. Version may be empty when the user gave a range or
	// no version at all.
	Ref intel.PackageRef

	// RawSpec is the spec as it appeared on the command line (e.g.
	// "lodash@^4.17", "git+https://...", "./local-path"). Surfaces in
	// diagnostics so users can correlate a block to what they typed.
	RawSpec string

	// LocalPath is a filesystem-relative or absolute path spec
	// (`./pkg`, `/abs/pkg`, `file:./pkg`). The intel store is name-keyed,
	// so we can't look these up — the gate's policy decides whether to
	// pass them through (default true) or refuse (`AllowLocalPath=false`).
	LocalPath bool

	// OpaqueRemote is a URL/git/tarball/github-shorthand spec
	// (`git+https://...`, `https://x.com/pkg.tgz`, `github:user/repo`,
	// `user/repo`). These fetch code from outside the registry and so
	// can't be name-keyed-looked-up either, but unlike LocalPath they
	// can carry malware payloads named in upstream intel by URL or
	// commit hash. The gate refuses these by default
	// (`AllowOpaqueRemote=false`); set `BOUNCER_ALLOW_OPAQUE=1` to opt
	// each one through.
	OpaqueRemote bool
}

// ManifestKind tags a ManifestRef so the gate's expander can dispatch on it.
// New kinds are added as new PMs grow manifest-aware (npm's package.json,
// poetry's pyproject.toml, etc.).
type ManifestKind string

const (
	// ManifestKindRequirements is a pip-style requirements.txt referenced via
	// `-r path` or `--requirement path` on the command line.
	ManifestKindRequirements ManifestKind = "requirements"

	// ManifestKindConstraint is a pip-style constraints file referenced via
	// `-c path` or `--constraint path`. Constraints files share the
	// requirements.txt grammar; the gate treats them the same.
	ManifestKindConstraint ManifestKind = "constraint"

	// ManifestKindPackageJSON is an npm-family package.json the gate reads when
	// an install verb names no explicit specs (e.g. `npm install`, `npm ci`).
	// The expander reports the file's direct dependencies; transitive
	// resolution is intentionally out of scope.
	ManifestKindPackageJSON ManifestKind = "package.json"

	// ManifestKindPyProject is a Python pyproject.toml read for the same reason
	// as ManifestKindPackageJSON: install verbs that derive their work from the
	// local manifest (`poetry install`, `uv sync`, `pdm install`).
	ManifestKindPyProject ManifestKind = "pyproject.toml"

	// Lockfile kinds — the resolved, version-pinned, transitively-complete
	// tree that the package manager will actually install. Gating against
	// the lockfile is the closest thing bouncer can do to "gate every
	// transitive dependency" without running the resolver itself: the PM
	// already wrote the answer to disk.
	//
	// Each kind is emitted alongside the manifest kind for install verbs
	// that consult either. The expander returns nil, nil when the file is
	// missing, so PMs can safely emit both refs without coordinating.

	// ManifestKindPackageLockJSON is npm's package-lock.json. Covers
	// lockfileVersion 2 (npm 7+) and 3 (npm 9+) — earlier nested-dependency
	// schemas degrade to direct-deps-only.
	ManifestKindPackageLockJSON ManifestKind = "package-lock.json"

	// ManifestKindNpmShrinkwrap is npm-shrinkwrap.json, package-lock.json's
	// older sibling. Same schema; emitted in case projects pin via shrinkwrap.
	ManifestKindNpmShrinkwrap ManifestKind = "npm-shrinkwrap.json"

	// ManifestKindPnpmLockYAML is pnpm-lock.yaml. Schema versions 5 through
	// 9 are recognised; older versions degrade gracefully.
	ManifestKindPnpmLockYAML ManifestKind = "pnpm-lock.yaml"

	// ManifestKindYarnLock is yarn.lock (yarn classic / v1). Yarn 2+
	// ("berry") uses a different schema; gating against it is best-effort.
	ManifestKindYarnLock ManifestKind = "yarn.lock"

	// ManifestKindUvLock is uv's uv.lock (TOML).
	ManifestKindUvLock ManifestKind = "uv.lock"

	// ManifestKindPoetryLock is poetry's poetry.lock (TOML).
	ManifestKindPoetryLock ManifestKind = "poetry.lock"

	// ManifestKindPdmLock is pdm's pdm.lock (TOML).
	ManifestKindPdmLock ManifestKind = "pdm.lock"
)

// ManifestRef is a parser-extracted pointer to an on-disk manifest the gate
// must read to discover transitive Install records. Parsers return refs;
// the gate's ManifestExpander does the I/O.
//
// Path is taken verbatim from argv. The expander resolves it (relative to
// cwd for top-level refs; relative to the referencing file for nested refs
// inside a requirements.txt).
type ManifestRef struct {
	Path string
	Kind ManifestKind
}

// PackageManager parses install-style commands for one binary.
//
// Name returns the binary name we shadow (e.g. "npm"). Ecosystem identifies
// which intel ecosystem this PM resolves into.
//
// ParseInstalls inspects args after the PM name and returns the packages an
// install verb would fetch. It returns:
//
//   - nil when args do not describe an install-style command (e.g. "npm run
//     dev"); the bouncer passes through to the real binary unchecked.
//   - an empty slice when args ARE an install verb but no explicit packages
//     were named (e.g. "npm install" resolving from package.json); the gate's
//     policy decides how to handle that case.
//   - a non-empty slice when explicit packages were named.
//
// ManifestRefs inspects args and returns any on-disk manifests the command
// would read (pip's `-r requirements.txt`, `-c constraints.txt`, etc.).
// Returns nil when no refs are present. Order follows argv. Implementations
// must not open the files — that's the gate's job (see ManifestExpander).
//
// Implementations must not perform I/O — they parse argv only. Reading
// package.json or pyproject.toml is the gate's responsibility, where the
// policy lives.
type PackageManager interface {
	Name() string
	Ecosystem() intel.Ecosystem
	ParseInstalls(args []string) []Install
	ManifestRefs(args []string) []ManifestRef
}
