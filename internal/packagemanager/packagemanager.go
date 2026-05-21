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

	// Local indicates a file-path or git-ref spec we cannot meaningfully look
	// up against a name-keyed intel store. The gate may treat these as
	// allow-with-warning rather than refuse outright.
	Local bool
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
// Implementations must not perform I/O — they parse argv only. Reading
// package.json or pyproject.toml is the gate's responsibility, where the
// policy lives.
type PackageManager interface {
	Name() string
	Ecosystem() intel.Ecosystem
	ParseInstalls(args []string) []Install
}
