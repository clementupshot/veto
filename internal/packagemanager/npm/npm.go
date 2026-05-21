// Package npm implements packagemanager.PackageManager for the npm CLI.
//
// All real parsing lives in jsspec; this package just declares npm's install
// verb set, the flag-with-value table, and wires the binary name. Same shape
// for pnpm/yarn/bun.
package npm

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/argv"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/jsspec"
)

const binaryName = "npm"

var installVerbs = map[string]struct{}{
	"install": {}, "i": {}, "add": {},
	"ci":     {}, // clean install from lockfile; no explicit specs
	"update": {}, "up": {}, "upgrade": {},
}

// alwaysReadsManifest names the install verbs that consult package.json /
// package-lock.json regardless of argv. `ci` is the canonical case: it always
// resolves from the lockfile and refuses to accept positional specs.
var alwaysReadsManifest = map[string]struct{}{
	"ci": {},
}

// flagsWithValues lists npm flags whose next argv token is the flag's
// value, drawn from `npm --help` plus the common config-overriding flags
// agents and CI scripts actually reach for. Keeping this slim is fine —
// the goal is to stop the parser from mistaking values for the verb, not
// to model the full npm flag surface.
var flagsWithValues = argv.FlagsWithValues{
	"--prefix":       {},
	"--registry":     {},
	"--userconfig":   {},
	"--globalconfig": {},
	"--tag":          {},
	"--workspace":    {},
	"-w":             {},
	"--omit":         {},
	"--include":      {},
	"--cache":        {},
	"--logfile":      {},
	"--loglevel":     {},
	"--depth":        {},
	"--save-prefix":  {},
	"--access":       {},
}

// Manager parses npm install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds an npm manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemNPM }

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	return jsspec.ParseInstallArgs(args, installVerbs, flagsWithValues)
}

// ManifestRefs implements packagemanager.PackageManager. Emits a package.json
// ref when the install verb would derive its work from the local manifest —
// `npm install` / `npm i` with no specs, `npm ci` regardless of args — so the
// gate's expander can read the file and gate its direct dependencies.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	return jsspec.PackageJSONManifestRefs(args, installVerbs, alwaysReadsManifest, flagsWithValues)
}
