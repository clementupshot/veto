// Package yarn implements packagemanager.PackageManager for Yarn (classic and
// berry; verb sets overlap enough that one parser handles both).
package yarn

import (
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
	"github.com/brynbellomy/veto/internal/packagemanager/jsspec"
)

const binaryName = "yarn"

var installVerbs = map[string]struct{}{
	"install": {}, "add": {},
	"upgrade": {}, "up": {},
	"dlx": {}, // yarn berry's `yarn dlx <pkg>` — equivalent to npx
}

// alwaysReadsManifest is empty for yarn: `yarn install` resolves from the
// manifest only when no specs are given (caught by the empty-specs branch).
var alwaysReadsManifest = map[string]struct{}{}

// flagsWithValues lists yarn flags whose next argv token is the value.
// Covers both classic (--cache-folder, --modules-folder) and berry
// (--cwd, --cache-folder) shapes where they differ; the union is safe
// since the goal is to avoid mistaking a flag-value for a positional.
var flagsWithValues = argv.FlagsWithValues{
	"--cwd":             {},
	"--cache-folder":    {},
	"--modules-folder":  {},
	"--registry":        {},
	"--prefix":          {},
	"--use-yarnrc":      {},
	"--proxy":           {},
	"--https-proxy":     {},
	"--network-timeout": {},
	"--network-concurrency": {},
	"--mutex":           {},
	"--otp":             {},
	"--tag":             {},
}

// Manager parses yarn install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a yarn manager.
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
// ref when an install verb was given with no explicit specs, so the gate's
// expander can read the manifest and gate its direct dependencies.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	return jsspec.PackageJSONManifestRefs(args, installVerbs, alwaysReadsManifest, flagsWithValues)
}
