// Package yarn implements packagemanager.PackageManager for Yarn (classic and
// berry; verb sets overlap enough that one parser handles both).
package yarn

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/jsspec"
)

const binaryName = "yarn"

var installVerbs = map[string]struct{}{
	"install": {}, "add": {},
	"upgrade": {}, "up": {},
	"dlx": {}, // yarn berry's `yarn dlx <pkg>` — equivalent to npx
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
	return jsspec.ParseInstallArgs(args, installVerbs)
}
