// Package npm implements packagemanager.PackageManager for the npm CLI.
//
// All real parsing lives in jsspec; this package just declares npm's install
// verb set and wires the binary name. Same shape for pnpm/yarn/bun.
package npm

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/jsspec"
)

const binaryName = "npm"

var installVerbs = map[string]struct{}{
	"install": {}, "i": {}, "add": {},
	"ci":     {}, // clean install from lockfile; no explicit specs
	"update": {}, "up": {}, "upgrade": {},
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
	return jsspec.ParseInstallArgs(args, installVerbs)
}
