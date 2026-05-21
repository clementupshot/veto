// Package pnpm implements packagemanager.PackageManager for pnpm.
package pnpm

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/jsspec"
)

const binaryName = "pnpm"

var installVerbs = map[string]struct{}{
	"install": {}, "i": {}, "add": {},
	"update": {}, "up": {}, "upgrade": {},
	"dlx": {}, // fetches and runs a package; equivalent risk to npx/bunx
}

// Manager parses pnpm install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a pnpm manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemNPM }

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	return jsspec.ParseInstallArgs(args, installVerbs)
}
