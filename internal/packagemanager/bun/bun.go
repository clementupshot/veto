// Package bun implements packagemanager.PackageManager for the bun CLI.
//
// Bun is the motivating case for command-level gating: safe-chain's proxy-only
// approach for bun fails open in non-interactive shells (the bug that prompted
// this project). At the command level we don't care how bun fetches packages
// — we check the names against intel before bun ever runs.
package bun

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/jsspec"
)

const binaryName = "bun"

var installVerbs = map[string]struct{}{
	"install": {}, "i": {}, "add": {},
	"update": {}, "upgrade": {},
	"x":      {}, // `bun x <pkg>` — fetches and runs
	"create": {}, // `bun create <template>` — fetches a starter template
}

// Manager parses bun install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a bun manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemNPM }

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	return jsspec.ParseInstallArgs(args, installVerbs)
}
