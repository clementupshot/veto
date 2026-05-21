// Package poetry implements packagemanager.PackageManager for Poetry.
package poetry

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/argv"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pyspec"
)

const binaryName = "poetry"

var installVerbs = map[string]struct{}{
	"install": {}, "add": {}, "update": {}, "lock": {},
}

// Manager parses poetry install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a poetry manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemPyPI }

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	verb, rest, ok := argv.FirstNonFlag(args)
	if !ok {
		return nil
	}
	if _, isInstall := installVerbs[verb]; !isInstall {
		return nil
	}
	installs := []packagemanager.Install{}
	for _, tok := range rest {
		if argv.IsFlag(tok) {
			continue
		}
		installs = append(installs, pyspec.Parse(tok))
	}
	return installs
}
