// Package pip implements packagemanager.PackageManager for pip and pip3.
package pip

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/argv"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pyspec"
)

const binaryName = "pip"

var installVerbs = map[string]struct{}{
	"install":  {},
	"download": {},
}

// Manager parses pip install commands.
type Manager struct {
	name string
}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a pip Manager. binName lets callers register both "pip" and
// "pip3" with the same parser.
func New(binName string) *Manager {
	if binName == "" {
		binName = binaryName
	}
	return &Manager{name: binName}
}

// Name implements packagemanager.PackageManager.
func (m *Manager) Name() string { return m.name }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemPyPI }

// ParseInstalls implements packagemanager.PackageManager.
//
// @@TODO: expand -r requirements.txt and VCS URLs.
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
